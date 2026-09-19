"""LLM layer (spec v2.1.1 §7): LiteLLM router with provider routing.

House rule (spec §6.4): when secrets are present, compaction ALWAYS routes to
a local model. LLM calls for general chat prefer the configured model with a
local fallback when the preferred provider is unavailable.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from typing import Any, NamedTuple

from .config import KryonsecConfig

log = logging.getLogger(__name__)

# Per-process caches: is Ollama answering, and which models are pulled?
# A server can be listening on the port yet wedged, and /api/chat silently
# hangs when asked for a model that was never pulled — probe once, cache.
_ollama_available: bool | None = None
_ollama_models: list[str] | None = None


def reset_provider_cache() -> None:
    """Tests: forget the cached provider availability."""
    global _ollama_available, _ollama_models
    _ollama_available = None
    _ollama_models = None


def ollama_models(host: str) -> list[str] | None:
    """Models pulled on an Ollama server, or None when it is not
    answering (shared with the setup wizard)."""
    import json as _json
    import urllib.request

    normalized = _normalize_host(host)
    try:
        with urllib.request.urlopen(f"{normalized}/api/tags", timeout=2) as r:
            body = _json.loads(r.read())
            return [m.get("name", "") for m in body.get("models", [])]
    except Exception:
        return None


def _normalize_host(host: str) -> str:
    """Litellm requires a scheme; OLLAMA_HOST is often set bare (host:port)."""
    host = host.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"http://{host}"
    return host


# keep the old private name working (used across modules/tests)
_normalize_ollama_host = _normalize_host


# OpenAI reasoning-era models (gpt-5*, gpt-6*, o1/o3/o4*) have API quirks that
# are hard 400 errors: they reject `temperature`, and they reject function
# tools while a reasoning effort is active (must be 'none'). Detected by
# model id prefix — a rigid code rule, not a prompt hope.
_REASONING_PREFIXES = ("gpt-5", "gpt-6", "gpt-7", "o1", "o3", "o4", "o5")


def is_reasoning_model(model: str) -> bool:
    base = model.split("/")[-1].lower()
    return any(base.startswith(p) for p in _REASONING_PREFIXES)


def preload_litellm() -> threading.Thread:
    """Warm the litellm import in a daemon thread.

    `import litellm` loads every provider adapter and takes seconds (4-9s
    on a slow disk) — kryonsec imports it lazily at the first LLM call,
    which used to park that cost on the user's FIRST message. Starting
    the import here, while the user is still reading the banner/typing,
    hides it entirely. The thread is a no-op when litellm is already in
    sys.modules.
    """
    import sys

    if "litellm" in sys.modules:
        return _PRELOAD_DONE

    def _load() -> None:
        try:
            # litellm fetches its cost map over the network on import
            # (~3s extra) unless told to use the bundled copy
            os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
            import litellm  # noqa: F401 — the import IS the point

            _quiet_litellm()
        except Exception as e:  # not installed / broken env — the lazy
            # import later raises the same error with a real traceback
            log.info("litellm preload failed (will surface on first call): %s", e)

    t = threading.Thread(target=_load, name="litellm-preload", daemon=True)
    t.start()
    return t


_PRELOAD_DONE = threading.Thread()  # already-finished sentinel


def _quiet_litellm() -> None:
    """Apply the two process-wide litellm flags, once per call.

    suppress_debug_info: stop litellm printing its 'Give Feedback / Get
    Help' banner on every failed call — the warning log has the real error.

    drop_params: let litellm omit a parameter the model does not accept.
    We ask for temperature=0.0 because deterministic answers are the point
    for a security tool, but a growing number of models are fixed at
    temperature=1 and reject anything else as a hard 400 *before* the call
    is made — `global.anthropic.claude-fable-5` on Bedrock did exactly
    that, and it reached the user as "no AWS Bedrock model answered", which
    describes none of what happened. Which models carry the restriction is
    a list we cannot keep current: it changes with every provider release,
    and litellm already tracks it per model. Applying what litellm knows
    beats us guessing, and the temperature still goes out unchanged
    everywhere it is accepted.
    """
    try:
        import litellm

        litellm.suppress_debug_info = True
        litellm.drop_params = True
    except Exception:
        pass


# ---- Bedrock: kryonsec's model id vs the call litellm actually makes ------
#
# kryonsec's own model format is `bedrock/<model-id>`, and it stays that way
# everywhere a human sees it: config.toml, the wizard, the banner, the logs.
# It is unambiguous and it is what the provider-isolation checks key off.
#
# At the invocation boundary it has to become something else. litellm's
# native `bedrock/` route authenticates with SigV4 or with credentials it
# looks up itself, and a Bedrock API key is neither — it is an opaque bearer
# token. Handing that route a bearer token ends in an AttributeError from
# inside litellm's Converse handler before any request is sent. Bedrock
# answers this with an OpenAI-compatible Chat Completions endpoint, which
# takes the token as an ordinary `Authorization: Bearer`, so that is the
# call kryonsec makes.
BEDROCK_PREFIX = "bedrock/"
_BEDROCK_ROUTE = "openai/"
_BEDROCK_OPENAI_PATH = "/openai/v1"


def bedrock_openai_base(region: str) -> str:
    """Bedrock's OpenAI-compatible base URL for a region.

    The region lives in the host, which is why nothing here needs
    aws_region_name: the endpoint IS the region.
    """
    return f"https://bedrock-runtime.{region}.amazonaws.com{_BEDROCK_OPENAI_PATH}"


def litellm_model(cfg: KryonsecConfig, model: str) -> str:
    """kryonsec's model id -> the string litellm routes on.

    The one place the two formats meet, and the only translation in the
    system. `cfg` is unused for now and taken anyway so the signature does
    not have to change if a provider ever needs more than the id to route.
    """
    if model.startswith(BEDROCK_PREFIX):
        return _BEDROCK_ROUTE + model[len(BEDROCK_PREFIX):]
    return model


def completion_kwargs(
    cfg: KryonsecConfig,
    model: str,
    temperature: float = 0.0,
    tools: bool = False,
) -> dict[str, Any]:
    """Provider/shape kwargs shared by every litellm.completion call:
    the config.toml api key (litellm only reads the env var), the Ollama
    host, the Bedrock endpoint, and the reasoning-model quirks above.

    `model` is kryonsec's id — `bedrock/<id>`, not the routed `openai/<id>`
    litellm will actually be given. That distinction is load-bearing: the
    branches below key off the prefix, so handing this the routed string
    would match the OpenAI branch and send cfg.openai_api_key. Use
    build_call(), which produces the model string and these kwargs together.
    """
    kwargs: dict[str, Any] = {}
    if model.startswith("ollama/"):
        kwargs["api_base"] = _normalize_host(cfg.ollama_host)
    elif model.startswith(BEDROCK_PREFIX):
        # A Bedrock API key (ABSK…) is a bearer token and nothing else: there
        # is no access key, no secret key, no instance profile, and no SigV4
        # anywhere on this path. litellm's native bedrock/ route reaches for
        # static credentials and dies before it sends anything, so kryonsec
        # calls Bedrock's OpenAI-compatible Chat Completions endpoint instead.
        # The region travels in the URL, which is why aws_region_name is not
        # set here — it would be meaningless to an OpenAI-shaped request.
        #
        # api_base and api_key are set together, in this one branch, and
        # build_call() asserts they arrived. A routed `openai/<id>` that lost
        # its api_base would be sent to api.openai.com carrying the Bedrock
        # key, so the pair must never be able to drift apart.
        kwargs["api_base"] = bedrock_openai_base(cfg.bedrock_region)
        if cfg.bedrock_api_key:
            kwargs["api_key"] = cfg.bedrock_api_key
    elif cfg.openai_api_key:
        kwargs["api_key"] = cfg.openai_api_key
    if is_reasoning_model(model):
        if tools:
            # OpenAI: function tools need the effort off; litellm only
            # forwards reasoning_effort when it's in allowed_openai_params
            kwargs["reasoning_effort"] = "none"
            kwargs["allowed_openai_params"] = ["reasoning_effort"]
        # temperature unsupported — leave it out entirely
    else:
        kwargs["temperature"] = temperature
    return kwargs


def _ollama_ok(cfg: KryonsecConfig) -> bool:
    global _ollama_available
    if _ollama_available is None:
        host = _normalize_host(cfg.ollama_host)
        try:
            import json as _json
            import urllib.request

            with urllib.request.urlopen(f"{host}/api/tags", timeout=2) as r:
                body = _json.loads(r.read())
                _ollama_available = r.status == 200
                _ollama_models = [m.get("name", "") for m in body.get("models", [])]
        except Exception:
            _ollama_available = False
        if not _ollama_available:
            log.info("Ollama not answering at %s — skipping straight to fallback", host)
    return _ollama_available


def _ollama_model_ok(cfg: KryonsecConfig, model: str) -> bool:
    """True when the Ollama server is up AND the model is pulled.

    Model ids look like 'ollama/llama3.1'; /api/tags names like 'llama3.1:latest'.
    Match on the base name (before ':') so tags still match.
    """
    if not model.startswith("ollama/"):
        return True  # not an Ollama model — nothing to check here
    if not _ollama_ok(cfg):
        return False
    global _ollama_models
    if _ollama_models is None:
        return False
    base = model.split("/", 1)[1].split(":")[0]
    return any(name.split(":")[0] == base for name in _ollama_models)


class LlmUnavailable(RuntimeError):
    """No LLM provider could serve the request."""


def _complete(cfg: KryonsecConfig, model: str, messages: list[dict], **kwargs: Any) -> str:
    """Call litellm.completion; return the assistant text.

    `model` is kryonsec's id (`bedrock/<id>`); build_call turns it into the
    call litellm actually makes. kwargs may include `tools` (list of
    JSON-schema tool definitions) — passed straight through for the agent
    loop. The agent loop reads tool_calls itself from the raw response, so
    this helper stays the plain-text entry point.
    """
    import litellm

    _quiet_litellm()

    tool_schemas = kwargs.pop("tools", None)
    temperature = kwargs.pop("temperature", 0.0)
    call_kwargs: dict[str, Any] = {
        "messages": messages,
        "timeout": kwargs.pop("timeout", 30),
        "num_retries": kwargs.pop("num_retries", 0),  # we own the fallback chain
        **kwargs,
    }
    if tool_schemas:
        call_kwargs["tools"] = tool_schemas
        call_kwargs["tool_choice"] = kwargs.pop("tool_choice", "auto")
    call_kwargs.update(
        build_call(cfg, model, temperature, tools=bool(tool_schemas)))

    try:
        resp = litellm.completion(**call_kwargs)
    except Exception as e:
        # kryonsec's id, not the routed one: the log should say
        # `bedrock/…`, which is what the user configured and can search for.
        # The exception text is scrubbed — it is the provider's words, and
        # may quote the Authorization header back at us.
        log.warning("LLM call failed for %s: %s", model, scrub_secrets(str(e)))
        raise
    try:
        return resp.choices[0].message.content or ""
    except (AttributeError, IndexError) as e:
        raise LlmUnavailable(f"malformed response from {model}: {e}") from e


class SecretsMustStayLocal(RuntimeError):
    """Secrets are in the outgoing messages and no local model is up —
    refuse rather than send them to a third-party LLM (spec §6.4,
    CLAUDE.md rule 4)."""


# Credential shapes that must never reach a log line or an error shown to
# the user. Shape-based, not just literal: the text being scrubbed is
# usually a provider's own error, which may quote the request back —
# headers and all — and we did not compose it. The Bedrock API key is the
# one that matters most here, because the OpenAI-compatible route puts it
# in an Authorization header litellm can echo.
_SECRET_SHAPES = (
    re.compile(r"\bABSK[A-Za-z0-9+/=_\-]{4,}"),          # Bedrock API key
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"),              # OpenAI API key
    re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._\-+/=]{8,}"),
)


def scrub_secrets(text: str) -> str:
    """Replace anything credential-shaped with «redacted»."""
    for pattern in _SECRET_SHAPES:
        # group(1) exists only on the bearer pattern, where the scheme word
        # is worth keeping: "Bearer «redacted»" still says what was wrong
        text = pattern.sub(
            lambda m: (m.group(1) if m.groups() else "") + "«redacted»", text)
    return text


def build_call(
    cfg: KryonsecConfig,
    model: str,
    temperature: float = 0.0,
    tools: bool = False,
) -> dict[str, Any]:
    """Everything one litellm.completion needs for a kryonsec model id.

    The model string and its provider kwargs are produced together, here,
    so they cannot disagree: the kwargs are derived from kryonsec's id
    (which branch decides the credentials) while litellm is handed the
    routed one. Passing a routed `openai/<id>` to completion_kwargs instead
    would take the OpenAI branch and send cfg.openai_api_key to Bedrock.

    Callers must pass kryonsec's id, and must not pass `model=` themselves —
    it is in the returned dict.
    """
    call = completion_kwargs(cfg, model, temperature, tools=tools)
    call["model"] = litellm_model(cfg, model)

    if model.startswith(BEDROCK_PREFIX):
        if not cfg.bedrock_api_key:
            # Refuse before building the call rather than sending a keyless
            # request. litellm falls back to OPENAI_API_KEY from the
            # environment when no api_key is given, which would put an
            # OpenAI credential in an Authorization header aimed at AWS.
            raise LlmUnavailable(
                "AWS Bedrock is the configured provider but no API key is "
                "set — run `kryonsec setup`"
            )
        if not call.get("api_base"):
            # belt and braces: this is the shape that would leak the Bedrock
            # key to api.openai.com, so it must be impossible to construct
            raise LlmUnavailable(
                f"{model} would be sent to OpenAI without its Bedrock "
                "endpoint — refusing"
            )
    return call


def provider_reason(exc: BaseException | None, limit: int = 240) -> str:
    """The provider's own words for a failed call, shortened and scrubbed.

    A hosted failure is usually the provider *telling* you what is wrong —
    "Operation not allowed", "on-demand throughput isn't supported", a
    quota message. Replacing that with our own guess ("check the API key or
    the network") hides the one useful sentence, and the guess is often
    wrong: the first Bedrock user to hit "Operation not allowed" had a
    working key and a working network, and was told to check both.

    Everything returned here is scrubbed: this text is shown to the user and
    written to the log, and a provider error can quote the request back —
    headers included.
    """
    if exc is None:
        return "no response"
    text = " ".join(str(exc).split())
    if not text:
        return type(exc).__name__
    # litellm prefixes its own module path; the class name is already shown
    # by the caller, so drop the duplicate
    prefix = f"litellm.{type(exc).__name__}: "
    if text.startswith(prefix):
        text = text[len(prefix):]
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return scrub_secrets(text)


class CompactionMustStayLocal(SecretsMustStayLocal):
    """Secrets present and no local model available — refuse rather than
    send redacted-material upstream (spec §6.4)."""


def _secrets_in_messages(messages: list[dict]) -> bool:
    """True when any message content matches a secret pattern."""
    from .secrets import detect_secrets

    for m in messages:
        content = m.get("content")
        if isinstance(content, str) and detect_secrets(content):
            return True
    return False


def secrets_safe_model(
    cfg: KryonsecConfig, model: str, messages: list[dict]
) -> str:
    """The model to actually call for these messages (spec §6.4).

    When the outgoing messages contain secrets and the selected model is
    hosted, route to the local model; refuse (SecretsMustStayLocal) when
    no local model is available. Local (ollama/*) models pass through
    unchanged — this gate is the general form of the compaction rule.
    """
    if model.startswith("ollama/"):
        return model
    if not _secrets_in_messages(messages):
        return model
    if not _ollama_model_ok(cfg, cfg.local_model):
        raise SecretsMustStayLocal(
            "secrets detected in the conversation and the local model is "
            "unavailable — refusing to send them to a third-party provider "
            "(start Ollama: `ollama serve` and pull a model)"
        )
    log.warning("secrets detected — routing this call to the local model (spec §6.4)")
    return cfg.local_model


def secrets_safe_prompt(
    cfg: KryonsecConfig, model: str, prompt: str
) -> tuple[str, str]:
    """The (model, prompt) pair that is safe to send (spec §6.4).

    Single-prompt form of the secrets gate for the purple-team LLM states
    (HYPOTHESIZE, BLUE_TEAM), whose instructor path calls the provider
    directly and would otherwise bypass chat()'s gate. Secrets in the
    engagement data route to the local model; when no local model is up
    the prompt is REDACTED instead — redacted material may go upstream,
    raw secrets never (CLAUDE.md rule 4). Never raises, so a false-
    positive secret pattern in recon data cannot kill an LLM state.
    """
    from .secrets import detect_secrets, redact

    if model.startswith("ollama/") or not detect_secrets(prompt):
        return model, prompt
    if _ollama_model_ok(cfg, cfg.local_model):
        log.warning("secrets detected — routing this call to the local model (spec §6.4)")
        return cfg.local_model, prompt
    log.warning(
        "secrets detected and no local model up — sending a redacted "
        "prompt upstream (spec §6.4)")
    return model, redact(prompt)[0]


class _HostedProvider(NamedTuple):
    """What the hosted branch of chat() needs to know per provider."""

    label: str  # shown in errors, so the user knows which key to fix
    key_attr: str  # KryonsecConfig attribute holding the API key


# Hosted (third-party) providers. `ollama` is deliberately absent: it is the
# local branch, handled separately below.
_HOSTED_PROVIDERS: dict[str, _HostedProvider] = {
    "openai": _HostedProvider("OpenAI", "openai_api_key"),
    "bedrock": _HostedProvider("AWS Bedrock", "bedrock_api_key"),
}


def _owns_model(provider: str, model: str) -> bool:
    """True when `model` belongs to `provider` and may be called as-is.

    Provider isolation (v1.1): the provider chosen in setup is THE provider,
    so a model id carrying a different provider's prefix is rerouted to the
    configured chat model instead of silently calling someone else.
    """
    if provider == "bedrock":
        return model.startswith("bedrock/")
    # OpenAI ids are bare ("gpt-4o") or "openai/…" — anything carrying
    # another provider's prefix is not ours.
    return not model.startswith(("ollama/", "bedrock/"))


def chat(
    cfg: KryonsecConfig,
    messages: list[dict],
    model: str,
    local_only: bool = False,
    **kwargs: Any,
) -> str:
    """Chat with a preferred model. v1.1 provider isolation: the provider
    chosen in setup is THE provider — openai config never calls Ollama and
    an ollama config never calls a hosted API. Fallbacks stay inside the
    selected provider only.

    local_only=True restricts every attempt to the local model — used for
    compaction with secrets (spec §6.4: never a third-party provider).
    """
    if local_only:
        # Try the local model; a dead local is a hard error, not a fallback.
        try:
            return _complete(cfg, cfg.local_model, messages, **kwargs)
        except Exception as e:
            if not _ollama_ok(cfg):
                raise CompactionMustStayLocal(
                    "secrets present but local model unavailable — refusing to "
                    "summarize via a third-party provider (spec §6.4)"
                ) from e
            raise

    # ---- provider isolation first (v1.1): pick the branch's model ---------
    # secrets gate (spec §6.4 / CLAUDE.md rule 4) applies AFTER, so it can
    # override the branch's hosted choice with the local model — the one
    # sanctioned cross-provider move (secrets never leave the machine).
    secrets_present = _secrets_in_messages(messages)

    if cfg.provider == "ollama":
        # ---- ollama config: Ollama only, ever ---------------------------
        if not model.startswith("ollama/"):
            model = cfg.local_model
        if not _ollama_model_ok(cfg, model):
            # dead server or model not pulled — no other provider to try
            raise LlmUnavailable(
                f"Ollama unavailable or {model} not pulled — start it "
                "(`ollama serve`) and pull the model (`ollama pull llama3.1`)"
            )
        return _complete(cfg, model, messages, **kwargs)

    # ---- hosted config (openai | bedrock): that API only -----------------
    # An unrecognised provider value in config.toml falls back to the OpenAI
    # rules rather than calling something the user never chose.
    hosted = _HOSTED_PROVIDERS.get(cfg.provider, _HOSTED_PROVIDERS["openai"])
    if not _owns_model(cfg.provider, model):
        model = cfg.general_chat_model  # never silently call another provider
    if secrets_present:
        # never send the hosted call; local model or hard refusal
        model = secrets_safe_model(cfg, model, messages)
        return _complete(cfg, model, messages, **kwargs)
    if not getattr(cfg, hosted.key_attr, None):
        raise LlmUnavailable(
            f"{hosted.label} is the configured provider but no API key is "
            "set — run `kryonsec setup`"
        )
    last_error: BaseException | None = None
    try:
        return _complete(cfg, model, messages, **kwargs)
    except Exception as e:
        last_error = e
    # same-provider fallback: the cheap search model, when it differs
    if cfg.general_search_model != model:
        log.warning("LLM %s failed; falling back to %s", model, cfg.general_search_model)
        try:
            return _complete(cfg, cfg.general_search_model, messages, **kwargs)
        except Exception as e:
            last_error = e

    raise LlmUnavailable(
        f"no {hosted.label} model answered — {provider_reason(last_error)}"
    )


def compaction_model_for(cfg: KryonsecConfig, secrets_present: bool) -> str:
    """Spec §6.4: secrets present => local model, always."""
    if secrets_present:
        return cfg.local_model
    return cfg.compaction_model


def count_tokens(text: str, model: str = "gpt-4o-mini") -> int:
    """Token counting with conservative fallback (spec §6.3)."""
    try:
        import litellm

        return litellm.token_counter(model=model, text=text)
    except Exception:
        return len(text.encode("utf-8"))
