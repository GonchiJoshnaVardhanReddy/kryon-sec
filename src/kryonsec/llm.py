"""LLM layer (spec v2.1.1 §7): LiteLLM router with provider routing.

House rule (spec §6.4): when secrets are present, compaction ALWAYS routes to
a local model. LLM calls for general chat prefer the configured model with a
local fallback when the preferred provider is unavailable.
"""

from __future__ import annotations

import logging
from typing import Any

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


def _quiet_litellm() -> None:
    """Stop litellm printing its 'Give Feedback / Get Help' banner on
    every failed call — the warning log already has the real error."""
    try:
        import litellm

        litellm.suppress_debug_info = True
    except Exception:
        pass


def completion_kwargs(
    cfg: KryonsecConfig,
    model: str,
    temperature: float = 0.0,
    tools: bool = False,
) -> dict[str, Any]:
    """Provider/shape kwargs shared by every litellm.completion call:
    the config.toml api key (litellm only reads the env var), the Ollama
    host, and the reasoning-model quirks above."""
    kwargs: dict[str, Any] = {}
    if model.startswith("ollama/"):
        kwargs["api_base"] = _normalize_host(cfg.ollama_host)
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

    kwargs may include `tools` (list of JSON-schema tool definitions) —
    passed straight through for the agent loop. The agent loop reads
    tool_calls itself from the raw response, so this helper stays the
    plain-text entry point.
    """
    import litellm

    _quiet_litellm()

    tool_schemas = kwargs.pop("tools", None)
    temperature = kwargs.pop("temperature", 0.0)
    call_kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "timeout": kwargs.pop("timeout", 30),
        "num_retries": kwargs.pop("num_retries", 0),  # we own the fallback chain
        **kwargs,
    }
    if tool_schemas:
        call_kwargs["tools"] = tool_schemas
        call_kwargs["tool_choice"] = kwargs.pop("tool_choice", "auto")
    call_kwargs.update(
        completion_kwargs(cfg, model, temperature, tools=bool(tool_schemas)))

    try:
        resp = litellm.completion(**call_kwargs)
    except Exception as e:
        log.warning("LLM call failed for %s: %s", model, e)
        raise
    try:
        return resp.choices[0].message.content or ""
    except (AttributeError, IndexError) as e:
        raise LlmUnavailable(f"malformed response from {model}: {e}") from e


class CompactionMustStayLocal(RuntimeError):
    """Secrets present and no local model available — refuse rather than
    send redacted-material upstream (spec §6.4)."""


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

    # ---- openai config: hosted API only ---------------------------------
    if model.startswith("ollama/"):
        model = cfg.general_chat_model  # never silently call a local model
    if not cfg.openai_api_key:
        raise LlmUnavailable(
            "OpenAI is the configured provider but no API key is set — "
            "run `kryonsec setup`"
        )
    try:
        return _complete(cfg, model, messages, **kwargs)
    except Exception:
        pass
    # same-provider fallback: the cheap search model, when it differs
    if cfg.general_search_model != model:
        log.warning("LLM %s failed; falling back to %s", model, cfg.general_search_model)
        try:
            return _complete(cfg, cfg.general_search_model, messages, **kwargs)
        except Exception:
            pass

    raise LlmUnavailable(
        "no OpenAI model answered — check the API key (`kryonsec setup`) "
        "or the network"
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
