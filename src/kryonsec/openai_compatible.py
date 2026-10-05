"""OpenAI-compatible endpoint support: model listing, and the capability
probe the setup wizard runs before it saves a config.

Nothing in this file knows which server is on the other end, and that is the
point. LiteLLM, vLLM, llama.cpp, LM Studio, LocalAI and OpenRouter speak the
same protocol, and so does the gateway someone stood up this morning — so
there is no vendor table here to keep current, and no branch that keys off a
name or an address (llm.py holds the same rule for routing).

The probe is deliberately three-valued. "The server accepted the `tools`
parameter" is not "the model will use tools", and a model that answers a
tool-shaped prompt in plain text has told us nothing. Those cases report
unknown rather than a False that would read as "broken" — the spec's rule,
and the honest one.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass

from .config import KryonsecConfig
from .llm import normalize_base_url, provider_reason

log = logging.getLogger(__name__)

PROBE_TIMEOUT_S = 10

# A server accepting `stream=true` is not the claim "kryonsec can consume a
# stream", and kryonsec cannot: there is no streaming path in the codebase.
# The probe reports the SERVER's capability because that is what it can
# observe; this constant is the kryonsec-side answer, kept beside it so no
# caller or reader can mistake one for the other. It is not a config knob —
# it changes when a streaming path is actually written.
KRYONSEC_SUPPORTS_STREAMING = False

# One trivial tool, used only to ask "does this server take tools at all?".
# The shape is the OpenAI wire format the agent loop already sends
# (copilot/agent.py), so a server that answers here is answering the real
# question. It is never executed by anything.
_PROBE_TOOL = {
    "type": "function",
    "function": {
        "name": "kryonsec_probe",
        "description": "Probe tool. Never executed.",
        "parameters": {
            "type": "object",
            "properties": {"echo": {"type": "string"}},
            "required": ["echo"],
        },
    },
}
_PROBE_TOOL_PROMPT = "Call the kryonsec_probe tool with echo set to 'ok'."

# A 400 in reply to a tools request, after a plain request to the same model
# already succeeded, is the server saying it does not take the parameter.
# Matched by class name — bedrock.py reads litellm's error taxonomy the same
# way rather than importing a private hierarchy for one check.
_REJECTED_PARAM_ERRORS = ("BadRequestError", "UnsupportedParamsError")


def _auth_headers(api_key: str | None) -> dict[str, str]:
    """The header an OpenAI-compatible endpoint expects, or none at all.

    Never logged, never echoed: this is the only place the configured key
    becomes a header, and callers only ever pass it straight to urlopen.
    """
    return {"Authorization": f"Bearer {api_key}"} if api_key else {}


def list_models(base_url: str, api_key: str | None = None) -> list[str] | None:
    """Model ids from ``GET <base>/models``, or None when the endpoint did
    not answer.

    Never raises. A server that cannot list models is common enough — some
    gateways do not implement the route — and that is not a failure the
    wizard should stop on; it just means the user types the model name
    instead of picking one.
    """
    base = normalize_base_url(base_url)
    if not base:
        return None
    req = urllib.request.Request(f"{base}/models", headers=_auth_headers(api_key))
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT_S) as r:
            data = json.loads(r.read())
    except Exception:
        return None
    entries = data.get("data", data.get("models", []))
    if not isinstance(entries, list):
        return None
    ids = [e.get("id") or e.get("name") for e in entries if isinstance(e, dict)]
    return [i for i in ids if i]


@dataclass
class Capabilities:
    """What an endpoint actually answered — not what its software claims.

    ``tools`` and ``streaming`` are three-valued on purpose: True (the probe
    got a positive answer), False (the server refused the parameter), None
    (no verdict). None is a real result, not a missing one.

    ``streaming`` is the *server's* capability. Whether kryonsec can use a
    stream is a separate question with a separate answer —
    ``kryonsec_streaming`` — because a server that accepts ``stream=true``
    does not make streaming a kryonsec feature.
    """

    connected: bool = False
    answers: bool = False
    tools: bool | None = None
    streaming: bool | None = None
    detail: str = ""

    @property
    def kryonsec_streaming(self) -> bool:
        """Whether kryonsec can consume a stream from this endpoint.

        Always False: no probe result can turn this on, which is the point.
        Read this — not ``streaming`` — when asking what kryonsec will do.
        """
        return KRYONSEC_SUPPORTS_STREAMING


def _rejected_parameter(exc: BaseException) -> bool:
    return type(exc).__name__ in _REJECTED_PARAM_ERRORS


def _probe_tools(cfg: KryonsecConfig, model: str) -> bool | None:
    import litellm

    from .llm import _quiet_litellm, build_call

    _quiet_litellm()
    try:
        resp = litellm.completion(
            messages=[{"role": "user", "content": _PROBE_TOOL_PROMPT}],
            tools=[_PROBE_TOOL],
            tool_choice="auto",
            timeout=PROBE_TIMEOUT_S,
            num_retries=0,
            **build_call(cfg, model, tools=True),
        )
    except Exception as e:
        # The server answered and said no -> False. Anything else (network,
        # auth, a rate limit) says nothing about tools -> None.
        return False if _rejected_parameter(e) else None
    try:
        return bool(resp.choices[0].message.tool_calls)
    except Exception:
        return None


def _probe_streaming(cfg: KryonsecConfig, model: str) -> bool | None:
    """True when chunks arrived, False when the server refused stream=True,
    None when there was no verdict. The stream is closed right away and
    nothing is accumulated from it."""
    import litellm

    from .llm import _quiet_litellm, build_call

    _quiet_litellm()
    try:
        stream = litellm.completion(
            messages=[{"role": "user", "content": "hi"}],
            stream=True,
            max_tokens=1,
            timeout=PROBE_TIMEOUT_S,
            num_retries=0,
            **build_call(cfg, model),
        )
    except Exception as e:
        return False if _rejected_parameter(e) else None
    try:
        return True if next(iter(stream), None) is not None else None
    except Exception:
        return None
    finally:
        close = getattr(stream, "close", None)
        if close:
            try:
                close()
            except Exception:
                pass


def probe(cfg: KryonsecConfig, model: str) -> Capabilities:
    """Ask a configured endpoint what it can do. Never raises.

    The plain completion goes through ``llm._complete`` — the same call path
    kryonsec uses at run time — so ``answers`` means "the call kryonsec will
    actually make works", timeout and parameters included, rather than "the
    server responded to something".

    Each later check is skipped when an earlier one had no verdict: probing
    tools on an endpoint that could not answer a message would only produce
    three more no-verdicts, and one detail line that says so is more useful
    than four.
    """
    from .llm import _complete

    caps = Capabilities()
    base = normalize_base_url(cfg.openai_compatible_base_url or "")
    if not base or not model:
        caps.detail = "no base URL or model configured"
        return caps

    caps.connected = list_models(base, cfg.openai_compatible_api_key) is not None

    try:
        _complete(
            cfg,
            model,
            [{"role": "user", "content": "hi"}],
            max_tokens=1,
            timeout=PROBE_TIMEOUT_S,
        )
    except Exception as e:
        caps.detail = provider_reason(e)
        return caps
    # A chat completion is proof of connection even when /models is missing.
    caps.answers = True
    caps.connected = True

    caps.tools = _probe_tools(cfg, model)
    caps.streaming = _probe_streaming(cfg, model)
    return caps


def format_capabilities(caps: Capabilities) -> str:
    """The probe result as indented rich-markup lines (wizard and doctor
    both read the same three-valued answers, so they render them the same
    way)."""

    def mark(value: bool | None) -> str:
        if value is True:
            return "[green]yes[/green]"
        if value is False:
            return "[red]no[/red]"
        return "[yellow]unknown[/yellow]"

    lines = [
        f"  connection            {mark(caps.connected)}",
        f"  model response        {mark(caps.answers)}",
        f"  tool calling          {mark(caps.tools)}",
        f"  server streaming      {mark(caps.streaming)}",
        # Every row above answers for the SERVER. A bare "streaming yes" read
        # as "kryonsec can stream", which would be a claim about a feature
        # that does not exist — so the kryonsec-side answer is stated.
        "  [dim]kryonsec streaming is unimplemented — the rows above "
        "describe the endpoint.[/dim]",
    ]
    if caps.detail:
        lines.append(f"  [dim]{caps.detail}[/dim]")
    return "\n".join(lines)
