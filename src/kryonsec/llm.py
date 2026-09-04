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


def _ollama_ok(cfg: KryonsecConfig) -> bool:
    global _ollama_available
    if _ollama_available is None:
        host = _normalize_ollama_host(cfg.ollama_host)
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


def _normalize_ollama_host(host: str) -> str:
    """Litellm requires a scheme; OLLAMA_HOST is often set bare (host:port)."""
    host = host.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"http://{host}"
    return host


def _complete(cfg: KryonsecConfig, model: str, messages: list[dict], **kwargs: Any) -> str:
    """Call litellm.completion; return the assistant text."""
    import litellm

    call_kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": kwargs.pop("temperature", 0.0),
        "timeout": kwargs.pop("timeout", 30),
        "num_retries": kwargs.pop("num_retries", 0),  # we own the fallback chain
        **kwargs,
    }
    if model.startswith("ollama/"):
        call_kwargs["api_base"] = _normalize_ollama_host(cfg.ollama_host)

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
    """Chat with a preferred model; fall back local -> third-party -> error.

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

    if model.startswith("gpt") and not cfg.openai_api_key:
        log.info("OpenAI key absent; routing to local model %s", cfg.local_model)
        model = cfg.local_model

    # Dead-but-listening Ollama: skip it instead of waiting out the timeout.
    # (Also skip when the model simply isn't pulled — /api/chat hangs then.)
    skip_local = False
    if model.startswith("ollama/") and not _ollama_model_ok(cfg, model):
        skip_local = True
        model = ""  # go straight to the fallback chain

    if model:
        try:
            return _complete(cfg, model, messages, **kwargs)
        except Exception:
            pass

    # Fallback chain: try the other provider before giving up.
    tried: list[str] = [model] if model else []
    candidates: list[str] = []
    if not skip_local and model != cfg.local_model:
        candidates.append(cfg.local_model)
    if cfg.openai_api_key and not model.startswith("gpt"):
        candidates.append(cfg.general_search_model)  # hosted fallback
    for candidate in candidates:
        if candidate in tried or (
            candidate.startswith("ollama/") and not _ollama_model_ok(cfg, candidate)
        ):
            continue
        log.warning("LLM %s failed; falling back to %s", model or "(skipped)", candidate)
        try:
            return _complete(cfg, candidate, messages, **kwargs)
        except Exception:
            continue

    raise LlmUnavailable(
        "no LLM provider available — start Ollama (`ollama serve`, "
        "`ollama pull llama3.1`) or set OPENAI_API_KEY"
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
