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


def chat(cfg: KryonsecConfig, messages: list[dict], model: str, **kwargs: Any) -> str:
    """Chat with a preferred model; fall back local -> third-party -> error."""
    if model.startswith("gpt") and not cfg.openai_api_key:
        log.info("OpenAI key absent; routing to local model %s", cfg.local_model)
        model = cfg.local_model

    try:
        return _complete(cfg, model, messages, **kwargs)
    except Exception:
        pass

    # Fallback chain: try the other provider before giving up.
    tried: list[str] = [model]
    candidates: list[str] = []
    if model != cfg.local_model:
        candidates.append(cfg.local_model)
    if cfg.openai_api_key and not model.startswith("gpt"):
        candidates.append(cfg.general_search_model)  # hosted fallback
    for candidate in candidates:
        if candidate in tried:
            continue
        log.warning("LLM %s failed; falling back to %s", model, candidate)
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
