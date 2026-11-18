"""Real model discovery and safe switching for the workspace.

Nothing here invents availability.  Every provider branch either asks the
provider what it has, or refuses with the reason it could not be asked.
Switching changes only ``provider`` and ``general_chat_model`` — the local
fallback, search model, compaction model, session ids, and history are
untouched.  The change is written with ``KryonsecConfig.save()`` (atomic,
mode 600); if the write fails the previous selection is restored.
"""

from __future__ import annotations

from typing import Any

from .config import KryonsecConfig

PROVIDERS: dict[str, str] = {
    "openai": "OpenAI",
    "ollama": "Ollama",
    "bedrock": "AWS Bedrock",
    "openai_compatible": "OpenAI-compatible endpoint",
}


def provider_label(provider: str) -> str:
    return PROVIDERS.get(provider, provider or "not configured")


def _ollama_models(host: str) -> list[str] | None:
    from .llm import ollama_models

    return ollama_models(host)


def _openai_models(key: str) -> list[dict[str, Any]] | None:
    from .wizard import list_openai_models

    return list_openai_models(key)


def _bedrock_models(key: str, region: str) -> list[dict[str, Any]] | None:
    from .bedrock import list_bedrock_models

    return list_bedrock_models(key, region)


def _compatible_models(base_url: str, key: str | None) -> list[str] | None:
    from .openai_compatible import list_models

    return list_models(base_url, key)


def _bedrock_id(model_id: str) -> str:
    from .bedrock import format_model_id

    return format_model_id(model_id)


def _base_model_name(provider: str, model: str) -> str:
    value = str(model or "").strip()
    if provider == "ollama" and value.startswith("ollama/"):
        value = value[len("ollama/"):]
    elif provider == "bedrock" and value.startswith("bedrock/"):
        value = value[len("bedrock/"):]
    return value


def normalize_model(provider: str, model: str) -> str:
    """The config spelling for a model id, matching setup's rules."""
    value = str(model or "").strip()
    if not value:
        return ""
    if provider == "ollama":
        value = _base_model_name(provider, value)
        if value.endswith(":latest"):
            value = value[: -len(":latest")]
        return f"ollama/{value}"
    if provider == "bedrock":
        return _bedrock_id(_base_model_name(provider, value))
    if provider == "openai":
        if value.startswith("openai/"):
            value = value[len("openai/"):]
        if value.startswith("gpt"):
            return value
        return f"openai/{value}"
    return value


def discover_models(
    cfg: KryonsecConfig, provider: str
) -> tuple[list[str] | None, str]:
    """(model ids as the provider reports them, "") or (None, reason).

    ``[]`` is a real answer: the provider replied but offers nothing
    usable.  ``None`` means discovery itself was impossible.
    """
    provider = str(provider or "").strip().lower()
    if provider not in PROVIDERS:
        return None, f"unknown provider {provider!r}; choose one of {', '.join(PROVIDERS)}"
    if provider == "ollama":
        names = _ollama_models(cfg.ollama_host)
        if names is None:
            return None, (
                f"Ollama is not answering at {cfg.ollama_host}. "
                "Start it (`ollama serve`) and pull a model, then try again."
            )
        return sorted(set(names)), ""
    if provider == "openai":
        if not cfg.openai_api_key:
            return None, "No OpenAI API key is set. Run `kryonsec setup` or choose another provider."
        data = _openai_models(cfg.openai_api_key)
        if data is None:
            return None, "OpenAI model discovery failed. Check the API key and network."
        return sorted({str(row.get("id")) for row in data if row.get("id")}), ""
    if provider == "bedrock":
        if not cfg.bedrock_api_key:
            return None, "No AWS Bedrock API key is set. Run `kryonsec setup` or choose another provider."
        data = _bedrock_models(cfg.bedrock_api_key, cfg.bedrock_region)
        if data is None:
            return None, "AWS Bedrock model discovery failed. Check the key and region."
        return sorted({_bedrock_id(str(row.get("id"))) for row in data if row.get("id")}), ""
    if not cfg.openai_compatible_base_url:
        return None, "No OpenAI-compatible endpoint is configured. Run `kryonsec setup`."
    models = _compatible_models(
        cfg.openai_compatible_base_url, cfg.openai_compatible_api_key
    )
    if models is None:
        return None, (
            "The endpoint did not list models. Type the exact model name "
            "your server expects."
        )
    return sorted(set(models)), ""


def verify_model(
    cfg: KryonsecConfig, provider: str, model: str
) -> tuple[str | None, str]:
    """Validate one requested switch against the provider's real answer.

    On success the second value is an informational note (usually empty).
    On failure the first value is None and the second is the reason.
    """
    provider = str(provider or "").strip().lower()
    requested = _base_model_name(provider, model)
    if not requested:
        return None, "A model name is required."
    available, reason = discover_models(cfg, provider)
    if available is None:
        # Some OpenAI-compatible gateways do not implement GET /models.  The
        # setup wizard already handles that by asking for the name directly;
        # honour the same contract here, but say plainly that it is unverified.
        if provider == "openai_compatible" and cfg.openai_compatible_base_url:
            return (
                normalize_model(provider, requested),
                "the endpoint did not list models, so this name was not "
                "verified against the server",
            )
        return None, reason
    # Providers spell the same model differently (`llama3.1` vs
    # `llama3.1:latest`, bare vs `ollama/`).  Compare the config spelling so a
    # real listed model is not rejected over a suffix.
    wanted = normalize_model(provider, requested)
    matches = [item for item in available if normalize_model(provider, item) == wanted]
    if not matches:
        shown = ", ".join(available[:8]) or "none"
        more = "" if len(available) <= 8 else f" … and {len(available) - 8} more"
        return None, (
            f"{provider_label(provider)} does not list {requested!r}. "
            f"Available: {shown}{more}. Run /models list to see the full list."
        )
    return normalize_model(provider, matches[0]), ""


def switch_model(
    cfg: KryonsecConfig, provider: str, model: str
) -> tuple[bool, str]:
    """Switch provider+chat model, persist atomically, or keep the old one."""
    provider = str(provider or "").strip().lower()
    if provider not in PROVIDERS:
        return False, (
            f"Unknown provider {provider!r}. Choose one of: {', '.join(PROVIDERS)}."
        )
    normalized, note = verify_model(cfg, provider, model)
    if normalized is None:
        return False, note
    old_provider, old_model = cfg.provider, cfg.general_chat_model
    if provider == old_provider and normalized == old_model:
        return True, f"Already using {provider_label(provider)} · {normalized}."
    cfg.provider = provider
    cfg.general_chat_model = normalized
    try:
        cfg.save()
    except Exception as exc:
        cfg.provider, cfg.general_chat_model = old_provider, old_model
        return False, (
            f"Model switch was not saved ({type(exc).__name__}); "
            "the previous selection is still active."
        )
    message = (
        f"Model set to {provider_label(provider)} · {normalized} and saved. "
        "Local fallback, search, and compaction models are unchanged."
    )
    if note:
        message = f"{message} Note: {note}."
    return True, message


def current_model_view(cfg: KryonsecConfig) -> dict[str, str]:
    return {
        "provider": cfg.provider,
        "provider_label": provider_label(cfg.provider),
        "model": cfg.general_chat_model or "(not configured)",
        "local_fallback": cfg.local_model,
        "search_model": cfg.general_search_model,
        "compaction_model": cfg.compaction_model,
    }


__all__ = [
    "PROVIDERS",
    "current_model_view",
    "discover_models",
    "normalize_model",
    "provider_label",
    "switch_model",
    "verify_model",
]
