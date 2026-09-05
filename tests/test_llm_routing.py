"""Tests for the LLM routing (spec §7.1, §6.4) — v1.1 strict provider
isolation: an openai config never calls Ollama and an ollama config never
calls a hosted API. Fallbacks stay inside the selected provider."""

from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.llm import (
    CompactionMustStayLocal,
    LlmUnavailable,
    _ollama_model_ok,
    chat,
    completion_kwargs,
    is_reasoning_model,
    reset_provider_cache,
)


@pytest.fixture()
def cfg():
    reset_provider_cache()
    c = KryonsecConfig()
    c.provider = "openai"
    c.general_chat_model = "gpt-4o"  # a hosted chat model (default is ollama/)
    c.openai_api_key = "sk-test"  # hosted API available (.env no longer auto-loads)
    yield c
    reset_provider_cache()


@pytest.fixture()
def ollama_cfg():
    reset_provider_cache()
    c = KryonsecConfig()
    c.provider = "ollama"
    c.openai_api_key = None  # isolation: nothing hosted is even configured
    yield c
    reset_provider_cache()


def test_ollama_provider_dead_ollama_is_a_hard_error(ollama_cfg):
    """Ollama config + dead Ollama = clear error, NOT a hosted fallback."""
    with (
        patch("kryonsec.llm._complete", side_effect=RuntimeError("ollama down")),
        patch("kryonsec.llm._ollama_model_ok", return_value=False),
    ):
        with pytest.raises(LlmUnavailable, match="[Oo]llama"):
            chat(ollama_cfg, [], "ollama/llama3.1")


def test_ollama_provider_never_calls_hosted(ollama_cfg):
    """Even a gpt-style model name routes to the local model — never
    silently out to a third-party API."""
    with (
        patch("kryonsec.llm._complete", return_value="local answer") as fake,
        patch("kryonsec.llm._ollama_model_ok", return_value=True),
    ):
        assert chat(ollama_cfg, [], "gpt-4o-mini") == "local answer"
    assert fake.call_args[0][1].startswith("ollama/")


def test_ollama_provider_unpulled_model_is_a_hard_error(ollama_cfg):
    """Server up but model not pulled: /api/chat would hang — raise a clear
    error instead of falling back or timing out."""
    with (
        patch("kryonsec.llm._complete", side_effect=RuntimeError("hang")),
        patch("kryonsec.llm._ollama_model_ok",
              side_effect=lambda c, m: "llama3.1" not in m),
    ):
        with pytest.raises(LlmUnavailable, match="not pulled"):
            chat(ollama_cfg, [], "ollama/llama3.1")


def test_openai_provider_ollama_model_rerouted_to_chat_model(cfg):
    """OpenAI config + an ollama/ model name = use the configured chat
    model, never a silent local call."""
    with patch("kryonsec.llm._complete", return_value="hosted answer") as fake:
        assert chat(cfg, [], "ollama/llama3.1") == "hosted answer"
    assert fake.call_args[0][1] == cfg.general_chat_model


def test_openai_provider_falls_back_within_provider(cfg):
    """Chat model fails -> the cheap search model (same provider) answers."""
    calls = []

    def fake_complete(c, model, messages, **kw):
        calls.append(model)
        if model == cfg.general_chat_model:
            raise RuntimeError("primary down")
        return "search-model answer"

    with patch("kryonsec.llm._complete", side_effect=fake_complete):
        assert chat(cfg, [], cfg.general_chat_model) == "search-model answer"
    assert calls == [cfg.general_chat_model, cfg.general_search_model]


def test_openai_provider_no_key_is_a_clear_error(cfg):
    cfg.openai_api_key = None
    with pytest.raises(LlmUnavailable, match="setup"):
        chat(cfg, [], "gpt-4o-mini")


def test_local_only_refuses_third_party_when_local_down(cfg):
    cfg.openai_api_key = "sk-test"  # third party IS available

    with (
        patch("kryonsec.llm._complete", side_effect=RuntimeError("ollama down")),
        patch("kryonsec.llm._ollama_ok", return_value=False),
    ):
        with pytest.raises(CompactionMustStayLocal):
            chat(cfg, [], "gpt-4o-mini", local_only=True)  # secrets path


def test_local_only_uses_local_when_alive(cfg):
    with (
        patch("kryonsec.llm._complete", return_value="local answer") as fake,
        patch("kryonsec.llm._ollama_ok", return_value=True),
    ):
        assert chat(cfg, [], "gpt-4o-mini", local_only=True) == "local answer"
    assert fake.call_args[0][1].startswith("ollama/")


def test_ollama_model_ok_matches_base_name(cfg):
    with patch("kryonsec.llm._ollama_ok", return_value=True), patch(
        "kryonsec.llm._ollama_models", ["llama3.1:latest", "mistral:7b"]
    ):
        assert _ollama_model_ok(cfg, "ollama/llama3.1")
        assert not _ollama_model_ok(cfg, "ollama/llama3")
        assert not _ollama_model_ok(cfg, "ollama/gemma2")
        # non-ollama models are not our business here
        assert _ollama_model_ok(cfg, "gpt-4o-mini")


# ---- completion_kwargs: provider + reasoning-model quirks -------------------

def test_is_reasoning_model_prefixes():
    assert is_reasoning_model("gpt-6-astra")
    assert is_reasoning_model("openai/gpt-6-astra")
    assert is_reasoning_model("gpt-5.5")
    assert is_reasoning_model("o3-mini")
    assert not is_reasoning_model("gpt-4o-mini")
    assert not is_reasoning_model("ollama/llama3.1")


def test_completion_kwargs_plain_model_gets_temperature(cfg):
    kw = completion_kwargs(cfg, "gpt-4o-mini")
    assert kw["temperature"] == 0.0
    assert kw["api_key"] == "sk-test"
    assert "reasoning_effort" not in kw


def test_completion_kwargs_reasoning_model_no_temperature(cfg):
    kw = completion_kwargs(cfg, "gpt-6-astra")
    assert "temperature" not in kw
    assert kw["api_key"] == "sk-test"


def test_completion_kwargs_reasoning_with_tools_sets_effort_none(cfg):
    kw = completion_kwargs(cfg, "gpt-6-astra", tools=True)
    assert kw["reasoning_effort"] == "none"
    # litellm refuses to forward reasoning_effort without this
    assert kw["allowed_openai_params"] == ["reasoning_effort"]
    assert "temperature" not in kw


def test_completion_kwargs_plain_with_tools_no_effort(cfg):
    kw = completion_kwargs(cfg, "gpt-4o-mini", tools=True)
    assert kw["temperature"] == 0.0
    assert "reasoning_effort" not in kw


def test_completion_kwargs_ollama_gets_api_base(cfg):
    cfg.ollama_host = "localhost:11434"
    kw = completion_kwargs(cfg, "ollama/llama3.1")
    assert kw["api_base"].endswith(":11434")
    assert "api_key" not in kw
