"""Tests for the LLM fallback chain (spec §7.1, §6.4)."""

from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.llm import (
    CompactionMustStayLocal,
    _ollama_model_ok,
    chat,
    reset_provider_cache,
)


@pytest.fixture()
def cfg():
    reset_provider_cache()
    yield KryonsecConfig()
    reset_provider_cache()


def test_ollama_probed_once_and_skipped_when_dead(cfg):
    calls = []

    def fake_complete(cfg, model, messages, **kw):
        calls.append(model)
        if model.startswith("ollama/"):
            raise RuntimeError("ollama down")
        return "openai answer"

    with (
        patch("kryonsec.llm._complete", side_effect=fake_complete),
        patch("kryonsec.llm._ollama_model_ok", return_value=False),
        patch("kryonsec.llm._ollama_ok", return_value=False),
    ):
        assert chat(cfg, [], "ollama/llama3.1") == "openai answer"

    # dead ollama was skipped entirely — only the hosted fallback ran
    assert calls == ["gpt-4o-mini"]


def test_unpulled_model_skipped_without_calling_it(cfg):
    """Ollama is up, but llama3.1 was never pulled: /api/chat would hang —
    the router must skip the model instead of timing out on it."""
    calls = []

    def fake_complete(cfg, model, messages, **kw):
        calls.append(model)
        return "hosted answer"

    with (
        patch("kryonsec.llm._complete", side_effect=fake_complete),
        patch("kryonsec.llm._ollama_model_ok", side_effect=lambda c, m: "llama3.1" not in m),
    ):
        assert chat(cfg, [], "ollama/llama3.1") == "hosted answer"
    assert calls == ["gpt-4o-mini"]


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
