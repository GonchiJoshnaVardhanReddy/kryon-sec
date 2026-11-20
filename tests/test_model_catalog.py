"""Model discovery and switching contracts.

Every provider answer is mocked.  These tests never contact a real model
provider, never read a real API key, and never write outside tmp_path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from kryonsec import model_catalog
from kryonsec.config import KryonsecConfig, config_path
from kryonsec.model_catalog import (
    current_model_view,
    discover_models,
    normalize_model,
    switch_model,
    verify_model,
)


@pytest.fixture()
def cfg(tmp_path: Path) -> KryonsecConfig:
    value = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    value.provider = "openai"
    value.general_chat_model = "gpt-4o-mini"
    value.general_search_model = "gpt-4o-mini"
    value.compaction_model = "gpt-4o-mini"
    value.local_model = "ollama/llama3.1"
    value.openai_api_key = "test-key"
    return value


def test_normalize_model_matches_setup_spelling():
    assert normalize_model("ollama", "llama3.1:latest") == "ollama/llama3.1"
    assert normalize_model("ollama", "ollama/llama3.1") == "ollama/llama3.1"
    assert normalize_model("openai", "gpt-4o") == "gpt-4o"
    assert normalize_model("openai", "openai/gpt-4o") == "gpt-4o"
    assert normalize_model("openai_compatible", "my-model") == "my-model"
    assert normalize_model("ollama", "") == ""


def test_discover_ollama_returns_real_names(monkeypatch):
    monkeypatch.setattr(model_catalog, "_ollama_models", lambda host: ["b:latest", "a:latest"])
    models, reason = discover_models(KryonsecConfig(), "ollama")
    assert models == ["a:latest", "b:latest"]
    assert reason == ""


def test_discover_ollama_down_returns_a_reason(monkeypatch):
    monkeypatch.setattr(model_catalog, "_ollama_models", lambda host: None)
    models, reason = discover_models(KryonsecConfig(), "ollama")
    assert models is None
    assert "not answering" in reason


def test_discover_openai_without_key_refuses_without_a_call(monkeypatch, cfg):
    cfg.openai_api_key = None
    called = False

    def never(_key):
        nonlocal called
        called = True
        return []

    monkeypatch.setattr(model_catalog, "_openai_models", never)
    models, reason = discover_models(cfg, "openai")
    assert models is None
    assert "No OpenAI API key" in reason
    assert called is False


def test_unknown_provider_is_named(cfg):
    models, reason = discover_models(cfg, "made-up")
    assert models is None
    assert "unknown provider" in reason


def test_switch_model_persists_only_provider_and_chat_model(monkeypatch, cfg):
    monkeypatch.setattr(
        model_catalog, "_ollama_models", lambda host: ["llama3.1:latest", "phi3:latest"]
    )
    before = {
        "search": cfg.general_search_model,
        "compaction": cfg.compaction_model,
        "local": cfg.local_model,
        "history": "unchanged",
    }
    ok, message = switch_model(cfg, "ollama", "llama3.1")
    assert ok, message
    assert cfg.provider == "ollama"
    assert cfg.general_chat_model == "ollama/llama3.1"
    assert cfg.general_search_model == before["search"]
    assert cfg.compaction_model == before["compaction"]
    assert cfg.local_model == before["local"]
    assert config_path(cfg.home).is_file()


def test_switch_model_refuses_a_model_the_provider_does_not_list(monkeypatch, cfg):
    monkeypatch.setattr(model_catalog, "_openai_models", lambda key: [{"id": "gpt-4o"}])
    ok, message = switch_model(cfg, "openai", "gpt-does-not-exist")
    assert ok is False
    assert "does not list" in message
    assert cfg.provider == "openai"
    assert cfg.general_chat_model == "gpt-4o-mini"


def test_switch_model_restores_the_previous_selection_when_save_fails(monkeypatch, cfg):
    monkeypatch.setattr(model_catalog, "_openai_models", lambda key: [{"id": "gpt-4o"}])

    def explode():
        raise OSError("disk full")

    monkeypatch.setattr(cfg, "save", explode)
    ok, message = switch_model(cfg, "openai", "gpt-4o")
    assert ok is False
    assert "previous selection" in message
    assert cfg.provider == "openai"
    assert cfg.general_chat_model == "gpt-4o-mini"


def test_openai_compatible_unlisted_model_is_allowed_but_marked_unverified(monkeypatch, cfg):
    cfg.provider = "openai_compatible"
    cfg.general_chat_model = "old-model"
    cfg.openai_compatible_base_url = "http://localhost:8000/v1"
    monkeypatch.setattr(model_catalog, "_compatible_models", lambda base, key: None)

    ok, message = switch_model(cfg, "openai_compatible", "typed-model")
    assert ok is True
    assert cfg.general_chat_model == "typed-model"
    assert "not verified" in message


def test_openai_compatible_without_a_base_url_is_refused(monkeypatch, cfg):
    cfg.openai_compatible_base_url = None
    models, reason = discover_models(cfg, "openai_compatible")
    assert models is None
    assert "No OpenAI-compatible endpoint" in reason
    normalized, problem = verify_model(cfg, "openai_compatible", "anything")
    assert normalized is None
    assert "No OpenAI-compatible endpoint" in problem


def test_verify_model_returns_the_normalized_match(monkeypatch, cfg):
    monkeypatch.setattr(model_catalog, "_openai_models", lambda key: [{"id": "gpt-4o"}])
    normalized, note = verify_model(cfg, "openai", "gpt-4o")
    assert normalized == "gpt-4o"
    assert note == ""


def test_current_model_view_is_honest_about_defaults(cfg):
    cfg.general_chat_model = ""
    view = current_model_view(cfg)
    assert view["model"] == "(not configured)"
    assert view["local_fallback"] == "ollama/llama3.1"
