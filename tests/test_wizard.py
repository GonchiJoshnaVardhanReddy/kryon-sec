"""Tests for the setup wizard's pure layer: OpenAI key check, model
listing/filtering/sorting, Ollama model listing, and the scripted
plain-mode wizard flow."""

import json
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig, config_path, read_config
from kryonsec.wizard import (
    MCP_PRESETS,
    check_openai_key,
    list_openai_models,
    ollama_model_names,
    run_setup,
)

MODELS_PAYLOAD = {
    "data": [
        {"id": "gpt-4o", "created": 1715367049},
        {"id": "gpt-4o-mini", "created": 1721172741},
        {"id": "text-embedding-3-large", "created": 1705953180},
        {"id": "tts-1", "created": 1681940951},
        {"id": "whisper-1", "created": 1677532384},
        {"id": "gpt-3.5-turbo", "created": 1677610602},
        {"id": "omni-moderation-latest", "created": 1701160954},
    ]
}


def _patch_urlopen(monkeypatch, body: str, status: int = 200):
    class Resp:
        def __init__(self, body: str, status: int):
            self._body = body
            self.status = status

        def read(self):
            return self._body.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(req, timeout):
        return Resp(body, status)

    monkeypatch.setattr(
        "kryonsec.wizard.urllib.request.urlopen", fake)


def test_check_openai_key_ok(monkeypatch):
    _patch_urlopen(monkeypatch, json.dumps(MODELS_PAYLOAD))
    ok, msg = check_openai_key("sk-fine")
    assert ok and "works" in msg


def test_check_openai_key_empty():
    ok, msg = check_openai_key("  ")
    assert not ok
    assert "empty" in msg


def test_check_openai_key_rejected(monkeypatch):
    import urllib.error

    def raise_401(req, timeout):
        raise urllib.error.HTTPError(
            "url", 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(
        "kryonsec.wizard.urllib.request.urlopen", raise_401)
    ok, msg = check_openai_key("sk-bad")
    assert not ok
    assert "rejected" in msg


def test_list_openai_models_filters_and_sorts(monkeypatch):
    _patch_urlopen(monkeypatch, json.dumps(MODELS_PAYLOAD))
    models = list_openai_models("sk-fine")
    assert models is not None
    ids = [m["id"] for m in models]
    # non-chat models filtered out
    assert "text-embedding-3-large" not in ids
    assert "tts-1" not in ids
    assert "whisper-1" not in ids
    assert "omni-moderation-latest" not in ids
    # chat models present, most recent first
    assert ids.index("gpt-4o-mini") < ids.index("gpt-4o")
    assert ids.index("gpt-4o") < ids.index("gpt-3.5-turbo")


def test_list_openai_models_network_failure_is_none(monkeypatch):
    def boom(req, timeout):
        raise OSError("no network")

    monkeypatch.setattr(
        "kryonsec.wizard.urllib.request.urlopen", boom)
    assert list_openai_models("sk-fine") is None


def test_ollama_model_names(monkeypatch):
    monkeypatch.setattr("kryonsec.wizard.ollama_models",
                        lambda host: ["llama3.1:latest", "mistral:latest"])
    assert ollama_model_names("http://x:1") == [
        "llama3.1:latest", "mistral:latest"]


def test_ollama_model_names_server_down(monkeypatch):
    monkeypatch.setattr("kryonsec.wizard.ollama_models", lambda host: None)
    assert ollama_model_names("http://x:1") is None


def test_mcp_presets_have_required_fields():
    for preset in MCP_PRESETS:
        assert preset["name"]
        assert preset["command"]
        assert isinstance(preset["args"], list)
        assert isinstance(preset["env"], dict)


# ---- scripted plain-mode wizard flow ---------------------------------------

@pytest.fixture()
def scripted_wizard(monkeypatch, tmp_path):
    """Force plain-input mode and make the OpenAI key test pass."""
    monkeypatch.setattr("kryonsec.wizard._is_tty", lambda: False)
    monkeypatch.setattr("kryonsec.wizard.check_openai_key",
                        lambda key: (True, "key works"))
    monkeypatch.setattr(
        "kryonsec.wizard.list_openai_models",
        lambda key: [{"id": "gpt-4o-mini", "created": 2},
                     {"id": "gpt-4o", "created": 1}])

    def run(answers: list[str]) -> KryonsecConfig:
        cfg = KryonsecConfig(home=tmp_path)
        return run_setup(cfg, answers=answers)

    return run


def test_wizard_openai_flow_writes_config(scripted_wizard, tmp_path):
    # provider -> key -> model number -> tools -> mcp -> (no custom)
    cfg = scripted_wizard([
        "1",            # OpenAI
        "sk-test-123",  # api key
        "1",            # first model (gpt-4o-mini, most recent)
        "1,4",          # tools: file_read (1) + cve_lookup (4)
        "1",            # mcp: fetch preset only
    ])
    assert cfg.provider == "openai"
    assert cfg.openai_api_key == "sk-test-123"
    assert cfg.general_chat_model == "gpt-4o-mini"
    assert cfg.enabled_tools == ["file_read", "cve_lookup"]
    assert [s["name"] for s in cfg.mcp_servers] == ["fetch"]

    # config.toml written and reloads to the same values
    data = read_config(config_path(tmp_path))
    assert data["llm"]["provider"] == "openai"
    assert data["llm"]["openai_api_key"] == "sk-test-123"
    assert data["tools"]["enabled"] == ["file_read", "cve_lookup"]
    assert data["mcp"]["servers"][0]["name"] == "fetch"


def test_wizard_ollama_flow(scripted_wizard, monkeypatch, tmp_path):
    monkeypatch.setattr("kryonsec.wizard.ollama_model_names",
                        lambda host: ["llama3.1:latest", "mistral:latest"])
    cfg = scripted_wizard([
        "2",       # Ollama
        "1",       # llama3.1:latest
        "2,4",     # file_write, cve_lookup
        "",        # no MCP
    ])
    assert cfg.provider == "ollama"
    assert cfg.general_chat_model == "ollama/llama3.1"  # tag stripped
    assert cfg.local_model == "ollama/llama3.1"
    assert cfg.enabled_tools == ["file_write", "cve_lookup"]
    assert cfg.mcp_servers == []


def test_wizard_custom_mcp_server(scripted_wizard, tmp_path):
    cfg = scripted_wizard([
        "1", "sk-x", "1",
        "4",                 # cve_lookup
        "3,1",               # custom + fetch — picks __custom__ and fetch
        "myserver",          # custom name
        "python my_mcp.py",  # custom command
    ])
    names = [s["name"] for s in cfg.mcp_servers]
    assert "myserver" in names
    my = next(s for s in cfg.mcp_servers if s["name"] == "myserver")
    assert my["command"] == "python my_mcp.py"


def test_wizard_filesystem_mcp_asks_allowed_dir(scripted_wizard, tmp_path):
    cfg = scripted_wizard([
        "1", "sk-x", "1",
        "4",        # cve_lookup
        "2",        # mcp: filesystem preset
        "/home/me/projects",  # allowed directory
    ])
    fs = next(s for s in cfg.mcp_servers if s["name"] == "filesystem")
    assert fs["args"] == ["/home/me/projects"]


def test_wizard_filesystem_mcp_blank_uses_home(scripted_wizard, tmp_path):
    cfg = scripted_wizard([
        "1", "sk-x", "1",
        "4",   # cve_lookup
        "2",   # mcp: filesystem
        "",    # blank -> home directory
    ])
    fs = next(s for s in cfg.mcp_servers if s["name"] == "filesystem")
    assert fs["args"] == [str(Path.home())]


def test_wizard_filesystem_mcp_none_skips_server(scripted_wizard, tmp_path):
    cfg = scripted_wizard([
        "1", "sk-x", "1",
        "4",     # cve_lookup
        "1,2",   # fetch + filesystem
        "none",  # skip the filesystem tool
    ])
    names = [s["name"] for s in cfg.mcp_servers]
    assert names == ["fetch"]


def test_wizard_retries_bad_key(scripted_wizard, tmp_path, monkeypatch):
    calls: list[str] = []

    def fake_test(key):
        calls.append(key)
        return (False, "rejected (HTTP 401)") if len(calls) == 1 else (True, "key works")

    monkeypatch.setattr("kryonsec.wizard.check_openai_key", fake_test)
    cfg = scripted_wizard([
        "1",            # OpenAI
        "sk-bad",       # first key fails
        "y",            # retry
        "sk-good",      # second key works
        "1", "1,2,3,4", "1",
    ])
    assert cfg.openai_api_key == "sk-good"
    assert len(calls) == 2


def test_wizard_abort_on_key_failure(scripted_wizard, tmp_path, monkeypatch):
    monkeypatch.setattr("kryonsec.wizard.check_openai_key",
                        lambda key: (False, "rejected (HTTP 401)"))
    cfg = scripted_wizard([
        "1",       # OpenAI
        "sk-bad",  # fails
        "n",       # give up
    ])
    # aborted: provider set but nothing written
    assert cfg.provider == "openai"
    assert not config_path(tmp_path).is_file()

