"""Tests for the TOML config (v1.1): read/write round-trip, env
overrides, and the hand-rolled TOML writer."""

import os

import pytest

from kryonsec.config import (
    BUILTIN_TOOLS,
    KryonsecConfig,
    config_path,
    read_config,
    write_config,
)


@pytest.fixture()
def clean_env(monkeypatch):
    """These env vars override TOML — clear them for a clean test."""
    for var in ("OPENAI_API_KEY", "DATABASE_URL", "OLLAMA_HOST"):
        monkeypatch.delenv(var, raising=False)


def test_write_config_scalars_and_tables(tmp_path):
    path = tmp_path / "config.toml"
    write_config(path, {
        "version_note": "hello",
        "count": 3,
        "flag": True,
        "llm": {"provider": "openai", "key": 'has "quotes" and \\ backslash'},
        "tools": {"enabled": ["file_read", "web_search"]},
    })
    text = path.read_text(encoding="utf-8")
    # scalar keys must precede the first [table]
    assert text.splitlines()[0] == 'version_note = "hello"'
    assert "[llm]" in text
    assert "[tools]" in text

    data = read_config(path)
    assert data["version_note"] == "hello"
    assert data["count"] == 3
    assert data["flag"] is True
    assert data["llm"]["key"] == 'has "quotes" and \\ backslash'
    assert data["tools"]["enabled"] == ["file_read", "web_search"]


def test_write_config_rejects_unknown_type(tmp_path):
    with pytest.raises(TypeError):
        write_config(tmp_path / "x.toml", {"bad": {"nested": {"deeper": 1}}})


def test_read_config_missing_file_is_empty(tmp_path):
    assert read_config(tmp_path / "nope.toml") == {}


def test_read_config_corrupt_file_is_empty(tmp_path):
    path = tmp_path / "broken.toml"
    path.write_text("this is not [ valid toml", encoding="utf-8")
    assert read_config(path) == {}


def test_config_round_trip(tmp_path, clean_env):
    cfg = KryonsecConfig(home=tmp_path)
    cfg.provider = "openai"
    cfg.general_chat_model = "gpt-4o"
    cfg.openai_api_key = "sk-test"
    cfg.enabled_tools = ["file_read", "cve_lookup"]
    cfg.mcp_servers = [
        {"name": "fetch", "command": "mcp-server-fetch", "args": [], "env": {}},
        {"name": "custom", "command": "python s.py", "args": ["--flag"],
         "env": {"API_TOKEN": "tok-123"}},
    ]

    path = write_config(config_path(tmp_path), cfg.to_toml_dict())
    assert path.exists()

    loaded = KryonsecConfig.from_toml(read_config(path), home=tmp_path)
    assert loaded.provider == "openai"
    assert loaded.general_chat_model == "gpt-4o"
    assert loaded.openai_api_key == "sk-test"
    assert loaded.enabled_tools == ["file_read", "cve_lookup"]
    assert len(loaded.mcp_servers) == 2
    assert loaded.mcp_servers[0]["name"] == "fetch"
    assert loaded.mcp_servers[0]["command"] == "mcp-server-fetch"
    # env dict survives the TOML JSON-encoding round trip
    assert loaded.mcp_servers[1]["args"] == ["--flag"]
    assert loaded.mcp_servers[1]["env"] == {"API_TOKEN": "tok-123"}


def test_from_toml_defaults_when_partial(clean_env):
    cfg = KryonsecConfig.from_toml(
        {"llm": {"provider": "ollama", "chat_model": "ollama/llama3.1"}},
        home=None,
    )
    assert cfg.provider == "ollama"
    assert cfg.openai_api_key is None
    assert cfg.enabled_tools == list(BUILTIN_TOOLS)  # default: all on
    assert cfg.mcp_servers == []


def test_env_overrides_toml(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
    monkeypatch.setenv("OLLAMA_HOST", "http://env-host:11434")
    path = write_config(tmp_path / "config.toml", {
        "llm": {
            "provider": "openai",
            "openai_api_key": "sk-from-toml",
            "ollama_host": "http://toml-host:11434",
        },
    })
    cfg = KryonsecConfig.from_toml(read_config(path))
    assert cfg.openai_api_key == "sk-from-env"
    assert cfg.ollama_host == "http://env-host:11434"


def test_env_absent_toml_wins(tmp_path, clean_env):
    path = write_config(tmp_path / "config.toml", {
        "llm": {"openai_api_key": "sk-from-toml"},
    })
    cfg = KryonsecConfig.from_toml(read_config(path))
    assert cfg.openai_api_key == "sk-from-toml"


def test_save_writes_to_home(tmp_path, clean_env):
    cfg = KryonsecConfig(home=tmp_path)
    cfg.provider = "ollama"
    cfg.save()
    assert config_path(tmp_path).is_file()
    loaded = KryonsecConfig.from_toml(read_config(config_path(tmp_path)), home=tmp_path)
    assert loaded.provider == "ollama"
