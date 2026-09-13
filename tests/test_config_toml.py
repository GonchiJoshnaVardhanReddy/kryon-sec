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
    for var in (
        "OPENAI_API_KEY", "DATABASE_URL", "OLLAMA_HOST",
        "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
    ):
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
    # L23: tunables round-trip too
    assert loaded.max_session_tokens == cfg.max_session_tokens
    assert loaded.compaction_trigger_ratio == cfg.compaction_trigger_ratio
    assert loaded.max_tool_output_chars == cfg.max_tool_output_chars
    assert loaded.sandbox_image == cfg.sandbox_image
    assert len(loaded.mcp_servers) == 2
    assert loaded.mcp_servers[0]["name"] == "fetch"
    assert loaded.mcp_servers[0]["command"] == "mcp-server-fetch"
    # env dict survives the TOML JSON-encoding round trip
    assert loaded.mcp_servers[1]["args"] == ["--flag"]
    assert loaded.mcp_servers[1]["env"] == {"API_TOKEN": "tok-123"}


def test_config_empty_tools_round_trips_as_empty(tmp_path, clean_env):
    """M13 regression: deselecting ALL tools in the wizard writes
    enabled = []; on load it must NOT resurrect the default all-tools set
    (which includes file_write)."""
    cfg = KryonsecConfig(home=tmp_path)
    cfg.enabled_tools = []
    path = write_config(config_path(tmp_path), cfg.to_toml_dict())
    assert read_config(path)["tools"]["enabled"] == []

    loaded = KryonsecConfig.from_toml(read_config(path), home=tmp_path)
    assert loaded.enabled_tools == []


def test_config_changed_tunables_round_trip(tmp_path, clean_env):
    cfg = KryonsecConfig(home=tmp_path)
    cfg.max_session_tokens = 32000
    cfg.compaction_trigger_ratio = 0.9
    cfg.compaction_keep_tokens = 12000
    cfg.max_messages = 30
    cfg.max_tool_output_chars = 5000
    cfg.sandbox_image = "kryonsec/sandbox@sha256:" + "a" * 64
    path = write_config(config_path(tmp_path), cfg.to_toml_dict())

    loaded = KryonsecConfig.from_toml(read_config(path), home=tmp_path)
    assert loaded.max_session_tokens == 32000
    assert loaded.compaction_trigger_ratio == 0.9
    assert loaded.compaction_keep_tokens == 12000
    assert loaded.max_messages == 30
    assert loaded.max_tool_output_chars == 5000
    assert loaded.sandbox_image == cfg.sandbox_image


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


def test_api_keys_round_trip(tmp_path, clean_env):
    """Phase 2: Shodan/Censys keys land in the [api] table and reload."""
    cfg = KryonsecConfig(home=tmp_path)
    cfg.shodan_api_key = "sh-test-key"
    cfg.censys_api_id = "censys-id-1"
    cfg.censys_api_secret = "censys-secret-1"
    path = write_config(config_path(tmp_path), cfg.to_toml_dict())
    text = path.read_text(encoding="utf-8")
    assert "[api]" in text

    loaded = KryonsecConfig.from_toml(read_config(path), home=tmp_path)
    assert loaded.shodan_api_key == "sh-test-key"
    assert loaded.censys_api_id == "censys-id-1"
    assert loaded.censys_api_secret == "censys-secret-1"
    # Phase 8: the GitHub token rides along in the same [api] table
    cfg.github_token = "gh-test-token"
    path = write_config(config_path(tmp_path), cfg.to_toml_dict())
    assert "github_token" in path.read_text(encoding="utf-8")
    loaded = KryonsecConfig.from_toml(read_config(path), home=tmp_path)
    assert loaded.github_token == "gh-test-token"


def test_api_keys_env_overrides_toml(tmp_path, monkeypatch):
    for var in ("SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
                "GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SHODAN_API_KEY", "sh-from-env")
    monkeypatch.setenv("CENSYS_API_ID", "cid-from-env")
    monkeypatch.setenv("GITHUB_TOKEN", "gh-from-env")

    cfg = KryonsecConfig(home=tmp_path)
    cfg.shodan_api_key = "sh-from-toml"
    cfg.censys_api_id = "cid-from-toml"
    cfg.github_token = "gh-from-toml"
    path = write_config(config_path(tmp_path), cfg.to_toml_dict())
    loaded = KryonsecConfig.from_toml(read_config(path), home=tmp_path)
    assert loaded.shodan_api_key == "sh-from-env"
    assert loaded.censys_api_id == "cid-from-env"
    assert loaded.github_token == "gh-from-env"


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
