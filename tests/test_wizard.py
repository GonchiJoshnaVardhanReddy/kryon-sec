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
    # provider -> key -> model number -> tools -> mcp -> (no custom) -> no api keys
    cfg = scripted_wizard([
        "1",            # OpenAI
        "sk-test-123",  # api key
        "1",            # first model (gpt-4o-mini, most recent)
        "1,4",          # tools: file_read (1) + cve_lookup (4)
        "1",            # mcp: fetch preset only
        "n",            # skip passive-recon API keys
    ])
    assert cfg.provider == "openai"
    assert cfg.openai_api_key == "sk-test-123"
    assert cfg.general_chat_model == "gpt-4o-mini"
    # H2: search/compaction reuse the chosen chat model, not hardcoded gpt-4o-mini
    assert cfg.general_search_model == "gpt-4o-mini"  # == the chosen model here
    assert cfg.compaction_model == "gpt-4o-mini"
    assert cfg.enabled_tools == ["file_read", "cve_lookup"]
    assert [s["name"] for s in cfg.mcp_servers] == ["fetch"]

    # config.toml written and reloads to the same values
    data = read_config(config_path(tmp_path))
    assert data["llm"]["provider"] == "openai"
    assert data["llm"]["openai_api_key"] == "sk-test-123"
    assert data["tools"]["enabled"] == ["file_read", "cve_lookup"]
    assert data["mcp"]["servers"][0]["name"] == "fetch"


def test_wizard_ollama_down_loops_back_to_openai(scripted_wizard, monkeypatch, tmp_path):
    """Ollama picked but not running must NOT abort setup — the wizard
    loops back to the provider question so OpenAI can be picked instead."""
    monkeypatch.setattr("kryonsec.wizard.ollama_model_names", lambda host: None)
    cfg = scripted_wizard([
        "2",            # Ollama — server down
        "1",            # loop back: pick OpenAI instead
        "sk-test-456",  # api key
        "1",            # first model
        "",             # no tools
        "",             # no MCP
        "n",            # no passive-recon API keys
    ])
    assert cfg.provider == "openai"
    assert cfg.openai_api_key == "sk-test-456"
    assert config_path(tmp_path).is_file()


def test_wizard_ollama_flow(scripted_wizard, monkeypatch, tmp_path):
    monkeypatch.setattr("kryonsec.wizard.ollama_model_names",
                        lambda host: ["llama3.1:latest", "mistral:latest"])
    # a stale OpenAI key from a previous setup must not survive Ollama setup
    monkeypatch.setenv("OPENAI_API_KEY", "sk-stale-from-before")
    cfg = scripted_wizard([
        "2",       # Ollama
        "1",       # llama3.1:latest
        "2,4",     # file_write, cve_lookup
        "",        # no MCP
        "n",       # no passive-recon API keys
    ])
    assert cfg.provider == "ollama"
    assert cfg.general_chat_model == "ollama/llama3.1"  # implicit :latest stripped
    assert cfg.local_model == "ollama/llama3.1"
    # M1: picking Ollama clears any stale OpenAI key (strict isolation)
    assert cfg.openai_api_key is None
    assert cfg.enabled_tools == ["file_write", "cve_lookup"]
    assert cfg.mcp_servers == []


def test_wizard_ollama_keeps_explicit_tag(scripted_wizard, monkeypatch, tmp_path):
    """M12 regression: 'llama3.1:8b' must NOT be stripped to 'llama3.1' —
    a bare name resolves to :latest, a model the user never pulled."""
    monkeypatch.setattr("kryonsec.wizard.ollama_model_names",
                        lambda host: ["llama3.1:8b", "mistral:latest"])
    cfg = scripted_wizard([
        "2",       # Ollama
        "1",       # llama3.1:8b
        "2,4",     # file_write, cve_lookup
        "",        # no MCP
        "n",       # no passive-recon API keys
    ])
    assert cfg.general_chat_model == "ollama/llama3.1:8b"  # tag preserved
    assert cfg.local_model == "ollama/llama3.1:8b"


def test_wizard_provider_o_means_ollama(scripted_wizard, monkeypatch, tmp_path):
    """L20 regression: plain-mode 'o' reads as Ollama, never OpenAI."""
    monkeypatch.setattr("kryonsec.wizard.ollama_model_names",
                        lambda host: ["llama3.1:latest"])
    cfg = scripted_wizard([
        "o",       # ambiguous abbreviation — must be Ollama
        "1",       # llama3.1
        "",        # no tools
        "",        # no MCP
        "n",       # no passive-recon API keys
    ])
    assert cfg.provider == "ollama"


def test_wizard_custom_mcp_server(scripted_wizard, tmp_path):
    cfg = scripted_wizard([
        "1", "sk-x", "1",
        "4",                 # cve_lookup
        "3,1",               # custom + fetch — picks __custom__ and fetch
        "myserver",          # custom name
        "python my_mcp.py",  # custom command
        "n",                 # no passive-recon API keys
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
        "n",        # no passive-recon API keys
    ])
    fs = next(s for s in cfg.mcp_servers if s["name"] == "filesystem")
    assert fs["args"] == ["/home/me/projects"]


def test_wizard_filesystem_mcp_blank_uses_home(scripted_wizard, tmp_path):
    cfg = scripted_wizard([
        "1", "sk-x", "1",
        "4",   # cve_lookup
        "2",   # mcp: filesystem
        "",    # blank -> home directory
        "n",   # no passive-recon API keys
    ])
    fs = next(s for s in cfg.mcp_servers if s["name"] == "filesystem")
    assert fs["args"] == [str(Path.home())]


def test_wizard_filesystem_mcp_none_skips_server(scripted_wizard, tmp_path):
    cfg = scripted_wizard([
        "1", "sk-x", "1",
        "4",     # cve_lookup
        "1,2",   # fetch + filesystem
        "none",  # skip the filesystem tool
        "n",     # no passive-recon API keys
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
        "n",            # no passive-recon API keys
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


# ---- AWS Bedrock flow -------------------------------------------------------
#
# The bedrock helpers are imported inside _setup_bedrock, so patching them on
# kryonsec.bedrock is what the wizard actually sees.

_BEDROCK_MODELS = [
    {"id": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
     "label": "Claude Sonnet 4.5 (cross-region profile)",
     "kind": "inference-profile"},
    {"id": "amazon.nova-pro-v1:0", "label": "Amazon Nova Pro",
     "kind": "foundation-model"},
]


def _patch_bedrock(monkeypatch, regions=("us-east-1",), models=None):
    # a developer machine may export AWS_BEARER_TOKEN_BEDROCK for real AWS
    # work; the wizard tests must not inherit it
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.setattr("kryonsec.bedrock.probe_regions", lambda key, **kw: list(regions))
    monkeypatch.setattr(
        "kryonsec.bedrock.list_bedrock_models",
        lambda key, region, **kw: (
            _BEDROCK_MODELS if models is None else models))


def test_wizard_bedrock_flow_writes_config(scripted_wizard, tmp_path, monkeypatch):
    _patch_bedrock(monkeypatch)
    cfg = scripted_wizard([
        "3",          # AWS Bedrock
        "ABSKtest",   # api key
        "1",          # first model (the inference profile)
        "1,4",        # file_read + cve_lookup
        "1",          # mcp: fetch
        "n",          # no passive-recon API keys
    ])
    assert cfg.provider == "bedrock"
    assert cfg.bedrock_api_key == "ABSKtest"
    assert cfg.bedrock_region == "us-east-1"  # auto-detected, never asked
    # the bedrock/ prefix is what makes litellm apply the region + token
    assert cfg.general_chat_model == (
        "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0")
    assert cfg.general_search_model == cfg.general_chat_model
    assert cfg.compaction_model == cfg.general_chat_model
    assert cfg.enabled_tools == ["file_read", "cve_lookup"]

    data = read_config(config_path(tmp_path))
    assert data["llm"]["provider"] == "bedrock"
    assert data["llm"]["bedrock_api_key"] == "ABSKtest"
    assert data["llm"]["bedrock_region"] == "us-east-1"


def test_wizard_bedrock_model_selection_picks_the_right_id(
        scripted_wizard, tmp_path, monkeypatch):
    """The menu shows readable names; the stored value must be the model id,
    with the litellm prefix."""
    _patch_bedrock(monkeypatch)
    cfg = scripted_wizard([
        "3", "ABSKtest",
        "2",       # second entry: the foundation model, not the profile
        "", "", "n",
    ])
    assert cfg.general_chat_model == "bedrock/amazon.nova-pro-v1:0"


def test_wizard_bedrock_prompts_when_several_regions_work(
        scripted_wizard, tmp_path, monkeypatch):
    """A key valid in more than one region must not be guessed at — it
    decides where calls are billed."""
    _patch_bedrock(monkeypatch, regions=("us-east-1", "ap-south-1"))
    cfg = scripted_wizard([
        "3", "ABSKtest",
        "2",   # region: ap-south-1
        "1",   # model
        "", "", "n",
    ])
    assert cfg.bedrock_region == "ap-south-1"


def test_wizard_bedrock_rejected_key_retries(scripted_wizard, tmp_path, monkeypatch):
    """The region probe doubles as the key check: nothing answering 200
    means the key is bad, and the user gets another go."""
    seen = []

    def fake_probe(key, **kw):
        seen.append(key)
        return ["us-east-1"] if len(seen) > 1 else []

    monkeypatch.setattr("kryonsec.bedrock.probe_regions", fake_probe)
    monkeypatch.setattr(
        "kryonsec.bedrock.list_bedrock_models", lambda key, region, **kw: _BEDROCK_MODELS)
    cfg = scripted_wizard([
        "3",
        "ABSKbad",   # rejected everywhere
        "y",         # retry
        "ABSKgood",
        "1", "", "", "n",
    ])
    assert seen == ["ABSKbad", "ABSKgood"]
    assert cfg.bedrock_api_key == "ABSKgood"


def test_wizard_bedrock_giving_up_loops_back_to_provider(
        scripted_wizard, tmp_path, monkeypatch):
    """Declining to retry must not abort setup — it returns to the provider
    question, so OpenAI or Ollama is still reachable."""
    _patch_bedrock(monkeypatch, regions=())
    cfg = scripted_wizard([
        "3", "ABSKbad",  # rejected
        "n",             # give up on Bedrock
        "1", "sk-test-123", "1",  # fall through to OpenAI instead
        "", "", "n",
    ])
    assert cfg.provider == "openai"
    assert cfg.openai_api_key == "sk-test-123"
    assert config_path(tmp_path).is_file()


def test_wizard_bedrock_empty_key_loops_back(scripted_wizard, tmp_path, monkeypatch):
    _patch_bedrock(monkeypatch)
    monkeypatch.setattr("kryonsec.wizard.ollama_model_names",
                        lambda host: ["llama3.1:latest"])
    cfg = scripted_wizard([
        "3", "",          # blank key
        "2", "1", "", "", "n",   # pick Ollama instead
    ])
    assert cfg.provider == "ollama"
    assert cfg.bedrock_api_key is None


def test_wizard_bedrock_falls_back_to_typed_model_id(
        scripted_wizard, tmp_path, monkeypatch):
    """A key scoped to runtime-only cannot list models. That must degrade to
    typing an id, not dead-end the setup."""
    _patch_bedrock(monkeypatch, models=[])
    cfg = scripted_wizard([
        "3", "ABSKtest",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",  # typed by hand
        "", "", "n",
    ])
    assert cfg.general_chat_model == (
        "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0")

