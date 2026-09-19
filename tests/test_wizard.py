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


def _patch_bedrock(monkeypatch, regions=("us-east-1",), models=None,
                   verify=("ok", "ok")):
    # a developer machine may export AWS_BEARER_TOKEN_BEDROCK for real AWS
    # work; the wizard tests must not inherit it
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.setattr("kryonsec.bedrock.probe_regions", lambda key, **kw: list(regions))
    monkeypatch.setattr(
        "kryonsec.bedrock.list_bedrock_models",
        lambda key, region, **kw: (
            _BEDROCK_MODELS if models is None else models))
    # the wizard proves the chosen model with a REAL call. Unpatched, every
    # one of these tests would reach AWS — and worse, would reach it on
    # machines where litellm's Converse path dies before sending anything.
    # The default is "it answers", the path all the pre-existing tests take.
    monkeypatch.setattr("kryonsec.bedrock.verify_model", lambda cfg, *a, **kw: verify)


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


# ---- proving the model before saving it -------------------------------------
#
# A model being listed proves only that the catalog knows it. The first user
# picked a `global.` cross-region profile and got "Operation not allowed" on
# their first prompt, from a setup that had just reported success.


def test_wizard_bedrock_scans_for_a_model_that_actually_answers(
        scripted_wizard, tmp_path, monkeypatch):
    """A refused pick costs one call, not an evening of retyping.

    The list is the region's catalog, not a menu of working models, and it
    gives the user no way to tell them apart. Handing back "pick another?"
    makes them do the search one model at a time — which is exactly the loop
    a user with a whole region of refused models gets stuck in, and it reads
    as "kryonsec is broken" rather than "these will not work". So the wizard
    tests the rest itself and stops at the first that answers.
    """
    calls = []

    def fake_verify(cfg, model_id=None, **kw):
        target = model_id or cfg.general_chat_model
        calls.append(target)
        # the global cross-region profile is refused; the plain one works
        if "global." in target:
            return "rejected", 'BedrockException - {"message":"Operation not allowed"}'
        return "ok", "ok"

    _patch_bedrock(monkeypatch, models=[
        {"id": "global.openai.gpt-5.6-sol", "label": "OpenAI GPT-5.6 (global)",
         "kind": "inference-profile"},
        {"id": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
         "label": "Claude Sonnet 4.5 (cross-region profile)",
         "kind": "inference-profile"},
    ])
    monkeypatch.setattr("kryonsec.bedrock.verify_model", fake_verify)

    cfg = scripted_wizard([
        "3", "ABSKtest",
        "1",   # global.openai.gpt-5.6-sol — refused
        # NOTE: no "pick another" answer — the scan supplies the next model
        "", "", "n",
    ])
    # it tried the refusal, then the alternative, and stopped there
    assert calls == [
        "bedrock/global.openai.gpt-5.6-sol",
        "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    ]
    # and never re-tested the one it had just been refused
    assert calls.count("bedrock/global.openai.gpt-5.6-sol") == 1
    assert cfg.general_chat_model == (
        "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0")
    assert cfg.general_search_model == cfg.general_chat_model


def test_every_model_refused_is_reported_as_the_account_not_the_pick(
        scripted_wizard, tmp_path, monkeypatch, capsys):
    """The one message a screen full of identical errors cannot give.

    "Every model in this region was refused" is a fact about the account,
    and it is the fact that says stop picking and go to Model access. Both
    of the other answers — silence, or "pick another" — send the user round
    the loop again with no new information.
    """
    _patch_bedrock(monkeypatch, verify=("rejected", "Operation not allowed"))
    cfg = scripted_wizard([
        "3", "ABSKtest",
        "1",   # refused; the scan then refuses the other one too
        "n",   # keep it anyway
        "", "", "n",
    ])
    out = capsys.readouterr().out
    assert "none of the 1 other models answered either" in out
    assert "refused every one of them" in out
    assert "us-east-1" in out          # which region was searched
    assert "Model access" in out       # and where to go about it
    # the user was never asked to pick again before being told why
    assert cfg.provider == "bedrock"


def test_a_scan_that_reaches_nothing_stops_instead_of_grinding(
        scripted_wizard, tmp_path, monkeypatch, capsys):
    """Three calls with no verdict means the endpoint is not answering.

    Without this the scan would spend its full allowance of 30-second
    timeouts — twenty minutes — to learn what the first three already said.
    """
    calls = []

    def fake_verify(cfg, model_id=None, **kw):
        target = model_id or cfg.general_chat_model
        calls.append(target)
        if len(calls) == 1:
            return "rejected", "Operation not allowed"
        return "unknown", "APIConnectionError: connection refused"

    models = [{"id": f"vendor.model-{i}", "label": f"Model {i}",
               "kind": "foundation-model"} for i in range(40)]
    _patch_bedrock(monkeypatch, models=models)
    monkeypatch.setattr("kryonsec.bedrock.verify_model", fake_verify)

    scripted_wizard([
        "3", "ABSKtest",
        "1",       # refused, so the scan starts
        # then three no-verdict calls abort it
        "n", "", "", "n",
    ])
    # 1 pick + 3 no-answer probes, not 1 + 39
    assert len(calls) == 4
    out = capsys.readouterr().out
    assert "None of the calls reached AWS" in out


def test_a_lone_model_that_is_refused_still_offers_the_manual_path(
        scripted_wizard, tmp_path, monkeypatch):
    """Nothing to scan is not the same as nothing to try.

    With one model in the list there is no alternative to test, so the
    wizard must go straight to letting the user type an id — for a model
    they know about that the listing did not return.
    """
    calls = []

    def fake_verify(cfg, model_id=None, **kw):
        target = model_id or cfg.general_chat_model
        calls.append(target)
        if target == "bedrock/my.known-good-v1:0":
            return "ok", "ok"
        return "rejected", "Operation not allowed"

    _patch_bedrock(monkeypatch, models=[
        {"id": "amazon.nova-pro-v1:0", "label": "Amazon Nova Pro",
         "kind": "foundation-model"},
    ])
    monkeypatch.setattr("kryonsec.bedrock.verify_model", fake_verify)

    cfg = scripted_wizard([
        "3", "ABSKtest",
        "1",                  # the only listed model — refused
        "y",                  # pick another
        "my.known-good-v1:0",  # typed by hand
        "", "", "n",
    ])
    assert calls == [
        "bedrock/amazon.nova-pro-v1:0",
        "bedrock/my.known-good-v1:0",
    ]
    assert cfg.general_chat_model == "bedrock/my.known-good-v1:0"


def test_the_scan_runs_once_not_on_every_pass(
        scripted_wizard, tmp_path, monkeypatch):
    """After a full scan the list has been answered for.

    Re-scanning on the next pass would repeat the whole set of calls to
    reach a conclusion it already has.
    """
    calls = []

    def fake_verify(cfg, model_id=None, **kw):
        target = model_id or cfg.general_chat_model
        calls.append(target)
        return "rejected", "Operation not allowed"

    _patch_bedrock(monkeypatch)
    monkeypatch.setattr("kryonsec.bedrock.verify_model", fake_verify)

    scripted_wizard([
        "3", "ABSKtest",
        "1",   # refused -> scan tests the other one -> refused too
        "y",   # pick another by hand
        "2",   # refused, and no second scan
        "n",   # keep it
        "", "", "n",
    ])
    assert calls == [
        "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",  # the pick
        "bedrock/amazon.nova-pro-v1:0",                          # the scan
        "bedrock/amazon.nova-pro-v1:0",                          # picked by hand
    ]


def test_wizard_bedrock_can_keep_a_model_that_failed_verification(
        scripted_wizard, tmp_path, monkeypatch):
    """Never trap the user: someone who knows the model is fine (a quota that
    resets, a permission being granted) must be able to keep their choice."""
    _patch_bedrock(monkeypatch, verify=("rejected", "ThrottlingException"))
    # NOTE: the wizard reads answers before falling back to input(); the
    # order is key -> model -> "pick another? [Y/n]" -> the rest of setup
    cfg = scripted_wizard([
        "3", "ABSKtest",
        "1",   # model
        "n",   # no, keep it anyway
        "", "", "n",
    ])
    assert cfg.general_chat_model == (
        "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0")


def test_wizard_bedrock_unknown_verdict_does_not_nag(
        scripted_wizard, tmp_path, monkeypatch):
    """No verdict from AWS is not a bad model.

    litellm's Converse path reads `credentials.access_key` before it checks
    for a bearer token, so on a machine with no SigV4 credentials the probe
    dies in our own call stack with "'NoneType' object has no attribute
    'access_key'". Blaming the user's model choice for that would push them
    off a model that works, so an inconclusive check keeps the choice and
    asks nothing — note there is no "pick another?" answer in the script."""
    _patch_bedrock(
        monkeypatch,
        verify=("unknown", "APIConnectionError: 'NoneType' object has no "
                           "attribute 'access_key'"))
    cfg = scripted_wizard([
        "3", "ABSKtest",
        "1",   # model — the check is inconclusive, so setup carries on
        "", "", "n",
    ])
    assert cfg.general_chat_model == (
        "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0")
    assert cfg.provider == "bedrock"


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
    # this test builds its own patches rather than calling _patch_bedrock,
    # so it must patch the verifier too — unpatched it makes a real call
    # and the retry prompt then reads from captured stdin
    monkeypatch.setattr("kryonsec.bedrock.verify_model",
                        lambda cfg, *a, **kw: ("ok", "ok"))
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

