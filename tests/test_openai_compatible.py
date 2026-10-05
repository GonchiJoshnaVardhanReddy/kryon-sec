"""Tests for the generic OpenAI-compatible provider.

No real endpoint is contacted. Where a server is needed (model listing, the
capability probe) a fake one is started on an ephemeral localhost port; where
only the request shape matters, litellm.completion is replaced and the kwargs
it would have been called with are inspected.

The security tests here are the point of the file as much as the routing
ones: litellm's openai/ route falls back to $OPENAI_API_KEY when no api_key
is given, which would put a real OpenAI credential in an Authorization
header aimed at whatever endpoint the user configured.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig, config_path, read_config, write_config
from kryonsec.llm import (
    LlmUnavailable,
    _is_compat_model,
    build_call,
    chat,
    litellm_model,
    normalize_base_url,
    provider_reason,
    scrub_secrets,
)
from kryonsec.openai_compatible import Capabilities, format_capabilities, list_models, probe

# Placeholders, never defaults — the tests say what they mean and the code
# under test has no opinion about any of them.
MODEL = "some-model"
BASE = "https://endpoint.invalid/v1"


@pytest.fixture()
def cfg():
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = BASE
    c.openai_compatible_api_key = "k"
    c.general_chat_model = MODEL
    c.general_search_model = MODEL
    c.compaction_model = MODEL
    c.openai_api_key = None
    return c


# ---- URL normalization ----------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    # a trailing slash is dropped; the path the user chose is otherwise kept
    ("https://h/v1/", "https://h/v1"),
    ("https://h/v1", "https://h/v1"),
    ("https://h", "https://h"),
    ("https://h//", "https://h"),
    # a duplicated slash would reach the server as /v1//chat/completions
    ("https://h/v1//", "https://h/v1"),
    # a scheme is supplied when missing, the way OLLAMA_HOST already is
    ("h:1234/v1", "http://h:1234/v1"),
    ("  https://h/v1  ", "https://h/v1"),
    # nothing is appended — kryonsec does not know where the server mounts
    ("https://h/api/v1", "https://h/api/v1"),
])
def test_normalize_base_url(raw, expected):
    assert normalize_base_url(raw) == expected


def test_normalize_does_not_invent_a_v1_path():
    # the whole point: a server rooted at / must not be guessed at
    assert normalize_base_url("https://h") == "https://h"


# ---- model routing --------------------------------------------------------

def test_configured_model_is_passed_through_unchanged(cfg):
    call = build_call(cfg, MODEL)
    # the user's id, untouched — only the protocol route is added
    assert call["model"] == f"openai/{MODEL}"
    assert MODEL in call["model"]


def test_a_name_that_looks_like_a_route_still_goes_to_the_configured_endpoint(cfg):
    """`openai/…` and `meta-llama/…` are ordinary model names at a gateway.

    Reading the prefix as a route sent them to api.openai.com carrying the
    user's OpenAI key — an endpoint and a credential they never configured.
    litellm strips exactly one `openai/` segment, so the model that reaches
    the wire is the user's string, unchanged (verified on the wire in
    test_the_exact_wire_request below).
    """
    for name in ("openai/gpt-oss-120b", "meta-llama/llama-3.1-70b"):
        cfg.general_chat_model = name
        assert _is_compat_model(cfg, name)
        assert build_call(cfg, name)["api_base"] == BASE
        assert litellm_model(cfg, name) == f"openai/{name}"


def test_local_fallback_model_is_never_routed_through_the_endpoint(cfg):
    # the secrets gate substitutes ollama/… — that must not become
    # openai/ollama/…
    assert litellm_model(cfg, "ollama/anything") == "ollama/anything"
    assert not _is_compat_model(cfg, "ollama/anything")
    assert not _is_compat_model(cfg, "bedrock/anything")

    # ...and not just the model string: the call itself must carry the Ollama
    # host, and must not pick up the configured endpoint or its credential.
    # This is the secrets gate's path — nothing sensitive goes to a third
    # party because the compat seat happens to be selected.
    call = build_call(cfg, "ollama/anything")
    assert call["api_base"] != BASE
    assert call.get("api_key") != cfg.openai_compatible_api_key


def test_other_providers_are_unaffected():
    c = KryonsecConfig()
    c.provider = "openai"
    c.general_chat_model = MODEL
    assert litellm_model(c, MODEL) == MODEL  # no route added for openai
    b = KryonsecConfig()
    b.provider = "bedrock"
    assert litellm_model(b, "bedrock/x") == "openai/x"


# ---- request shape --------------------------------------------------------

def test_configured_url_and_key_are_used(cfg):
    call = build_call(cfg, MODEL)
    assert call["api_base"] == BASE
    assert call["api_key"] == "k"


def test_trailing_slash_is_normalized_into_the_call():
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = "https://h/v1/"
    c.general_chat_model = MODEL
    assert build_call(c, MODEL)["api_base"] == "https://h/v1"


def test_missing_base_url_is_refused_before_the_call():
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = None
    c.general_chat_model = MODEL
    with pytest.raises(LlmUnavailable) as e:
        build_call(c, MODEL)
    assert "base URL" in str(e.value)


def test_keyless_endpoint_sends_no_credential(cfg, monkeypatch):
    """The regression this whole branch exists for.

    litellm's openai/ route reads $OPENAI_API_KEY when api_key is absent (or
    empty — measured, not assumed), so a keyless local server would ship the
    user's real OpenAI key to an endpoint kryonsec has no relationship with.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env-key-must-not-travel")
    cfg.openai_compatible_api_key = None

    call = build_call(cfg, MODEL)
    assert call["api_base"] == BASE
    assert call["api_key"] != "sk-env-key-must-not-travel"
    # the sentinel satisfies litellm's client; the header it would produce is
    # blanked, so nothing credential-shaped reaches the wire at all
    assert call["extra_headers"] == {"Authorization": ""}


def test_configured_key_is_not_echoed_into_the_log(cfg, caplog):
    with caplog.at_level("DEBUG"):
        reason = provider_reason(RuntimeError(f"401 unauthorized for {BASE}"))
    assert "401" in reason          # the useful part survives
    assert cfg.openai_compatible_api_key not in reason


# ---- chat() routing -------------------------------------------------------

def test_chat_routes_to_the_configured_endpoint(cfg):
    with patch("litellm.completion") as completion:
        completion.return_value.choices = [
            type("C", (), {"message": type("M", (), {"content": "hi"})()})()
        ]
        assert chat(cfg, [{"role": "user", "content": "q"}], MODEL) == "hi"
    kwargs = completion.call_args.kwargs
    assert kwargs["model"] == f"openai/{MODEL}"
    assert kwargs["api_base"] == BASE
    assert kwargs["api_key"] == "k"


def test_chat_does_not_demand_a_key_for_a_keyless_endpoint(cfg):
    cfg.openai_compatible_api_key = None
    with patch("litellm.completion") as completion:
        completion.return_value.choices = [
            type("C", (), {"message": type("M", (), {"content": "hi"})()})()
        ]
        chat(cfg, [{"role": "user", "content": "q"}], MODEL)
    assert "api_key" in completion.call_args.kwargs


def test_chat_reports_the_endpoint_on_failure(cfg):
    with patch("litellm.completion", side_effect=RuntimeError("connection refused")):
        with pytest.raises(LlmUnavailable) as e:
            chat(cfg, [{"role": "user", "content": "q"}], MODEL)
    # the provider's own words, not a guess about them
    assert "connection refused" in str(e.value)


def test_tools_are_forwarded_to_the_configured_endpoint(cfg, tmp_path):
    """The tool loop must reach the endpoint with the model the user chose,
    on the URL they configured, and tool arguments must survive the trip."""
    from kryonsec.copilot.agent import build_toolbox, run_agent
    from kryonsec.copilot.tools import FileTools

    cfg.home = tmp_path / "home"
    cfg.workspace = tmp_path / "ws"
    cfg.ensure_dirs()

    class F:
        def __init__(self, name, arguments):
            self.name, self.arguments = name, arguments

    class TC:
        def __init__(self, i, name, args):
            self.id, self.function = i, F(name, args)

    calls = []

    def fake_completion(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            msg = type("M", (), {"content": "", "tool_calls": [
                TC("1", "file_read", json.dumps({"path": str(cfg.workspace / "x.txt")}))]})()
        else:
            msg = type("M", (), {"content": "done", "tool_calls": None})()
        return type("R", (), {"choices": [type("C", (), {"message": msg})()]})()

    with patch("litellm.completion", side_effect=fake_completion):
        out = run_agent(cfg, [{"role": "user", "content": "read it"}],
                        build_toolbox(cfg, FileTools(cfg)), MODEL)

    assert out == "done"
    first = calls[0]
    # the configured model and URL, through the real tool loop
    assert first["model"] == f"openai/{MODEL}"
    assert first["api_base"] == BASE
    assert first["api_key"] == "k"
    # tools went out in the OpenAI format
    assert any(t["function"]["name"] == "file_read"
               for t in first["tools"] if t.get("type") == "function")
    # the arguments the model produced came back intact
    assert json.loads(calls[1]["messages"][-2]["tool_calls"][0]["function"]["arguments"])


# ---- config round-trip ----------------------------------------------------

def test_config_round_trips_base_url_and_key(tmp_path):
    c = KryonsecConfig(home=tmp_path)
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = "https://h/v1"
    c.openai_compatible_api_key = "secret-value"
    c.general_chat_model = MODEL

    path = write_config(config_path(tmp_path), c.to_toml_dict())
    data = read_config(path)
    assert data["llm"]["base_url"] == "https://h/v1"
    assert data["llm"]["provider"] == "openai_compatible"

    loaded = KryonsecConfig.from_toml(data, home=tmp_path)
    assert loaded.openai_compatible_base_url == "https://h/v1"
    assert loaded.openai_compatible_api_key == "secret-value"
    assert loaded.general_chat_model == MODEL


def test_model_is_accepted_as_an_alias_for_chat_model(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYONSEC_OPENAI_COMPATIBLE_BASE_URL", raising=False)
    loaded = KryonsecConfig.from_toml(
        {"llm": {"provider": "openai_compatible", "model": MODEL}},
        home=tmp_path)
    assert loaded.general_chat_model == MODEL


def test_compat_seat_without_a_model_refuses_instead_of_borrowing_one(tmp_path):
    """The dataclass defaults belong to the other providers.

    A hand-written config that selects this provider and names no model must
    not inherit `ollama/llama3.1` (the call would silently run against local
    Ollama with the configured endpoint unused) or `gpt-4o-mini` (an OpenAI
    model name aimed at a server that never heard of it).
    """
    loaded = KryonsecConfig.from_toml(
        {"llm": {"provider": "openai_compatible", "base_url": BASE}},
        home=tmp_path)
    assert loaded.general_chat_model == ""

    with pytest.raises(LlmUnavailable, match="no model is configured"):
        build_call(loaded, loaded.general_chat_model)


def test_a_model_named_explicitly_is_never_blanked(tmp_path):
    loaded = KryonsecConfig.from_toml(
        {"llm": {"provider": "openai_compatible", "base_url": BASE,
                 "chat_model": MODEL}},
        home=tmp_path)
    assert loaded.general_chat_model == MODEL


def test_other_providers_keep_their_own_default_model(tmp_path):
    """The blanking is scoped to this seat: an Ollama config with no model
    key must still resolve to the Ollama default, as it always did."""
    loaded = KryonsecConfig.from_toml({"llm": {"provider": "ollama"}}, home=tmp_path)
    assert loaded.general_chat_model == "ollama/llama3.1"


def test_env_overrides_toml(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYONSEC_OPENAI_COMPATIBLE_BASE_URL", "https://env.invalid/v1")
    monkeypatch.setenv("KRYONSEC_OPENAI_COMPATIBLE_API_KEY", "env-key")
    loaded = KryonsecConfig.from_toml(
        {"llm": {"provider": "openai_compatible", "base_url": "https://toml.invalid/v1"}},
        home=tmp_path)
    assert loaded.openai_compatible_base_url == "https://env.invalid/v1"
    assert loaded.openai_compatible_api_key == "env-key"


# ---- security -------------------------------------------------------------

def test_scrub_secrets_hides_a_bearer_header():
    text = "httpx error: {'Authorization': 'Bearer sk-live-abcdefghijklmnop'}"
    scrubbed = scrub_secrets(text)
    assert "sk-live-abcdefghijklmnop" not in scrubbed
    assert "Bearer" in scrubbed  # the scheme word still says what went wrong


def test_the_configured_key_never_reaches_a_warning_log(caplog):
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = BASE
    c.openai_compatible_api_key = "sk-this-must-not-be-logged"
    c.general_chat_model = MODEL

    leak = RuntimeError("401 from server, Authorization: Bearer sk-this-must-not-be-logged")
    with caplog.at_level("WARNING"):
        with patch("litellm.completion", side_effect=leak):
            with pytest.raises(LlmUnavailable):
                chat(c, [{"role": "user", "content": "q"}], MODEL)
    assert "sk-this-must-not-be-logged" not in caplog.text


# ---- fake endpoint: listing and capability probe --------------------------

class _Endpoint(BaseHTTPRequestHandler):
    """A minimal OpenAI-compatible server. Class attributes (set per test)
    decide what it supports."""

    models: list[str] = ["a-model"]
    supports_tools = True
    supports_streaming = True
    seen: list[dict] = []

    def do_GET(self):
        if self.path.endswith("/models"):
            body = json.dumps({"data": [{"id": m} for m in self.models]}).encode()
        else:
            body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        payload = json.loads(raw or b"{}")
        type(self).seen.append({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "payload": payload,
        })
        if payload.get("tools") and not self.supports_tools:
            self._error(400, "tools is not supported")
            return
        if payload.get("stream"):
            if not self.supports_streaming:
                self._error(400, "stream is not supported")
                return
            chunks = b"".join(
                b"data: " + json.dumps({
                    "id": "1", "object": "chat.completion.chunk", "created": 0,
                    "model": "m",
                    "choices": [{"index": 0, "delta": {"content": "h"},
                                 "finish_reason": None}],
                }).encode() + b"\n\n"
                for _ in range(1)
            ) + b"data: [DONE]\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(chunks)))
            self.end_headers()
            self.wfile.write(chunks)
            return
        if payload.get("tools"):
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "1", "type": "function",
                "function": {"name": "kryonsec_probe", "arguments": '{"echo":"ok"}'},
            }]}
        else:
            message = {"role": "assistant", "content": "ok"}
        body = json.dumps({"id": "1", "object": "chat.completion", "created": 0,
                           "model": "m", "choices": [
                               {"index": 0, "message": message,
                                "finish_reason": "stop"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message):
        body = json.dumps({"error": {"message": message}}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def endpoint():
    _Endpoint.models = ["a-model"]
    _Endpoint.supports_tools = True
    _Endpoint.supports_streaming = True
    _Endpoint.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _Endpoint)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    finally:
        srv.shutdown()
        srv.server_close()


def test_list_models_reads_the_endpoint(endpoint):
    assert list_models(endpoint) == ["a-model"]


def test_list_models_returns_none_when_the_endpoint_is_down():
    # nothing is listening on this port: no exception, just no answer
    assert list_models("http://127.0.0.1:1/v1") is None


def test_probe_reports_the_full_picture(endpoint):
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = endpoint
    c.general_chat_model = "a-model"

    caps = probe(c, "a-model")
    assert (caps.connected, caps.answers, caps.tools, caps.streaming) == (
        True, True, True, True)
    # /chat/completions is where it went, under the configured path
    assert all(s["path"] == "/v1/chat/completions" for s in _Endpoint.seen)


def test_probe_reports_unsupported_tools_rather_than_guessing(endpoint):
    _Endpoint.supports_tools = False
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = endpoint
    c.general_chat_model = "a-model"

    caps = probe(c, "a-model")
    assert caps.answers is True
    assert caps.tools is False   # the server said no, not "unknown"


def test_probe_reports_unsupported_streaming(endpoint):
    _Endpoint.supports_streaming = False
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = endpoint
    c.general_chat_model = "a-model"

    assert probe(c, "a-model").streaming is False


def test_probe_never_sends_a_credential_when_none_is_configured(endpoint, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env-key-must-not-travel")
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = endpoint
    c.openai_compatible_api_key = None
    c.general_chat_model = "a-model"

    probe(c, "a-model")
    sent = {s["auth"] for s in _Endpoint.seen}
    assert "sk-env-key-must-not-travel" not in " ".join(str(a) for a in sent)


def test_probe_sends_the_configured_key_when_there_is_one(endpoint):
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = endpoint
    c.openai_compatible_api_key = "the-key"
    c.general_chat_model = "a-model"

    probe(c, "a-model")
    assert _Endpoint.seen[0]["auth"] == "Bearer the-key"


def test_probe_reports_unknown_when_nothing_is_there():
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = "http://127.0.0.1:1/v1"
    c.general_chat_model = "a-model"

    caps = probe(c, "a-model")
    assert caps.answers is False
    assert caps.tools is None and caps.streaming is None  # never guessed
    assert caps.detail  # and it says what the endpoint said


def test_probe_without_configuration_says_so():
    caps = probe(KryonsecConfig(), "")
    assert caps.answers is False
    assert "no base URL" in caps.detail


def test_capability_render_marks_unknown_distinctly():
    text = format_capabilities(Capabilities(connected=True, answers=True))
    assert text.count("unknown") == 2      # tools and the server's streaming
    # unknown must never borrow the mark that means "the server said no"
    assert "[red]no[/red]" not in text


# ---- setup wizard ---------------------------------------------------------

def _patch_wizard_endpoint(monkeypatch, models, caps=None):
    monkeypatch.setattr("kryonsec.wizard._is_tty", lambda: False)
    monkeypatch.setattr(
        "kryonsec.openai_compatible.list_models",
        lambda base, key=None: models)
    monkeypatch.setattr(
        "kryonsec.openai_compatible.probe",
        lambda cfg, model: caps or Capabilities(connected=True, answers=True))


def _run_wizard(tmp_path, answers):
    from kryonsec.wizard import run_setup

    return run_setup(KryonsecConfig(home=tmp_path), answers=answers)


def test_wizard_configures_a_compatible_endpoint(monkeypatch, tmp_path):
    _patch_wizard_endpoint(monkeypatch, ["some-model", "other-model"])
    cfg = _run_wizard(tmp_path, [
        "4",                            # OpenAI-compatible endpoint
        "https://endpoint.invalid/v1/",  # base URL, trailing slash
        "",                             # no API key (keyless server)
        "1",                            # first listed model
        "",                             # no built-in tools
        "",                             # no MCP servers
        "n",                            # no passive-recon keys
    ])
    assert cfg.provider == "openai_compatible"
    # normalized on the way in, so the stored URL is exactly what is called
    assert cfg.openai_compatible_base_url == "https://endpoint.invalid/v1"
    assert cfg.openai_compatible_api_key is None
    assert cfg.general_chat_model == "some-model"
    # a default here would name a model on a server kryonsec knows nothing of
    assert cfg.general_search_model == "some-model"
    assert cfg.compaction_model == "some-model"

    data = read_config(config_path(tmp_path))
    assert data["llm"]["provider"] == "openai_compatible"
    assert data["llm"]["base_url"] == "https://endpoint.invalid/v1"
    assert data["llm"]["chat_model"] == "some-model"


def test_wizard_accepts_a_typed_model_when_listing_fails(monkeypatch, tmp_path):
    # plenty of servers do not implement GET /models
    _patch_wizard_endpoint(monkeypatch, None)
    cfg = _run_wizard(tmp_path, [
        "4",
        "http://endpoint.invalid:1234/v1",
        "a-configured-key",
        "typed-model",   # typed by hand
        "",
        "",
        "n",
    ])
    assert cfg.general_chat_model == "typed-model"
    assert cfg.openai_compatible_api_key == "a-configured-key"


def test_wizard_probe_result_is_shown(monkeypatch, tmp_path, capsys):
    out = Capabilities(connected=True, answers=True, tools=False, streaming=None)
    _patch_wizard_endpoint(monkeypatch, ["m"], caps=out)
    _run_wizard(tmp_path, ["4", "http://h/v1", "", "1", "", "", "n"])
    printed = capsys.readouterr().out
    # the endpoint's own answers, including the one it refused
    assert "tool calling" in printed


# ---- arbitrary model names: there is no allowlist -------------------------

@pytest.mark.parametrize("model", [
    "my-model",
    "my-local-model",
    "provider/model-name",
    "company/deployment-name",
    "custom-finetune-2026",
    "anything-the-server-supports",
    "model-with-many-dashes",
    "a-model-nobody-has-ever-heard-of",
    # names that look like OpenAI's reasoning models but are not
    "o1-something",
    "gpt-5-local",
])
def test_any_model_name_reaches_the_configured_endpoint_unchanged(cfg, model):
    """The list is of names that must WORK, not a list of names allowed."""
    cfg.general_chat_model = model
    call = build_call(cfg, model)
    assert call["model"] == f"openai/{model}"
    assert call["api_base"] == BASE


@pytest.mark.parametrize("model", [
    "o1-something", "o3-local", "o4-custom",
    "gpt-5-local", "gpt-6-custom", "gpt-7-test",
])
@pytest.mark.parametrize("tools", [False, True])
def test_a_name_that_looks_like_reasoning_gets_no_openai_parameters(
        cfg, model, tools):
    """No capability may be inferred from a model name on this seat.

    `reasoning_effort` is OpenAI's parameter; a server that merely speaks the
    protocol would reject it, so this provider must not invent it — and must
    keep sending the temperature it always sent.
    """
    kw = build_call(cfg, model, tools=tools)
    assert "reasoning_effort" not in kw
    assert "allowed_openai_params" not in kw
    assert kw["temperature"] == 0.0


def test_a_model_the_endpoint_never_lists_is_still_used(endpoint):
    """/models is discovery. It must never become the gate on what runs."""
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = endpoint
    c.general_chat_model = "never-listed-anywhere"
    _Endpoint.seen.clear()

    assert list_models(endpoint) == ["a-model"]      # not in that list...
    assert chat(c, [{"role": "user", "content": "hi"}], "never-listed-anywhere") == "ok"
    assert _Endpoint.seen[-1]["payload"]["model"] == "never-listed-anywhere"


@pytest.mark.parametrize("body", [
    b'{"data": "not-a-list"}',        # unusual shape
    b'{"models": 42}',                # the other key, also wrong
    b"<html>not json at all</html>",  # not even JSON
    b"{}",                            # valid JSON, nothing in it
])
def test_an_unusable_models_listing_is_not_an_error(monkeypatch, body):
    """A server that cannot list models is common; that is not a failure."""

    class _Response:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return body

    monkeypatch.setattr(
        "kryonsec.openai_compatible.urllib.request.urlopen",
        lambda *a, **k: _Response())
    # None or empty: either way the caller falls back to asking, never raising
    assert not list_models("https://h/v1")


# ---- the probe is informational, never a gate -----------------------------

def test_a_failed_probe_does_not_block_configuration(monkeypatch, tmp_path):
    _patch_wizard_endpoint(
        monkeypatch, ["m"],
        caps=Capabilities(connected=False, answers=False, detail="refused"))
    cfg = _run_wizard(tmp_path, ["4", "http://h/v1", "", "1", "", "", "n"])
    assert cfg.openai_compatible_base_url == "http://h/v1"
    assert cfg.general_chat_model == "m"


def test_a_streaming_server_does_not_make_streaming_a_kryonsec_feature(endpoint):
    """The endpoint offering streams and kryonsec consuming them are two
    different claims, and only the first is true."""
    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = endpoint
    c.general_chat_model = "a-model"

    caps = probe(c, "a-model")
    assert caps.streaming is True            # the server accepts stream=true
    assert caps.kryonsec_streaming is False  # kryonsec cannot consume it

    rendered = format_capabilities(caps)
    assert "server streaming" in rendered
    assert "unimplemented" in rendered       # stated, not left to inference


def test_kryonsec_streaming_stays_false_whatever_the_server_says():
    for server_answer in (True, False, None):
        assert Capabilities(streaming=server_answer).kryonsec_streaming is False


# ---- the exact wire request ----------------------------------------------

def test_the_exact_wire_request(endpoint):
    """One request asserted field by field on a real HTTP server: URL, method,
    model, messages, tools and the Authorization header.

    Only POST is implemented for chat on the fake server, so a recorded entry
    IS the assertion that the method was POST — anything else is a 501 and
    leaves nothing in `seen`.
    """
    from kryonsec.openai_compatible import _probe_tools

    c = KryonsecConfig()
    c.provider = "openai_compatible"
    c.openai_compatible_base_url = endpoint
    c.openai_compatible_api_key = "configured-key"
    c.general_chat_model = "company/deployment-name"
    _Endpoint.seen.clear()

    chat(c, [{"role": "user", "content": "hello"}], "company/deployment-name")
    _probe_tools(c, "company/deployment-name")

    plain, with_tools = _Endpoint.seen
    assert plain["path"] == "/v1/chat/completions"   # the configured path
    assert plain["auth"] == "Bearer configured-key"
    assert plain["payload"]["model"] == "company/deployment-name"
    assert plain["payload"]["messages"] == [{"role": "user", "content": "hello"}]
    assert "tools" not in plain["payload"]

    # tool definitions go out in the OpenAI wire format, unchanged
    fn = with_tools["payload"]["tools"][0]
    assert fn["type"] == "function"
    assert fn["function"]["name"] == "kryonsec_probe"
    assert "parameters" in fn["function"]
