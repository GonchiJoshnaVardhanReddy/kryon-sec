"""Tests for the vetted api-probe Mode B adapter (Phase 2B.5).

Everything here runs against harmless fakes and an IN-PROCESS lab
HTTP server bound to 127.0.0.1 (disposable, operator-controlled by
construction — it only serves the fixtures these tests define). The
ONE genuine integration test at the bottom is opt-in
(KRYONSEC_API_IT=1) and skipped silently otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapters import (
    AdapterError,
    AdapterNotRegistered,
    AdapterRegistry,
    AdapterRunRecord,
    AdapterScopeRefused,
    execute_adapter,
    prepare_adapter_run,
)
from kryonsec.purple.adapter_api import (
    ADAPTER_ID,
    API_PROBE_TEMPLATE,
    SECURITY_HEADERS,
    TOOL_EXECUTABLE,
    find_adapter_attempt_node,
    make_api_probe_adapter,
    parse_api_probe_payload,
    production_registry,
    record_api_evidence,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult

TARGET = "target-corp.com"
LAB_BASE = "http://target-corp.com:8080/"


# ---- harmless fakes ------------------------------------------------------------


class _StubEgressPolicy:
    """Duck-typed egress-policy stub (the executor only needs presence;
    the REAL enforcement lives inside the sandbox's own spawn)."""

    dns_resolvers = ("192.0.2.53",)  # TEST-NET-1 fixture for the dnsx lane's -r


class FakeSandbox:
    """Duck-typed sandbox double carrying the attributes the adapter
    path reads (spawn/egress_policy/timeout_s/image)."""

    def __init__(self, result=None, *, script=None, egress_policy=None,
                 timeout_s=330,
                 image="kryonsec/sandbox@sha256:abcdef123456"):
        self._result = result
        self._script = script
        self.spawned = []
        self.egress_policy = egress_policy
        self.timeout_s = timeout_s
        self.image = image

    def spawn(self, argv, timeout_s=None):
        self.spawned.append((list(argv), timeout_s))
        if self._script is not None:
            return self._script(argv)
        return self._result


def _payload_line(url=LAB_BASE, status="complete", requests_sent=7,
                  base_status=200, security_headers=None,
                  cors_probe=None, options=None, docs=None) -> str:
    payload = {
        "kind": "kryonsec_api_probe",
        "url": url,
        "started_at": "2026-11-12T14:00:00Z",
        "requests_sent": requests_sent,
        "status": status,
        "base": {
            "status": base_status,
            "content_type": "application/json",
            "security_headers": security_headers or {
                "x-content-type-options": "nosniff",
                "server": "lab",
            },
            "redirect": None,
            "error": None,
        },
        "cors_probe": cors_probe or {
            "status": 200,
            "test_origin": "https://kryonsec-cors-probe.invalid",
            "access_control_allow_origin": "",
            "access_control_allow_credentials": "",
            "vary": "",
            "origin_reflected": False,
            "wildcard": False,
        },
        "options": options or {
            "status": 200, "allow": "GET, HEAD, OPTIONS", "cors": {},
            "error": None,
        },
        "docs": docs or {
            "probed": ["/openapi.json", "/swagger.json", "/api-docs",
                       "/graphql"],
            "found": [], "unreachable": [],
        },
        "limitations": ["read-only GET/OPTIONS only — no state-changing "
                        "method"],
        "errors": [],
    }
    return json.dumps(payload)


def _events(audit) -> "list[dict]":
    return [json.loads(line) for line in open(audit.path, encoding="utf-8")
            if line.strip()]


def _event_names(audit) -> "list[str]":
    return [e["event"] for e in _events(audit)]


def _graph(hypotheses=True) -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    if hypotheses:
        graph.add_node("hypothesis", "H1", {
            "title": "probe-me", "target_asset": "/", "rationale": "x",
            "cvss_vector": "", "tools": [], "confidence": 0.5,
            "approved": False,      # NOT approved — adapter must never
        })                          # upgrade this
    return graph


def _cfg(tmp_path):
    from kryonsec.config import KryonsecConfig

    return KryonsecConfig(home=tmp_path / "home")


# ---- 0. the baked wrapper script's own logic (in process) -----------------------

_SCRIPT_PATH = (Path(__file__).resolve().parents[1]
                / "containers" / "sandbox" / "scripts" / "api_probe.py")


def _load_script():
    spec = importlib.util.spec_from_file_location("api_probe_script",
                                                  _SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_wrapper_script_exists_in_the_image_source_tree():
    assert _SCRIPT_PATH.is_file()


def test_wrapper_request_policy_is_frozen():
    """The read-only request policy is CODE, not configuration: GET and
    OPTIONS only; the dangerous methods are structurally absent from
    the script's text."""
    script = _load_script()
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    # no state-changing method ANYWHERE in the script (the HTTP method
    # vocabulary in HTTP_METHODS is a metadata list for the doc parse;
    # only GET and OPTIONS are ever SENT)
    assert 'method="PUT"' not in text
    assert 'method="PATCH"' not in text
    assert 'method="DELETE"' not in text
    assert 'method="POST"' not in text
    # the only emitted methods are GET and OPTIONS (the default-parameter
    # signature of _request and the single OPTIONS call site)
    assert "method: str = \"GET\"" in text
    assert 'method="OPTIONS"' in text
    assert text.count("method=") == 2
    # redirects are disabled at the handler level (docstring mention is
    # fine; the handler is what does the work)
    assert "HTTPRedirectHandler" in text
    # no credentials are ever read, sent or stored
    for bad in ("Authorization", "Cookie", "Bearer", "api_key", "apikey",
                "password=", "token="):
        assert bad not in text, bad
    # the test origin is the ONE fixed inert literal
    assert script.CORS_TEST_ORIGIN == "https://kryonsec-cors-probe.invalid"
    # bounds are code constants
    assert script.MAX_REQUESTS == 7
    assert script.MAX_BODY_BYTES == 524_288
    assert script.PER_REQUEST_TIMEOUT_S == 10
    assert script.MAX_ENDPOINTS == 50


def test_wrapper_redirect_refusal():
    """A redirect is an OBSERVATION: never a follow-up request, and a
    cross-host target is flagged explicitly."""
    script = _load_script()

    class _H:
        def __init__(self, location):
            self._loc = location

        def get(self, name):
            return self._loc if name == "Location" else None

    obs = script._redirect_observation(
        "http://t-corp.com:8080/", _H("http://evil.example.net/x"))
    assert obs["followed"] is False
    assert obs["cross_host"] is True and obs["same_host"] is False
    same = script._redirect_observation(
        "http://t-corp.com:8080/", _H("/admin"))
    assert same["followed"] is False
    assert same["cross_host"] is False


def test_wrapper_document_parse_is_metadata_only():
    """OpenAPI parsing: json.loads only, refs counted never resolved,
    remote references OBSERVED and never fetched, operations
    enumerated but never invoked."""
    script = _load_script()
    spec = {
        "openapi": "3.0.1",
        "info": {"title": "Lab API"},
        "paths": {
            "/users": {"get": {}, "post": {}},
            "/users/{id}": {"delete": {"$ref": "#/paths/x"}},
            "/remote": {"get": {"$ref": "https://elsewhere.example.net/x"}},
        },
    }
    doc = script._parse_document(
        json.dumps(spec).encode(), "/openapi.json")
    assert doc["parsed"] is True
    assert doc["spec_version"] == "3.0.1"
    assert doc["title"] == "Lab API"
    assert doc["endpoint_count"] == 3
    assert doc["external_refs"] == ["https://elsewhere.example.net/x"]
    assert doc["ref_count_total"] == 2
    assert doc["endpoints"] == [
        "GET,POST /users", "DELETE /users/{id}", "GET /remote"]
    # oversized: metadata only, never parsed
    doc2 = script._parse_document(b"x" * script.MAX_BODY_BYTES, "/openapi.json")
    assert doc2["oversized"] is True and "parsed" not in doc2
    # a non-JSON body is recorded honestly
    doc3 = script._parse_document(b"<html>not a doc</html>", "/openapi.json")
    assert doc3["parsed"] is False
    # deep nesting is bounded (no runaway walk)
    deep = {"paths": {"/d": {"get": {}}}}
    node = deep
    for _ in range(50):
        node["paths"] = {"k": {"$ref": "http://x/"}}
        node = node["paths"]
    doc4 = script._parse_document(json.dumps(deep).encode(), "/openapi.json")
    assert doc4["ref_count_total"] <= 200


# ---- an in-process lab server (127.0.0.1 only, disposable) ----------------------

_LAB: "dict[str, str]" = {}
_LAB_HITS: "list[str]" = []


class _LabHandler(BaseHTTPRequestHandler):
    def _send(self, code, headers, body=b""):
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        _LAB_HITS.append(f"GET {self.path}")
        if self.path == "/":
            self._send(200, {
                "Content-Type": "text/html",
                "X-Content-Type-Options": "nosniff",
            }, b"<html>lab</html>")
        elif self.path == "/redirect-elsewhere":
            self._send(302, {"Location": "http://unapproved.example.test/"})
        elif self.path == "/openapi.json":
            spec = {"openapi": "3.0.1",
                    "info": {"title": "Lab API"},
                    "paths": {"/users": {"get": {}, "post": {}}}}
            self._send(200, {"Content-Type": "application/json"},
                       json.dumps(spec).encode())
        elif self.path == "/swagger.json":
            # an oversized document on a well-known doc path: recorded,
            # never parsed (the probe reads the 512KiB cap and stops)
            self._send(200, {"Content-Type": "application/json"},
                       b"x" * 600_000)
        elif self.path == "/origin":
            self._send(200, {
                "Access-Control-Allow-Origin":
                    _LAB["origin"],
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }, b"{}")
        else:
            self._send(404, {}, b"")

    def do_OPTIONS(self):
        _LAB_HITS.append(f"OPTIONS {self.path}")
        self._send(204, {"Allow": "GET, HEAD, OPTIONS"})

    def do_PUT(self):      # pragma: no cover — the probe must NEVER send this
        _LAB_HITS.append("PUT (FORBIDDEN ARRIVED)")
        self._send(405, {})

    def log_message(self, *args):   # silence the test output
        return


@pytest.fixture()
def lab_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _LAB["origin"] = "https://kryonsec-cors-probe.invalid"
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        server.server_close()


def test_wrapper_full_run_against_the_local_lab(lab_url):
    """Real requests over loopback: security-header observation, CORS
    reflection evidence, OPTIONS metadata, doc discovery, and the
    cross-host redirect recorded and NEVER followed."""
    script = _load_script()
    _LAB_HITS.clear()
    argv = [str(_SCRIPT_PATH), lab_url]
    sys_argv = sys.argv
    sys.argv = argv
    try:
        code = script.main()
    finally:
        sys.argv = sys_argv
    assert code == 0
    # exactly one script emitted payload
    # (capsys not needed: re-run main through its JSON contract instead)
    # re-run capturing stdout via the documented contract
    import io
    import contextlib

    buf = io.StringIO()
    sys_argv = sys.argv
    sys.argv = argv
    with contextlib.redirect_stdout(buf):
        script.main()
    sys.argv = sys_argv
    payload = json.loads(buf.getvalue())
    assert payload["kind"] == "kryonsec_api_probe"
    assert payload["requests_sent"] <= script.MAX_REQUESTS
    # base observation: the present header is data, the missing ones are
    # absent from the map (the adapter counts the gaps explicitly)
    base_headers = payload["base"]["security_headers"]
    assert "x-content-type-options" in base_headers
    assert "content-security-policy" not in base_headers
    # OPTIONS is metadata (an Allow header), nothing more
    assert payload["options"]["allow"] == "GET, HEAD, OPTIONS"
    # doc discovery found the fixture and enumerated its operations
    found = [d for d in payload["docs"]["found"] if d.get("path") ==
             "/openapi.json"]
    assert found and found[0]["parsed"] is True
    assert found[0]["endpoint_count"] == 1
    assert found[0]["endpoints"] == ["GET,POST /users"]
    # the oversized document was refused, honestly
    big = [d for d in payload["docs"]["found"] if d.get("path") ==
           "/swagger.json"]
    assert big and big[0].get("oversized") is True
    assert "parsed" not in big[0]
    # the redirect target: recorded, NEVER followed, no secondary request
    assert "unapproved.example.test" not in json.dumps(payload)
    hits = _LAB_HITS
    assert all(h.split()[0] in ("GET", "OPTIONS") for h in hits)
    assert not any(h.startswith("PUT") for h in hits)


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------


def test_production_registry_registers_api_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("api-probe",)         # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "web_recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "url"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()
    assert adapter.evidence_kind == "json_report"
    assert adapter.executable == TOOL_EXECUTABLE
    assert TOOL_EXECUTABLE.startswith("/opt/kryonsec/")
    assert reg.get(ADAPTER_ID) == make_api_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_api_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_the_api_lane():
    from kryonsec.purple.adapter_whatweb import recon_active_registry

    reg = recon_active_registry()
    assert "api-probe" in reg.adapter_ids()
    adapter = reg.get(ADAPTER_ID)
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.approvals == ()
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"


# ---- 2. the fixed template + frozen policy --------------------------------------


def test_fixed_template_rendering():
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET, target_asset=LAB_BASE)
    rebuilt = [LAB_BASE if a == "{url}" else a for a in API_PROBE_TEMPLATE]
    assert prep.argv == [TOOL_EXECUTABLE, *rebuilt]
    # exactly ONE argument: the approved URL
    assert prep.argv == [TOOL_EXECUTABLE, LAB_BASE]


def test_security_header_list_lockstep():
    """The adapter's baseline header list is the SAME list the baked
    script inspects (kept in lockstep by this test)."""
    script = _load_script()
    assert tuple(script.SECURITY_HEADERS) == SECURITY_HEADERS


def test_entrypoint_allowlist_carries_both_scripts():
    entrypoint = (Path(__file__).resolve().parents[1] / "containers"
                  / "sandbox" / "entrypoint.sh").read_text(
                      encoding="utf-8")
    assert '"/opt/kryonsec/api_probe.py"' in entrypoint
    assert '"/opt/kryonsec/tls_probe.py"' in entrypoint


# ---- 4. scope enforcement --------------------------------------------------------


def test_out_of_scope_target_refused_at_preparation():
    reg = production_registry()
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="https://elsewhere.example.com/api")
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="https://target-corp.net:8080/")
    # in-scope subdomain composes fine
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        target_asset="https://api.target-corp.com/")
    assert "api.target-corp.com" in prep.target


def test_invalid_targets_rejected():
    reg = production_registry()
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="https://x/;rm -rf /tmp")
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="https://x/ -X PUT")
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="https://x/ -o /tmp/pwned")


def test_option_shaped_values_refused_by_the_framework_guard():
    from kryonsec.purple.adapters import _no_option_shaped_values

    with pytest.raises(AdapterError):
        _no_option_shaped_values(API_PROBE_TEMPLATE,
                                 {"url": "--fuzz"})
    assert _no_option_shaped_values(
        API_PROBE_TEMPLATE, {"url": LAB_BASE}) is None


def test_layer2_deviating_argv_rejected():
    """The registry compiles the adapter's own template as its Layer-2
    allowlist: ANY deviation — an added flag, a second argument — is
    refused exactly like any other violation."""
    from kryonsec.purple.allowlist import AllowlistViolation, ToolAllowlist

    allow = ToolAllowlist(make_api_probe_adapter().templates_map())
    good = [TOOL_EXECUTABLE, LAB_BASE]
    allow.validate(TOOL_EXECUTABLE, good)            # the real shape passes

    for deviating in (
        # a caller-added flag — the script takes no flags
        [TOOL_EXECUTABLE, LAB_BASE, "--crawl"],
        # a second argument
        [TOOL_EXECUTABLE, LAB_BASE, "extra"],
        # a swapped executable
        ["/bin/sh", "-c", "curl -X PUT http://target-corp.com/"],
    ):
        with pytest.raises(AllowlistViolation):
            allow.validate(TOOL_EXECUTABLE, deviating)


# ---- 7. missing sandbox -------------------------------------------------------------


def test_missing_sandbox_no_host_fallback(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset=LAB_BASE)
    for bad in (None, object()):
        record = execute_adapter(reg, prep, sandbox=bad, audit=audit)
        assert record.executed is False and record.outcome == "refused"
        assert "no sandbox" in record.error_excerpt
    assert _event_names(audit).count("adapter_refused") == 2


# ---- 8. egress boundary unavailable ---------------------------------------------------


def test_no_egress_boundary_refused(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset=LAB_BASE)
    unegressed = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""))
    record = execute_adapter(reg, prep, sandbox=unegressed, audit=audit)
    assert record.executed is False and record.outcome == "refused"
    assert "egress policy" in record.error_excerpt
    assert unegressed.spawned == []
    assert _event_names(audit).count("adapter_refused") == 1


# ---- 9. tool timeout ----------------------------------------------------------------------


def test_tool_timeout_is_an_honest_failure(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset=LAB_BASE)
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                  error="tool exceeded 300s sandbox timeout"),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert output == ""
    assert find_adapter_attempt_node(graph, record.request_id) is None
    assert graph.by_type("api_observation") == []
    assert graph.by_type("vuln_candidate") == []


# ---- 10. nonzero tool exit -------------------------------------------------------------------


def test_nonzero_exit_is_not_success(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset=LAB_BASE)
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=1, stdout="",
                                  error="api probe failed"),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert graph.by_type("api_observation") == []
    assert graph.by_type("vuln_candidate") == []


# ---- 11. malformed and oversized output -------------------------------------------------------


def test_malformed_output_never_becomes_observations():
    run, malformed = parse_api_probe_payload(
        "api_probe is scanning...\nnot json\n{\"kind\": \"other\"}\n"
        + _payload_line() + "\n{half-written tail\n")
    assert run is not None
    assert run.url == LAB_BASE
    assert malformed == 3          # stops at the first well-formed payload
    run, malformed = parse_api_probe_payload(
        json.dumps({"kind": "kryonsec_api_probe", "requests_sent": 3}))
    assert run is None and malformed == 1
    run, malformed = parse_api_probe_payload("")
    assert run is None and malformed == 0
    # a bogus request count is malformed, never normalized
    run, malformed = parse_api_probe_payload(
        _payload_line(requests_sent=99))
    assert run is None and malformed == 1
    run, malformed = parse_api_probe_payload(
        _payload_line(requests_sent="three"))
    assert run is None and malformed == 1


def test_parser_real_shape_and_bounds():
    docs = {"probed": ["/openapi.json"], "found": [{
        "path": "/openapi.json", "status": 200,
        "spec_version": "3.0.1",
        "endpoints": ["GET,POST /users", "DELETE /users/{id}"],
        "endpoint_count": 2, "external_refs": [], "ref_count_total": 0,
    }], "unreachable": []}
    run, malformed = parse_api_probe_payload(_payload_line(
        docs=docs, security_headers={
            "x-content-type-options": "nosniff",
            "strict-transport-security": "max-age=31536000",
        }))
    assert malformed == 0
    assert run.requests_sent == 7
    assert run.base_status == 200
    assert run.security_headers["x-content-type-options"] == "nosniff"
    assert run.docs["found"][0]["endpoint_count"] == 2
    # header values are bounded data (200 chars max at the schema)
    long_headers = {h: "v" * 500 for h in SECURITY_HEADERS}
    run2, _ = parse_api_probe_payload(_payload_line(
        security_headers=long_headers))
    for value in run2.security_headers.values():
        assert len(value) <= 200


def test_weak_candidates_are_capped_at_low_severity():
    """The script's own flagged weaknesses stay LOW: header/CORS facts
    are baseline observations, never claims — nothing here can read as
    a high/critical finding."""
    run, _ = parse_api_probe_payload(
        _payload_line(security_headers={"server": "lab"}))
    cands = run.weak_candidates()
    assert {c["id"] for c in cands} == {
        "missing-strict-transport-security",
        "missing-content-security-policy",
        "missing-x-frame-options",
        "missing-x-content-type-options",
        "missing-referrer-policy",
        "missing-permissions-policy",
    }
    assert all(c["severity_as_reported"] == "low" for c in cands)
    # reflected wildcard CORS WITH credentials: still only evidence
    # (all six baseline headers present, so the header gaps flag nothing)
    run2, _ = parse_api_probe_payload(_payload_line(cors_probe={
        "status": 200, "test_origin": "https://kryonsec-cors-probe.invalid",
        "access_control_allow_origin":
            "https://kryonsec-cors-probe.invalid",
        "access_control_allow_credentials": "true",
        "vary": "Origin", "origin_reflected": True, "wildcard": False,
    }, security_headers={
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "x",
    }))
    cands2 = run2.weak_candidates()
    assert [c["id"] for c in cands2] == \
        ["cors-reflected-with-credentials"]
    assert cands2[0]["severity_as_reported"] == "low"
    assert "not a demonstrated exposure" in cands2[0]["finding"]
    # a normal, non-reflecting CORS answer flags nothing (all six
    # baseline headers present in this fixture)
    run3, _ = parse_api_probe_payload(_payload_line(cors_probe={
        "status": 200, "test_origin": "https://kryonsec-cors-probe.invalid",
        "access_control_allow_origin": "",
        "access_control_allow_credentials": "",
        "vary": "", "origin_reflected": False, "wildcard": False,
    }, security_headers={
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "x",
    }))
    assert run3.weak_candidates() == []


# ---- 12. evidence recording: full mapping + refusal without attempt node ----------------


def _prepared_record(executed=True, stdout=_payload_line()):
    return AdapterRunRecord(
        adapter_id=ADAPTER_ID,
        request_id="req-api-0001-abcd",
        executed=executed,
        outcome="executed" if executed else "not_run",
        exit_code=0 if executed else -1,
        error_excerpt="" if executed else "x",
        output_excerpt=stdout[:2000] if executed else "",
        evidence_kind="json_report",
        argv=[TOOL_EXECUTABLE, LAB_BASE],
        target=TARGET,
        tool=TOOL_EXECUTABLE,
        max_seconds=120,
        network="target_scope",
        approvals=(),
    )


def _with_attempt(graph):
    graph.add_node(
        node_type="adapter_attempt", label="adapter_attempt",
        properties={"request_id": "req-api-0001-abcd",
                    "adapter": ADAPTER_ID})
    return graph


def test_record_evidence_refuses_without_attempt_node(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    run, _ = parse_api_probe_payload(_payload_line())
    created = record_api_evidence(graph, audit,
                                  run_record=_prepared_record(), run=run)
    assert created == []
    names = _event_names(audit)
    assert names.count("api_adapter_evidence_refused") == 1
    assert graph.by_type("api_observation") == []
    assert graph.by_type("vuln_candidate") == []


def test_record_evidence_refuses_an_unparseable_payload(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _with_attempt(_graph())
    created = record_api_evidence(graph, audit,
                                  run_record=_prepared_record(
                                      stdout="garbage\n"),
                                  run=None, malformed_lines=1)
    assert created == []
    names = _event_names(audit)
    assert names.count("api_adapter_evidence_refused") == 1
    assert graph.by_type("api_observation") == []
    assert graph.by_type("vuln_candidate") == []


def test_evidence_mapping_and_idempotence(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _with_attempt(_graph())
    docs = {"probed": ["/openapi.json"], "found": [{
        "path": "/openapi.json", "status": 200,
        "spec_version": "3.0.1",
        "endpoints": ["GET,POST /users", "DELETE /users/{id}"],
        "endpoint_count": 2,
    }], "unreachable": []}
    run, malformed = parse_api_probe_payload(_payload_line(
        docs=docs, security_headers={
            "x-content-type-options": "nosniff",
        }))
    created = record_api_evidence(graph, audit,
                                  run_record=_prepared_record(),
                                  run=run, malformed_lines=malformed)
    # one run-summary api_observation node + two OpenAPI path nodes
    # (metadata only) + the baseline-gap candidates (6 missing headers)
    obs = graph.by_type("api_observation")
    assert len(obs) == 1
    props = obs[0]["properties"]
    assert props["verification"] == "not_verified"
    assert props["classification"] == "tool_reported_observation"
    assert props["base_status"] == 200
    assert "x-content-type-options" in props["security_headers"]
    assert "content-security-policy" in props["missing_security_headers"]
    assert props["untrusted"] is True
    paths = graph.by_type("path")
    assert {p["label"] for p in paths} == {"/users", "/users/{id}"}
    for p in paths:
        assert p["properties"]["source"] == "api_probe"
        assert p["properties"]["verification"] == "not_verified"
        assert p["properties"]["methods"] in ("GET,POST", "DELETE")
    cands = graph.by_type("vuln_candidate")
    # x-content-type-options was present in the fixture, so exactly the
    # other five baseline headers are flagged
    assert len(cands) == 5
    for node in cands:
        assert node["properties"]["verification"] == "not_verified"
        assert node["properties"]["classification"] == "detected_candidate"
        assert node["properties"]["severity_as_reported"] == "low"
    attempt = find_adapter_attempt_node(graph, "req-api-0001-abcd")
    produced = [e for e in graph.edges
                if e.get("relationship") == "produced"
                and e.get("source_node_id") == attempt["id"]]
    assert len(produced) == 8
    ok, reason = audit.verify()
    assert ok, reason
    names = _event_names(audit)
    assert names.count("api_adapter_evidence") == 1
    # IDEMPOTENCE: a repeat run adds nothing (first observation wins)
    created2 = record_api_evidence(graph, audit,
                                   run_record=_prepared_record(), run=run)
    assert created2 == []
    assert len(graph.by_type("api_observation")) == 1
    assert len(graph.by_type("path")) == 2
    assert len(graph.by_type("vuln_candidate")) == 5


# ---- 13. detection is NEVER confirmation -------------------------------------------------


def test_observation_is_never_a_confirmed_finding(tmp_path):
    """A permissive CORS answer or a missing header stays a low-severity
    vuln_candidate with not_verified — no finding node, no verification
    upgrade, no capability write, no gate bypass, no exploit language."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _with_attempt(_graph())
    run, _ = parse_api_probe_payload(_payload_line(
        security_headers={}, cors_probe={
            "status": 200, "test_origin": "https://kryonsec-cors-probe.invalid",
            "access_control_allow_origin": "*",
            "access_control_allow_credentials": "true",
            "vary": "", "origin_reflected": False, "wildcard": True,
        }))
    record_api_evidence(graph, audit, run_record=_prepared_record(), run=run)
    assert graph.by_type("finding") == []
    for node in graph.by_type("vuln_candidate"):
        assert node["properties"]["verification"] == "not_verified"
        assert node["properties"]["severity_as_reported"] == "low"
    dump = json.dumps(graph.to_dict())
    for phrase in ("credential theft", "account takeover", "confirmed",
                   "exploited"):
        assert phrase not in dump
    record = _prepared_record()
    dump = record.model_dump_json()
    assert "confirmed" not in dump
    reg = production_registry()
    assert reg.get(ADAPTER_ID).approvals == ()
    assert reg.get(ADAPTER_ID).stages == ("RECON_ACTIVE",)


def test_no_host_execution_in_adapter_modules():
    """The adapter module never constructs a docker/subprocess/os.system
    call — host-side execution does not exist on this path."""
    mod = (Path(__file__).resolve().parents[1] / "src" /
           "kryonsec" / "purple" / "adapter_api.py").read_text(
               encoding="utf-8")
    assert "subprocess" not in mod
    assert "os.system" not in mod
    assert "docker run" not in mod
    assert "KaliSandbox" not in mod


# ---- 14. no duplicate Recon Active probing / deterministic wiring ------------------------


def _fake_stage1(script):
    return FakeSandbox(script=script, egress_policy=_StubEgressPolicy())


def _recon(sandbox, registry, tmp_path, target=TARGET):
    cfg = _cfg(tmp_path)
    audit = AuditLog(tmp_path / "ra.jsonl")
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", target, {})
    sub = ReconActiveSubagent(cfg, graph, audit, target, sandbox,
                              adapter_registry=registry)
    result = sub.run()
    return result, sandbox.spawned, graph, audit


def _script_api_lane(argv):
    """Stage 1 finds an HTTP port (8080); the api-probe script gets an
    honest payload; every other tool answers empty."""
    tool = argv[0]
    if tool == "nmap":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="8080/tcp   open  http    nginx")
    if tool == "naabu":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="target-corp.com:8080")
    if tool == "dnsx":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="target-corp.com [A] 203.0.113.7")
    if tool == TOOL_EXECUTABLE:
        url = argv[1]
        return SpawnResult(ok=True, exit_code=0, stdout=_payload_line(url=url))
    return SpawnResult(ok=True, exit_code=0, stdout="")


def test_api_lane_runs_once_replaces_legacy_openapi_probe(tmp_path):
    sandbox = _fake_stage1(_script_api_lane)
    result, spawned, graph, audit = _recon(
        sandbox, production_registry(), tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    # the legacy openapi_probe entry is REPLACED — never both
    assert [a for a in cmdl if a and a[0] ==
            "/opt/kryonsec/openapi_probe.py"] == []
    runs = [a for a in cmdl if a and a[0] == TOOL_EXECUTABLE]
    assert len(runs) == 1
    assert runs[0][1] == "http://target-corp.com:8080/"
    assert len(graph.by_type("api_observation")) == 1
    names = _event_names(audit)
    assert "recon_active_api_adapter" in names
    assert "recon_active_adapter_failure" not in names
    ok, reason = audit.verify()
    assert ok, reason


def test_empty_registry_keeps_the_legacy_openapi_entry(tmp_path):
    """No registered adapter -> the legacy plan unchanged (deterministic
    either/or in the other direction)."""
    sandbox = _fake_stage1(_script_api_lane)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    legacy = [a for a in cmdl if a and a[0] ==
              "/opt/kryonsec/openapi_probe.py"]
    assert len(legacy) == 1
    assert [a for a in cmdl if a and a[0] == TOOL_EXECUTABLE] == []
    assert graph.by_type("adapter_attempt") == []
    assert "recon_active_api_adapter" not in _event_names(audit)


def test_unreachable_target_is_an_honest_inconclusive(tmp_path):
    """A run whose payload says the base never answered classifies as
    INCONCLUSIVE — never as a negative finding."""
    def script(argv):
        tool = argv[0]
        if tool == "nmap":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="8080/tcp   open  http    nginx")
        if tool == "naabu":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com:8080")
        if tool == "dnsx":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com [A] 203.0.113.7")
        if tool == TOOL_EXECUTABLE:
            return SpawnResult(ok=True, exit_code=1, stdout=_payload_line(
                status="error", base_status=0))
        return SpawnResult(ok=True, exit_code=0, stdout="")

    sandbox = _fake_stage1(script)
    result, _spawned, graph, audit = _recon(
        sandbox, production_registry(), tmp_path)
    assert result.status == "ok"
    ev = [e for e in _events(audit)
          if e["event"] == "recon_active_api_adapter"]
    assert ev and ev[0]["outcome"] == "inconclusive"
    assert ev[0]["probe_status"] == "error"


def test_adapter_failure_never_fails_the_state(tmp_path):
    def script(argv):
        tool = argv[0]
        if tool == "nmap":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="8080/tcp   open  http    nginx")
        if tool == "naabu":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com:8080")
        if tool == "dnsx":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com [A] 203.0.113.7")
        if tool == TOOL_EXECUTABLE:
            return SpawnResult(ok=False, exit_code=1, stdout="",
                               error="probe crashed")
        return SpawnResult(ok=True, exit_code=0, stdout="")

    sandbox = _fake_stage1(script)
    result, _spawned, graph, audit = _recon(
        sandbox, production_registry(), tmp_path)
    assert result.status == "ok"
    names = _event_names(audit)
    assert names.count("recon_active_adapter_failure") == 1
    assert graph.by_type("api_observation") == []


# ---- 15. Gate 2 / Gate 3 behavior unchanged ---------------------------------------------------


def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset=LAB_BASE)
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=_payload_line()),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    assert record.executed is True
    for ev in _events(audit):
        label = json.dumps(ev)
        assert "gate_decision" not in label
        assert "capability" not in ev.get("event", "")
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    assert graph.by_type("capability") == []
    for adapter in reg.list_adapters():
        assert adapter.stages == ("RECON_ACTIVE",)
    from kryonsec.purple.adapters import ModeBToolAdapter

    with pytest.raises(ValidationError):
        ModeBToolAdapter(**{
            **make_api_probe_adapter().model_dump(),
            "adapter_id": "api-post", "stages": ("POST_EXPLOIT",),
        })


# ---- 16. no capability or Post-Exploit activation ---------------------------------------------


def test_no_capability_or_post_exploit_activation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset=LAB_BASE)
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=_payload_line()),
                      egress_policy=_StubEgressPolicy())
    execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    assert graph.by_type("capability") == []
    assert graph.by_type("finding") == []
    dump = json.dumps(graph.to_dict())
    assert "post_exploit_gate" not in dump
    adapter = reg.get(ADAPTER_ID)
    assert adapter.approvals == ()
    assert adapter.stages == ("RECON_ACTIVE",)


# ---- the ONE genuine integration test (opt-in, local lab only) ------------------------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab URL."""
    lab = os.environ.get("KRYONSEC_API_LAB_URL", "").strip()
    if not lab.lower().startswith(("http://", "https://")):
        return False, "KRYONSEC_API_LAB_URL must be an http(s) lab URL"
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_API_IT") != "1":
        return False, "KRYONSEC_API_IT=1 not set"
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    if not ok:
        return False, f"docker daemon: {reason}"
    if not rc.runsc_registered():
        return False, "runsc runtime not registered"
    from kryonsec.config import KryonsecConfig

    image = KryonsecConfig().sandbox_image
    if "@sha256:" not in image:
        return False, ("sandbox image is not digest-pinned in this "
                       "environment (rule 7) — set KRYONSEC_SANDBOX_IMAGE")
    if not rc.image_present(image):
        return False, f"pinned sandbox image absent: {image}"
    return True, ""


def test_real_api_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real read-only api_probe.py run — against the local lab
    endpoint the OPERATOR supplies (a disposable API lab with
    predictable security-header/CORS responses). Skipped silently
    otherwise.

    Authorize NOTHING public: point KRYONSEC_API_LAB_URL at an endpoint
    you control (e.g. a lab container on your own Docker bridge).
    """
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from urllib.parse import urlsplit

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.egress import EgressGate, build_policy, \
        register_active, release_active
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig()
    lab = os.environ["KRYONSEC_API_LAB_URL"].strip()
    host = urlsplit(lab).hostname or ""
    assert host, lab

    policy = build_policy(cfg, "api-it", target=host)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    # register so the finally-block teardown actually removes the
    # network (release_active is a silent no-op for unregistered ids)
    register_active(policy, gate)
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_api_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="api-it")
    graph.add_node("target", host, {})
    try:
        # out-of-scope stays refused even in a real environment
        with pytest.raises(AdapterScopeRefused):
            prepare_adapter_run(reg, ADAPTER_ID, target=host,
                                target_asset="http://elsewhere.example.com/")
        prep = prepare_adapter_run(reg, ADAPTER_ID, target=host,
                                   target_asset=lab)
        record, output = execute_adapter(reg, prep, sandbox=sbx,
                                         audit=audit, graph=graph,
                                         full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.exit_code == 0, (record.exit_code,
                                       record.output_excerpt[:400])
        assert record.verification == "not_verified"
        run, malformed = parse_api_probe_payload(output)
        assert run is not None, output[:400]
        assert run.requests_sent <= 7
        assert malformed == 0
        created = record_api_evidence(graph, audit, run_record=record,
                                      run=run, malformed_lines=malformed)
        assert graph.by_type("api_observation")
        # the event's node accounting matches the returned list
        ev = [e for e in _events(audit)
              if e["event"] == "api_adapter_evidence"]
        assert ev and ev[0]["requests_sent"] == run.requests_sent
        assert ev[0]["nodes_created"] == len(created)
        # no destructive request is possible — the script emits GET and
        # OPTIONS only (structurally; see the wrapper policy tests)
        assert graph.by_type("finding") == []
        for node in graph.by_type("vuln_candidate"):
            assert node["properties"]["verification"] == "not_verified"
            assert node["properties"]["classification"] == \
                "detected_candidate"
            assert node["properties"]["severity_as_reported"] == "low"
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("api-it")
        except Exception:
            pass
        for path in (Path("tmp_api_it_audit.jsonl"),):
            if path.exists():
                path.unlink()
