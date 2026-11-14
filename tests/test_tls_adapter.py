"""Tests for the vetted tls-probe Mode B adapter (Phase 2B.5).

Everything here runs against harmless fakes; the ONE genuine
integration test at the bottom is opt-in (KRYONSEC_TLS_IT=1) and
skipped silently otherwise, like the other adapter ITs.

The baked wrapper script itself (containers/sandbox/scripts/
tls_probe.py) is exercised IN PROCESS for its pure logic (node
parsing, truncated-JSON salvage) — no subprocess, no network.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
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
from kryonsec.purple.adapter_tls import (
    ADAPTER_ID,
    TLS_PROBE_TEMPLATE,
    TOOL_EXECUTABLE,
    find_adapter_attempt_node,
    make_tls_probe_adapter,
    parse_tls_probe_payload,
    production_registry,
    record_tls_evidence,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult

TARGET = "target-corp.com"
LAB_BASE = "https://target-corp.com:8443/"


# ---- harmless fakes ------------------------------------------------------------


class _StubEgressPolicy:
    """Duck-typed egress-policy stub (the executor only needs presence;
    the REAL enforcement lives inside the sandbox's own spawn)."""


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


def _payload_line(url=LAB_BASE,
                  status="complete",
                  findings=None) -> str:
    """The REAL tls_probe.py payload shape (the wrapper's contract)."""
    payload = {
        "kind": "kryonsec_tls_probe",
        "url": url,
        "node": "target-corp.com:8443",
        "tool": "testssl",
        "tool_version": "3.2.4",
        "status": status,
        "exit_code": 0,
        "argv_reference": ["/usr/bin/testssl", "--quiet", "--color",
                           "0", "--warnings", "batch",
                           "--connect-timeout", "10", "--jsonfile",
                           "/tmp/kryonsec_tls_probe.json",
                           "target-corp.com:8443"],
        "started_at": "2026-11-12T14:00:00Z",
        "findings": findings if findings is not None else [],
        "finding_count": len(findings or []),
        "truncated": False,
    }
    return json.dumps(payload)


def _finding(fid="cert_expirationStatus",
             severity="HIGH",
             finding="Certificate expired",
             cve="", port="8443") -> dict:
    return {"id": fid, "severity_as_reported": severity,
            "finding": finding, "cve": cve, "port": port}


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
                / "containers" / "sandbox" / "scripts" / "tls_probe.py")


def _load_script():
    spec = importlib.util.spec_from_file_location("tls_probe_script",
                                                  _SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_wrapper_script_exists_in_the_image_source_tree():
    assert _SCRIPT_PATH.is_file()


def test_wrapper_parses_https_nodes_only():
    script = _load_script()
    node, host, port = script._parse_node("https://t-corp.com:8443/")
    assert (node, host, port) == ("t-corp.com:8443", "t-corp.com", 8443)
    # default port 443
    node, _h, port = script._parse_node("https://t-corp.com/")
    assert port == 443 and node == "t-corp.com:443"
    # a path is dropped: TLS is a host:port property
    node, _h, port = script._parse_node("https://t-corp.com:9443/admin")
    assert node == "t-corp.com:9443"
    # plain http and junk are refused (fail closed — no TLS inspection
    # is forced onto a non-TLS target)
    assert script._parse_node("http://t-corp.com/") is None
    assert script._parse_node("not a url") is None
    assert script._parse_node("https:///") is None


def test_wrapper_salvages_truncated_json_honestly():
    """A killed testssl leaves an incrementally-written, truncated
    findings file (verified live): the salvage parser recovers only
    the COMPLETE flat finding objects — never invents one."""
    script = _load_script()
    complete = json.dumps([
        {"id": "TLS1_3", "severity": "OK", "finding": "offered",
         "port": "8443"},
        {"id": "cert_expirationStatus", "severity": "HIGH",
         "finding": "Certificate expired", "port": "8443"},
    ])
    assert len(script._salvage_findings(complete)) == 2
    # truncated mid-object: the first is recovered, the partial one is not
    truncated = complete[: complete.index('"Certificate expired"') - 30]
    salvage = script._salvage_findings(truncated)
    assert [f["id"] for f in salvage] == ["TLS1_3"]
    # nested junk is never guessed into a finding
    assert script._salvage_findings('{"a": {"b": {"c": 1}}}') == []


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------


def test_production_registry_registers_tls_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("tls-probe",)         # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "web_recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "url"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()          # RECON_ACTIVE authorization =
                                            # engagement model, not silent
    assert adapter.evidence_kind == "json_report"
    assert adapter.executable == TOOL_EXECUTABLE
    assert TOOL_EXECUTABLE.startswith("/opt/kryonsec/")
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_tls_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_tls_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_the_tls_lane():
    from kryonsec.purple.adapter_whatweb import recon_active_registry

    reg = recon_active_registry()
    assert "tls-probe" in reg.adapter_ids()
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
    rebuilt = [LAB_BASE if a == "{url}" else a for a in TLS_PROBE_TEMPLATE]
    assert prep.argv == [TOOL_EXECUTABLE, *rebuilt]
    # exactly ONE argument: the approved URL — the wrapper refuses
    # everything else
    assert prep.argv == [TOOL_EXECUTABLE, LAB_BASE]


def test_wrapper_policy_is_frozen():
    """THE core policy test: every testssl flag is a literal INSIDE the
    reviewed wrapper script's frozen argv tuple; the adapter's template
    can never carry one. The dangerous surface is named and asserted
    absent from the REAL invocation tuple: no phone-out (external
    reporting), no user-selected checks, no custom openssl, no
    basicauth, no proxy, no caller config file."""
    assert TLS_PROBE_TEMPLATE == ("{url}",)
    script = _load_script()
    invocation = (script.TESTSSL_BIN,) + tuple(script._ARGV_TEMPLATE)
    forbidden = {
        "--phone-out",       # external reporting / telemetry
        "--basicauth",       # authenticated testing
        "--proxy",           # third-party proxy path
        "--add-ca",          # caller-chosen CA trust material
        "--configfile", "--config",
        "--user", "--user-magic",
        "--mode",            # mass-testing modes the wrapper doesn't own
        "--fast", "--exhaustive", "--sequential", "--parallel",
        "--each-cipher", "--each-proto", "--protocols", "--targets-in",
        "--file", "--logfile", "--csvfile", "--htmlfile",
        "--ciphers", "--openssl",   # caller-chosen binary or cipher set
    }
    for flag in forbidden:
        assert flag not in invocation, flag
    # the frozen flag set is exactly the reviewed one: no user flag can
    # appear, nothing else can be appended (argv is [bin, *template,
    # node] and the wrapper refuses len(sys.argv) != 2)
    assert invocation == (
        "/usr/bin/testssl",
        "--quiet", "--color", "0", "--warnings", "batch",
        "--connect-timeout", "10", "--jsonfile",
        script.JSONFILE,
    )
    # the invocation is a subprocess ARGV LIST, never a shell string
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "subprocess.run(" in text
    assert "shell=True" not in text
    assert "os.system" not in text
    assert "Popen(" not in text
    # the wrapper kills the tool itself, INSIDE the sandbox ceiling
    assert script.TESTSSL_TIMEOUT_S == 240
    # Phase 2B.8 bounded summary: the self-bound stays well inside the
    # host's unchanged 20,000-char cap (the entrypoint's jq escaping
    # grows the payload); the selection bounds keep the sections small
    assert script.OUTPUT_BOUND_CHARS == 10_000
    assert script.OUTPUT_BOUND_CHARS < 20_000
    assert script.TOP_WEAK_FINDINGS == 20
    assert script.ARTIFACT_MAX_BYTES == 2_000_000


def test_image_tools_match_the_wrapper_contract():
    """Dockerfile.kali already installs the tool and COPYs the script
    dir; the wrapper's binary name matches the Kali package reality
    (the package testssl.sh installs /usr/bin/testssl — verified live
    in the pinned image)."""
    dockerfile = (Path(__file__).resolve().parents[1] / "containers"
                  / "sandbox" / "Dockerfile.kali").read_text(encoding="utf-8")
    assert "testssl.sh" in dockerfile     # the apt package name
    entrypoint = (Path(__file__).resolve().parents[1] / "containers"
                  / "sandbox" / "entrypoint.sh").read_text(
                      encoding="utf-8")
    assert '"/opt/kryonsec/tls_probe.py"' in entrypoint
    assert '"/opt/kryonsec/api_probe.py"' in entrypoint


# ---- 4. scope enforcement --------------------------------------------------------


def test_out_of_scope_target_refused_at_preparation():
    reg = production_registry()
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="https://elsewhere.example.com:8443/")
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="https://target-corp.net:8443/")
    # in-scope subdomain composes fine
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        target_asset="https://mail.target-corp.com/")
    assert "mail.target-corp.com" in prep.target


def test_invalid_targets_rejected():
    reg = production_registry()
    # shell-metacharacter / injection-shaped "url" is refused by Layer 2
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="https://x/;rm -rf /tmp")
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="https://x/ -o /tmp/pwned")


def test_option_shaped_values_refused_by_the_framework_guard():
    """The framework's option-injection guard applies to the {url}
    variable this template carries: a value beginning with '-' can
    never be rendered into it."""
    from kryonsec.purple.adapters import _no_option_shaped_values

    with pytest.raises(AdapterError):
        _no_option_shaped_values(TLS_PROBE_TEMPLATE,
                                 {"url": "--phone-out"})
    assert _no_option_shaped_values(
        TLS_PROBE_TEMPLATE, {"url": LAB_BASE}) is None


def test_layer2_deviating_argv_rejected():
    """The registry compiles the adapter's own template as its Layer-2
    allowlist: ANY deviation — an added flag, a second argument — is
    refused exactly like any other violation."""
    from kryonsec.purple.allowlist import AllowlistViolation, ToolAllowlist

    allow = ToolAllowlist(make_tls_probe_adapter().templates_map())
    good = [TOOL_EXECUTABLE, LAB_BASE]
    allow.validate(TOOL_EXECUTABLE, good)            # the real shape passes

    for deviating in (
        # a caller-added testssl flag — the wrapper owns the flags
        [TOOL_EXECUTABLE, LAB_BASE, "--phone-out"],
        # a second argument
        [TOOL_EXECUTABLE, LAB_BASE, "extra"],
        # a swapped executable (the wrapper path is fixed)
        ["/bin/sh", "-c", "testssl --phone-out"],
    ):
        with pytest.raises(AllowlistViolation):
            allow.validate(TOOL_EXECUTABLE, deviating)


# ---- 7. missing sandbox -------------------------------------------------------------


def test_missing_sandbox_no_host_fallback(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset=LAB_BASE)
    for bad in (None, object()):          # none + no-spawn blob
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
    assert "300s" in record.error_excerpt
    assert output == ""
    # no attempt node, no observation nodes — a timeout fabricates nothing
    assert find_adapter_attempt_node(graph, record.request_id) is None
    assert graph.by_type("tls_observation") == []
    assert graph.by_type("vuln_candidate") == []


# ---- 10. nonzero tool exit -------------------------------------------------------------------


def test_nonzero_exit_is_not_success(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset=LAB_BASE)
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=1, stdout="",
                                  error="tls probe failed"),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert graph.by_type("tls_observation") == []
    assert graph.by_type("vuln_candidate") == []


# ---- 11. malformed and oversized output -------------------------------------------------------


def test_malformed_output_never_becomes_observations():
    run, malformed = parse_tls_probe_payload(
        "testssl is scanning...\nnot json at all\n{\"kind\": \"other\"}\n"
        + _payload_line() + "\n{half-written tail\n")
    assert run is not None
    assert run.node == "target-corp.com:8443"
    # the loop stops at the FIRST well-formed payload; the lines before
    # it (and the tail after, never reached) are not re-counted
    assert malformed == 3
    # a payload missing its kind marker or node is malformed too
    run, malformed = parse_tls_probe_payload(
        json.dumps({"kind": "kryonsec_tls_probe", "url": "x"}))
    assert run is None and malformed == 1
    run, malformed = parse_tls_probe_payload("")
    assert run is None and malformed == 0
    # findings without an id are skipped, not guessed
    run, _ = parse_tls_probe_payload(_payload_line(findings=[
        _finding(), {"no_id": True}, {"id": "", "severity": "HIGH"}]))
    assert run is not None and len(run.findings) == 1


def test_parser_real_shape_and_bounds():
    findings = [_finding("TLS1_3", "OK", "offered with final"),
                _finding("cert_expirationStatus", "HIGH",
                         "Certificate expired"),
                _finding("cipherlist_OBSOLETED", "LOW",
                         "offered", cve="CVE-2014-3566"),
                _finding("ROBOT", "CRITICAL", "VULNERABLE"),
                _finding("header_hsts", "INFO", "not present")]
    run, malformed = parse_tls_probe_payload(
        _payload_line(findings=findings, status="complete"))
    assert malformed == 0
    assert run.tool == "testssl"
    assert run.tool_version == "3.2.4"
    assert run.status == "complete"
    assert len(run.findings) == 5
    # the severity label is DATA: only the known label set is trusted
    # into the field (the schema bounds the string either way)
    bad = [_finding("weird", "APOCALYPTIC", "nonsense")]
    run2, _ = parse_tls_probe_payload(_payload_line(findings=bad))
    assert run2.findings[0].severity_as_reported == "APOCALYPTIC"
    # a 200-finding payload is BOUNDED to the schema's 120
    huge = [_finding(f"f{i}") for i in range(200)]
    run3, _ = parse_tls_probe_payload(
        _payload_line(findings=huge[:200]))
    assert run3.findings == run3.findings[:120]
    assert run3.truncated is False    # the wrapper's flag is data, not ours


def test_weakness_semantics_are_the_label_set():
    """Only the tool's OWN weakness labels become candidates; OK/INFO
    stay observations-only. A tool-reported weakness is a candidate
    until the project's verification contracts say otherwise."""
    run, _ = parse_tls_probe_payload(_payload_line(findings=[
        _finding("cert_expirationStatus", "HIGH", "expired"),
        _finding("TLS1", "OK", "not offered"),
        _finding("hsts", "INFO", "absent"),
        _finding("ROBOT", "CRITICAL", "vulnerable"),
    ]))
    weak = {f.finding_id for f in run.weak_findings}
    assert weak == {"cert_expirationStatus", "ROBOT"}


# ---- 12. evidence recording: full mapping + refusal without attempt node ----------------


def _prepared_record(executed=True, stdout=_payload_line()):
    return AdapterRunRecord(
        adapter_id=ADAPTER_ID,
        request_id="req-tls-0001-abcd",
        executed=executed,
        outcome="executed" if executed else "not_run",
        exit_code=0 if executed else -1,
        error_excerpt="" if executed else "x",
        output_excerpt=stdout[:2000] if executed else "",
        evidence_kind="json_report",
        argv=[TOOL_EXECUTABLE, LAB_BASE],
        target=TARGET,
        tool=TOOL_EXECUTABLE,
        max_seconds=300,
        network="target_scope",
        approvals=(),
    )


def test_record_evidence_refuses_without_attempt_node(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    created = record_tls_evidence(graph, audit,
                                  run_record=_prepared_record(),
                                  run=parse_tls_probe_payload(
                                      _payload_line(findings=[
                                          _finding("ROBOT", "CRITICAL",
                                                   "vulnerable")]))[0])
    assert created == []
    names = _event_names(audit)
    assert names.count("tls_adapter_evidence_refused") == 1
    # nothing was fabricated onto the graph
    assert graph.by_type("tls_observation") == []
    assert graph.by_type("vuln_candidate") == []


def test_record_evidence_refuses_an_unparseable_payload(tmp_path):
    """A run that produced garbage output records the refusal and
    leaves NOTHING behind — silence about TLS is never a clean bill."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    attempt = graph.add_node(
        node_type="adapter_attempt",
        label="adapter_attempt",
        properties={"request_id": "req-tls-0001-abcd", "adapter": ADAPTER_ID},
    )
    assert attempt is not None
    created = record_tls_evidence(graph, audit,
                                  run_record=_prepared_record(
                                      stdout="garbage\n"),
                                  run=None, malformed_lines=1)
    assert created == []
    names = _event_names(audit)
    assert names.count("tls_adapter_evidence_refused") == 1
    assert graph.by_type("tls_observation") == []
    assert graph.by_type("vuln_candidate") == []


def test_evidence_mapping_and_idempotence(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    attempt = graph.add_node(
        node_type="adapter_attempt",
        label="adapter_attempt",
        properties={"request_id": "req-tls-0001-abcd", "adapter": ADAPTER_ID},
    )
    run, malformed = parse_tls_probe_payload(_payload_line(findings=[
        _finding("cert_expirationStatus", "HIGH", "Certificate expired"),
        _finding("TLS1_3", "OK", "offered with final"),
        _finding("ROBOT", "CRITICAL", "VULNERABLE"),
    ]))
    created = record_tls_evidence(graph, audit, run_record=_prepared_record(),
                                  run=run, malformed_lines=malformed)
    # one run-summary tls_observation node + TWO weakness candidates
    # (OK findings never become candidates)
    assert len(graph.by_type("tls_observation")) == 1
    cands = graph.by_type("vuln_candidate")
    assert len(cands) == 2
    labels = {n["label"] for n in cands}
    assert labels == {
        "testssl cert_expirationStatus @ target-corp.com:8443",
        "testssl ROBOT @ target-corp.com:8443",
    }
    summary = graph.by_type("tls_observation")[0]
    props = summary["properties"]
    assert props["verification"] == "not_verified"
    assert props["classification"] == "tool_reported_observation"
    assert props["tool_version"] == "3.2.4"
    assert props["protocol_offers"] == {"TLS1_3": "offered with final"}
    assert props["certificate_observations"] == {
        "cert_expirationStatus": "Certificate expired"}
    assert len(props["weak_findings"]) == 2
    assert props["untrusted"] is True
    for node in cands:
        assert node["properties"]["verification"] == "not_verified"
        assert node["properties"]["classification"] == "detected_candidate"
        assert node["properties"]["severity_as_reported"] in \
            ("HIGH", "CRITICAL")
    # lineage: every created node hangs off the run's attempt node
    produced = [e for e in graph.edges if e.get("relationship") == "produced"
                and e.get("source_node_id") == attempt["id"]]
    assert len(produced) == 3
    ok, reason = audit.verify()
    assert ok, reason
    names = _event_names(audit)
    assert names.count("tls_adapter_evidence") == 1
    # IDEMPOTENCE: a repeat run adds nothing (first observation wins)
    created2 = record_tls_evidence(graph, audit, run_record=_prepared_record(),
                                   run=run)
    assert created2 == []
    assert len(graph.by_type("tls_observation")) == 1
    assert len(graph.by_type("vuln_candidate")) == 2


# ---- 13. detection is NEVER confirmation -------------------------------------------------


def test_observation_is_never_a_confirmed_finding(tmp_path):
    """A CRITICAL testssl label on the graph stays a vuln_candidate
    with not_verified — no finding node, no verification upgrade, no
    capability write, no gate bypass."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    graph.add_node(
        node_type="adapter_attempt", label="adapter_attempt",
        properties={"request_id": "req-tls-0001-abcd",
                    "adapter": ADAPTER_ID})
    run, _ = parse_tls_probe_payload(_payload_line(findings=[
        _finding("ROBOT", "CRITICAL", "VULNERABLE")]))
    record_tls_evidence(graph, audit, run_record=_prepared_record(), run=run)
    assert graph.by_type("finding") == []
    for node in graph.by_type("vuln_candidate"):
        assert node["properties"]["verification"] == "not_verified"
    # the record type itself cannot carry a confirmation
    record = _prepared_record()
    assert record.verification == "not_verified"
    dump = record.model_dump_json()
    assert "confirmed" not in dump
    # registration vocabulary excludes gates for RECON_ACTIVE-only
    reg = production_registry()
    assert reg.get(ADAPTER_ID).approvals == ()
    assert reg.get(ADAPTER_ID).stages == ("RECON_ACTIVE",)


def test_no_host_execution_in_adapter_modules():
    """The adapter modules never construct a docker/subprocess/os.system
    call — host-side execution does not exist on this path."""
    for name in ("adapter_tls.py",):
        mod = (Path(__file__).resolve().parents[1] / "src" /
               "kryonsec" / "purple" / name).read_text(encoding="utf-8")
        assert "subprocess" not in mod, name
        assert "os.system" not in mod, name
        assert "docker run" not in mod, name
        assert "KaliSandbox" not in mod, name


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


def _script_tls_lane(argv):
    """Stage 1 finds an HTTPS port (8443); the tls-probe wrapper gets an
    honest payload; every other tool answers empty."""
    tool = argv[0]
    if tool == "nmap":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="8443/tcp   open  https   nginx")
    if tool == "naabu":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="target-corp.com:8443")
    if tool == "dnsx":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="target-corp.com [A] 203.0.113.7")
    if tool == TOOL_EXECUTABLE:
        url = argv[1]
        return SpawnResult(ok=True, exit_code=0, stdout=_payload_line(
            url=url, findings=[
                _finding("cert_expirationStatus", "HIGH",
                         "Certificate expired")]))
    return SpawnResult(ok=True, exit_code=0, stdout="")


def test_tls_lane_runs_once_on_https_bases_only(tmp_path):
    sandbox = _fake_stage1(_script_tls_lane)
    result, spawned, graph, audit = _recon(
        sandbox, production_registry(), tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    # the legacy sslscan/testssl.sh entries are REPLACED — never both
    assert [a for a in cmdl if a and a[0] in ("sslscan", "testssl.sh")] == []
    runs = [a for a in cmdl if a and a[0] == TOOL_EXECUTABLE]
    assert len(runs) == 1
    assert runs[0][1] == "https://target-corp.com:8443/"
    obs = graph.by_type("tls_observation")
    assert len(obs) == 1
    assert obs[0]["properties"]["adapter"] == ADAPTER_ID
    cands = graph.by_type("vuln_candidate")
    assert len(cands) == 1
    assert cands[0]["properties"]["adapter"] == ADAPTER_ID
    assert cands[0]["properties"]["verification"] == "not_verified"
    names = _event_names(audit)
    assert "recon_active_tls_adapter" in names
    assert "recon_active_adapter_failure" not in names
    ok, reason = audit.verify()
    assert ok, reason


def test_tls_lane_never_runs_on_plain_http(tmp_path):
    """A TLS baseline is not forced onto an http base: with only an
    http port open the tls-probe lane does not run, the legacy plan
    runs no TLS tool either, and the state completes honestly."""
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
            raise AssertionError("tls probe must not run for an http base")
        return SpawnResult(ok=True, exit_code=0, stdout="")

    sandbox = _fake_stage1(script)
    result, spawned, graph, audit = _recon(
        sandbox, production_registry(), tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    assert [a for a in cmdl if a and a[0] == TOOL_EXECUTABLE] == []
    assert [a for a in cmdl if a and a[0] in ("sslscan", "testssl.sh")] == []


def test_empty_registry_keeps_the_legacy_tls_entries(tmp_path):
    """No registered adapter -> the legacy plan unchanged (deterministic
    either/or in the other direction)."""
    def script(argv):
        tool = argv[0]
        if tool == "nmap":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="8443/tcp   open  https   nginx")
        if tool == "naabu":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com:8443")
        if tool == "dnsx":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com [A] 203.0.113.7")
        return SpawnResult(ok=True, exit_code=0, stdout="")

    sandbox = _fake_stage1(script)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    legacy = [a for a in cmdl if a and a[0] in ("sslscan", "testssl.sh")]
    assert len(legacy) == 2        # sslscan + testssl.sh, as before
    assert [a for a in cmdl if a and a[0] == TOOL_EXECUTABLE] == []
    assert graph.by_type("adapter_attempt") == []
    assert "recon_active_tls_adapter" not in _event_names(audit)


def test_partial_probe_is_not_a_clean_bill(tmp_path):
    """A wrapper run that hit its own time bound reports ``partial``:
    the lane executes, records what it got, and classifies honestly —
    never as a complete scan."""
    def script(argv):
        if argv[0] == "nmap":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="8443/tcp   open  https   nginx")
        if argv[0] == "naabu":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com:8443")
        if argv[0] == "dnsx":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com [A] 203.0.113.7")
        if argv[0] == TOOL_EXECUTABLE:
            return SpawnResult(ok=True, exit_code=0, stdout=_payload_line(
                status="partial", findings=[
                    _finding("cipherlist_OBSOLETED", "LOW",
                             "offered")]))
        return SpawnResult(ok=True, exit_code=0, stdout="")

    sandbox = _fake_stage1(script)
    result, _spawned, graph, audit = _recon(
        sandbox, production_registry(), tmp_path)
    assert result.status == "ok"
    ev = [e for e in _events(audit)
          if e["event"] == "recon_active_tls_adapter"]
    assert ev and ev[0]["probe_status"] == "partial"
    assert ev[0]["outcome"] == "observed"
    assert graph.by_type("tls_observation")
    names = _event_names(audit)
    assert names.count("recon_active_adapter_failure") == 0


def test_adapter_failure_never_fails_the_state(tmp_path):
    """Preparation refusals and execution refusals are audited and
    skipped — exactly like a legacy tool failure."""
    def script(argv):
        if argv[0] == "nmap":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="8443/tcp   open  https   nginx")
        if argv[0] == "naabu":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com:8443")
        if argv[0] == "dnsx":
            return SpawnResult(ok=True, exit_code=0,
                               stdout="target-corp.com [A] 203.0.113.7")
        if argv[0] == TOOL_EXECUTABLE:
            return SpawnResult(ok=False, exit_code=1, stdout="",
                               error="probe crashed")
        return SpawnResult(ok=True, exit_code=0, stdout="")

    sandbox = _fake_stage1(script)
    result, _spawned, graph, audit = _recon(
        sandbox, production_registry(), tmp_path)
    assert result.status == "ok"
    names = _event_names(audit)
    assert names.count("recon_active_adapter_failure") == 1
    assert graph.by_type("tls_observation") == []
    assert graph.by_type("vuln_candidate") == []


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
    # no gate events, no hypothesis approval writes, no capability writes
    for ev in _events(audit):
        label = json.dumps(ev)
        assert "gate_decision" not in label
        assert "capability" not in ev.get("event", "")
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    assert graph.by_type("capability") == []
    # the shipped registry CANNOT reach gated stages
    for adapter in reg.list_adapters():
        assert adapter.stages == ("RECON_ACTIVE",)
    # ...and the registration rules still forbid illegal climb
    from kryonsec.purple.adapters import ModeBToolAdapter

    with pytest.raises(ValidationError):
        ModeBToolAdapter(**{
            **make_tls_probe_adapter().model_dump(),
            "adapter_id": "tls-post", "stages": ("POST_EXPLOIT",),
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
    assert "confirmed" not in dump
    adapter = reg.get(ADAPTER_ID)
    assert adapter.approvals == ()
    assert adapter.stages == ("RECON_ACTIVE",)


# ---- the ONE genuine integration test (opt-in, local lab only) ------------------------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab URL."""
    lab = os.environ.get("KRYONSEC_TLS_LAB_URL", "").strip()
    if not lab.lower().startswith("https://"):
        return False, "KRYONSEC_TLS_LAB_URL must be an https lab URL"
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_TLS_IT") != "1":
        return False, "KRYONSEC_TLS_IT=1 not set"
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


def test_real_tls_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real testssl run through the baked wrapper — against the
    local lab endpoint the OPERATOR supplies (a disposable TLS lab with
    controlled certificates). Skipped silently otherwise.

    Authorize NOTHING public: point KRYONSEC_TLS_LAB_URL at an https
    endpoint you control (e.g. an openssl s_server on your own Docker
    bridge).
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
    lab = os.environ["KRYONSEC_TLS_LAB_URL"].strip()
    host = urlsplit(lab).hostname or ""
    assert host, lab

    policy = build_policy(cfg, "tls-it", target=host)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    # register so the finally-block teardown actually removes the
    # network (release_active is a silent no-op for unregistered ids)
    register_active(policy, gate)
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_tls_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="tls-it")
    graph.add_node("target", host, {})
    try:
        # out-of-scope stays refused even in a real environment
        with pytest.raises(AdapterScopeRefused):
            prepare_adapter_run(reg, ADAPTER_ID, target=host,
                                target_asset="https://elsewhere.example.com/")
        prep = prepare_adapter_run(reg, ADAPTER_ID, target=host,
                                   target_asset=lab)
        record, output = execute_adapter(reg, prep, sandbox=sbx,
                                         audit=audit, graph=graph,
                                         full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.exit_code == 0, (record.exit_code,
                                       record.output_excerpt[:400])
        assert record.verification == "not_verified"
        run, malformed = parse_tls_probe_payload(output)
        assert run is not None, output[:400]
        assert run.status in ("complete", "partial"), run.status
        assert run.tool == "testssl"
        assert malformed == 0
        created = record_tls_evidence(graph, audit, run_record=record,
                                      run=run, malformed_lines=malformed)
        # the summary node + every tool-reported weakness as a candidate
        assert graph.by_type("tls_observation")
        for node in graph.by_type("vuln_candidate"):
            assert node["properties"]["verification"] == "not_verified"
            assert node["properties"]["classification"] == \
                "detected_candidate"
            assert node["properties"]["adapter"] == ADAPTER_ID
        assert graph.by_type("finding") == []
        # the event's node accounting matches the returned list
        ev = [e for e in _events(audit)
              if e["event"] == "tls_adapter_evidence"]
        assert ev and ev[0]["findings"] == len(run.findings)
        assert ev[0]["nodes_created"] == len(created)
        # weaknesses become candidates
        if run.weak_findings:
            assert graph.by_type("vuln_candidate")
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("tls-it")
        except Exception:
            pass
        for path in (Path("tmp_tls_it_audit.jsonl"),):
            if path.exists():
                path.unlink()
