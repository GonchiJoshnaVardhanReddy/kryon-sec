"""Tests for the vetted nuclei-probe Mode B adapter (Phase 2B.4).

Everything here runs against harmless fakes; the ONE genuine
integration test at the bottom is opt-in (KRYONSEC_NUCLEI_IT=1) and
skipped silently otherwise, like the whatweb/httpx adapter ITs.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

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
from kryonsec.purple.adapter_nuclei import (
    ADAPTER_ID,
    NUCLEI_PROBE_TEMPLATE,
    TOOL_EXECUTABLE,
    VETTED_TEMPLATE_DIRS,
    find_adapter_attempt_node,
    make_nuclei_probe_adapter,
    parse_nuclei_json_lines,
    production_registry,
    record_nuclei_evidence,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult

TARGET = "target-corp.com"


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


def _candidate_line(url="http://target-corp.com:8080/",
                    template_id="panel-admin",
                    name="Admin Panel Detected",
                    severity="info",
                    matcher_status=True) -> str:
    """The REAL nuclei v3.11.1 JSONL match-line shape — keys, nesting
    and field placement captured live from a run of the adapter's exact
    argv in the pinned sandbox image (the engine emits ``matched-at``,
    never ``matched``; ``host`` is the BARE host and the port lives in
    its own ``port`` field)."""
    parsed = urlsplit(url)
    event = {
        "template-url": f"https://cloud.projectdiscovery.io/public/"
                        f"{template_id}",
        "template-id": template_id,
        "template-path": f"/opt/nuclei-templates/http/exposed-panels/"
                         f"{template_id}.yaml",
        "info": {
            "name": name,
            "author": ["pd"],
            "severity": severity,
            "description": "an exposed panel",
            "tags": ["panel", "exposure"],
            "metadata": {"max-request": 1},
            "classification": {"cve-id": None,
                               "cwe-id": ["cwe-200"]},
        },
        "matcher-name": "first-matcher",
        "type": "http",
        "host": parsed.hostname or "target-corp.com",
        "port": parsed.port or "",
        "scheme": parsed.scheme or "http",
        "url": url,
        "path": parsed.path or "/",
        "matched-at": url,
        "ip": "203.0.113.7",
        "timestamp": "2026-11-12T00:00:00.000000000Z",
        "curl-command": f"curl -X 'GET' -d '' '{url}'",
        "matcher-status": matcher_status,
    }
    return json.dumps(event)


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


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------


def test_production_registry_registers_nuclei_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("nuclei-probe",)         # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "web_recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "url"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()          # RECON_ACTIVE authorization =
                                            # engagement model, not silent
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_nuclei_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_nuclei_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_five_web_adapters():
    from kryonsec.purple.adapter_whatweb import recon_active_registry

    reg = recon_active_registry()
    assert reg.adapter_ids() == (
        "api-probe", "httpx-probe", "nuclei-probe", "tls-probe",
        "whatweb-probe")
    # all five stay RECON_ACTIVE-only; none mounted a gate
    for adapter in reg.list_adapters():
        assert adapter.stages == ("RECON_ACTIVE",)
        assert adapter.approvals == ()
        assert adapter.network == "target_scope"
        assert adapter.risk == "active"


# ---- 2. the fixed template + FROZEN template policy -----------------------------


def test_fixed_template_rendering():
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        target_asset="http://target-corp.com:8080/")
    rebuilt = ["http://target-corp.com:8080/" if a == "{url}" else a
               for a in NUCLEI_PROBE_TEMPLATE]
    assert prep.argv == [TOOL_EXECUTABLE, *rebuilt]
    # every one of the four pinned dirs is a literal in the argv, in a
    # -t <dir> pair — never a caller-chosen value
    for d in VETTED_TEMPLATE_DIRS:
        i = prep.argv.index(d)
        assert prep.argv[i - 1] == "-t"
    assert prep.argv.count("-t") == len(VETTED_TEMPLATE_DIRS)


def test_template_policy_is_frozen():
    """THE core policy test: the adapter's argv template can never
    carry a caller-chosen template, a remote template/workflow source,
    an update command, an OAST server, local-file access, fuzzing,
    DAST, headless or code templates — the vetted local categories and
    the safety flags are LITERALS."""
    template = list(NUCLEI_PROBE_TEMPLATE)
    # no template variable at all: the caller cannot choose a template
    assert "{template}" not in " ".join(template)
    # remote template/workflow sources, updates, OOB, local-file,
    # fuzz/DAST/headless/code/self-contained — none may appear
    forbidden = [
        "-turl", "-wurl", "-ut", "-update-templates", "-ud",
        "-iserver", "-itoken",                       # OAST endpoints
        "-lfa", "-allow-local-file-access",
        "-esc", "-enable-self-contained",
        "-code", "-fuzz", "-dast", "-headless",
        "-automatic-scan", "-new-templates", "-ai",  # dynamic templates
        "-config", "-profile",                       # config-injected flags
        "-itags",                                    # tag filter override
    ]
    for flag in forbidden:
        assert flag not in template, flag
    # the four vetted local categories are the ONLY -t values
    t_values = [template[i + 1] for i, a in enumerate(template)
                if a == "-t"]
    assert t_values == list(VETTED_TEMPLATE_DIRS)
    for d in t_values:
        assert d.startswith("/opt/nuclei-templates/http/")
        assert d not in ("/opt/nuclei-templates/http/cves/",
                         "/opt/nuclei-templates/http/vulnerabilities/",
                         "/opt/nuclei-templates/http/default-logins/",
                         "/opt/nuclei-templates/http/fuzzing/",
                         "/opt/nuclei-templates/http/credential-stuffing/")
    # safety literals are pinned
    for flag in ("-etags", "intrusive", "-ni", "-duc", "-j", "-silent",
                 "-nc", "-or"):
        assert flag in template, flag
    # bounded rate/concurrency/timeout/retry/max-time literals
    pairs = dict(zip(template, template[1:]))
    assert pairs["-rl"] == "20"
    assert pairs["-c"] == "10"
    assert pairs["-timeout"] == "15"
    assert pairs["-retries"] == "1"
    assert pairs["-mt"] == "2m"
    # the run bound fits the sandbox ceiling and nuclei's own
    # graceful max-time sits INSIDE it
    adapter = make_nuclei_probe_adapter()
    assert adapter.max_seconds == 300 <= 330


def test_exploit_stage_nuclei_semantics_untouched():
    """The legacy EXPLOIT nuclei path is NOT touched by this adapter:
    the shipped allowlist template, the fixed exploit argv shape and
    the verdict-word confirmation markers stay exactly as audited, and
    the adapter never claims the EXPLOIT stage."""
    from kryonsec.purple.allowlist import EXPLOIT_TEMPLATES
    from kryonsec.purple.exploit import _CONFIRMED_MARKERS

    assert EXPLOIT_TEMPLATES["nuclei"] == [
        "-u", "{url}", "-t", "{template}",
        "-rate-limit", "{rate}", "-timeout", "30"]
    assert _CONFIRMED_MARKERS["nuclei"] == [
        "[info]", "[low]", "[medium]", "[high]", "[critical]"]
    adapter = make_nuclei_probe_adapter()
    assert adapter.stages == ("RECON_ACTIVE",)
    assert "hypothesis_gate" not in adapter.approvals
    # the adapter does not run the legacy confirm-words flow: its
    # evidence node type is a candidate, not a finding
    assert adapter.evidence_kind == "json_report"


# ---- 4. scope enforcement --------------------------------------------------------


def test_out_of_scope_target_refused_at_preparation():
    reg = production_registry()
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="https://elsewhere.example.com/")
    # a sibling domain that is NOT a subdomain of the target
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="http://target-corp.net/")
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="http://sub.target-corp.net/")
    # in-scope subdomain composes fine
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="https://mail.target-corp.com/")
    assert "mail.target-corp.com" in prep.target


# ---- 5. invalid URL / option injection rejection ---------------------------------


def test_invalid_urls_rejected():
    reg = production_registry()
    # shell-metacharacter / injection-shaped "url" is refused by Layer 2
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="http://x/;$rm -rf /tmp")
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="http://x/ -o /tmp/pwned")
def test_option_shaped_values_refused_by_the_framework_guard():
    """The framework's option-injection guard (Phase 2B.4) applies to
    the {url} variable this template carries: a value beginning with
    '-' can never be rendered into it (option injection is refused
    before any argv exists)."""
    from kryonsec.purple.adapters import _no_option_shaped_values

    with pytest.raises(AdapterError):
        _no_option_shaped_values(NUCLEI_PROBE_TEMPLATE,
                                 {"url": "-exclude-hosts"})
    # a real url passes the guard
    assert _no_option_shaped_values(NUCLEI_PROBE_TEMPLATE, {"url":
        "http://target-corp.com:8080/"}) is None


# ---- 6. Layer-2 allowlist rejection ------------------------------------------------


def test_layer2_deviating_argv_rejected():
    """The registry compiles the adapter's own template as its Layer-2
    allowlist: any deviation — an added flag, a changed bound, an
    extra template dir — is refused exactly like any other violation."""
    from kryonsec.purple.allowlist import AllowlistViolation, ToolAllowlist

    allow = ToolAllowlist(make_nuclei_probe_adapter().templates_map())
    url = "http://target-corp.com:8080/"
    good = [TOOL_EXECUTABLE] + [
        url if a == "{url}" else a for a in NUCLEI_PROBE_TEMPLATE]
    allow.validate(TOOL_EXECUTABLE, good)            # the real shape passes

    for deviating in (
        # one more template dir (even an innocuous one) — out of template
        [TOOL_EXECUTABLE, "-u", url, "-t",
         "/opt/nuclei-templates/http/cves/", *NUCLEI_PROBE_TEMPLATE[2:]],
        # a changed rate bound
        [TOOL_EXECUTABLE, "-u", url, *NUCLEI_PROBE_TEMPLATE[2:-8],
         "-rl", "9999", *NUCLEI_PROBE_TEMPLATE[-8:]],
        # the intrusive-tag exclusion removed
        [TOOL_EXECUTABLE, "-u", url, *NUCLEI_PROBE_TEMPLATE[2:10],
         *NUCLEI_PROBE_TEMPLATE[12:]],
    ):
        with pytest.raises(AllowlistViolation):
            allow.validate(TOOL_EXECUTABLE, deviating)


# ---- 7. missing sandbox -------------------------------------------------------------


def test_missing_sandbox_no_host_fallback(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
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
                               target_asset="http://target-corp.com:8080/")
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
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                  error="tool exceeded 300s sandbox timeout"),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert "300s" in record.error_excerpt
    assert output == ""
    # no attempt node, no candidate nodes — a timeout fabricates nothing
    assert graph.by_type("adapter_attempt") == []
    assert graph.by_type("vuln_candidate") == []
    # timeout bound respected on the spawn call (adapter max_seconds)
    assert sbx.spawned and sbx.spawned[0][1] == make_nuclei_probe_adapter(
    ).max_seconds


# ---- 10. nonzero tool exit -------------------------------------------------------------------


def test_nonzero_exit_is_not_success(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=1, stdout="",
                                  error="no templates found"),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    assert record.executed is False and record.outcome == "not_run"
    assert record.exit_code == 1
    assert graph.by_type("vuln_candidate") == []
    names = _event_names(audit)
    assert "adapter_result" in names
    for ev in _events(audit):
        if ev["event"] == "adapter_result":
            assert ev["ok"] is False and ev["exit_code"] == 1


# ---- 11. malformed and oversized output -------------------------------------------------------


def test_malformed_output_never_becomes_candidates():
    garbage = (
        # an explicit non-result (matcher-status false) — not a detection
        _candidate_line(matcher_status=False) + "\n"
        # nuclei's own log chatter ([INF]/[WRN]/[ERR] — stderr in real
        # runs, but be paranoid about stdout too)
        "[INF] Nuclei Engine Version: v3.11.1\n"
        "[WRN] Found 0 templates loaded\n"
        "[ERR] Could not read template\n"
        # plain text and half-written tails
        "not json at all\n"
        '{"truncated": tru\n'
        # a JSON object that is NOT a result line
        '{"cloned": true}\n'
        # a JSON object missing the template id / matched target
        '{"info": {"severity": "info"}}\n'
    )
    candidates, malformed = parse_nuclei_json_lines(garbage)
    assert candidates == [] and malformed == 8

    # a VALID line among garbage still parses (defensive, not paranoid)
    candidates, malformed = parse_nuclei_json_lines(
        garbage + _candidate_line())
    assert len(candidates) == 1 and malformed == 8


def test_parser_real_shape_and_bounds():
    line = _candidate_line()
    candidates, malformed = parse_nuclei_json_lines(line + "\n")
    assert len(candidates) == 1 and malformed == 0
    c = candidates[0]
    assert c.template_id == "panel-admin"
    assert c.name == "Admin Panel Detected"
    assert c.severity_as_reported == "info"
    assert c.matched == "http://target-corp.com:8080/"
    # the REAL shape: host is the bare host (the port is its own field)
    assert c.host == "target-corp.com"
    assert c.tags == ("panel", "exposure")
    assert c.template_path.startswith("/opt/nuclei-templates/http/")
    # the real-shape line is long (curl-command, classification, …):
    # the excerpt is the bounded HEAD of it, verbatim
    assert len(line) > 600
    assert c.excerpt == line[:600]
    # the matcher that fired is captured as honest metadata
    assert c.matcher_name == "first-matcher"

    # the legacy "matched" key (older nuclei emits it) still parses —
    # defensively, the fallback chain ends at host
    legacy = json.loads(_candidate_line())
    legacy["matched"] = legacy.pop("matched-at")
    candidates, _m = parse_nuclei_json_lines(json.dumps(legacy) + "\n")
    assert len(candidates) == 1
    assert candidates[0].matched == "http://target-corp.com:8080/"

    # an unknown severity value is NOT trusted into the field
    candidates, _ = parse_nuclei_json_lines(
        _candidate_line(severity="apocalyptic") + "\n")
    assert candidates[0].severity_as_reported == ""

    # oversized: the candidate cap holds
    flood = "\n".join(_candidate_line(url=f"http://t:{i}/")
                      for i in range(80))
    candidates, _ = parse_nuclei_json_lines(flood)
    assert len(candidates) == 50        # max_candidates default


# ---- 12. evidence recording: full mapping + refusal without attempt node ----------------


def test_record_evidence_refuses_without_attempt_node(tmp_path):
    """A refused run must never fabricate candidate evidence."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    prep = prepare_adapter_run(registry, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    record = execute_adapter(registry, prep,
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    candidates, _ = parse_nuclei_json_lines(_candidate_line())
    ids = record_nuclei_evidence(graph, audit, run_record=record,
                                 candidates=candidates)
    assert ids == []
    assert graph.by_type("vuln_candidate") == []
    names = _event_names(audit)
    assert "nuclei_adapter_evidence_refused" in names


def test_evidence_mapping_and_idempotence(tmp_path):
    """The run maps to vuln_candidate nodes keyed (template @ matched);
    a repeat mapping adds NOTHING (first wins)."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    prep = prepare_adapter_run(registry, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout=_candidate_line()),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(
        registry, prep, sandbox=sbx, audit=audit, graph=graph,
        full_output=True)
    candidates, malformed = parse_nuclei_json_lines(output)
    assert len(candidates) == 1 and malformed == 0
    created = record_nuclei_evidence(graph, audit, run_record=record,
                                     candidates=candidates,
                                     malformed_lines=malformed)
    assert len(created) == 1
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None
    restored = AdapterRunRecord.model_validate(attempt["properties"])
    assert restored.adapter_id == ADAPTER_ID
    # the node carries the parsed candidate + adapter provenance; a
    # REPEAT mapping is idempotent
    node = graph.by_type("vuln_candidate")[0]
    props = node["properties"]
    assert props["source"] == TOOL_EXECUTABLE
    assert props["adapter"] == ADAPTER_ID
    assert props["verification"] == "not_verified"
    assert props["classification"] == "detected_candidate"
    assert props["template_id"] == "panel-admin"
    assert props["severity_as_reported"] == "info"
    assert node["label"] == "panel-admin @ http://target-corp.com:8080/"
    ids2 = record_nuclei_evidence(graph, audit, run_record=record,
                                  candidates=candidates)
    assert ids2 == []
    assert len(graph.by_type("vuln_candidate")) == 1
    # the sibling adapters' node types stay untouched — no cross-evidence
    assert graph.by_type("web_endpoint") == []
    assert graph.by_type("tech_fingerprint") == []
    ev = [e for e in _events(audit)
          if e["event"] == "nuclei_adapter_evidence"]
    assert ev[0]["candidates"] == 1
    assert ev[0]["vuln_candidate_nodes"] == 1
    assert ev[0]["duplicate_or_refused"] == 0
    ok, reason = audit.verify()
    assert ok, reason


# ---- 13. detection is NEVER confirmation -------------------------------------------------


def test_candidate_is_never_a_confirmed_finding(tmp_path):
    """The hard semantic invariant: whatever nuclei matched, whatever
    severity it printed, the candidate node is pre-confirmation
    evidence — no finding node, no confirmed property, verification
    stays not_verified everywhere."""
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(
        ok=True, exit_code=0, stdout=(
            _candidate_line(severity="critical",
                            template_id="rce-thing") + "\n")),
        egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is True and record.exit_code == 0
    # HARD invariants on the record:
    assert record.verification == "not_verified"
    assert record.untrusted is True
    assert "confirmed" not in record.model_dump()
    candidates, _m = parse_nuclei_json_lines(output)
    record_nuclei_evidence(graph, audit, run_record=record,
                           candidates=candidates)
    node = graph.by_type("vuln_candidate")[0]["properties"]
    assert node["verification"] == "not_verified"
    assert node["classification"] == "detected_candidate"
    assert node["severity_as_reported"] == "critical"
    # nothing on the graph became a finding / capability / approval —
    # a critical-labelled DETECTION is not a confirmed EXPLOIT result
    assert graph.by_type("finding") == []
    assert graph.by_type("exploit_attempt") == []
    assert graph.by_type("capability") == []
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False


def test_no_host_execution_in_adapter_modules():
    for mod in ("adapter_httpx.py", "adapter_whatweb.py",
                "adapter_nuclei.py", "adapters.py"):
        source = Path("src/kryonsec/purple") / mod
        text = source.read_text(encoding="utf-8")
        assert "subprocess" not in text, mod
        assert "import mcp" not in text, mod
        assert "docker " + "run" not in text, mod


# ---- 14. no duplicate Recon Active probing / deterministic wiring ------------------------


def _recon(sandbox, registry, tmp_path):
    cfg = _cfg(tmp_path)
    audit = AuditLog(tmp_path / "ra.jsonl")
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    sub = ReconActiveSubagent(cfg, graph, audit, TARGET, sandbox,
                              adapter_registry=registry)
    result = sub.run()
    return result, sandbox.spawned, graph, audit


def _fake_stage1(script):
    """Sandbox fake: stage1 always finds 8080; tools callback-scripted."""
    return FakeSandbox(script=script, egress_policy=_StubEgressPolicy())


def _script_all_adapters(argv):
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
    if tool == "whatweb":
        url = argv[-1]
        return SpawnResult(ok=True, exit_code=0, stdout=(
            f"{url} [200 OK] HTTPServer[SimpleHTTP/0.6], HTML5"))
    if tool == "httpx-toolkit":
        url = argv[argv.index("-u") + 1]
        return SpawnResult(ok=True, exit_code=0, stdout=(
            json.dumps({"url": url, "status_code": 200,
                        "title": "Login", "tech": ["Nginx"],
                        "webserver": "nginx"}) + "\n"))
    if tool == "nuclei":
        url = argv[argv.index("-u") + 1]
        return SpawnResult(ok=True, exit_code=0, stdout=(
            _candidate_line(url=url) + "\n"))
    return SpawnResult(ok=True, exit_code=0, stdout="")


def test_adapter_mode_runs_nuclei_once_per_base(tmp_path):
    sandbox = _fake_stage1(_script_all_adapters)
    from kryonsec.purple.adapter_whatweb import recon_active_registry

    result, spawned, graph, audit = _recon(sandbox, recon_active_registry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs = [a for a in cmdl if a and a[0] == "nuclei"]
    # exactly ONE nuclei probe for the one web base, carrying the
    # pinned template policy
    assert len(runs) == 1
    run = runs[0]
    assert run[run.index("-u") + 1] == "http://target-corp.com:8080/"
    assert run.count("-t") == len(VETTED_TEMPLATE_DIRS)
    assert "-ni" in run and "-duc" in run and "-etags" in run
    candidates = graph.by_type("vuln_candidate")
    assert len(candidates) == 1
    assert candidates[0]["properties"]["adapter"] == ADAPTER_ID
    assert candidates[0]["properties"]["verification"] == "not_verified"
    # all three adapters ran; each left its own attempt node
    # all FOUR adapters with a lane here ran (httpx/whatweb/api/nuclei);
    # the tls-probe lane correctly does NOT run — the stage-2 base is
    # plain http, and a TLS baseline is never forced onto an http base
    assert len(graph.by_type("adapter_attempt")) == 4
    names = _event_names(audit)
    assert "recon_active_nuclei_adapter" in names
    assert "recon_active_adapter_failure" not in names
    ev = [e for e in _events(audit)
          if e["event"] == "recon_active_nuclei_adapter"]
    assert ev[0]["outcome"] == "detected_candidates"
    assert ev[0]["candidates"] == 1
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_match_run_is_an_honest_inconclusive(tmp_path):
    """A clean run that detected NOTHING is INCONCLUSIVE — its own
    audit classification, never a negative finding and never silence."""
    def script(argv):
        r = _script_all_adapters(argv)
        if argv[0] == "nuclei":
            return SpawnResult(ok=True, exit_code=0, stdout="")
        return r

    sandbox = _fake_stage1(script)
    from kryonsec.purple.adapter_whatweb import recon_active_registry

    result, _spawned, graph, audit = _recon(sandbox, recon_active_registry(),
                                            tmp_path)
    assert result.status == "ok"
    assert graph.by_type("vuln_candidate") == []
    ev = [e for e in _events(audit)
          if e["event"] == "recon_active_nuclei_adapter"]
    assert ev and ev[0]["outcome"] == "inconclusive"
    assert ev[0]["candidates"] == 0
    # the attempt node still exists (the run happened; its outcome is
    # recorded honestly on it)
    # all FOUR adapters with a lane here ran (httpx/whatweb/api/nuclei);
    # the tls-probe lane correctly does NOT run — the stage-2 base is
    # plain http, and a TLS baseline is never forced onto an http base
    assert len(graph.by_type("adapter_attempt")) == 4
    ok, reason = audit.verify()
    assert ok, reason


def test_registry_without_nuclei_runs_no_vuln_checks(tmp_path):
    """Explicit registration, both directions: an EMPTY registry (or
    one without the nuclei id) means the classic fixed plan only — no
    nuclei spawn, no candidate nodes, unchanged behavior."""
    sandbox = _fake_stage1(_script_all_adapters)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    assert not [a for a, _t in spawned if a and a[0] == "nuclei"]
    assert graph.by_type("vuln_candidate") == []
    assert "recon_active_nuclei_adapter" not in _event_names(audit)

    # a registry that carries the other two but NOT nuclei behaves the
    # same way for the nuclei lane
    from kryonsec.purple.adapter_httpx import make_httpx_probe_adapter
    from kryonsec.purple.adapter_whatweb import make_whatweb_probe_adapter

    reg = AdapterRegistry()
    reg.register(make_whatweb_probe_adapter())
    reg.register(make_httpx_probe_adapter())
    sandbox2 = _fake_stage1(_script_all_adapters)
    res2, spawned2, graph2, _a2 = _recon(sandbox2, reg, tmp_path / "u2")
    assert res2.status == "ok"
    assert not [a for a, _t in spawned2 if a and a[0] == "nuclei"]
    assert graph2.by_type("vuln_candidate") == []


# ---- 15. Gate 2 / Gate 3 behavior unchanged -------------------------------------------------


def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout=_candidate_line()),
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
    # the shipped registry CANNOT reach gated stages: every adapter
    # runs in RECON_ACTIVE only
    for adapter in reg.list_adapters():
        assert adapter.stages == ("RECON_ACTIVE",)
    # ...and the registration rules still forbid illegal climb:
    from kryonsec.purple.adapters import ModeBToolAdapter

    with pytest.raises(ValidationError):
        ModeBToolAdapter(**{
            **make_nuclei_probe_adapter().model_dump(),
            "adapter_id": "nuclei-post", "stages": ("POST_EXPLOIT",),
        })


# ---- 16. no capability or Post-Exploit activation ---------------------------------------------


def test_no_capability_or_post_exploit_activation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout=_candidate_line()),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    candidates, _m = parse_nuclei_json_lines(_candidate_line())
    record_nuclei_evidence(graph, audit, run_record=record,
                           candidates=candidates)
    # a detection does NOT create capability claims, exploit attempts
    # or post-exploit inputs
    assert graph.by_type("capability") == []
    assert graph.by_type("exploit_attempt") == []
    assert graph.by_type("finding") == []
    # the run record cannot open any capability lifecycle
    dump = record.model_dump()
    assert "confirmed" not in dump and "approvals" not in dump
    # the entire registration vocabulary excludes gates for
    # RECON_ACTIVE-only production
    adapter = reg.get(ADAPTER_ID)
    assert adapter.approvals == ()
    assert adapter.stages == ("RECON_ACTIVE",)
    # post-exploit gate text is untouched (module imports still resolve)
    from kryonsec.purple.capability import capability_gate_text

    assert callable(capability_gate_text)


# ---- the ONE genuine integration test (opt-in, local lab only) ------------------------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab URL."""
    lab = os.environ.get("KRYONSEC_NUCLEI_LAB_URL", "").strip()
    if not lab.lower().startswith(("http://", "https://")):
        return False, "KRYONSEC_NUCLEI_LAB_URL must be an http(s) lab URL"
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_NUCLEI_IT") != "1":
        return False, "KRYONSEC_NUCLEI_IT=1 not set"
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


def test_real_nuclei_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real Nuclei run over the pinned local template allowlist —
    against the local lab endpoint the OPERATOR supplies. Skipped
    silently otherwise.

    Authorize NOTHING public: point KRYONSEC_NUCLEI_LAB_URL at an
    endpoint you control (e.g. a lab container on your own Docker
    bridge).
    """
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from urllib.parse import urlsplit

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.egress import EgressGate, build_policy, \
        release_active
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig()
    lab = os.environ["KRYONSEC_NUCLEI_LAB_URL"].strip()
    host = urlsplit(lab).hostname or ""
    assert host, lab

    policy = build_policy(cfg, "nuclei-it", target=host)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_nuclei_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="nuclei-it")
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
        candidates, malformed = parse_nuclei_json_lines(output)
        created = record_nuclei_evidence(graph, audit, run_record=record,
                                         candidates=candidates,
                                         malformed_lines=malformed)
        # a well-formed run maps its DISTINCT candidates onto the graph
        # with pre-confirmation provenance only (first observation wins
        # per (template @ matched) label — nuclei can fire several
        # sub-matchers of one template at one URL; those are one
        # candidate on the graph)
        distinct = {(c.template_id, c.matched) for c in candidates}
        assert len(created) == len(distinct)
        for node in graph.by_type("vuln_candidate"):
            assert node["properties"]["verification"] == "not_verified"
            assert node["properties"]["classification"] == \
                "detected_candidate"
            assert node["properties"]["template_path"].startswith(
                "/opt/nuclei-templates/http/")
        assert graph.by_type("finding") == []
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("nuclei-it")
        except Exception:
            pass
