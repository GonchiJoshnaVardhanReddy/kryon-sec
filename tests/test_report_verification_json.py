"""Phase 1C tests: report accuracy, coverage honesty, and the atomic
deterministic report.json export."""

import json

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.report import (
    REPORT_JSON_SCHEMA_VERSION,
    ReportSubagent,
    build_report_json,
    coverage_summary,
    post_exploit_view,
    render_report,
    write_report_json,
)
from kryonsec.purple.recon_passive import EngagementGraph

_JWT = ("eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jwfOwscqXlEnLpAcRuVOjeB4iPQM4HM")


def _events(audit):
    return [json.loads(l) for l in open(audit.path, encoding="utf-8")
            if l.strip()]


# -- shared fixtures -----------------------------------------------------------

BASE_PROPS = {
    "title": "SQL injection on thread view",
    "target_asset": "target-corp.com/showthread.asp",
    "rationale": "old asp app", "cvss_vector": "",
    "tools": ["sqlmap"], "confidence": 0.8, "approved": True,
}


def _report_graph(verify_props=None, confirmed=True):
    """Exploit attempt + finding (+ optional verify_attempt sharing H1).
    The attempt output and argv carry secret-looking strings: everything
    that reaches a report must have gone through the redactor."""
    graph = EngagementGraph(engagement_id="e-rep")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", dict(BASE_PROPS))
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "ok": True, "exit_code": 0, "confirmed": confirmed,
        "argv": ["sqlmap", "-u", "http://target-corp.com/Login.asp",
                 "--cookie", f"session={_JWT}"],
        "output_excerpt": "is vulnerable — password=hunter2 in dump",
    })
    if confirmed:
        graph.add_node("finding", "H1", {
            "tool": "sqlmap", "confirmed_by": "sandbox sqlmap output",
            "excerpt": "is vulnerable",
        })
    if verify_props is not None:
        graph.add_node("verify_attempt", "H1", dict(verify_props))
    return graph


def render(graph, tmp_path, name="audit.jsonl"):
    return render_report(graph, AuditLog(tmp_path / name), "e-rep")


# -- 8. report rendering for every status --------------------------------------

def test_report_renders_verified_disagreed_inconclusive_not_run(tmp_path):
    cases = [
        ("second tool re-tested it and agreed", {
            "verified": True, "method": "curl boolean probe",
            "true_len": 100, "false_len": 5, "baseline_len": 100}),
        # disagreed keeps the operator caution the old report had
        ("did NOT agree", {
            "verified": False, "method": "curl boolean probe",
            "true_len": 5, "false_len": 5, "baseline_len": 5}),
        # inconclusive: ran, no conclusion either way — not a clean bill
        ("treat this finding with care", {
            "verified": False, "method": "curl boolean probe",
            "true_len": 100, "false_len": 100, "baseline_len": None}),
        # not_run: the blocked check keeps its reason, never "safe"
        ("unverified, not disproven", {
            "verified": False, "method": "n/a",
            "reason": "no numeric query parameter"}),
    ]
    for expected, props in cases:
        report = render(_report_graph(props), tmp_path)
        assert expected in report, props


def test_report_never_calls_unverified_findings_clean(tmp_path):
    """A finding with no verification at all is unverified — the report
    must not describe it as checked, safe or disproven."""
    graph = _report_graph(None)
    report = render(graph, tmp_path)
    assert "second check never ran" in report
    assert "no vulnerability" not in report.lower()
    assert "not vulnerable" not in report.lower()
    # the finding is still listed — not_run is not absence of finding
    assert "SQL injection on thread view" in report


# -- 9. coverage accuracy, including no findings at all ------------------------

def test_coverage_with_no_findings_is_not_clean_sweep(tmp_path):
    """An empty engagement: machine rows are zero and nothing is claimed
    clean — unassessed is unassessed."""
    graph = EngagementGraph(engagement_id="e-empty")
    audit = AuditLog(tmp_path / "a9.jsonl")
    audit.write({"event": "engagement_created", "engagement_id": "e-empty"})
    cov = coverage_summary(graph, audit)
    assert cov["model_claims"] == 0
    assert cov["confirmed_findings"] == []
    assert cov["tested_surfaces"] == []
    assert cov["machine_observed_runs"] == 0
    assert cov["unassessed"] == []
    # and the report renders it honestly
    report = render_report(graph, audit, "e-empty")
    assert "no tool ran against this target" in report


def test_coverage_distinguishes_claims_from_machine_observed(tmp_path):
    graph = EngagementGraph(engagement_id="e-cov")
    graph.add_node("target", "target-corp.com", {})
    # two claims, one really ran and confirmed, one never started
    graph.add_node("hypothesis", "H1", dict(
        BASE_PROPS, target_asset="corp.com/Login.asp"))
    graph.add_node("hypothesis", "H2", dict(
        BASE_PROPS, target_asset="corp.com/Search.asp"))
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "ok": True, "exit_code": 0, "confirmed": True,
        "argv": ["sqlmap"], "output_excerpt": "vulnerable",
    })
    graph.add_node("finding", "H1", {"tool": "sqlmap"})
    graph.add_node("exploit_attempt", "H2:sqlmap", {
        "tool": "sqlmap", "ok": False, "exit_code": -1, "confirmed": False,
        "argv": ["sqlmap"], "error_excerpt": "sandbox spawn refused",
    })
    cov = coverage_summary(graph, AuditLog(tmp_path / "a9b.jsonl"))
    assert cov["model_claims"] == 2
    assert cov["machine_observed_runs"] == 1      # only H1 really ran
    assert cov["tool_runs_never_started"] == 1
    assert cov["confirmed_findings"] == ["H1"]
    assert "corp.com/Login.asp" in cov["tested_surfaces"]
    assert cov["skipped_or_blocked"] and "sandbox" in \
        cov["skipped_or_blocked"][0]["reason"]


def test_coverage_counts_scope_refusals_from_audit(tmp_path):
    graph = EngagementGraph(engagement_id="e-cov2")
    audit = AuditLog(tmp_path / "a9c.jsonl")
    audit.write({"event": "exploit_scope_refused", "cmd": "nmap"})
    audit.write({"event": "verify_skipped",
                 "reason": "hypothesis asset outside engagement scope"})
    audit.write({"event": "verify_skipped", "reason": "probe run failed"})
    cov = coverage_summary(graph, audit)
    assert cov["out_of_scope_refused"] == 2   # the two scope refusals only


# -- 10. atomic, deterministic, redacted report.json ----------------------------

def test_report_json_is_deterministic_and_schema_versioned(tmp_path):
    graph = _report_graph({
        "verified": True, "method": "curl boolean probe",
        "true_len": 100, "false_len": 5, "baseline_len": 100})
    audit = AuditLog(tmp_path / "a10.jsonl")

    one = build_report_json(graph, audit, "e-rep")
    two = build_report_json(graph, audit, "e-rep")
    assert one == two                       # same graph+chain -> same bytes
    doc = json.loads(one)
    assert doc["schema_version"] == REPORT_JSON_SCHEMA_VERSION == "1.0"
    assert doc["engagement_id"] == "e-rep"
    assert json.dumps(json.loads(one), sort_keys=True,
                      separators=(",", ":")) == one  # canonical already
    assert doc["summary"]["verification_statuses"]["verified"] == 1
    assert doc["findings"][0]["verification"]["status"] == "verified"


def test_report_json_redacts_secrets_and_bounds_evidence(tmp_path):
    graph = _report_graph({
        "verified": False, "method": "n/a",
        "reason": "no numeric query parameter"})
    audit = AuditLog(tmp_path / "a10b.jsonl")
    doc = json.loads(build_report_json(graph, audit, "e-rep"))

    blob = json.dumps(doc)
    assert "hunter2" not in blob            # password value redacted
    assert "password" in blob               # label kept, value replaced
    assert _JWT not in blob                 # session token redacted
    attempt = doc["exploit_attempts"][0]
    assert len(attempt["output_excerpt"]) <= 300
    assert all(len(a) <= 120 for a in attempt["argv"])


def test_write_report_json_is_atomic_replacements(tmp_path):
    """(tmp, fsync, rename): a crash mid-write can leave only a .tmp,
    never a truncated report.json at the destination."""
    path = tmp_path / "report.json"
    write_report_json(json.dumps({"a": 1}), path)
    assert path.read_text(encoding="utf-8") == '{"a": 1}'
    assert not path.with_name("report.json.tmp").exists()
    write_report_json(json.dumps({"a": 2}), path)
    assert json.loads(path.read_text(encoding="utf-8")) == {"a": 2}


def test_report_json_provenance_uses_lineage_edges(tmp_path):
    from kryonsec.purple.lineage import link

    graph = _report_graph({
        "verified": True, "method": "curl boolean probe",
        "true_len": 100, "false_len": 5, "baseline_len": 100})
    finding = graph.by_type("finding")[0]
    attempt = graph.by_type("verify_attempt")[0]
    link(graph, "verified_by", finding, attempt,
         provenance={"agent": "VERIFY", "source_type": "tool"})
    doc = json.loads(build_report_json(
        graph, AuditLog(tmp_path / "a10c.jsonl"), "e-rep"))
    prov = doc["findings"][0]["provenance"]
    assert prov["verified_by"] == ["H1"]    # read back through lineage edges
    assert prov["hypothesis_id"]            # node id — survives dedup/load


# -- 11. missing or malformed capability records --------------------------------

def _capability_node(graph, props, label="capability:H1:sqlmap"):
    graph.add_node("capability", label, props,
                   provenance={"agent": "EXPLOIT", "source_type": "tool"})


def test_post_exploit_view_with_no_records_is_honest():
    graph = EngagementGraph(engagement_id="e-pev")
    view = post_exploit_view(graph)
    assert view["authorized"] is False
    assert "was ever claimed" in view["note"]
    doc = json.loads(build_report_json(
        graph, AuditLog(_tmp("a11.jsonl")), "e-pev"))
    assert doc["post_exploit"]["authorized"] is False
    assert doc["summary"]["post_exploit_authorized"] is False


def _tmp(name):
    import tempfile
    from pathlib import Path
    return Path(tempfile.mkdtemp()) / name


def test_post_exploit_view_malformed_record_reads_dormant():
    graph = EngagementGraph(engagement_id="e-pev2")
    _capability_node(graph, {"junk": True, "status": "approved",
                             "verification": "verified"})
    view = post_exploit_view(graph)
    assert view["authorized"] is False       # malformed -> nothing genuine
    assert "No post-exploitation was performed" in view["note"]


def test_post_exploit_view_legacy_record_without_verification_is_dormant():
    """A pre-Phase-1C record (no ``verification`` field) defaults to
    not_run: approval alone is not eligibility — fail closed."""
    from tests.test_capability_handoff import approved_record

    graph = EngagementGraph(engagement_id="e-pev3")
    props = approved_record()
    del props["verification"]                # legacy shape
    _capability_node(graph, props)
    view = post_exploit_view(graph)
    assert view["authorized"] is False


def test_report_json_never_embeds_unauthorized_post_exploit_evidence():
    """No capability record -> the JSON post_exploit section claims and
    embeds nothing, even when stray evidence nodes exist."""
    graph = EngagementGraph(engagement_id="e-pev4")
    graph.add_node("post_exploit_evidence", "whoami", {
        "ok": True, "stdout_chars": 9, "summary": "root"})
    doc = json.loads(build_report_json(
        graph, AuditLog(_tmp("a11b.jsonl")), "e-pev4"))
    assert doc["post_exploit"]["authorized"] is False
    assert doc["post_exploit"].get("evidence") is None


def test_report_json_secret_bearing_post_exploit_evidence_is_redacted():
    """When genuine authorized records DO exist, their free text is
    bounded and secret-redacted."""
    from tests.test_capability_handoff import approved_record

    graph = EngagementGraph(engagement_id="e-pev5")
    _capability_node(graph, approved_record())
    for _ in range(1):
        graph.add_node("post_exploit_evidence", "credscan", {
            "ok": True, "stdout_chars": 40,
            "summary": "found password=hunter2 on server",
        })
    doc = json.loads(build_report_json(
        graph, AuditLog(_tmp("a11c.jsonl")), "e-pev5"))
    ev = doc["post_exploit"]["evidence"]
    assert ev and "hunter2" not in json.dumps(ev)
    ev[0].pop("summary", None)
    ev[0].pop("excerpt", None)


# -- the run: report.json failure never kills report.md -------------------------

def test_json_failure_is_audited_and_markdown_stands(tmp_path, monkeypatch):
    graph = _report_graph({
        "verified": True, "method": "curl boolean probe",
        "true_len": 100, "false_len": 5, "baseline_len": 100})
    audit = AuditLog(tmp_path / "a12.jsonl")

    def boom(*args, **kwargs):
        raise RuntimeError("serializer exploded")

    monkeypatch.setattr(
        "kryonsec.purple.report.build_report_json", boom)
    cfg = KryonsecConfig(home=tmp_path)
    sub = ReportSubagent(cfg=cfg, graph=graph, audit=audit,
                         engagement_id="e-sub-fail")
    result = sub.run()
    assert result.status == "ok"               # markdown deliverable stands
    md = tmp_path / "engagements" / "e-sub-fail" / "report.md"
    assert md.exists()
    assert _JWT not in md.read_text(encoding="utf-8")
    events = [e["event"] for e in _events(audit)]
    assert "report_json_failed" in events
    assert "report_written" in events          # report.md event unchanged
    # and no report.json was left behind half-written
    assert not (md.parent / "report.json").exists()


def test_report_subagent_writes_both_files(tmp_path):
    graph = _report_graph({
        "verified": True, "method": "curl boolean probe",
        "true_len": 100, "false_len": 5, "baseline_len": 100})
    audit = AuditLog(tmp_path / "a12b.jsonl")
    cfg = KryonsecConfig(home=tmp_path)
    sub = ReportSubagent(cfg=cfg, graph=graph, audit=audit,
                         engagement_id="e-sub")
    result = sub.run()
    assert result.status == "ok"
    engage_dir = tmp_path / "engagements" / "e-sub"
    assert (engage_dir / "report.md").exists()
    assert (engage_dir / "report.json").exists()
    doc = json.loads((engage_dir / "report.json").read_text(encoding="utf-8"))
    assert doc["engagement_id"] == "e-sub"
    assert "report_json_written" in [e["event"] for e in _events(audit)]
