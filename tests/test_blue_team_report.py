"""Tests for BLUE_TEAM + REPORT subagents (spec §4.2, §4.9)."""

import json

import pytest
from pydantic import ValidationError

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.blue_team import (
    BlueTeamSubagent,
    Remediation,
    RemediationSet,
    render_blue_team_prompt,
)
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.report import (
    ReportSubagent,
    redact_secrets,
    render_report,
    validate_report,
)


def _graph(target="target-corp.com"):
    graph = EngagementGraph(engagement_id="e-bt")
    graph.add_node("target", target, {})
    graph.add_node("subdomain", "www." + target, {"source": "crt.sh"})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi on login",
        "target_asset": target,
        "rationale": "evidence",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tools": ["sqlmap"],
        "confidence": 0.8,
        "approved": True,
    })
    graph.add_node("hypothesis", "H2", {
        "title": "XSS on search",
        "target_asset": target,
        "rationale": "evidence",
        "cvss_vector": "",
        "tools": ["ffuf"],
        "confidence": 0.6,
        "approved": False,
    })
    return graph


# ---- BLUE_TEAM ----------------------------------------------------------

def test_blue_team_prompt_contains_hypotheses_and_decisions():
    prompt = render_blue_team_prompt(_graph())
    assert "H1" in prompt and "H2" in prompt
    assert "SQLi on login" in prompt
    assert "approved by operator: True" in prompt
    assert "approved by operator: False" in prompt


def test_blue_team_success(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()

    def llm(prompt):
        assert "H1" in prompt
        return RemediationSet(remediations=[
            Remediation(hypothesis_id="H1", title="Parameterize queries",
                        fix="Use prepared statements", detection="WAF rule X",
                        severity="critical"),
            Remediation(hypothesis_id="H2", title="Escape output",
                        fix="Context-aware encoding", severity="medium"),
        ])

    sub = BlueTeamSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=llm)
    result = sub.run()

    assert result.status == "ok"
    nodes = graph.by_type("remediation")
    assert len(nodes) == 2
    assert nodes[0]["properties"]["severity"] == "critical"

    events = [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "blue_team_done" in events
    assert events.count("remediation_proposed") == 2
    ok, reason = audit.verify()
    assert ok, reason


def test_blue_team_llm_failure(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()

    def dead(prompt):
        raise RuntimeError("no provider")

    sub = BlueTeamSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=dead)
    result = sub.run()

    assert result.status == "failed"
    assert graph.by_type("remediation") == []


def test_remediation_set_caps_at_20():
    items = [Remediation(hypothesis_id=f"H{i}", title="t", fix="f")
             for i in range(21)]
    with pytest.raises(ValidationError):
        RemediationSet(remediations=items)


# ---- REPORT ----------------------------------------------------------

def _remediated_graph():
    graph = _graph()
    for h, sev in (("H1", "critical"), ("H2", "medium")):
        graph.add_node("remediation", h, {
            "title": f"fix {h}",
            "fix": f"steps {h}",
            "detection": f"rule {h}",
            "severity": sev,
        })
    return graph


def test_report_renders_everything(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _remediated_graph()

    report = render_report(
        graph, audit, "e-bt",
        completed_states=["INIT", "RECON_PASSIVE", "HYPOTHESIZE"],
        halt_reason=None,
    )
    assert "# Security Test Report" in report
    assert "target-corp.com" in report
    assert "www.target-corp.com" in report
    assert "SQLi on login" in report
    assert "Fix for H1" in report
    assert "approved" in report
    assert audit.head_hash() in report
    # no exploit_attempt nodes => the report must NOT claim testing happened
    assert "No testing was done against the website" in report


def test_report_claims_testing_only_with_real_attempts(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("exploit_attempt", "H1-run", {"tool": "sqlmap", "exit_code": 0})

    report = render_report(graph, audit, "e-bt")
    assert "Tools were run against the target" in report
    assert "No testing was done" not in report


def test_report_validation_clean(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _remediated_graph()
    report = render_report(graph, audit, "e-bt")
    assert validate_report(report, graph) == []


def test_report_validation_catches_missing_hypothesis(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _remediated_graph()
    report = render_report(graph, audit, "e-bt")
    # drop H2 from the report text
    broken = report.replace("H2", "XX")
    problems = validate_report(broken, graph)
    assert any("H2" in p for p in problems)


def test_report_subagent_writes_file(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _remediated_graph()

    sub = ReportSubagent(cfg=cfg, graph=graph, audit=audit, engagement_id="e-bt")
    sub.completed_states = ["INIT", "RECON_PASSIVE"]
    sub.halt_reason = "Zone B requires Linux"
    result = sub.run()

    assert result.status == "ok"
    report_path = tmp_path / "engagements" / "e-bt" / "report.md"
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "The engagement stopped early" in content
    assert "No testing was done against the website" in content
    events = [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "report_written" in events


@pytest.mark.parametrize("secret,expected", [
    ("sk-proj-abc123def456ghi789jkl", True),
    ("password: hunter2secret", True),
    ("BEGIN PRIVATE KEY", False),  # partial text — must not redact innocuous text
])
def test_redact_secrets(secret, expected):
    text = f"leak: {secret}"
    redacted = redact_secrets(text)
    assert (secret not in redacted) is expected
    if expected:
        assert "[REDACTED]" in redacted


def test_redact_jwt():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0TWs-abc"
    assert jwt not in redact_secrets(f"token={jwt}")


def test_report_claims_testing_only_with_real_attempts(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "exit_code": 0, "confirmed": True,
    })

    report = render_report(graph, audit, "e-bt")
    assert "Tools were run against the target" in report
    assert "No testing was done" not in report
    # the attempt summary lists the tool, and the hypothesis shows
    # tested/confirmed status
    assert "H1:sqlmap" in report
    assert "confirmed by the test tool" in report
    assert "Tested: yes" in report
    # H2 was not tested
    assert "Tested: no" in report


def test_empty_graph_report(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-empty")
    report = render_report(graph, audit, "e-empty", completed_states=["INIT"])
    assert "none found" in report
    assert "No issues were suggested" in report
    assert validate_report(report, graph) == []
