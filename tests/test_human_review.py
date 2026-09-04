"""Tests for the HUMAN_REVIEW gate (spec §4.4 Gate 2).

The reviewer is injected — these tests verify: only approved hypotheses
carry forward, decisions are audited, crash/failure never approves.
"""

import json

import pytest

from kryonsec.purple.audit import AuditLog
from kryonsec.purple.human_review import HumanReviewSubagent
from kryonsec.purple.recon_passive import EngagementGraph


def _graph_with_hypotheses():
    graph = EngagementGraph(engagement_id="e-hr")
    graph.add_node("target", "target-corp.com", {})
    for i, (title, tool) in enumerate([
        ("SQLi on login", "sqlmap"),
        ("XSS on search", "ffuf"),
        ("Open redirect", "curl"),
    ], start=1):
        graph.add_node("hypothesis", f"H{i}", {
            "title": title,
            "target_asset": "target-corp.com",
            "rationale": "evidence",
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "tools": [tool],
            "confidence": 0.7,
        })
    return graph


def _events(audit):
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line)["event"] for line in f if line.strip()]


def test_all_approved(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_hypotheses()
    sub = HumanReviewSubagent(graph=graph, audit=audit,
                              reviewer=lambda hyps: {"H1", "H2", "H3"})
    result = sub.run()

    assert result.status == "ok"
    assert result.approved_count == 3
    assert all(h["properties"]["approved"] for h in graph.by_type("hypothesis"))
    ok, reason = audit.verify()
    assert ok, reason


def test_partial_approval_marks_nodes(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_hypotheses()
    sub = HumanReviewSubagent(graph=graph, audit=audit,
                              reviewer=lambda hyps: {"H2"})
    result = sub.run()

    assert result.approved_count == 1
    flags = {h["label"]: h["properties"]["approved"]
             for h in graph.by_type("hypothesis")}
    assert flags == {"H1": False, "H2": True, "H3": False}


def test_zero_approved_routes_to_blue_team(tmp_path):
    """approved_count == 0 => orchestrator goes to BLUE_TEAM, not EXPLOIT."""
    from kryonsec.purple.orchestrator import next_state

    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_hypotheses()
    sub = HumanReviewSubagent(graph=graph, audit=audit,
                              reviewer=lambda hyps: set())
    result = sub.run()

    assert result.approved_count == 0
    assert next_state("HUMAN_REVIEW", result) == "BLUE_TEAM"


def test_positive_count_routes_to_exploit(tmp_path):
    from kryonsec.purple.orchestrator import next_state

    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_hypotheses()
    sub = HumanReviewSubagent(graph=graph, audit=audit,
                              reviewer=lambda hyps: {"H1"})
    result = sub.run()

    assert next_state("HUMAN_REVIEW", result) == "EXPLOIT"


def test_every_decision_audited(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_hypotheses()
    sub = HumanReviewSubagent(graph=graph, audit=audit,
                              reviewer=lambda hyps: {"H1", "H3"})
    sub.run()

    events = _events(audit)
    assert events.count("hypothesis_reviewed") == 3
    assert "human_review_done" in events
    # review decisions survive in the audit chain with their verdicts
    with open(audit.path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    verdicts = {e["hypothesis_id"]: e["approved"]
                for e in entries if e["event"] == "hypothesis_reviewed"}
    assert verdicts == {"H1": True, "H2": False, "H3": True}


def test_reviewer_crash_never_approves(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_hypotheses()

    def crashing_reviewer(hyps):
        raise RuntimeError("terminal exploded")

    sub = HumanReviewSubagent(graph=graph, audit=audit, reviewer=crashing_reviewer)
    result = sub.run()

    assert result.status == "failed"
    assert result.approved_count == 0
    assert "human_review_failed" in _events(audit)
    # no node was marked approved
    assert "approved" not in graph.by_type("hypothesis")[0]["properties"]


def test_empty_hypotheses(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-empty")
    seen = []

    def reviewer(hyps):
        seen.append(hyps)
        return set()

    sub = HumanReviewSubagent(graph=graph, audit=audit, reviewer=reviewer)
    result = sub.run()

    assert result.status == "ok"
    assert result.approved_count == 0
    assert seen == [[]]


@pytest.mark.parametrize("answer,expected", [
    ("y", True), ("yes", True), ("Y", True),
    ("n", False), ("", False), ("no", False), ("maybe", False),
])
def test_terminal_y_n_parsing(answer, expected, monkeypatch):
    from kryonsec.purple.human_review import terminal_reviewer

    hyps = [{"label": "H1", "properties": {"title": "t", "target_asset": "a",
             "rationale": "r", "cvss_vector": "", "tools": [], "confidence": 0.5}}]
    monkeypatch.setattr("builtins.input", lambda prompt: answer)
    # pretend stdin is a TTY so the interactive path runs
    monkeypatch.setattr("sys.stdin", type("FakeStdin", (), {"isatty": staticmethod(lambda: True)})())
    approved = terminal_reviewer(hyps)
    assert (approved == {"H1"}) is expected


def test_terminal_non_tty_approves_nothing(monkeypatch):
    """Piped/pytest stdin: silence is never consent."""
    from kryonsec.purple.human_review import terminal_reviewer

    hyps = [{"label": "H1", "properties": {"title": "t", "target_asset": "a",
             "rationale": "r", "cvss_vector": "", "tools": [], "confidence": 0.5}}]
    monkeypatch.setattr("builtins.input", lambda prompt: "y")  # would approve…
    monkeypatch.setattr("sys.stdin", type("FakeStdin", (), {"isatty": staticmethod(lambda: False)})())
    approved = terminal_reviewer(hyps)
    assert approved == set()  # …but non-TTY guard wins: nothing approved
