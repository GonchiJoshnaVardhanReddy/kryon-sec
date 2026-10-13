"""A12 — hypothesis deduplication must preserve meaningful security
distinctions and structured multi-asset claims.

The audit (docs/A12-DEDUP-AUDIT-2026-10-12.md) reproduced four collisions on
the old ``(tool set, target asset)`` key. Each section below is one of them,
plus the properties the spec requires of the merge itself.
"""

from __future__ import annotations

import json
import re

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.report import (
    dedup_hypotheses,
    mergeable,
    render_report,
    validate_report,
)

TARGET = "target-corp.com"
ASSET = "/ListProducts.asp?artist=1"

HOSTILE = "first\n## Severity: critical\n- bullet\n\x07\x1b[31mtail"


def _graph(*nodes) -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-a12")
    graph.add_node("target", TARGET, {})
    graph.add_node("path", "/admin/list.asp", {"source": "wayback"})
    for node in nodes:
        graph.add_node("hypothesis", node["id"], node["props"])
    return graph


def _h(hid: str, **over) -> dict:
    props = {
        "title": "SQL injection in the artist parameter",
        "target_asset": ASSET,
        "rationale": "recon shows a query parameter",
        "cvss_vector": "",
        "cve": "",
        "tools": ["sqlmap"],
        "confidence": 0.5,
    }
    props.update(over)
    return {"id": hid, "props": props}


def _audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _events(audit: AuditLog) -> list[dict]:
    if not audit.path.exists():
        return []
    return [json.loads(line) for line in
            audit.path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---- 1. same target/tools, materially different hypotheses ------------------

def test_same_tools_and_asset_but_a_different_class_stays_two(tmp_path):
    """Case 1: a SQL-injection claim and a stored-XSS claim at one asset,
    testable by one tool, are two different issues. The old key merged them
    and dropped the second one's title and rationale on the floor."""
    graph = _graph(
        _h("H1"),
        _h("H2", title="Stored XSS in the artist parameter"),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0
    assert [n["label"] for n in graph.by_type("hypothesis")] == ["H1", "H2"]


def test_the_same_class_worded_differently_is_still_one_claim(tmp_path):
    """The reason the key is tools+asset and not the text: the model rewords
    the same idea between passes, and that must still merge."""
    graph = _graph(
        _h("H1", title="SQL injection in the artist parameter"),
        _h("H2", title="Possible SQLi via the artist parameter"),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 1
    assert [n["label"] for n in graph.by_type("hypothesis")] == ["H1"]


def test_an_unrecognised_title_is_not_merged_into_a_recognised_one(tmp_path):
    """A15/D6 changed this one, and only in the direction that loses nothing.

    A12's table could only say "different" or "unknown", so an unrecognised
    title merged into any known class (A13 demonstrated the cost: a Log4Shell
    claim absorbed by a SQLi one). "Unknown" is a verdict on the *title*, not
    on the claim, and the report must not present one kind of issue where the
    model claimed two. Two unknowns — including two legacy nodes with no title
    at all — still merge: see
    ``test_legacy_hypotheses_without_the_new_fields_still_merge``."""
    graph = _graph(
        _h("H1", title="Search page may reflect input"),
        _h("H2", title="XSS on search"),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0
    assert [n["label"] for n in graph.by_type("hypothesis")] == ["H1", "H2"]


# ---- 2. equivalent hypotheses with different asset claims -------------------

def test_equivalent_asset_spellings_merge(tmp_path):
    """Same asset, differently spelled (case, trailing slash, query, fragment)
    — A11's identity says these are one asset, so this is one claim."""
    graph = _graph(
        _h("H1", related_assets=[{"asset": "/admin/list.asp"}]),
        _h("H2", related_assets=[{"asset": "/ADMIN/list.asp/?x=1#frag"}]),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 1


def test_an_asset_spelled_with_a_host_recon_does_not_know_is_a_different_one(tmp_path):
    """A11 keeps the host in the identity, so ``https://target-corp.com/x``
    and ``/x`` are two assets, not one. That has to keep them two claims as
    well — the merge must not be the place the distinction is lost."""
    graph = _graph(
        _h("H1", related_assets=[{"asset": "/admin/list.asp"}]),
        _h("H2", related_assets=[{"asset": "https://elsewhere.test/admin/list.asp"}]),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0


def test_an_absent_asset_claim_conflicts_with_nothing(tmp_path):
    """A single-asset hypothesis and a multi-asset one proposing the same
    test: the richer claim is kept, and the merge still happens — an absent
    claim is not a disagreement."""
    graph = _graph(
        _h("H1"),
        _h("H2", related_assets=[{"asset": "/admin/list.asp"}],
           relationship="admin/list.asp is reached through the product page"),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 1


# ---- 3. conflicting relationship claims -------------------------------------

def test_conflicting_relationship_claims_are_not_merged(tmp_path):
    """Case 4: two different proposed relationships between two different
    assets are two claims. Merging them silently dropped one."""
    graph = _graph(
        _h("H1", related_assets=[{"asset": "/admin/list.asp"}],
           relationship="the product page writes rows /admin/list.asp renders"),
        _h("H2", related_assets=[{"asset": "/reports/daily.asp"}],
           relationship="the product page writes rows /reports/daily.asp renders"),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0
    assert len(graph.by_type("hypothesis")) == 2


def test_neither_conflicting_claim_is_lost_from_the_report(tmp_path):
    graph = _graph(
        _h("H1", related_assets=[{"asset": "/admin/list.asp"}],
           relationship="the product page writes rows /admin/list.asp renders"),
        _h("H2", related_assets=[{"asset": "/reports/daily.asp"}],
           relationship="the product page writes rows /reports/daily.asp renders"),
    )
    audit = _audit(tmp_path)
    dedup_hypotheses(graph, audit)
    report = render_report(graph, audit, "e-a12")
    assert "/admin/list.asp" in report
    assert "/reports/daily.asp" in report
    assert validate_report(report, graph) == []


# ---- 4. divergent review decisions ------------------------------------------

def test_different_review_decisions_are_not_merged(tmp_path):
    """Case 2: the operator said yes to one and no to the other. Two
    different records of a decision are not one hypothesis."""
    graph = _graph(
        _h("H1", approved=False),
        _h("H2", approved=True),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0


def test_a_rejected_hypothesis_is_never_reported_as_tested(tmp_path):
    """The damage case 2 did: the rejected node absorbed the approved one's
    exploit_attempt and rendered "not approved" next to "confirmed"."""
    graph = _graph(_h("H1", approved=False), _h("H2", approved=True))
    graph.add_node("exploit_attempt", "H2:sqlmap", {"tool": "sqlmap",
                                                    "confirmed": True})
    audit = _audit(tmp_path)
    dedup_hypotheses(graph, audit)

    report = render_report(graph, audit, "e-a12")
    rejected = report.split("### H1", 1)[1].split("### H2", 1)[0]
    assert "- Your decision: not approved" in rejected
    assert "confirmed by the test tool" not in rejected


# ---- 5. degenerate fields: no test identity at all --------------------------

def test_hypotheses_with_no_tool_and_no_asset_never_merge(tmp_path):
    """Case 3: ``((), "")`` was a universal key — every hypothesis without a
    tool or an asset collapsed into one. Nothing there identifies a test."""
    graph = _graph(
        _h("H1", title="unrelated idea 1", tools=[], target_asset=""),
        _h("H2", title="unrelated idea 2", tools=[], target_asset=""),
        _h("H3", title="unrelated idea 3", tools=[], target_asset=""),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0
    assert len(graph.by_type("hypothesis")) == 3


# ---- 6. legacy hypotheses ---------------------------------------------------

def test_legacy_hypotheses_without_the_new_fields_still_merge(tmp_path):
    """Backward compatibility: a node written before A11 has no title, no
    related_assets, no relationship and no approved flag. It must merge
    exactly as it always did."""
    graph = EngagementGraph(engagement_id="e-a12")
    graph.add_node("hypothesis", "H1", {"tools": ["sqlmap"],
                                        "target_asset": TARGET})
    graph.add_node("hypothesis", "H2", {"tools": ["sqlmap"],
                                        "target_asset": TARGET})
    audit = _audit(tmp_path)
    assert dedup_hypotheses(graph, audit) == 1
    survivor = graph.by_type("hypothesis")[0]["properties"]
    assert survivor["merged_from"] == ["H2"]
    assert survivor["merged_claims"] == [
        {"id": "H2", "title": "", "rationale": "", "relationship": "",
         "related_assets": []}]


def test_a_legacy_node_renders_without_the_merged_claims_row(tmp_path):
    """A graph that never merged anything gains no new rows in its report."""
    graph = EngagementGraph(engagement_id="e-a12")
    graph.add_node("hypothesis", "H1", {"title": "t",
                                        "target_asset": TARGET,
                                        "rationale": "r", "cvss_vector": "",
                                        "cve": "", "tools": ["sqlmap"],
                                        "confidence": 0.5})
    report = render_report(graph, _audit(tmp_path), "e-a12")
    assert "folded these into this item" not in report
    assert validate_report(report, graph) == []


# ---- 7. evidence preservation -----------------------------------------------

def test_a_merge_keeps_the_claim_it_absorbed(tmp_path):
    graph = _graph(
        _h("H1", title="SQL injection in the artist parameter"),
        _h("H2", title="SQLi in artist parameter",
           rationale="the archive shows the same parameter",
           related_assets=[{"asset": "/admin/list.asp"}],
           relationship="the product page writes rows /admin/list.asp renders"),
    )
    audit = _audit(tmp_path)
    assert dedup_hypotheses(graph, audit) == 1

    props = graph.by_type("hypothesis")[0]["properties"]
    assert props["merged_from"] == ["H2"]
    (kept,) = props["merged_claims"]
    assert kept["id"] == "H2"
    assert kept["title"] == "SQLi in artist parameter"
    assert kept["rationale"] == "the archive shows the same parameter"
    assert kept["related_assets"] == [{"asset": "/admin/list.asp", "role": ""}]
    assert "admin/list.asp" in kept["relationship"]


def test_the_absorbed_claim_survives_into_the_report(tmp_path):
    graph = _graph(
        _h("H1"),
        _h("H2", title="SQLi in artist parameter",
           rationale="the archive shows the same parameter"),
    )
    audit = _audit(tmp_path)
    dedup_hypotheses(graph, audit)
    report = render_report(graph, audit, "e-a12")
    assert "folded these into this item" in report
    assert "SQLi in artist parameter" in report
    assert "the archive shows the same parameter" in report
    assert validate_report(report, graph) == []


def test_validate_report_notices_a_dropped_merged_claim(tmp_path):
    graph = _graph(_h("H1"), _h("H2", title="SQLi in artist parameter"))
    audit = _audit(tmp_path)
    dedup_hypotheses(graph, audit)
    report = render_report(graph, audit, "e-a12")
    damaged = re.sub(re.escape("SQLi in artist parameter"), "x", report)
    problems = validate_report(damaged, graph)
    assert any("folded into" in p for p in problems)


def test_a_hostile_absorbed_claim_cannot_add_a_line_to_the_report(tmp_path):
    graph = _graph(_h("H1"))
    props = graph.by_type("hypothesis")[0]["properties"]
    props["merged_from"] = ["H9"]
    props["merged_claims"] = [{
        "id": "H9", "title": HOSTILE, "rationale": HOSTILE,
        "relationship": HOSTILE, "related_assets": [{"asset": ASSET,
                                                     "role": HOSTILE}],
    }]
    report = render_report(graph, _audit(tmp_path), "e-a12")
    for line in report.splitlines():
        assert not line.startswith("## Severity: critical")
        assert not line.startswith("- bullet")
    assert "\x07" not in report and "\x1b" not in report
    assert validate_report(report, graph) == []


# ---- 8. standing before and after -------------------------------------------

def test_a_merge_never_grants_approval(tmp_path):
    """Requirement 6: approval is the operator's, never a merge's. (The two
    nodes here are only mergeable because they agree — so this pins that the
    absorbed node's flag is not copied either way.)"""
    graph = _graph(_h("H1", approved=False), _h("H2", approved=False))
    audit = _audit(tmp_path)
    assert dedup_hypotheses(graph, audit) == 1
    props = graph.by_type("hypothesis")[0]["properties"]
    assert props["approved"] is False
    assert "approved" not in props["merged_claims"][0]


def test_a_merge_does_not_upgrade_engine_derived_standing(tmp_path):
    """Requirement 5: two proposed claims merging stay proposed. Nothing on
    the merge path writes a basis, and no test can be conjured by folding two
    untested hypotheses together."""
    from kryonsec.purple.hypothesize import relationship_basis

    graph = _graph(
        _h("H1", title="SQL injection in the artist parameter"),
        _h("H2", title="SQLi in artist parameter"),
    )
    survivor = graph.by_type("hypothesis")[0]
    before = relationship_basis(survivor, graph)
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 1
    assert before == "proposed"
    assert relationship_basis(graph.by_type("hypothesis")[0], graph) == "proposed"


def test_a_merge_does_not_invent_a_verified_standing(tmp_path):
    """An absorbed claim that was never verified cannot make its survivor
    verified — the ladder reads verify_attempt nodes, and a merge creates
    none."""
    from kryonsec.purple.hypothesize import relationship_basis

    graph = _graph(_h("H1"), _h("H2", title="SQLi in artist parameter"))
    dedup_hypotheses(graph, _audit(tmp_path))
    assert relationship_basis(graph.by_type("hypothesis")[0], graph) != "validated"
    assert graph.by_type("verify_attempt") == []


# ---- 9. determinism and explainability --------------------------------------

def test_the_same_graph_always_merges_the_same_way(tmp_path):
    def run(tag):
        graph = _graph(_h("H1"), _h("H2", title="SQLi in artist parameter"),
                       _h("H3", title="Stored XSS in the artist parameter"))
        audit = _audit(tmp_path / tag)
        merged = dedup_hypotheses(graph, audit)
        return merged, [n["label"] for n in graph.by_type("hypothesis")]

    assert run("a") == run("b") == (1, ["H1", "H3"])


def test_a_kept_apart_pair_is_explained_on_the_audit_chain(tmp_path):
    """Requirement 8: a decision not to merge is as explainable as a merge —
    the chain carries the reason, not just the outcome."""
    graph = _graph(_h("H1"), _h("H2", title="Stored XSS in the artist parameter"))
    audit = _audit(tmp_path)
    assert dedup_hypotheses(graph, audit) == 0
    (event,) = [e for e in _events(audit) if e["event"] == "hypotheses_kept_apart"]
    (entry,) = event["kept_apart"]
    assert entry == {"kept": "H2", "apart_from": "H1",
                     "reason": "different vulnerability class (sqli vs xss)"}


def test_the_merge_event_records_the_alias_and_the_keep_aparts(tmp_path):
    graph = _graph(
        _h("H1"),
        _h("H2", title="SQLi in artist parameter"),
        _h("H3", title="Stored XSS in the artist parameter"),
    )
    audit = _audit(tmp_path)
    assert dedup_hypotheses(graph, audit) == 1
    (event,) = [e for e in _events(audit) if e["event"] == "hypotheses_merged"]
    assert event["aliases"] == {"H2": "H1"}
    assert event["kept_apart"][0]["kept"] == "H3"
    ok, reason = audit.verify()
    assert ok, reason


def test_the_kept_claims_are_json_and_survive_a_round_trip(tmp_path):
    """No migration: the record is plain JSON in ``properties``, so it is
    persisted and reloaded by the existing graph store."""
    from kryonsec.purple.graph_store import load_graph, save_graph
    from kryonsec.storage import get_purple_session, init_purple_db

    cfg = KryonsecConfig(home=tmp_path)
    graph = EngagementGraph(engagement_id="e-a12-store")
    graph.add_node("target", TARGET, {})
    graph.add_node("hypothesis", "H1", _h("H1")["props"])
    graph.add_node("hypothesis", "H2", _h("H2", title="SQLi in artist parameter")["props"])
    audit = AuditLog(cfg.home / "engagements" / "e-a12-store" / "audit.jsonl")
    dedup_hypotheses(graph, audit)

    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        save_graph(session, graph)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-a12-store")

    assert json.dumps(graph.by_type("hypothesis")[0]["properties"])
    props = loaded.by_type("hypothesis")[0]["properties"]
    assert props["merged_claims"][0]["title"] == "SQLi in artist parameter"


# ---- 10. the gates themselves are untouched ---------------------------------

def test_validate_report_does_not_flag_a_deliberate_keep_apart(tmp_path):
    """The validator uses the same relation dedup does, so a hypothesis the
    merge correctly left alone is not reported as a validation failure."""
    graph = _graph(_h("H1"), _h("H2", title="Stored XSS in the artist parameter"))
    audit = _audit(tmp_path)
    dedup_hypotheses(graph, audit)
    report = render_report(graph, audit, "e-a12")
    assert validate_report(report, graph) == []
    assert re.search(r"### H1", report) and re.search(r"### H2", report)


def test_validate_report_still_flags_an_unmerged_true_duplicate(tmp_path):
    graph = _graph(_h("H1"), _h("H2", title="SQLi in artist parameter"))
    report = render_report(graph, _audit(tmp_path), "e-a12")  # no dedup run
    problems = validate_report(report, graph)
    assert any("H2" in p and "not merged" in p for p in problems)


def test_mergeable_is_symmetric_and_matches_the_reason(tmp_path):
    left = _h("H1")
    right = _h("H2", title="Stored XSS in the artist parameter")
    g1 = _graph(left, right).by_type("hypothesis")
    assert mergeable(g1[0], g1[1]) == mergeable(g1[1], g1[0]) is False


@pytest.mark.parametrize("field,value", [
    ("tools", ["ffuf"]),
    ("target_asset", "/Other.asp"),
    ("approved", True),
])
def test_one_differing_field_is_enough_to_keep_them_apart(tmp_path, field, value):
    graph = _graph(_h("H1"), _h("H2", **{field: value}))
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0
