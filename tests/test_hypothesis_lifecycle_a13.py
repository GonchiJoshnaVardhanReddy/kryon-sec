"""A13 — end-to-end hypothesis integrity: the defects demonstrated in
docs/A13-LIFECYCLE-INTEGRITY-AUDIT-2026-10-12.md.

These tests were written *before* the fix, pinning each defect (D1–D7) so
A14 had a failing target. They are now inverted: every one of them asserts
the corrected behaviour, and the docstring of each says what the defect was
so the assertion cannot be mistaken for a description of today's code.

D3 was left as it is on purpose (moving dedup before BLUE_TEAM would touch
state ordering); A15 answered it inside BLUE_TEAM instead. D6 is closed by
A15 — the test below now asserts the corrected behaviour and says so.

Synthetic graphs and fake sandboxes only; nothing here spawns a container.
A14's own unit-level coverage lives in tests/test_execution_truth_a14.py.
"""

from __future__ import annotations

import json

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.blue_team import render_blue_team_prompt
from kryonsec.purple.exploit import ExploitSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.report import (
    dedup_hypotheses,
    render_report,
    validate_report,
)
from kryonsec.purple.sandbox import SpawnResult

TARGET = "target-corp.com"
ASSET = "/ListProducts.asp?artist=1"


class FakeSandbox:
    """Same shape the EXPLOIT tests use: record the argv, answer from a script."""

    def __init__(self, result):
        self.result = result
        self.spawned = []

    def spawn(self, argv):
        self.spawned.append(argv)
        return self.result


def _graph(*hypotheses) -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-a13")
    graph.add_node("target", TARGET, {})
    for h in hypotheses:
        graph.add_node("hypothesis", h["id"], h["props"])
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
        "approved": True,
    }
    props.update(over)
    return {"id": hid, "props": props}


def _audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


# ---- D1: a tool run that never executed is reported as a completed check -----

def test_an_unrun_tool_is_not_reported_as_a_check_that_found_nothing(tmp_path):
    """DEFECT (A13 D1, HIGH). The sandbox could not start, so sqlmap never
    ran — and the report told the reader it ran and found nothing. The
    engine record needed to say otherwise (`ok`, `exit_code`,
    `error_excerpt`) was on the very node the report reads and was ignored.

    A14: an attempt is only a check when it ran. `ok=False` means process
    creation failed, and the report now says nothing was checked."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = _audit(tmp_path)
    graph = _graph(_h("H1"))
    sandbox = FakeSandbox(SpawnResult(
        ok=False, exit_code=-1, stdout="",
        error="Cannot connect to the Docker daemon"))

    ExploitSubagent(cfg, graph, audit, TARGET, sandbox).run()

    # the engine knows the truth and wrote it down
    (attempt,) = graph.by_type("exploit_attempt")
    assert attempt["properties"]["ok"] is False
    assert "Cannot connect to the Docker daemon" in attempt["properties"]["error_excerpt"]
    assert graph.by_type("finding") == []

    report = render_report(graph, audit, "e-a13")

    # what the reader is told now matches the record
    assert "Tools were run against the target to test the approved items." \
        not in report
    assert "**The tests could not be run, so nothing was checked.**" in report
    assert "- **H1:sqlmap** (sqlmap): **could not be run**, so" in report
    assert "Cannot connect to the Docker daemon" in report  # the reason
    assert "- Tested: no — the tool could not be started" in report
    # the specific false claims the audit reproduced, one by one
    assert "ran, and **the tool said the issue is real**" not in report
    assert "it checked and got no proof" not in report
    assert "did **not** confirm the issue" not in report
    # and the repeatable-steps section does not offer steps that never ran
    assert "**This test did not run in this engagement**" in report
    assert "was run with these settings" not in report
    # a clean report is one that tells the truth, not one that is quiet
    assert validate_report(report, graph) == []


# ---- D2: BLUE_TEAM is told an approved hypothesis was tested ----------------

def test_blue_team_is_not_told_an_untested_hypothesis_was_tested(tmp_path):
    """DEFECT (A13 D2, HIGH). `approved` is set by HUMAN_REVIEW, before
    EXPLOIT runs, so it means "may be tested". The blue-team prompt rendered
    it as "tested-by-exploit-phase" — a lie handed to an LLM that is then
    asked to write remediation advice from it.

    A14: the status line is read from what the exploit phase actually
    recorded. An approved hypothesis with no run behind it is proposed-only,
    and the prompt says the approval only means a test was *allowed*."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = _audit(tmp_path)
    graph = _graph(_h("H1", tools=["jwt_tool"]))
    sandbox = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""))

    ExploitSubagent(cfg, graph, audit, TARGET, sandbox).run()

    # jwt_tool has no argv template, so EXPLOIT silently skipped it
    assert sandbox.spawned == []
    assert graph.by_type("exploit_attempt") == []

    prompt = render_blue_team_prompt(graph)
    assert "approved by operator: True" in prompt
    assert "status: proposed-only (not tested)" in prompt
    assert "tested-by-exploit-phase" not in prompt


# ---- D3: duplicates reach BLUE_TEAM, and survive into the report ------------

def test_one_claim_is_presented_as_two_independent_issues(tmp_path):
    """DEFECT (A13 D3, MEDIUM) — still open. Dedup runs inside REPORT — after
    BLUE_TEAM — and A12 keys a merge on the tool set, so the same claim tested
    by two different tools is never merged. The prompt lists it twice and the
    report counts it twice. Fixing it means moving dedup, which A14 was told
    not to do; the test stays as the record of the defect."""
    graph = _graph(
        _h("H1", tools=["sqlmap"]),
        _h("H2", tools=["nuclei"]),
    )
    audit = _audit(tmp_path)

    prompt = render_blue_team_prompt(graph)
    assert "- H1: SQL injection in the artist parameter" in prompt
    assert "- H2: SQL injection in the artist parameter" in prompt

    assert dedup_hypotheses(graph, audit) == 0
    report = render_report(graph, audit, "e-a13")
    assert "2 possible security issues" in report
    assert report.count("### H1 — ") == 1 and report.count("### H2 — ") == 1
    assert validate_report(report, graph) == []


# ---- D4: the Memory Browser shows the claim without the engine's answer -----

def test_the_memory_browser_shows_the_engines_standing_and_asset_resolution(
        tmp_path):
    """DEFECT (A13 D4, MEDIUM). The standing ladder was derived at render time
    and the observed/unobserved marker only ever existed in the report's view,
    so the inspection surface showed the model's claim with none of the
    engine's judgement attached.

    A14: the browser exposes the same engine-derived block the report renders,
    derived by the same function, and the model's own properties cannot
    outrank it. The persisted graph is untouched — this is a read-time view,
    so nothing had to migrate."""
    from kryonsec.memory.data import load_engagement
    from kryonsec.purple.graph_store import load_graph, save_graph
    from kryonsec.storage import get_purple_session, init_purple_db, reset_engine

    cfg = KryonsecConfig(home=tmp_path)
    graph = _graph(_h("H1",
                      # a model that wrote the engine's own answer into its
                      # properties: none of it may survive into the view
                      related_assets=[{"asset": "/never-recorded.asp",
                                       "role": "carries it"}],
                      relationship="the two are linked",
                      basis="validated",
                      tested=True,
                      confirmed=True,
                      engine={"basis": "validated"}))
    graph.add_node("path", ASSET, {})   # what recon actually recorded

    # the engagement engine is process-wide (storage.db caches it), so this
    # test has to start and end on a clean one or it reads another test's db
    reset_engine()
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        save_graph(session, graph)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-a13")

    # what was saved is what loads back — the "engine" the *model* wrote is
    # ordinary property text like any other, and persists as such
    props = loaded.by_type("hypothesis")[0]["properties"]
    assert props["related_assets"] == [{"asset": "/never-recorded.asp",
                                        "role": "carries it"}]
    assert props["engine"] == {"basis": "validated"}

    # the browser's own view carries the engine's answer
    view = load_engagement(cfg, "e-a13")["graph"]["nodes"]
    (hyp,) = [n for n in view if n["node_type"] == "hypothesis"]
    engine = hyp["properties"]["engine"]
    assert engine["basis"] == "proposed"
    assert engine["tested"] is False
    assert engine["confirmed"] is False
    assert engine["exploit_status"] == "none"
    assert engine["primary_asset_observed"] is True   # /ListProducts.asp?artist=1
    assert engine["related_assets"] == [{"asset": "/never-recorded.asp",
                                         "role": "carries it",
                                         "observed": False}]
    # the model's values are present as data, and outranked
    assert hyp["properties"]["basis"] == "validated"
    assert hyp["properties"]["engine"]["basis"] == "proposed"
    assert json.dumps(hyp["properties"]).count('"proposed"') >= 1

    # and the report, rendering the same node, says the same thing
    report = render_report(graph, _audit(tmp_path), "e-a13")
    assert "(this engagement never recorded this asset)" in report
    assert f"What the engagement itself can say about that claim: " \
           f"{engine['basis']}" in report
    reset_engine()


# ---- D5: a remediation attributed to an issue that does not exist -----------

def test_a_fix_section_says_when_its_issue_does_not_exist(tmp_path):
    """DEFECT (A13 D5, MEDIUM). The remediation's id is a free-form string
    from the model, resolved against nothing. The report printed a fix for
    "H7" when no H7 existed, and the validator only checked that the
    remediation's own label came through.

    A14: the id is resolved against the hypotheses and scans in the
    engagement. The advice is still shown — dropping it silently would be
    worse — but it is marked as unlinked, and validation records it."""
    graph = _graph(_h("H1"))
    graph.add_node("remediation", "H7", {
        "title": "Sanitise input",
        "fix": "escape the parameter",
        "severity": "high",
        "detection": "",
    })
    audit = _audit(tmp_path)

    report = render_report(graph, audit, "e-a13")

    assert "### Fix for H7 — Sanitise input" in report
    assert "**This fix is not linked to anything in this report.**" in report
    assert "escape the parameter" in report          # the advice survives
    assert [n for n in graph.by_type("hypothesis") if n["label"] == "H7"] == []
    problems = validate_report(report, graph)
    assert any("H7" in p and "refers to no hypothesis" in p for p in problems)


# ---- D6: an unknown class no longer merges into a known one ----------------

def test_an_unknown_vulnerability_class_no_longer_merges_into_a_known_one(tmp_path):
    """A13 D6 (LOW) — CLOSED by A15. The class table could only say
    "different" or "unknown", so an unrecognised title was mergeable with any
    class: the case below made a Log4Shell claim one with a SQLi claim, and
    the report presented one SQLi item where the model claimed two. Now the
    unreadable title is its own item — it loses no evidence, and the class it
    never named is no longer adopted from the other hypothesis."""
    graph = _graph(
        _h("H1", title="SQL injection in the artist parameter"),
        _h("H2", title="Log4Shell in the artist parameter"),
    )
    audit = _audit(tmp_path)

    assert dedup_hypotheses(graph, audit) == 0

    assert [n["label"] for n in graph.by_type("hypothesis")] == ["H1", "H2"]
    report = render_report(graph, audit, "e-a13")
    assert "### H1 — SQL injection in the artist parameter" in report
    assert "### H2 — Log4Shell in the artist parameter" in report
    # left alone deliberately: the pair is not a validation problem
    assert validate_report(report, graph) == []


# ---- D7: the primary asset is never marked as unobserved -------------------

def test_the_primary_asset_is_marked_when_the_engagement_never_saw_it(tmp_path):
    """DEFECT (A13 D7, LOW). Related assets carried "(this engagement never
    recorded this asset)"; the `Where:` line — the asset the test would
    actually act on — did not.

    A14 folded it in: a browser and a report that disagree about which assets
    the engagement saw would recreate exactly the inconsistency D4 is about."""
    graph = _graph(_h("H1",
                      target_asset="/never-recorded-by-recon.asp?artist=1",
                      related_assets=[{"asset": "/also-never-recorded.asp",
                                       "role": "carries it"}]))
    report = render_report(graph, _audit(tmp_path), "e-a13")

    where = next(l for l in report.splitlines()
                 if l.startswith("- Where: "))
    assert where == ("- Where: /never-recorded-by-recon.asp?artist=1 "
                     "(this engagement never recorded this asset)")
    # the related asset is still marked, and marked by the same rule
    assert "(this engagement never recorded this asset)" in report
    assert report.count("(this engagement never recorded this asset)") == 2
    # an asset recon did record is never marked
    recorded = _graph(_h("H1", target_asset=ASSET,
                         related_assets=[{"asset": ASSET}]))
    recorded.add_node("path", ASSET, {})     # what passive recon records
    ok_report = render_report(recorded, _audit(tmp_path), "e-a13")
    assert "never recorded this asset" not in ok_report


# ---- properties that hold (checked in the audit §3, pinned here) -----------

def test_a_failed_verification_is_not_reported_as_agreement(tmp_path):
    """Not a defect: VERIFY records "could not run" as `verified: False` with
    a reason, and the report says so rather than implying the issue is
    absent. This is the honest half of D1's asymmetry."""
    graph = _graph(_h("H1"))
    graph.add_node("exploit_attempt", "H1:sqlmap",
                   {"tool": "sqlmap", "ok": True, "exit_code": 0,
                    "confirmed": True, "output_excerpt": "is vulnerable",
                    "argv": [], "error_excerpt": "", "truncated": False})
    graph.add_node("verify_attempt", "H1",
                   {"verified": False, "reason": "probe run failed"})
    report = render_report(graph, _audit(tmp_path), "e-a13")

    assert "did not agree or could not run — treat this finding with care" in report
    assert "Double-checked: **yes" not in report


def test_no_node_label_refers_to_a_merged_away_hypothesis(tmp_path):
    """Not a defect: the id is not a foreign key, so a merge must rewrite
    every label that embeds it. Every field the reader joins on survives."""
    graph = _graph(_h("H1"), _h("H2", title="SQLi in artist parameter"))
    graph.add_node("exploit_attempt", "H2:sqlmap",
                   {"tool": "sqlmap", "ok": True, "exit_code": 0,
                    "confirmed": True, "output_excerpt": "", "argv": [],
                    "error_excerpt": "", "truncated": False})
    graph.add_node("finding", "H2", {"tool": "sqlmap"})
    graph.add_node("verify_attempt", "H2", {"verified": True})
    graph.add_node("remediation", "H2", {"title": "t", "fix": "f",
                                         "severity": "high"})

    assert dedup_hypotheses(graph, _audit(tmp_path)) == 1

    labels = [n["label"] for n in graph.nodes if n["node_type"] != "hypothesis"]
    assert not [l for l in labels if l == "H2" or l.startswith("H2:")]
    assert "H1:sqlmap" in labels and "H1" in labels


def test_the_persisted_graph_and_the_report_agree_on_the_nodes(tmp_path):
    """Not a defect: persistence runs after REPORT's dedup, so the browser
    and the report are looking at the same node set. (They differ in the
    fields they show — that is D4.)"""
    from kryonsec.purple.graph_store import load_graph, save_graph
    from kryonsec.storage import get_purple_session, init_purple_db

    cfg = KryonsecConfig(home=tmp_path)
    graph = _graph(_h("H1"), _h("H2", title="SQLi in artist parameter"))
    audit = _audit(tmp_path)
    dedup_hypotheses(graph, audit)

    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        save_graph(session, graph)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-a13")

    in_report = [n["label"] for n in graph.by_type("hypothesis")]
    in_store = [n["label"] for n in loaded.by_type("hypothesis")]
    assert in_report == in_store == ["H1"]
    assert "### H1 — " in render_report(graph, audit, "e-a13")
