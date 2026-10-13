"""A14 — truthful test and finding reporting.

The defects are reproduced in docs/A13-LIFECYCLE-INTEGRITY-AUDIT-2026-10-12.md
(D1, D2, D4, D5, D7) and the end-to-end versions live in
tests/test_hypothesis_lifecycle_a13.py. This file is the unit-level half: the
shared execution predicate, the report and browser reading one derivation, the
reference resolution, and the safety properties that must not have moved.

Synthetic graphs and fake sandboxes only — nothing here spawns a container,
opens a socket or calls a model.

The one fact everything here turns on: ``ok`` on an ``exploit_attempt`` node is
the sandbox's verdict on **process creation**. ``ok=True`` means docker was
reached and the output was parsed; it says nothing about whether the security
check succeeded. Only ``confirmed`` — the tool's own marker in its own stdout —
says that, and only for a run that started.
"""

from __future__ import annotations

import json

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.blue_team import render_blue_team_prompt
from kryonsec.purple.exploit import ExploitSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.report import (
    remediation_reference,
    render_report,
    validate_report,
)
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.views import (
    ATTEMPT_CONFIRMED,
    ATTEMPT_INCONCLUSIVE,
    ATTEMPT_NONE,
    ATTEMPT_NOT_RUN,
    ATTEMPT_UNRECORDED,
    OUTCOMES_RUN,
    attempt_names,
    attempt_outcome,
    exploit_status,
    hypothesis_engine_view,
)

TARGET = "target-corp.com"
ASSET = "/ListProducts.asp?artist=1"

SQLMAP_HIT = "sqlmap identified the following injection point: is vulnerable"


class FakeSandbox:
    def __init__(self, result):
        self.result = result
        self.spawned = []

    def spawn(self, argv):
        self.spawned.append(argv)
        return self.result


def _audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _graph(*hypotheses) -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-a14")
    graph.add_node("target", TARGET, {})
    graph.add_node("path", ASSET, {})
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


def _attempt(graph, label, **props):
    """An attempt node shaped exactly as EXPLOIT writes one."""
    base = {"tool": label.split(":")[-1], "argv": [], "ok": True,
            "exit_code": 0, "confirmed": False, "output_excerpt": "",
            "error_excerpt": "", "truncated": False}
    base.update(props)
    return graph.add_node("exploit_attempt", label, base)


# ---- the predicate: what the producer's fields actually mean ---------------

@pytest.mark.parametrize("props,expected", [
    # the tool ran and its own output carried the marker
    ({"ok": True, "confirmed": True}, ATTEMPT_CONFIRMED),
    # the tool ran; the marker was absent — a check that proved nothing,
    # which is not the same as a check that found nothing
    ({"ok": True, "confirmed": False}, ATTEMPT_INCONCLUSIVE),
    # the process never started: `ok` is the sandbox's verdict on spawn
    ({"ok": False, "confirmed": False}, ATTEMPT_NOT_RUN),
    # hand-built or pre-A14 nodes that carry neither field
    ({"confirmed": False}, ATTEMPT_UNRECORDED),
    ({}, ATTEMPT_UNRECORDED),
])
def test_an_attempt_outcome_reads_the_producers_own_fields(props, expected):
    assert attempt_outcome({"label": "H1:sqlmap", "properties": props}) \
        == expected


def test_a_missing_or_malformed_property_block_is_unrecorded_not_a_result():
    """Never a security verdict by default: no properties, no record."""
    for node in ({"label": "H1:sqlmap"}, {"label": "H1:sqlmap",
                                          "properties": None},
                 {"label": "H1:sqlmap", "properties": ["nope"]}):
        assert attempt_outcome(node) == ATTEMPT_UNRECORDED


def test_confirmed_alone_is_proof_the_process_started():
    """`confirmed` is only ever set by the producer for a run whose spawn
    succeeded, so a node carrying it is a record of execution even without
    `ok` — which is what keeps a graph written before A14 readable."""
    assert attempt_outcome(
        {"label": "H1:sqlmap", "properties": {"confirmed": True}}
    ) == ATTEMPT_CONFIRMED


def test_only_a_run_counts_as_execution():
    assert OUTCOMES_RUN == {ATTEMPT_INCONCLUSIVE, ATTEMPT_CONFIRMED}
    assert ATTEMPT_NOT_RUN not in OUTCOMES_RUN
    assert ATTEMPT_UNRECORDED not in OUTCOMES_RUN


def test_attempt_labels_belong_to_their_hypothesis_by_id_prefix():
    assert attempt_names("H1:sqlmap", "H1")
    assert attempt_names("H1", "H1")            # a label with no tool part
    assert not attempt_names("H10:sqlmap", "H1")   # prefix, but not this id
    assert not attempt_names("H1:sqlmap", "")
    assert not attempt_names(None, "H1")


def test_a_hypothesis_with_no_attempt_records_no_attempt():
    graph = _graph(_h("H1"))
    _attempt(graph, "H10:sqlmap", ok=True)     # a different hypothesis
    assert exploit_status("H1", graph) == ATTEMPT_NONE
    assert hypothesis_engine_view(
        graph.by_type("hypothesis")[0], graph)["tested"] is False


# ---- mixed outcomes --------------------------------------------------------

def test_the_best_recorded_outcome_wins_across_several_attempts():
    """A second tool that could not start must never undo a first that ran."""
    graph = _graph(_h("H1", tools=["sqlmap", "nuclei"]))
    _attempt(graph, "H1:sqlmap", ok=True, confirmed=False)
    _attempt(graph, "H1:nuclei", ok=False, exit_code=-1,
             error_excerpt="Cannot connect to the Docker daemon")
    assert exploit_status("H1", graph) == ATTEMPT_INCONCLUSIVE

    _attempt(graph, "H1:sqlmap", confirmed=False)   # duplicates do not lower it
    assert exploit_status("H1", graph) == ATTEMPT_INCONCLUSIVE

    graph.add_node("exploit_attempt", "H1:nuclei", {"confirmed": True})
    assert exploit_status("H1", graph) == ATTEMPT_CONFIRMED


def test_mixed_attempts_render_one_line_each_and_never_as_one_verdict(tmp_path):
    graph = _graph(_h("H1", tools=["sqlmap", "nuclei"]))
    _attempt(graph, "H1:sqlmap", ok=True, confirmed=True,
             output_excerpt=SQLMAP_HIT)
    _attempt(graph, "H1:nuclei", ok=False, exit_code=-1,
             error_excerpt="docker: not installed")
    report = render_report(graph, _audit(tmp_path), "e-a14")

    assert "- **H1:sqlmap** (sqlmap): ran, and **the tool said the" in report
    assert "- **H1:nuclei** (nuclei): **could not be run**, so" in report
    assert "docker: not installed" in report             # the reason is shown
    # the one that ran is a test that ran; the one that did not is not
    assert "- Tested: yes" in report
    assert "- Result: **confirmed by the test tool**" in report
    assert validate_report(report, graph) == []


# ---- D1 end to end: the four states, from EXPLOIT's own writes -------------

def test_a_sandbox_that_cannot_start_checks_nothing(tmp_path):
    cfg, audit = KryonsecConfig(home=tmp_path), _audit(tmp_path)
    graph = _graph(_h("H1"))
    sandbox = FakeSandbox(SpawnResult(
        ok=False, exit_code=-1, stdout="",
        error="Cannot connect to the Docker daemon"))

    ExploitSubagent(cfg, graph, audit, TARGET, sandbox).run()
    report = render_report(graph, audit, "e-a14")

    assert exploit_status("H1", graph) == ATTEMPT_NOT_RUN
    # the report may not infer an absence of vulnerabilities from this
    assert "**The tests could not be run, so nothing was checked.**" in report
    assert "no vulnerabilities" not in report.lower()
    assert "is not vulnerable" not in report.lower()
    assert "- Tested: no — the tool could not be started" in report
    assert validate_report(report, graph) == []


def test_a_run_without_the_marker_is_not_a_clean_bill_of_health(tmp_path):
    cfg, audit = KryonsecConfig(home=tmp_path), _audit(tmp_path)
    graph = _graph(_h("H1"))
    sandbox = FakeSandbox(SpawnResult(
        ok=True, exit_code=0, stdout="no parameters were injectable"))

    ExploitSubagent(cfg, graph, audit, TARGET, sandbox).run()
    report = render_report(graph, audit, "e-a14")

    assert exploit_status("H1", graph) == ATTEMPT_INCONCLUSIVE
    assert "- **H1:sqlmap** (sqlmap): ran and did **not** confirm" in report
    assert ("A test that finds nothing is not proof that nothing is there"
            in report)
    assert graph.by_type("finding") == []
    assert "- Tested: yes" in report          # a test did run
    assert "- Result: **confirmed by the test tool**" not in report


def test_a_run_that_confirms_the_marker_is_reported_as_confirmed(tmp_path):
    cfg, audit = KryonsecConfig(home=tmp_path), _audit(tmp_path)
    graph = _graph(_h("H1"))
    sandbox = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=SQLMAP_HIT))

    ExploitSubagent(cfg, graph, audit, TARGET, sandbox).run()
    report = render_report(graph, audit, "e-a14")

    assert exploit_status("H1", graph) == ATTEMPT_CONFIRMED
    assert "- **H1:sqlmap** (sqlmap): ran, and **the tool said the" in report
    assert "- Tested: yes" in report
    assert "- Result: **confirmed by the test tool**" in report
    assert len(graph.by_type("finding")) == 1


def test_an_approved_hypothesis_with_no_attempt_is_not_reported_as_tested(
        tmp_path):
    """D2: approval is set before EXPLOIT runs, so it is never evidence that
    a test happened — and it is not even evidence that one was attempted."""
    cfg, audit = KryonsecConfig(home=tmp_path), _audit(tmp_path)
    graph = _graph(_h("H1", tools=["jwt_tool"]))     # no argv template
    sandbox = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""))
    ExploitSubagent(cfg, graph, audit, TARGET, sandbox).run()

    assert sandbox.spawned == []
    assert exploit_status("H1", graph) == ATTEMPT_NONE

    report = render_report(graph, audit, "e-a14")
    assert "- Your decision: approved" in report          # the decision is shown
    assert "- Tested:" not in report                      # but nothing claims it
    assert "**No testing was done against the website.**" in report

    prompt = render_blue_team_prompt(graph)
    assert "approved by operator: True" in prompt
    assert "status: proposed-only (not tested)" in prompt
    assert "tested-by-exploit-phase" not in prompt


def test_an_unapproved_hypothesis_is_never_run_and_never_claimed(tmp_path):
    """The approval gate itself: unchanged by A14, and the report still has
    to be truthful about a hypothesis nobody allowed."""
    cfg, audit = KryonsecConfig(home=tmp_path), _audit(tmp_path)
    graph = _graph(_h("H1", approved=False))
    sandbox = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=SQLMAP_HIT))
    ExploitSubagent(cfg, graph, audit, TARGET, sandbox).run()

    assert sandbox.spawned == []                     # the gate held
    assert graph.by_type("exploit_attempt") == []
    assert graph.by_type("finding") == []
    report = render_report(graph, audit, "e-a14")
    assert "- Your decision: not approved" in report
    assert "- Tested:" not in report
    assert "confirmed by the test tool" not in report


def test_an_attempt_recorded_without_a_verdict_is_not_read_as_a_result(tmp_path):
    """Legacy/hand-built graphs: a node with neither `ok` nor `confirmed`
    says an attempt was recorded and nothing more — in the report too."""
    graph = _graph(_h("H1"))
    _attempt(graph, "H1:sqlmap", ok=None, confirmed=None, exit_code=None)
    report = render_report(graph, _audit(tmp_path), "e-a14")

    assert exploit_status("H1", graph) == ATTEMPT_UNRECORDED
    assert "did not record whether the tool actually started" in report
    assert "- Tested: no — an attempt was recorded, but the engagement did " \
           "not record whether the tool started" in report
    assert "ran and did **not** confirm" not in report
    assert validate_report(report, graph) == []


# ---- D2: the blue-team prompt reads execution, never approval -------------

@pytest.mark.parametrize("props,expected", [
    ({"ok": True, "confirmed": True},
     "tested-by-exploit-phase (the tool's own output confirmed it)"),
    ({"ok": True, "confirmed": False},
     "tested-by-exploit-phase (a test ran and did not confirm it)"),
    ({"ok": False, "confirmed": False},
     "approved, but the test could not run — treat as risk to verify"),
    # neither field is a record that says an attempt happened and nothing
    # about whether it started. ``ok`` has to be *absent* to say that —
    # ``_attempt`` defaults it to True, and ok=True is a run.
    ({"ok": None, "confirmed": False},
     "approved, but no test run was recorded — treat as risk to verify"),
])
def test_the_blue_team_status_line_follows_the_record(tmp_path, props, expected):
    graph = _graph(_h("H1"))
    _attempt(graph, "H1:sqlmap", **props)
    prompt = render_blue_team_prompt(graph)
    # on its own line, under the decision it is about: a jinja comment that
    # stripped the trailing whitespace once ran the two together
    # ("approved by operator: Truestatus: proposed-only (not tested)")
    assert f"approved by operator: True\n  status: {expected}" in prompt


def test_the_blue_team_prompt_cannot_be_lifted_by_the_models_own_prose(tmp_path):
    """A hypothesis whose properties claim the engine's answers still reaches
    the model as untested — the view is merged in after the properties."""
    graph = _graph(_h("H1", basis="validated", tested=True, confirmed=True,
                      exploit_status="confirmed"))
    prompt = render_blue_team_prompt(graph)
    assert "status: proposed-only (not tested)" in prompt


# ---- D5: remediation references -------------------------------------------

def test_a_remediation_naming_nothing_in_the_engagement_is_unresolved(tmp_path):
    graph = _graph(_h("H1"))
    graph.add_node("remediation", "H7",
                   {"title": "Sanitise input", "fix": "escape it",
                    "severity": "high", "detection": ""})
    assert remediation_reference("H7", graph)["resolved"] is False

    report = render_report(graph, _audit(tmp_path), "e-a14")
    assert "### Fix for H7 — Sanitise input" in report
    assert "**This fix is not linked to anything in this report.**" in report
    problems = validate_report(report, graph)
    assert any("refers to no hypothesis" in p for p in problems)


def test_a_remediation_naming_two_things_is_unresolved(tmp_path):
    """An id that names a hypothesis *and* a code scan has no record saying
    which was meant, so neither is claimed (§ the prompt invites both)."""
    graph = _graph(_h("semgrep"))
    graph.add_node("scanner_result", "semgrep", {"exit_code": 1})
    graph.add_node("remediation", "semgrep",
                   {"title": "Triage the scan", "fix": "fix the findings",
                    "severity": "medium", "detection": ""})
    reference = remediation_reference("semgrep", graph)
    assert reference["resolved"] is False
    assert "both an issue and a code scan" in reference["reference_note"]

    report = render_report(graph, _audit(tmp_path), "e-a14")
    assert "**This fix is not linked to anything in this report.**" in report
    assert any("refers to no hypothesis" in p
               for p in validate_report(report, graph))


def test_a_remediation_naming_one_thing_is_resolved(tmp_path):
    graph = _graph(_h("H1"))
    graph.add_node("remediation", "H1",
                   {"title": "Sanitise input", "fix": "escape it",
                    "severity": "high", "detection": ""})
    assert remediation_reference("H1", graph)["resolved"] is True

    report = render_report(graph, _audit(tmp_path), "e-a14")
    assert "**This fix is not linked to anything in this report.**" not in report
    assert validate_report(report, graph) == []


def test_a_scanner_named_remediation_is_resolved(tmp_path):
    """The prompt tells the model it may write a remediation for a scanner by
    tool name — that is a real target, not a dangling one."""
    graph = _graph(_h("H1"))
    graph.add_node("scanner_result", "bandit", {"exit_code": 1})
    graph.add_node("remediation", "bandit",
                   {"title": "Triage bandit", "fix": "fix them",
                    "severity": "medium", "detection": ""})
    assert remediation_reference("bandit", graph)["resolved"] is True
    assert validate_report(render_report(graph, _audit(tmp_path), "e-a14"),
                           graph) == []


def test_an_empty_remediation_id_is_unresolved_not_a_crash():
    graph = _graph(_h("H1"))
    assert remediation_reference("", graph)["resolved"] is False
    assert remediation_reference(None, graph)["resolved"] is False


# ---- D4: browser and report read one derivation ---------------------------

def test_the_browser_and_the_report_agree_on_standing_and_assets(tmp_path):
    from kryonsec.memory.data import load_engagement
    from kryonsec.purple.graph_store import save_graph
    from kryonsec.storage import get_purple_session, init_purple_db, reset_engine

    cfg = KryonsecConfig(home=tmp_path)
    graph = _graph(_h("H1", related_assets=[{"asset": "/gone.asp",
                                             "role": "carries it"}],
                      relationship="the two are linked"))
    _attempt(graph, "H1:sqlmap", ok=True, confirmed=False)
    graph.add_node("verify_attempt", "H1", {"verified": False})

    # the engagement engine is process-wide (storage.db caches it), so this
    # test has to start and end on a clean one or it reads another test's db
    reset_engine()
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        save_graph(session, graph)
    try:
        (hyp,) = [n for n in load_engagement(cfg, "e-a14")["graph"]["nodes"]
                  if n["node_type"] == "hypothesis"]
    finally:
        reset_engine()
    engine = hyp["properties"]["engine"]
    report = render_report(graph, _audit(tmp_path), "e-a14")

    # one derivation, two surfaces: the browser's values are the report's
    assert engine["basis"] == "tested"
    assert f"What the engagement itself can say about that claim: " \
           f"{engine['basis']}" in report
    assert engine["exploit_status"] == "inconclusive"
    assert "- Tested: yes" in report
    assert engine["primary_asset_observed"] is True
    assert "- Where: /ListProducts.asp?artist=1" in report
    assert "(this engagement never recorded this asset)" not in \
        report.split("- Where:")[1].split("\n")[0]
    assert engine["related_assets"] == [{"asset": "/gone.asp",
                                         "role": "carries it",
                                         "observed": False}]
    assert "/gone.asp — carries it (this engagement never recorded this asset)" \
        in report


def test_the_engine_view_cannot_be_overridden_by_node_properties():
    """Merged in *after* the properties, so the model's copy loses.

    Including the model's own ``observed: True`` on a reference: the engine
    answers that from the graph, so a claim about an asset the engagement
    never recorded reads ``observed: False`` and drags the ladder down to
    ``proposed`` — while the ``basis`` the model wrote says ``validated``.
    """
    graph = _graph(_h("H1", basis="validated", tested=True, confirmed=True,
                      exploit_status="confirmed", primary_asset_observed=False,
                      related_assets=[{"asset": "/made/up", "observed": True}]))
    node = graph.by_type("hypothesis")[0]
    view = hypothesis_engine_view(node, graph)

    assert view["basis"] == "proposed"
    assert view["tested"] is False
    assert view["confirmed"] is False
    assert view["exploit_status"] == ATTEMPT_NONE
    assert view["primary_asset_observed"] is True
    assert view["related_assets"] == [{"asset": "/made/up", "role": "",
                                       "observed": False}]


def test_legacy_graphs_without_the_a11_fields_still_render(tmp_path):
    """Nodes saved before A11/A14 carry none of the newer fields: the view is
    derived from what is there, and nothing raises."""
    graph = EngagementGraph(engagement_id="e-a14")
    graph.add_node("target", TARGET, {})
    graph.add_node("hypothesis", "H1", {"title": "old node",
                                        "approved": True})
    node = graph.by_type("hypothesis")[0]
    view = hypothesis_engine_view(node, graph)
    assert view["basis"] == "proposed"
    assert view["related_assets"] == []
    assert view["primary_asset_observed"] is True   # names no asset

    report = render_report(graph, _audit(tmp_path), "e-a14")
    assert "### H1 — old node" in report
    assert validate_report(report, graph) == []


# ---- browser output safety -------------------------------------------------

def test_the_engine_view_carries_no_secret_and_no_path():
    """The view is derived text, not raw evidence — but a property it echoes
    must not be able to smuggle a line break or a path into the page."""
    graph = _graph(_h("H1",
                      related_assets=[{"asset": "/a\n\n- **injected**",
                                       "role": "key: AKIAIOSFODNN7EXAMPLE"}]))
    node = graph.by_type("hypothesis")[0]
    view = hypothesis_engine_view(node, graph)
    blob = json.dumps(view)
    assert "\n" not in blob
    assert "injected**" in blob           # collapsed into the same one line
    assert blob.count("injected") == 1


def test_the_browser_scrubs_secrets_out_of_the_engine_view(tmp_path):
    """The response boundary is still the one place secrets are removed, and
    the new engine block goes through it like everything else.

    The secret rides in a reference's role — a field the engine view echoes —
    because that is the only way model text reaches it: ``hypothesis_engine_view``
    returns derived values, never the hypothesis's prose.
    """
    from kryonsec.memory.data import scrub
    from kryonsec.secrets import SECRET_PATTERNS

    graph = _graph(_h("H1", related_assets=[
        {"asset": "/a", "role": "key AKIAIOSFODNN7EXAMPLE"}]))
    node = graph.by_type("hypothesis")[0]
    payload = {"properties": {"engine": hypothesis_engine_view(node, graph)}}
    body, count = scrub(payload)
    assert SECRET_PATTERNS  # the detector this must not drift from
    assert count == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(body)
    # ensure_ascii=False: the placeholder's guillemets are what the operator
    # sees, and the default escaping would hide them behind «
    assert "«SECRET_1»" in json.dumps(body, ensure_ascii=False)


def test_the_memory_package_may_import_the_view_module_only(tmp_path):
    """The allowlist entry added for D4 is small on purpose: ``purple.views``
    is read-only and stdlib-only, and this pins that it stays so."""
    from kryonsec.memory import data

    source = __import__("pathlib").Path(data.__file__).read_text(
        encoding="utf-8")
    assert "from ..purple.views import hypothesis_engine_view" in source


# ---- the state machine and the audit chain did not move -------------------

def test_reporting_fixes_changed_no_state_transition(tmp_path):
    """A14 touched what the report *says*. The loop, the approval semantics
    and the audit events EXPLOIT writes are the same ones A13 recorded."""
    cfg, audit = KryonsecConfig(home=tmp_path), _audit(tmp_path)
    graph = _graph(_h("H1"))
    sandbox = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=SQLMAP_HIT))
    ExploitSubagent(cfg, graph, audit, TARGET, sandbox).run()

    events = [json.loads(line)["event"]
              for line in audit.path.read_text(encoding="utf-8").splitlines()]
    assert events[:2] == ["state_enter", "exploit_plan"]
    assert events[-1] == "exploit_done"
    assert "finding_confirmed" in events
