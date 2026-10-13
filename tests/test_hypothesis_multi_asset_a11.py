"""A11 — a hypothesis may name more than one asset, as a reviewable claim.

A9 measured the gap: prompt item 5 asked a multi-asset hypothesis to name
its assets and explain their relationship, but ``target_asset`` is a single
string and there was nowhere structured for either to go. A11 gives the
claim two optional, bounded fields — ``related_assets`` (assets, each with
its role) and ``relationship`` (how they are proposed to work together) —
without touching the graph's edges, the approval gate, or anything A6–A10
built.

What these tests pin, in the spec's order:

* an old hypothesis, and an old persisted graph, read exactly as before —
  when the model makes no claim, no new key is written at all;
* the *standing* of a claim is never a field. A model may describe a
  relationship; it cannot call it validated, and a model-supplied status
  key is dropped rather than stored;
* every cap is enforced by sanitising, not rejecting: hostile, oversized
  and malformed claim text is bounded into one line, never allowed to fail
  the HYPOTHESIZE state;
* an asset the engagement never recorded stays unresolved and is never
  matched against a similarly-named one;
* the claim reaches the report, the approval panel and the blue-team prompt
  as a proposal, and no graph edge appears.

The last section re-asserts the gates A11 must leave alone.
"""

from __future__ import annotations

import json

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.blue_team import render_blue_team_prompt
from kryonsec.purple.human_review import (
    HumanReviewSubagent,
    _approval_panel,
)
from kryonsec.purple.hypothesize import (
    BASIS_NOTES,
    BASIS_PROPOSED,
    BASIS_SUPPORTED,
    BASIS_TESTED,
    BASIS_VALIDATED,
    MAX_ASSET_CHARS,
    MAX_RELATED_ASSETS,
    MAX_RELATIONSHIP_CHARS,
    MAX_ROLE_CHARS,
    Hypothesis,
    HypothesisSet,
    HypothesizeSubagent,
    observed_assets,
    related_asset_views,
    relationship_basis,
)
from kryonsec.purple.orchestrator import SubagentResult, next_state
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.report import render_report, validate_report
from secret_fixtures import AWS_EXAMPLE_KEY

TARGET = "target-corp.com"
LOGIN = "/Login.asp?id=1"
ADMIN = "/admin/list.asp"


def _graph(*nodes) -> EngagementGraph:
    """A graph from ``(node_type, label, properties)`` rows."""
    graph = EngagementGraph(engagement_id="e-a11")
    for node_type, label, properties in nodes:
        graph.add_node(node_type, label, properties)
    return graph


def _observed() -> EngagementGraph:
    """The four assets the fixture engagement recorded — and nothing else."""
    return _graph(
        ("target", TARGET, {}),
        ("subdomain", f"api.{TARGET}", {}),
        ("path", "/Login.asp", {}),
        ("path", ADMIN, {}),
    )


def _claim(**over) -> dict:
    """The smallest complete multi-asset claim, for overriding per test.

    Carries every key the report template reads (StrictUndefined), so a
    node built from it renders without extra scaffolding.
    """
    return {
        "title": "the login writes what the admin list reads",
        "target_asset": LOGIN,
        "rationale": "r",
        "cvss_vector": "",
        "cve": "",
        "tools": ["sqlmap"],
        "confidence": 0.5,
        "related_assets": [{"asset": ADMIN,
                            "role": "acts on the rows the login writes"}],
        "relationship": f"{LOGIN} writes rows that {ADMIN} renders",
        **over,
    }


def _subagent(tmp_path, graph, hypotheses) -> HypothesizeSubagent:
    return HypothesizeSubagent(
        cfg=KryonsecConfig(home=tmp_path),
        graph=graph,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        llm_fn=lambda prompt: HypothesisSet(hypotheses=hypotheses),
    )


def _report(tmp_path, graph, name="audit.jsonl") -> str:
    return render_report(
        graph, AuditLog(tmp_path / name), "e-a11", completed_states=["REPORT"])


# --- requirement 1/2: legacy and single-asset hypotheses -------------------

def test_a_hypothesis_without_a_claim_writes_no_new_key(tmp_path):
    """The strongest form of compatibility: not "the new fields default to
    empty" but "the node is exactly the node v2 wrote"."""
    graph = _observed()
    assert _subagent(tmp_path, graph, [
        Hypothesis(id="H1", title="t", target_asset=LOGIN, rationale="r"),
    ]).run().status == "ok"

    props = graph.by_type("hypothesis")[0]["properties"]
    assert set(props) == {
        "title", "target_asset", "rationale", "cvss_vector", "cve",
        "tools", "confidence"}


def test_an_explicitly_empty_claim_is_also_written_as_nothing(tmp_path):
    """A model that emits the keys with empty values gets the legacy node —
    "no claim" has one representation, so a reader never has to know which
    producer wrote the node."""
    graph = _observed()
    assert _subagent(tmp_path, graph, [
        Hypothesis(id="H1", title="t", target_asset=LOGIN, rationale="r",
                   related_assets=[], relationship=""),
    ]).run().status == "ok"

    props = graph.by_type("hypothesis")[0]["properties"]
    assert "related_assets" not in props and "relationship" not in props


def test_a_legacy_hypothesis_dict_still_validates():
    """Deserialization compatibility: the persisted shape from before A11
    (a plain dict, no new keys) is still a valid Hypothesis."""
    h = Hypothesis.model_validate({
        "id": "H1", "title": "t", "target_asset": LOGIN, "rationale": "r",
        "cvss_vector": "AV:N", "cve": "CVE-2021-44228", "tools": ["nmap"],
        "confidence": 0.7,
    })
    assert h.related_assets == [] and h.relationship == ""
    assert h.target_asset == LOGIN  # requirement 2: the field is untouched


def test_a_legacy_graph_node_renders_without_the_new_rows(tmp_path):
    """Requirement 10: an engagement persisted before A11 renders exactly
    the report it rendered before — and still validates clean."""
    graph = _graph(
        ("target", TARGET, {}),
        ("hypothesis", "H1", {"title": "t", "target_asset": LOGIN,
                              "rationale": "r", "cvss_vector": "", "cve": "",
                              "tools": ["sqlmap"], "confidence": 0.5}),
    )
    report = _report(tmp_path, graph)
    assert "Also involves" not in report
    assert "Proposed relationship" not in report
    assert LOGIN in report
    assert validate_report(report, graph) == []


# --- requirement 3/4: the structured claim and its standing ----------------

def test_a_multi_asset_proposal_round_trips_to_the_report(tmp_path):
    graph = _observed()
    assert _subagent(tmp_path, graph, [
        Hypothesis(id="H1", **_claim()),
    ]).run().status == "ok"

    node = graph.by_type("hypothesis")[0]
    assert node["properties"]["related_assets"] == [
        {"asset": ADMIN, "role": "acts on the rows the login writes"}]
    assert node["status"] == "proposed"  # a claim, never an observation

    report = _report(tmp_path, graph)
    assert "Also involves" in report
    assert ADMIN in report and "acts on the rows the login writes" in report
    assert f"Proposed relationship (the assistant's claim" in report
    # both named assets are ones the engagement recorded, so the engine's
    # own best word for the claim is "supported" — still not "tested"
    assert f"the engagement itself can say about that claim: {BASIS_SUPPORTED}" \
        in report
    assert BASIS_NOTES[BASIS_SUPPORTED] in report
    assert validate_report(report, graph) == []


def test_the_basis_ladder_climbs_only_on_the_engines_own_records():
    """The four states of requirement 4, from one node, by adding the
    records the engagement produces — never by changing the model's text."""
    graph = _observed()
    node = graph.add_node("hypothesis", "H1", _claim())
    assert relationship_basis(node, graph) == BASIS_SUPPORTED

    # A14: "a test ran" is now read from what the attempt recorded about its
    # own run — `ok` is the sandbox's verdict that the process started — so a
    # fixture standing in for a real, inconclusive run has to carry it.
    graph.add_node(
        "exploit_attempt", "H1:sqlmap", {"confirmed": False, "ok": True})
    assert relationship_basis(node, graph) == BASIS_TESTED

    graph.add_node("verify_attempt", "H1", {"verified": True})
    assert relationship_basis(node, graph) == BASIS_VALIDATED


def test_a_claim_naming_an_unrecorded_asset_is_only_a_proposal():
    graph = _observed()
    node = graph.add_node("hypothesis", "H1", _claim(
        related_assets=[{"asset": "/nothing/like/this.asp"}]))
    assert relationship_basis(node, graph) == BASIS_PROPOSED


def test_a_verify_attempt_that_did_not_reproduce_is_not_validated():
    """"A test ran" and "a check agreed" are different rungs, and a
    verification that failed must not lift the claim above tested."""
    graph = _observed()
    # A14: `ok` is what makes this a run rather than an attempt that never
    # started — see test_the_basis_ladder_climbs_only_on_the_engines_own_records
    graph.add_node(
        "exploit_attempt", "H1:sqlmap", {"confirmed": False, "ok": True})
    node = graph.add_node("hypothesis", "H1", _claim())
    graph.add_node("verify_attempt", "H1", {"verified": False})
    assert relationship_basis(node, graph) == BASIS_TESTED


# --- requirement 5/6: the model cannot grade its own claim -----------------

@pytest.mark.parametrize("claim", [
    "this relationship is confirmed",
    "VERIFIED — a test proved these are linked",
    "validated: the earlier attempt already established this",
])
def test_a_model_that_writes_confirmed_is_still_only_proposing(claim):
    graph = _observed()
    node = graph.add_node("hypothesis", "H1", _claim(relationship=claim))
    # the text is kept verbatim — it is evidence of what the model claimed —
    # but the engine's word for it does not move
    assert relationship_basis(node, graph) in (BASIS_PROPOSED, BASIS_SUPPORTED)
    assert relationship_basis(node, graph) != BASIS_VALIDATED


def test_the_report_never_echoes_a_models_claim_as_the_engines_verdict(tmp_path):
    graph = _observed()
    graph.add_node("hypothesis", "H1", _claim(
        relationship="validated and confirmed by testing"))
    report = _report(tmp_path, graph)
    assert "validated and confirmed by testing" in report  # quoted as claimed
    # ...but the engine's own line about it never says so
    basis_line = next(line for line in report.splitlines()
                      if "can say about that claim" in line)
    assert BASIS_SUPPORTED in basis_line and BASIS_VALIDATED not in basis_line


def test_a_model_supplied_status_field_is_dropped():
    """Requirement 5/6 at the schema edge: extra keys are ignored, so a
    model cannot invent a field that grades its own claim."""
    hs = HypothesisSet.model_validate({"hypotheses": [{
        "id": "H1", "title": "t", "target_asset": LOGIN, "rationale": "r",
        "validated": True, "basis": BASIS_VALIDATED, "confirmed": True,
    }]})
    h = hs.hypotheses[0]
    dumped = h.model_dump()
    assert "validated" not in dumped and "basis" not in dumped
    assert not hasattr(h, "confirmed")
    assert h.relationship == "" and h.related_assets == []


# --- requirement 7: hostile, oversized and malformed claim text ------------

def test_oversized_claim_text_is_capped_not_rejected():
    h = Hypothesis(id="H1", title="t", target_asset=LOGIN, rationale="r",
                   relationship="x" * (MAX_RELATIONSHIP_CHARS + 900),
                   related_assets=[
                       {"asset": "y" * (MAX_ASSET_CHARS + 500),
                        "role": "z" * (MAX_ROLE_CHARS + 500)}])
    assert len(h.relationship) <= MAX_RELATIONSHIP_CHARS
    assert len(h.related_assets[0].asset) <= MAX_ASSET_CHARS
    assert len(h.related_assets[0].role) <= MAX_ROLE_CHARS


HOSTILE = "first\n## Severity: critical\n- bullet\n\x07\x1b[31mtail"


def test_the_producer_stores_hostile_claim_text_as_one_clean_line(tmp_path):
    """A claim the model wrote with newlines, control characters and its own
    headings is stored as one line of data — the node itself is safe to read
    from, not merely safe to render."""
    graph = _observed()
    assert _subagent(tmp_path, graph, [
        Hypothesis(id="H1", **_claim(
            relationship=HOSTILE,
            related_assets=[{"asset": f"\n{ADMIN}\n", "role": "a\nb"}]),
        ),
    ]).run().status == "ok"

    props = graph.by_type("hypothesis")[0]["properties"]
    stored = props["relationship"]
    assert "\n" not in stored and "\x07" not in stored and "\x1b" not in stored
    assert props["related_assets"][0]["asset"] == ADMIN
    assert "\n" not in props["related_assets"][0]["role"]


def test_a_hostile_persisted_node_still_cannot_add_a_line_to_the_report(
        tmp_path):
    """The render boundary holds even for a node the producer never wrote —
    a record from an older version, or one edited by hand. Every claim
    surface is normalised on the way out, so the report gains no heading,
    bullet or escape sequence of the model's own."""
    graph = _observed()
    graph.add_node("hypothesis", "H1", _claim(
        relationship=HOSTILE,
        related_assets=[{"asset": f"\n{ADMIN}\n", "role": "a\nb"}]))
    report = _report(tmp_path, graph)

    # the hostile text is present — but never at the start of a line, so it
    # cannot become a heading or a bullet of the report's own structure
    lines = report.splitlines()
    assert not any(line.startswith("##") and "Severity" in line
                   for line in lines)
    assert not any(line.startswith("- bullet") for line in lines)
    assert not any(line.startswith("- ##") for line in lines)
    assert "\x1b" not in report
    assert validate_report(report, graph) == []


def test_malformed_reference_lists_are_sanitised_not_fatal():
    h = Hypothesis(id="H1", title="t", target_asset=LOGIN, rationale="r",
                   related_assets="not a list at all")
    assert h.related_assets == []

    h = Hypothesis(id="H1", title="t", target_asset=LOGIN, rationale="r",
                   related_assets=[123, None, ["nested"], {"role": "no asset"},
                                   "   ", "", {"asset": "  "}, ADMIN])
    # only the one entry that names an asset survives
    assert [r.asset for r in h.related_assets] == [ADMIN]


def test_a_bare_string_entry_is_read_as_a_reference_with_no_role():
    h = Hypothesis(id="H1", title="t", target_asset=LOGIN, rationale="r",
                   related_assets=["/a", "/b"])
    assert [(r.asset, r.role) for r in h.related_assets] == [("/a", ""), ("/b", "")]


def test_the_reference_list_is_bounded():
    h = Hypothesis(id="H1", title="t", target_asset=LOGIN, rationale="r",
                   related_assets=[f"/p{i}" for i in range(20)])
    assert len(h.related_assets) == MAX_RELATED_ASSETS


def test_a_non_string_relationship_becomes_empty():
    for value in (None, 12, ["a", "b"], {"a": 1}):
        h = Hypothesis(id="H1", title="t", target_asset=LOGIN, rationale="r",
                       relationship=value)
        assert h.relationship == ""


# --- requirement 8: unknown and ambiguous assets stay unresolved -----------

def test_an_unrecorded_asset_is_never_resolved_to_a_similar_one():
    graph = _observed()  # records api.target-corp.com and /admin/list.asp
    node = graph.add_node("hypothesis", "H1", _claim(related_assets=[
        {"asset": f"api.{TARGET}"},        # observed, verbatim
        {"asset": "api.target-corp.co"},   # a lookalike host — not observed
        {"asset": "/admin/users.asp"},     # a sibling path — not observed
    ]))

    views = related_asset_views(node, graph)
    assert [v["observed"] for v in views] == [True, False, False]
    # the claim is shown as made; nothing is rewritten to the nearer match
    assert views[1]["asset"] == "api.target-corp.co"
    assert views[2]["asset"] == "/admin/users.asp"
    assert relationship_basis(node, graph) == BASIS_PROPOSED


def test_only_normalisation_that_cannot_change_which_asset_is_named():
    """Case, and a query or fragment, are not part of an asset's identity —
    the prompt asks for the parameter while recon records the path — so
    those read as the asset they name. A different path, or a URL carrying a
    host recon never recorded as that path, does not: resolving it would be
    inferring an asset the engagement never saw."""
    graph = _observed()
    node = graph.add_node("hypothesis", "H1", _claim(related_assets=[
        {"asset": "/ADMIN/List.ASP"},               # case
        {"asset": f"/admin/list.asp?sort=id#top"},  # query + fragment
        {"asset": f"https://{TARGET}/admin/list.asp"},  # host recon did not
        {"asset": "/admin/list.aspx"},              # different path
    ]))
    assert [v["observed"] for v in related_asset_views(node, graph)] == [
        True, True, False, False]


def test_the_observed_set_is_built_from_asset_nodes_only():
    """A tool result entry is not an asset the engagement observed — an
    exception message naming a path must not become one."""
    graph = _observed()
    graph.add_node("tool_result", "/etc/passwd", {"tool": "sqlmap"})
    assert observed_assets(graph) == {
        TARGET.lower(), f"api.{TARGET}".lower(), "/login.asp", ADMIN}


# --- requirement 9/10: reporting, memory browser, and the gates ------------

def test_the_approval_panel_shows_the_claim_as_the_assistants_proposal():
    import re as _re

    from rich.console import Console

    graph = _observed()
    node = graph.add_node("hypothesis", "H1", _claim())
    console = Console(record=True, width=100)
    console.print(_approval_panel(1, 1, node, graph))
    # the panel is a box that wraps, so compare against its content with the
    # border and the wrap-indentation collapsed away
    flat = " ".join(_re.sub(r"[│┌┐└┘─]", " ", console.export_text()).split())

    assert "Also involves" in flat and ADMIN in flat
    assert "acts on the rows the login writes" in flat
    assert "Proposed link" in flat
    assert "Engine's view" in flat
    assert BASIS_SUPPORTED in flat
    assert BASIS_NOTES[BASIS_SUPPORTED] in flat


def test_the_blue_team_prompt_carries_the_claim_and_the_engine_standing():
    graph = _observed()
    graph.add_node("hypothesis", "H1", {**_claim(), "approved": False})
    prompt = render_blue_team_prompt(graph)

    assert ADMIN in prompt
    assert "proposed relationship (the assistant's claim, untested)" in prompt
    assert f"what the engagement can say about it: {BASIS_SUPPORTED}" in prompt


def test_the_blue_team_prompt_still_renders_without_a_claim():
    """StrictUndefined must not trip on the legacy shape."""
    graph = _graph(
        ("target", TARGET, {}),
        ("hypothesis", "H1", {"title": "t", "target_asset": LOGIN,
                              "rationale": "r", "cvss_vector": "", "cve": "",
                              "tools": [], "confidence": 0.4}),
    )
    prompt = render_blue_team_prompt(graph)
    assert "H1" in prompt and LOGIN in prompt
    assert "proposed relationship" not in prompt


def test_a_multi_asset_claim_adds_no_graph_edge(tmp_path):
    """Requirement 9 — A11 records no relationship in the graph. The claim
    lives in the node's properties and nowhere else."""
    graph = _observed()
    edges_before = len(graph.edges)
    assert _subagent(tmp_path, graph, [
        Hypothesis(id="H1", **_claim()),
    ]).run().status == "ok"

    assert len(graph.edges) == edges_before


def test_the_approval_and_execution_gates_are_unchanged(tmp_path):
    """A claim never approves itself: EXPLOIT is still reached on
    approved_count alone, and the injected reviewer keeps its one-argument
    contract."""
    graph = _observed()
    graph.add_node("hypothesis", "H1", _claim())
    seen: list[list] = []

    def reviewer(hypotheses):  # the pre-A11 signature, unchanged
        seen.append(hypotheses)
        return set()  # approve nothing

    result = HumanReviewSubagent(
        graph=graph, audit=AuditLog(tmp_path / "audit.jsonl"),
        reviewer=reviewer).run()

    assert seen and len(seen[0]) == 1
    assert result.approved_count == 0
    assert graph.by_type("hypothesis")[0]["properties"]["approved"] is False
    assert next_state("HUMAN_REVIEW", result) == "BLUE_TEAM"
    assert next_state("HUMAN_REVIEW", SubagentResult(
        status="ok", approved_count=1)) == "EXPLOIT"


def test_validate_report_catches_a_dropped_claim(tmp_path):
    graph = _observed()
    graph.add_node("hypothesis", "H1", _claim())
    report = _report(tmp_path, graph)
    assert validate_report(report, graph) == []

    # strip the relationship line and the reference row: validation must say so
    broken = "\n".join(line for line in report.splitlines()
                       if "Proposed relationship" not in line
                       and "Also involves" not in line
                       and ADMIN not in line)
    problems = validate_report(broken, graph)
    assert any("relationship claim for H1" in p for p in problems)
    assert any(f"related asset for H1 ({ADMIN})" in p for p in problems)


# --- persistence and the memory browser ------------------------------------

@pytest.fixture()
def cfg(tmp_path):
    from kryonsec.storage import reset_engine

    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = None
    yield config
    reset_engine()


def test_the_claim_survives_save_and_load(cfg):
    """No migration: ``stm_nodes.properties`` is free-form JSON, so the new
    keys persist through the store untouched."""
    from kryonsec.purple.graph_store import load_graph, save_graph
    from kryonsec.storage import get_purple_session, init_purple_db

    init_purple_db(cfg)
    graph = _observed()
    graph.add_node("hypothesis", "H1", _claim())
    graph.add_node("hypothesis", "H2", {  # a legacy node in the same graph
        "title": "t", "target_asset": LOGIN, "rationale": "r",
        "cvss_vector": "", "cve": "", "tools": [], "confidence": 0.5})

    with get_purple_session(cfg) as session:
        save_graph(session, graph)
    with get_purple_session(cfg) as session:
        back = load_graph(session, "e-a11")

    nodes = {n["label"]: n["properties"] for n in back.by_type("hypothesis")}
    assert nodes["H1"]["related_assets"] == _claim()["related_assets"]
    assert nodes["H1"]["relationship"] == _claim()["relationship"]
    assert "related_assets" not in nodes["H2"]
    assert "relationship" not in nodes["H2"]


def test_the_memory_browser_serves_the_claim_already_redacted(cfg):
    """The browser reads the same properties dict; a secret-shaped span in a
    claim is replaced on the way into storage, so nothing new reaches the
    page."""
    from kryonsec.memory.data import load_engagement, scrub
    from kryonsec.purple.graph_store import save_graph
    from kryonsec.storage import get_purple_session, init_purple_db

    init_purple_db(cfg)
    graph = _observed()
    graph.add_node("hypothesis", "H1", _claim(
        related_assets=[{"asset": ADMIN,
                         "role": f"holds {AWS_EXAMPLE_KEY}"}],
        relationship=f"{LOGIN} and {ADMIN} share {AWS_EXAMPLE_KEY}"))
    with get_purple_session(cfg) as session:
        save_graph(session, graph)

    payload = load_engagement(cfg, "e-a11")
    node = next(n for n in payload["graph"]["nodes"]
                if n["node_type"] == "hypothesis")

    assert AWS_EXAMPLE_KEY not in json.dumps(payload)  # never reaches the page
    assert node["properties"]["related_assets"][0]["asset"] == ADMIN
    assert node["properties"]["relationship"].startswith(LOGIN)
    # the response-boundary scrub finds nothing left to do
    _, count = scrub(payload)
    assert count == 0
