"""A15 — the duplicate relation, narrowed where it was guessing.

Two things were fixed, and neither moves the loop:

* **D6 (conservative dedup).** A12's class table could say "different" or
  "unknown", and "unknown" lost to anything: a title naming no class the table
  knows merged into a title that named one, and REPORT then presented one kind
  of issue where the model had claimed two (A13's Log4Shell-into-SQLi case).
  An unreadable title is now its own item. Two unreadable titles still merge —
  that is legacy wording, and "neither title can be read" is not a
  disagreement.
* **D3 (Blue Team clarity).** Deduplication still runs in REPORT, after
  BLUE_TEAM. The prompt is instead told what the later merge will do, using the
  same relation the report acts on, and every hypothesis keeps its own id and
  its own evidence — nothing is suppressed for sharing a test.

Everything here is synthetic; nothing spawns a container or calls a model.
"""

from __future__ import annotations

import json
import re

import pytest

from kryonsec.purple.audit import AuditLog
from kryonsec.purple.blue_team import render_blue_team_prompt
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.report import (
    dedup_hypotheses,
    hypothesis_relations,
    mergeable,
    render_report,
    validate_report,
)

TARGET = "target-corp.com"
ASSET = "/ListProducts.asp?artist=1"


def _graph(*nodes) -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-a15")
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


def _kept_apart(audit: AuditLog) -> list[dict]:
    if not audit.path.exists():
        return []
    events = [json.loads(line) for line in
              audit.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [e for e in events if e["event"] == "hypotheses_kept_apart"]


# ---- 1. a class the table knows does not absorb a title it cannot read -------

def test_a_known_class_does_not_absorb_an_unreadable_title(tmp_path):
    """The D6 case end to end: SQLi and Log4Shell at one asset, one tool."""
    graph = _graph(
        _h("H1", title="SQL injection in the artist parameter"),
        _h("H2", title="Log4Shell in the artist parameter"),
    )
    audit = _audit(tmp_path)

    assert dedup_hypotheses(graph, audit) == 0
    assert [n["label"] for n in graph.by_type("hypothesis")] == ["H1", "H2"]

    report = render_report(graph, audit, "e-a15")
    assert "### H1 — SQL injection in the artist parameter" in report
    assert "### H2 — Log4Shell in the artist parameter" in report
    # Two items, and neither is a validation problem: the pair was left alone
    # on purpose, and the reason is on the chain.
    assert validate_report(report, graph) == []
    (event,) = _kept_apart(audit)
    assert event["kept_apart"] == [{
        "kept": "H2", "apart_from": "H1",
        "reason": "vulnerability class unclear on one side (sqli vs unknown)",
    }]


def test_the_rule_is_the_same_whichever_side_is_unreadable(tmp_path):
    """Order must not decide it — for either reading direction, and for every
    known class (the rule is about the *pair*, not about sqli)."""
    pairs = [
        ("SQL injection in the artist parameter", "Log4Shell in the artist parameter"),
        ("Stored XSS in the artist parameter", "a cache problem on the artist page"),
        ("Server-side request forgery via artist", "the artist page leaks something"),
    ]
    for known, unreadable in pairs:
        forward = _graph(_h("H1", title=known), _h("H2", title=unreadable))
        backward = _graph(_h("H1", title=unreadable), _h("H2", title=known))
        assert dedup_hypotheses(forward, _audit(tmp_path / "f")) == 0
        assert dedup_hypotheses(backward, _audit(tmp_path / "b")) == 0
        # and the relation itself is symmetric, not just the pass over it
        assert mergeable(*forward.by_type("hypothesis")) is False
        assert mergeable(*backward.by_type("hypothesis")) is False


@pytest.mark.parametrize("title", [
    None,            # a null from the model
    123,             # not a string at all
    "",              # empty
    "   ",           # whitespace only
    "\n\t\n",        # newlines only — normalises to nothing
])
def test_a_missing_or_malformed_title_is_not_merged_with_a_known_class(
        tmp_path, title):
    """No title means no class, whatever shape the "no" arrives in. Nothing
    here may crash REPORT, and nothing here may borrow the other claim's
    class."""
    graph = _graph(
        _h("H1", title="SQL injection in the artist parameter"),
        _h("H2", title=title),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0
    assert [n["label"] for n in graph.by_type("hypothesis")] == ["H1", "H2"]


def test_a_title_naming_two_classes_is_not_evidence_of_either(tmp_path):
    """The rule does not invent a class out of a partial textual match: a
    title naming both SQLi and RCE is neither, so it is not merged with a
    claim that names exactly one."""
    ambiguous = "SQL injection in the artist parameter leading to remote code execution"
    for known in ("SQL injection in the artist parameter",
                  "Remote code execution via the artist parameter"):
        graph = _graph(_h("H1", title=ambiguous), _h("H2", title=known))
        assert dedup_hypotheses(graph, _audit(tmp_path / known[:8])) == 0

    # symmetric, and the ambiguity itself is not treated as a class: two
    # identically-worded unreadable titles are still one claim, exactly like
    # two titles with no class word in them at all
    twice = _graph(_h("H1", title=ambiguous), _h("H2", title=ambiguous))
    assert dedup_hypotheses(twice, _audit(tmp_path / "same")) == 1


# ---- 2. what must NOT change ------------------------------------------------

def test_two_different_known_classes_stay_two(tmp_path):
    graph = _graph(
        _h("H1", title="SQL injection in the artist parameter"),
        _h("H2", title="Stored XSS in the artist parameter"),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0


@pytest.mark.parametrize("left,right", [
    ("SQL injection in the artist parameter", "Possible SQLi via the artist parameter"),
    ("Stored XSS in the artist parameter", "cross site scripting on artist parameter"),
    ("Path traversal in the artist parameter", "local file inclusion via artist"),
    ("Remote code execution via artist", "OS command injection in artist parameter"),
])
def test_one_class_worded_differently_is_still_one_claim(tmp_path, left, right):
    """The whole reason the key is not the title text: the model rewords the
    same idea between passes. A15 narrows the merge; it does not disable it."""
    graph = _graph(_h("H1", title=left), _h("H2", title=right))
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 1
    assert [n["label"] for n in graph.by_type("hypothesis")] == ["H1"]


def test_two_unreadable_titles_still_merge_as_they_always_did(tmp_path):
    """Legacy preservation: a node written before A11 has no title at all, and
    two of those are the same claim by the old key. Reading nothing on both
    sides is not a disagreement (A12 section 6)."""
    graph = EngagementGraph(engagement_id="e-a15-legacy")
    graph.add_node("hypothesis", "H1", {"tools": ["sqlmap"], "target_asset": TARGET})
    graph.add_node("hypothesis", "H2", {"tools": ["sqlmap"], "target_asset": TARGET})
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 1

    unreadable = _graph(
        _h("H1", title="Log4Shell in the artist parameter"),
        _h("H2", title="a cache problem on the artist page"),
    )
    assert dedup_hypotheses(unreadable, _audit(tmp_path / "u")) == 1


def test_empty_tools_and_an_empty_target_never_merge(tmp_path):
    """``((), "")`` identifies no test at all — not even when both titles name
    the same class. The degenerate guard is checked before the class rule, so
    it holds whatever the titles say."""
    graph = _graph(
        _h("H1", tools=[], target_asset=""),
        _h("H2", tools=[], target_asset=""),
        _h("H3", tools=[], target_asset="", title="Stored XSS in the artist parameter"),
    )
    assert dedup_hypotheses(graph, _audit(tmp_path)) == 0
    assert len(graph.by_type("hypothesis")) == 3

    # ...and with an empty tool set but a real asset, the asset still
    # identifies the test, so that pair is unchanged from Phase 6
    same_asset = _graph(
        _h("H1", tools=[]),
        _h("H2", tools=[], title="SQLi in artist parameter"),
    )
    assert dedup_hypotheses(same_asset, _audit(tmp_path / "a")) == 1


# ---- 3. determinism ---------------------------------------------------------

@pytest.mark.parametrize("left,right,expected", [
    ("SQL injection in the artist parameter",
     "SQLi in artist parameter", 1),
    ("SQL injection in the artist parameter",
     "Log4Shell in the artist parameter", 0),
    ("SQL injection in the artist parameter",
     "Stored XSS in the artist parameter", 0),
    ("Search page may reflect input",
     "the artist page leaks something", 1),
    ("SQL injection in the artist parameter",
     "SQL injection leading to remote code execution", 0),
])
def test_the_outcome_does_not_depend_on_the_order_the_pair_arrives(
        tmp_path, left, right, expected):
    """The relation is a property of the pair, so swapping the two nodes in the
    graph cannot change whether they merge — only, when they do merge, which
    of the two ids survives (insertion order, as documented)."""
    forward = _graph(_h("H1", title=left), _h("H2", title=right))
    backward = _graph(_h("H1", title=right), _h("H2", title=left))
    assert dedup_hypotheses(forward, _audit(tmp_path / "f")) == expected
    assert dedup_hypotheses(backward, _audit(tmp_path / "b")) == expected


def test_the_same_input_always_gives_the_same_answer(tmp_path):
    def run(tag):
        graph = _graph(
            _h("H1"),
            _h("H2", title="SQLi in artist parameter"),
            _h("H3", title="Log4Shell in the artist parameter"),
            _h("H4", title="Stored XSS in the artist parameter"),
            _h("H5", title="Log4Shell in the artist parameter"),
        )
        merged = dedup_hypotheses(graph, _audit(tmp_path / tag))
        return merged, [n["label"] for n in graph.by_type("hypothesis")]

    assert run("a") == run("b") == (2, ["H1", "H3", "H4"])
    # H5 merged into H3 (the other unreadable title), not into H1
    assert "H5" not in run("c")[1]


# ---- 4. Blue Team: duplicates are named, never suppressed -------------------

def test_the_prompt_names_a_duplicate_pair_and_keeps_both_entries(tmp_path):
    graph = _graph(_h("H1"), _h("H2", title="SQLi in artist parameter"))

    prompt = render_blue_team_prompt(graph)

    # both hypotheses reach the model with their own id, title and evidence
    assert "- H1: SQL injection in the artist parameter" in prompt
    assert "- H2: SQLi in artist parameter" in prompt
    assert "relation to the other entries: same test and same claim as H1" in prompt
    # rendering the prompt merges nothing — dedup still happens in REPORT
    assert len(graph.by_type("hypothesis")) == 2


def test_the_prompt_names_a_same_test_but_different_claim_pair(tmp_path):
    """The other half of "closely related": one tool, one asset, two issues.
    The model is told the report will keep them apart, so it writes two fixes
    rather than one that covers neither."""
    graph = _graph(_h("H1"), _h("H2", title="Stored XSS in the artist parameter"))

    prompt = render_blue_team_prompt(graph)

    assert ("relation to the other entries: same test as H1, but a different "
            "claim (different vulnerability class (sqli vs xss))") in prompt
    assert "- H2: Stored XSS in the artist parameter" in prompt


def test_no_hypothesis_is_dropped_for_sharing_a_test(tmp_path):
    graph = _graph(
        _h("H1"),
        _h("H2", title="SQLi in artist parameter"),          # duplicate of H1
        _h("H3", title="Stored XSS in the artist parameter"),  # same test, new claim
        _h("H4", tools=["ffuf"], target_asset="/search?q=1"),  # unrelated
    )

    prompt = render_blue_team_prompt(graph)

    for hid in ("H1", "H2", "H3", "H4"):
        assert prompt.count(f"- {hid}: ") == 1
    assert len(graph.by_type("hypothesis")) == 4
    assert "relation to the other entries: " in prompt
    # the unrelated one stands alone and says nothing about a relation
    assert re.search(r"- H4: [^\n]*\n  target: [^\n]*\n  approved by operator",
                     prompt)


def test_a_lone_hypothesis_gets_no_relation_note():
    prompt = render_blue_team_prompt(_graph(_h("H1")))
    assert "relation to the other entries: " not in prompt


def test_what_the_prompt_promises_is_what_the_report_does(tmp_path):
    """D3's whole point: the note is read off the same relation REPORT acts on,
    so the pair the model is told is one issue is the pair that gets merged —
    and the title it was told would be kept really is kept."""
    graph = _graph(_h("H1"), _h("H2", title="SQLi in artist parameter"))
    prompt = render_blue_team_prompt(graph)
    survivor = re.search(r"same test and same claim as (H\d+)", prompt)
    assert survivor and survivor.group(1) == "H1"

    aliases, kept_apart = hypothesis_relations(graph.by_type("hypothesis"))
    assert (aliases, kept_apart) == ({"H2": "H1"}, [])

    audit = _audit(tmp_path)
    assert dedup_hypotheses(graph, audit) == 1
    assert [n["label"] for n in graph.by_type("hypothesis")] == ["H1"]
    report = render_report(graph, audit, "e-a15")
    assert "folded these into this item" in report
    assert "SQLi in artist parameter" in report


def test_the_prompt_says_nothing_about_a_merge_that_will_not_happen(tmp_path):
    """A pair kept apart must not be announced as one issue anywhere in the
    prompt — the model would then write one fix for two issues."""
    graph = _graph(_h("H1"), _h("H2", title="Stored XSS in the artist parameter"))
    prompt = render_blue_team_prompt(graph)
    assert "same test and same claim" not in prompt
    # dedup agrees: nothing to merge, and the keep-apart is on the chain
    audit = _audit(tmp_path)
    assert dedup_hypotheses(graph, audit) == 0
    assert len(graph.by_type("hypothesis")) == 2
    assert _kept_apart(audit)
