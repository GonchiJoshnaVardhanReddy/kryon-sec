"""Batch 5C: evidence quality, counterevidence, and honest `unresolved`.

What these tests lock down:
- the executor RECORDS counterevidence it observed and never silently
  discards it — a rotation-explained "agreement" does not promote;
- a verdict with standing counterevidence reads ``unresolved`` — the
  question is left open, never settled either way by a word;
- the quality review (Strix/Shannon-style checks) annotates the
  derived status from the record's own fields: ran, reachability,
  baseline control, independence, conclusion-strength-vs-observations;
- quality analysis is annotation, never a promotion path: the status
  derivation stays authoritative, stored words stay ignored;
- counterevidence travels to the read views verbatim.
"""

import json

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.evidence_quality import (
    CHECK_FAILED,
    CHECK_NA,
    CHECK_OK,
    QUALITY_CONTESTED,
    QUALITY_CONTRADICTED,
    QUALITY_NONE,
    QUALITY_REACHABILITY,
    QUALITY_SUPPORTED,
    QUALITY_WEAK,
    evidence_quality,
)
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.verify import VerifySubagent
from kryonsec.purple.views import (
    VERIFICATION_DISAGREED,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_NOT_RUN,
    VERIFICATION_UNRESOLVED,
    VERIFICATION_VERIFIED,
    finding_verification_detail,
    finding_verification_status,
    verification_status,
)


def _events(audit):
    return [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8")
            if l.strip()]


def _entries(audit):
    return [json.loads(l) for l in open(audit.path, encoding="utf-8")
            if l.strip()]


def _is_probe(url):
    return "1%3D1" in url or "1%3D2" in url


def _finding_graph(tool="sqlmap", asset="/showthread.asp?id=1"):
    graph = EngagementGraph(engagement_id="e-v")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi on thread", "target_asset": asset,
        "rationale": "evidence", "cvss_vector": "",
        "tools": [tool], "confidence": 0.8, "approved": True,
    })
    graph.add_node("exploit_attempt", f"H1:{tool}", {
        "tool": tool, "ok": True, "exit_code": 0, "confirmed": True,
        "argv": [tool], "output_excerpt": "is vulnerable",
    })
    graph.add_node("finding", "H1", {
        "tool": tool, "confirmed_by": f"sandbox {tool} output",
        "excerpt": "is vulnerable",
    })
    return graph


class DiffSandbox:
    """true == baseline(1 and 2), false differs: the clean signature."""

    def __init__(self):
        self.calls = []

    def spawn(self, argv):
        url = argv[-1]
        self.calls.append(url)
        if not _is_probe(url):
            return SpawnResult(ok=True, exit_code=0, stdout="full page")
        is_true = "1%3D1" in url or "+AND+1%3D1" in url
        return SpawnResult(
            ok=True, exit_code=0,
            stdout="full page" if is_true else "empty result")


def _verify(tmp_path, sandbox, graph=None):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = graph or _finding_graph()
    VerifySubagent(cfg, graph, audit, "target-corp.com", sandbox).run()
    return graph, audit


# ---- counterevidence gathering: rotation -----------------------------------

class RotatingBaselineSandbox:
    """The false-positive case: true matches the FIRST baseline and false
    differs — but the baseline itself moves between requests. The observed
    difference may be rotation, not the injected boolean."""

    def __init__(self):
        self.n = 0

    def spawn(self, argv):
        url = argv[-1]
        self.n += 1
        if not _is_probe(url):
            # call 3 = first baseline, call 4 = confirmation: it moves
            page = "page A" if self.n <= 3 else f"page B-{self.n}"
            return SpawnResult(ok=True, exit_code=0, stdout=page)
        is_true = "1%3D1" in url or "+AND+1%3D1" in url
        return SpawnResult(
            ok=True, exit_code=0,
            stdout="page A" if is_true else "page B-false")


def test_rotation_records_counterevidence_and_does_not_promote(tmp_path):
    graph, audit = _verify(tmp_path, RotatingBaselineSandbox())

    props = graph.by_type("verify_attempt")[0]["properties"]
    # the raw boolean observation is still recorded (true matched the
    # first baseline, false differed)...
    assert props["verified"] is True
    # ...but the check observed the benign explanation and RECORDED it
    assert props["baseline2_len"] is not None
    assert props["counterevidence"], "counterevidence must be recorded"
    assert "rotat" in props["counterevidence"][0]
    # the derived status refuses promotion: unresolved, not verified
    assert verification_status(graph.by_type("verify_attempt")[0]) \
        == VERIFICATION_UNRESOLVED
    # the finding is NOT promoted — no verified word, no promotion event
    assert graph.by_type("finding")[0]["properties"].get("verified") \
        is not True
    assert "finding_verified" not in _events(audit)
    assert "finding_verification_failed" in _events(audit)
    ok, reason = audit.verify()
    assert ok, reason


def test_rotation_reads_unresolved_in_the_detail_view(tmp_path):
    """The read view carries the counterevidence verbatim — recorded,
    never discarded."""
    graph, _ = _verify(tmp_path, RotatingBaselineSandbox())

    detail = finding_verification_detail("H1", graph)
    assert detail["status"] == VERIFICATION_UNRESOLVED
    assert detail["counterevidence"]
    assert "rotat" in detail["counterevidence"][0]


def test_clean_verification_has_no_counterevidence_and_promotes(tmp_path):
    graph, audit = _verify(tmp_path, DiffSandbox())

    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["verified"] is True
    assert props["counterevidence"] == []
    assert props["baseline2_len"] is not None  # the confirmation fetch ran
    assert verification_status(graph.by_type("verify_attempt")[0]) \
        == VERIFICATION_VERIFIED
    assert graph.by_type("finding")[0]["properties"]["verified"] is True
    assert "finding_verified" in _events(audit)


# ---- counterevidence on the other outcomes ---------------------------------

class SameSandbox:
    def spawn(self, argv):
        return SpawnResult(ok=True, exit_code=0, stdout="same page")


def test_disagreement_records_the_contradiction(tmp_path):
    """A disagreed check records WHY: the injected boolean was not
    executed as SQL. Recorded — not discarded, not softened."""
    graph, _ = _verify(tmp_path, SameSandbox())

    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["verified"] is False
    assert props["counterevidence"]
    assert "not executed as SQL" in props["counterevidence"][0]
    assert verification_status(graph.by_type("verify_attempt")[0]) \
        == VERIFICATION_DISAGREED


class BaselineDeadSandbox:
    """Probes work; the baseline fetch fails (empty result). The two
    probe responses differ substantially (200 vs 1 chars)."""

    def spawn(self, argv):
        if _is_probe(argv[-1]):
            is_true = "1%3D1" in argv[-1] or "+AND+1%3D1" in argv[-1]
            return SpawnResult(
                ok=True, exit_code=0,
                stdout="p" * 200 if is_true else "q")
        return SpawnResult(ok=False, exit_code=1, stdout="",
                           error="baseline fetch failed")


def test_no_baseline_records_the_weakness(tmp_path):
    """Without a baseline, a difference proves nothing — the executor
    records that weakness as counterevidence and reads UNRESOLVED: the
    difference was seen, but dynamic content could explain it. This
    closes the old hole where a baseline-less difference read verified."""
    graph, audit = _verify(tmp_path, BaselineDeadSandbox())
    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["verified"] is True   # a substantial difference was seen
    assert props["baseline_len"] is None
    assert props["counterevidence"]
    assert "no baseline" in props["counterevidence"][0]
    assert verification_status(graph.by_type("verify_attempt")[0]) \
        == VERIFICATION_UNRESOLVED
    assert graph.by_type("finding")[0]["properties"].get("verified") \
        is not True
    assert "finding_verified" not in _events(audit)


class NoisyNoBaselineSandbox:
    """A difference too small to distinguish from noise, and no
    baseline: ran, cannot establish either conclusion."""

    def spawn(self, argv):
        if _is_probe(argv[-1]):
            is_true = "1%3D1" in argv[-1] or "+AND+1%3D1" in argv[-1]
            return SpawnResult(
                ok=True, exit_code=0,
                stdout="page-aaaa" if is_true else "page-ab")
        return SpawnResult(ok=False, exit_code=1, stdout="",
                           error="baseline fetch failed")


def test_inconclusive_reads_weak_quality_with_derived_counterevidence(tmp_path):
    graph, _ = _verify(tmp_path, NoisyNoBaselineSandbox())

    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["verified"] is False
    assert props["baseline_len"] is None
    assert props["counterevidence"] == []  # executor recorded nothing
    assert verification_status(graph.by_type("verify_attempt")[0]) \
        == VERIFICATION_INCONCLUSIVE

    q = evidence_quality(graph.by_type("verify_attempt")[0],
                         finding_tool="sqlmap")
    assert q.status == VERIFICATION_INCONCLUSIVE
    assert q.strength == QUALITY_WEAK
    # the quality review DERIVES the honest counterevidence the record
    # implies: without a baseline, the noise explanation stands
    assert any("dynamic content" in c for c in q.counterevidence)


# ---- the read-time derivation rule ------------------------------------------

def _node(**props):
    base = {"method": "curl boolean probe", "verified": True,
            "true_len": 100, "false_len": 50, "baseline_len": 100,
            "status": "verified"}
    base.update(props)
    return {"type": "verify_attempt", "label": "H1", "properties": base}


def test_hand_built_verified_with_counterevidence_reads_unresolved():
    node = _node(counterevidence=["content rotates between requests"])
    assert verification_status(node) == VERIFICATION_UNRESOLVED


def test_hand_built_verified_without_responses_never_reads_verified():
    node = {"type": "verify_attempt", "label": "H1",
            "properties": {"verified": True, "status": "verified"}}
    assert verification_status(node) == VERIFICATION_NOT_RUN


def test_counterevidence_field_of_wrong_shape_reads_empty():
    node = _node(counterevidence="totally verified, trust me")
    assert verification_status(node) == VERIFICATION_VERIFIED


def test_status_ordering_across_attempts():
    """Strongest status wins: a real conclusion beats a contested one,
    a contested one beats an open one."""
    from kryonsec.purple.views import _VERIFICATION_ORDER
    assert _VERIFICATION_ORDER.index(VERIFICATION_NOT_RUN) \
        < _VERIFICATION_ORDER.index(VERIFICATION_INCONCLUSIVE) \
        < _VERIFICATION_ORDER.index(VERIFICATION_UNRESOLVED) \
        < _VERIFICATION_ORDER.index(VERIFICATION_DISAGREED) \
        < _VERIFICATION_ORDER.index(VERIFICATION_VERIFIED)


def test_finding_level_status_prefers_conclusions_over_contested(tmp_path):
    graph = _finding_graph()
    graph.add_node("verify_attempt", "H1", {
        "verified": True, "true_len": 10, "false_len": 20,
        "baseline_len": 10, "status": "verified",
        "counterevidence": ["content rotates between requests"],
    })
    assert finding_verification_status("H1", graph) \
        == VERIFICATION_UNRESOLVED
    graph.add_node("verify_attempt", "H1", {
        "verified": False, "true_len": 10, "false_len": 10,
        "baseline_len": 10, "status": "disagreed",
    })
    assert finding_verification_status("H1", graph) == VERIFICATION_DISAGREED


# ---- the quality review ------------------------------------------------------

def test_quality_of_a_clean_verified_attempt(tmp_path):
    graph, _ = _verify(tmp_path, DiffSandbox())
    node = graph.by_type("verify_attempt")[0]

    q = evidence_quality(node, finding_tool="sqlmap")
    assert q.status == VERIFICATION_VERIFIED
    assert q.strength == QUALITY_SUPPORTED
    by_name = {c.name: c for c in q.checks}
    assert by_name["ran"].result == CHECK_OK
    assert by_name["reachability"].result == CHECK_OK
    assert by_name["baseline_control"].result == CHECK_OK
    assert "confirmation" in by_name["baseline_control"].detail
    assert by_name["independence"].result == CHECK_OK
    assert "sqlmap" in by_name["independence"].detail
    assert by_name["conclusion_matches_observations"].result == CHECK_OK
    assert q.counterevidence == ()
    # the print shape is complete
    d = q.detail()
    assert d["status"] == "verified" and d["strength"] == "supported"
    assert len(d["checks"]) == 5


def test_quality_of_the_contested_attempt(tmp_path):
    graph, _ = _verify(tmp_path, RotatingBaselineSandbox())
    node = graph.by_type("verify_attempt")[0]

    q = evidence_quality(node, finding_tool="sqlmap")
    assert q.status == VERIFICATION_UNRESOLVED
    assert q.strength == QUALITY_CONTESTED
    by_name = {c.name: c for c in q.checks}
    assert by_name["baseline_control"].result == CHECK_FAILED
    assert "rotat" in by_name["baseline_control"].detail
    # counterevidence carried verbatim, never discarded
    assert q.counterevidence
    assert any("rotat" in c for c in q.counterevidence)


def test_quality_of_a_disagreed_attempt(tmp_path):
    graph, _ = _verify(tmp_path, SameSandbox())
    q = evidence_quality(graph.by_type("verify_attempt")[0],
                         finding_tool="sqlmap")
    assert q.status == VERIFICATION_DISAGREED
    assert q.strength == QUALITY_CONTRADICTED
    assert q.counterevidence


def test_quality_of_an_inconclusive_attempt():
    node = {"type": "verify_attempt", "label": "H1", "properties": {
        "verified": False, "true_len": 8, "false_len": 7,
        "baseline_len": None, "status": "inconclusive",
        "method": "curl boolean probe",
        "contract": {"tool": "curl", "method": "m"},
    }}
    q = evidence_quality(node, finding_tool="sqlmap")
    assert q.status == VERIFICATION_INCONCLUSIVE
    assert q.strength == QUALITY_WEAK
    by_name = {c.name: c for c in q.checks}
    assert by_name["ran"].result == CHECK_OK
    assert by_name["baseline_control"].result == CHECK_FAILED
    # derived counterevidence: without a baseline, the noise explanation
    # stands — carried into the record's review verbatim
    assert any("dynamic content" in c for c in q.counterevidence)


def test_quality_flags_a_stored_word_the_evidence_does_not_support():
    node = _node(counterevidence=["content rotates between requests"],
                 status="verified")
    q = evidence_quality(node)
    by_name = {c.name: c for c in q.checks}
    assert by_name["conclusion_matches_observations"].result == CHECK_FAILED
    assert "ignored" in by_name["conclusion_matches_observations"].detail
    # and the annotated status is the derivation's, not the stored word's
    assert q.status == VERIFICATION_UNRESOLVED


def test_quality_of_a_never_ran_attempt_reads_reachability_only():
    node = {"type": "verify_attempt", "label": "H1", "properties": {
        "verified": False, "method": "n/a", "status": "not_run",
        "reason": "no numeric query parameter",
        "secondary_evidence": {"http": "ok", "nc": "ok", "dig": "ok"},
    }}
    q = evidence_quality(node)
    assert q.status == VERIFICATION_NOT_RUN
    assert q.strength == QUALITY_REACHABILITY
    by_name = {c.name: c for c in q.checks}
    assert by_name["ran"].result == CHECK_FAILED
    assert by_name["reachability"].result == CHECK_OK
    assert "reachability only" in by_name["reachability"].detail
    assert by_name["baseline_control"].result == CHECK_NA
    # honest: no independent evidence either way
    assert any("never ran" in c for c in q.counterevidence)


def test_quality_of_an_out_of_scope_refusal(tmp_path):
    """A scope refusal keeps its boundary: probing would have violated
    the engagement scope, so reachability is inapplicable, not failed."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-v")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi elsewhere", "target_asset":
            "https://other-host.example.com/x?id=1",
        "rationale": "evidence", "cvss_vector": "",
        "tools": ["sqlmap"], "confidence": 0.8, "approved": True,
    })
    graph.add_node("finding", "H1", {
        "tool": "sqlmap", "confirmed_by": "sandbox sqlmap output",
        "excerpt": "is vulnerable",
    })

    class NeverSpawn:
        def spawn(self, argv):  # pragma: no cover — must never happen
            raise AssertionError("spawn attempted")

    VerifySubagent(cfg, graph, audit, "target-corp.com", NeverSpawn()).run()

    q = evidence_quality(graph.by_type("verify_attempt")[0],
                         finding_tool="sqlmap")
    assert q.strength == QUALITY_NONE
    by_name = {c.name: c for c in q.checks}
    assert by_name["reachability"].result == CHECK_NA
    assert "outside engagement scope" in by_name["reachability"].detail


def test_quality_flags_a_repeat_as_not_independent():
    node = {"type": "verify_attempt", "label": "H1", "properties": {
        "verified": True, "true_len": 10, "false_len": 20,
        "baseline_len": 10, "status": "verified",
        "contract": {"tool": "sqlmap", "method": "m"},
    }}
    q = evidence_quality(node, finding_tool="sqlmap")
    by_name = {c.name: c for c in q.checks}
    assert by_name["independence"].result == CHECK_FAILED
    assert "repeat" in by_name["independence"].detail


def test_quality_without_the_finding_tool_is_inapplicable_not_failed():
    node = {"type": "verify_attempt", "label": "H1", "properties": {
        "verified": True, "true_len": 10, "false_len": 20,
        "baseline_len": 10, "status": "verified",
        "contract": {"tool": "curl", "method": "m"},
    }}
    q = evidence_quality(node)
    by_name = {c.name: c for c in q.checks}
    assert by_name["independence"].result == CHECK_NA


def test_quality_of_a_node_without_properties():
    q = evidence_quality({"type": "verify_attempt", "label": "H1"})
    assert q.status == VERIFICATION_NOT_RUN
    assert q.strength == QUALITY_NONE
    # honest even at the bottom: no evidence either way
    assert any("never ran" in c for c in q.counterevidence)
