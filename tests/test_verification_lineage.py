"""Phase 1C tests: verification statuses, lineage edges, and the
capability verification/approval separation."""

import json

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.capability import build_record
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.verify import VerifySubagent
from kryonsec.purple.views import (
    VERIFICATION_DISAGREED,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_NOT_RUN,
    VERIFICATION_VERIFIED,
    finding_verification_detail,
    finding_verification_status,
    hypothesis_engine_view,
    relationship_basis,
    verification_status,
)


def _events(audit):
    return [json.loads(l) for l in open(audit.path, encoding="utf-8")
            if l.strip()]


# ---- derived statuses (pure fixtures, no running) ---------------------------

def _attempt(**props):
    base = {"method": "curl boolean probe", "verified": False,
            "true_len": None, "false_len": None, "baseline_len": None}
    return {"properties": {**base, **props}}


def test_all_four_verification_statuses_derive():
    assert verification_status(_attempt(
        verified=True, true_len=100, false_len=0)) == VERIFICATION_VERIFIED
    assert verification_status(_attempt(
        verified=False, true_len=100, false_len=0,
        baseline_len=100)) == VERIFICATION_DISAGREED
    assert verification_status(_attempt(
        verified=False, true_len=100, false_len=100,
        baseline_len=None)) == VERIFICATION_INCONCLUSIVE
    # blocked: probes never returned responses, or nothing recorded at all
    assert verification_status(_attempt()) == VERIFICATION_NOT_RUN
    assert verification_status({"properties": {}}) == VERIFICATION_NOT_RUN
    assert verification_status({
        "properties": {"reason": "no numeric query parameter"}}) \
        == VERIFICATION_NOT_RUN
    # malformed node shape is not a run
    assert verification_status("not a node") == VERIFICATION_NOT_RUN


def test_tampered_stored_status_is_ignored():
    """A stored status word is producer convenience, never evidence: the
    derivation reads only the execution fields."""
    tampered = _attempt(verified=False, true_len=100, false_len=0,
                        baseline_len=100, status="verified")
    assert tampered["properties"]["status"] == "verified"  # the forge visible
    assert verification_status(tampered) == VERIFICATION_DISAGREED  # ignored

    # verified=True with NO probe responses behind it is not a run either
    assert verification_status(_attempt(verified=True)) \
        == VERIFICATION_NOT_RUN


def test_blocked_and_skipped_keep_their_reason():
    for reason in ("hypothesis asset outside engagement scope",
                   "no numeric query parameter",
                   "probe run failed"):
        detail = finding_verification_detail("H1", _graph_with(reason))
        assert detail["status"] == VERIFICATION_NOT_RUN
    assert finding_verification_detail(
        "H1", _graph_with("no numeric query parameter"))["block_reason"] \
        == "no numeric query parameter"


def _graph_with(reason):
    graph = EngagementGraph(engagement_id="e-r")
    graph.add_node("verify_attempt", "H1", {
        "verified": False, "method": "n/a", "reason": reason})
    return graph


def test_missing_independent_evidence_reads_not_run():
    """No verify_attempt at all — nothing was independently checked."""
    graph = EngagementGraph(engagement_id="e-r")
    graph.add_node("hypothesis", "H1", {"title": "t"})
    view = hypothesis_engine_view(
        {"label": "H1", "properties": {}}, graph)
    assert view["verification_status"] == VERIFICATION_NOT_RUN
    assert "unverified" in view["verification_note"]


def test_finding_status_strongest_record_wins():
    """A finding checked twice: the strongest status its records
    establish wins (verified over an earlier blocked pass)."""
    graph = EngagementGraph(engagement_id="e-r")
    graph.add_node("verify_attempt", "H1", {
        "verified": False, "method": "n/a", "reason": "probe run failed"})
    graph.add_node("verify_attempt", "H1", {
        "verified": True, "method": "curl boolean probe",
        "true_len": 100, "false_len": 50, "baseline_len": 100})
    assert finding_verification_status("H1", graph) == VERIFICATION_VERIFIED
    # a refused second finding unchanged: no records -> not_run
    assert finding_verification_status("H9", graph) == VERIFICATION_NOT_RUN


def test_basis_validated_requires_derived_verified():
    """The basis ladder reads the derived status, not the stored word."""
    graph = EngagementGraph(engagement_id="e-r")
    node = {"label": "H1", "properties": {}}
    graph.add_node("verify_attempt", "H1", _attempt(
        verified=True, true_len=100, false_len=5, baseline_len=100)[
        "properties"])
    assert relationship_basis(node, graph) == "validated"
    graph2 = EngagementGraph(engagement_id="e-r2")
    graph2.add_node("verify_attempt", "H1", {
        "verified": True,  # tampered: no responses behind it
    })
    assert relationship_basis(node, graph2) != "validated"


# ---- live verification flow: statuses + lineage edges -----------------------

def _is_probe(url):
    return "1%3D1" in url or "1%3D2" in url


def _finding_graph():
    graph = EngagementGraph(engagement_id="e-lv")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi on thread",
        "target_asset": "/showthread.asp?id=1",
        "rationale": "evidence", "cvss_vector": "",
        "tools": ["sqlmap"], "confidence": 0.8, "approved": True,
    })
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "ok": True, "exit_code": 0, "confirmed": True,
        "argv": ["sqlmap"], "output_excerpt": "is vulnerable",
    })
    graph.add_node("finding", "H1", {
        "tool": "sqlmap", "confirmed_by": "sandbox sqlmap output",
        "excerpt": "is vulnerable",
    })
    return graph


class _CannedSandbox:
    """true-probe / false-probe / baseline responses by URL shape."""

    def __init__(self, true_page, false_page, baseline_page):
        self.calls = []
        self._true, self._false = true_page, false_page
        self._baseline = baseline_page

    def spawn(self, argv):
        url = argv[-1]
        self.calls.append(url)
        if not _is_probe(url):
            return SpawnResult(ok=True, exit_code=0, stdout=self._baseline)
        is_true = "1%3D1" in url or "+AND+1%3D1" in url
        return SpawnResult(ok=True, exit_code=0,
                           stdout=self._true if is_true else self._false)


def test_live_verification_writes_lineage_edge_by_ids(tmp_path):
    """finding --verified_by--> verify_attempt, edges resolved by node
    ids and carrying provenance/properties."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()
    finding_before = graph.by_type("finding")[0]
    # true injection leaves the page unchanged, false injection changes it
    sandbox = _CannedSandbox("full page content", "no such thread",
                             "full page content")
    VerifySubagent(cfg, graph, audit, "target-corp.com", sandbox).run()

    edges = graph.find_edges("verified_by")
    assert len(edges) == 1
    e = edges[0]
    assert e["source_node_id"] == finding_before["id"]
    assert e["target_node_id"] == graph.by_type("verify_attempt")[0]["id"]
    assert e["properties"]["finding_id"] == "H1"
    assert e["provenance"] == {"agent": "VERIFY", "source_type": "tool"}
    assert verification_status(
        graph.by_type("verify_attempt")[0]) == VERIFICATION_VERIFIED
    # no audit shape changed — the old events still stand
    assert "finding_verified" in [x["event"] for x in _events(audit)]
    ok, reason = audit.verify()
    assert ok, reason


def test_not_run_attempt_is_still_linked_to_its_finding(tmp_path):
    """Lineage records WHICH check examined the finding, not that it
    succeeded — a `disagreed` attempt is already linked the same way. An
    unsupported category keeps its honest `not_run` AND the edge, so a
    report can walk finding -> attempt. Found by the real Phase-2 lab
    run (2026-11-19): a template_scan finding had its not_run attempt and
    no edge at all."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()
    # nuclei maps to template_scan, which has no registered contract
    graph.by_type("finding")[0]["properties"]["tool"] = "nuclei"
    sandbox = _CannedSandbox("a", "b", "a")
    VerifySubagent(cfg, graph, audit, "target-corp.com", sandbox).run()

    attempts = graph.by_type("verify_attempt")
    assert len(attempts) == 1
    assert verification_status(attempts[0]) == VERIFICATION_NOT_RUN
    edges = graph.find_edges("verified_by")
    assert len(edges) == 1
    assert edges[0]["source_node_id"] == graph.by_type("finding")[0]["id"]
    assert edges[0]["target_node_id"] == attempts[0]["id"]
    assert edges[0]["properties"]["finding_id"] == "H1"


def test_contradictory_check_reads_disagreed(tmp_path):
    """Every response identical (including the baseline): the boolean
    method ran its full course and contradicts the original finding."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()
    sandbox = _CannedSandbox("same page", "same page", "same page")
    VerifySubagent(cfg, graph, audit, "target-corp.com", sandbox).run()

    node = graph.by_type("verify_attempt")[0]
    assert node["properties"]["verified"] is False
    assert node["properties"]["baseline_len"] is not None
    assert verification_status(node) == VERIFICATION_DISAGREED
    assert finding_verification_status("H1", graph) == VERIFICATION_DISAGREED


def test_noise_without_baseline_reads_inconclusive(tmp_path):
    """ crawled fine but the true/false probes differ by noise only and
    no baseline exists — ran, cannot establish either conclusion."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class NoBaseline:
        def spawn(self, argv):
            url = argv[-1]
            if _is_probe(url):
                is_true = "1%3D1" in url or "+AND+1%3D1" in url
                # only 8 chars apart: below the noise threshold
                return SpawnResult(ok=True, exit_code=0,
                                   stdout="pageAA" if is_true else "pageBB")

            return SpawnResult(ok=False, exit_code=56, stdout="",
                               error="no baseline")  # baseline fetch fails

    VerifySubagent(cfg, graph, AuditLog(tmp_path / "a2.jsonl"),
                   "target-corp.com", NoBaseline()).run()
    node = graph.by_type("verify_attempt")[0]
    assert node["properties"]["baseline_len"] is None
    assert verification_status(node) == VERIFICATION_INCONCLUSIVE
    assert finding_verification_status("H1", graph) \
        == VERIFICATION_INCONCLUSIVE


def test_scope_refusal_keeps_reason_and_never_marks_disproven(tmp_path):
    """An out-of-scope finding: the check is refused with its reason —
    never read as disproven or safe."""
    graph = EngagementGraph(engagement_id="e-sr")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "asset off-scope",
        "target_asset": "http://evil.example.org/x?id=1",
        "rationale": "evidence", "cvss_vector": "",
        "tools": ["sqlmap"], "confidence": 0.8, "approved": True,
    })
    graph.add_node("finding", "H1", {"tool": "sqlmap", "excerpt": "x"})

    class NeverSpawn:
        def spawn(self, argv):  # pragma: no cover — must never happen
            raise AssertionError("host-side call attempted")

    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    VerifySubagent(cfg, graph, audit, "target-corp.com",
                   NeverSpawn()).run()

    node = graph.by_type("verify_attempt")[0]
    assert node["properties"]["status"] == VERIFICATION_NOT_RUN
    assert node["properties"]["reason"] == "asset outside engagement scope"
    assert finding_verification_status("H1", graph) == VERIFICATION_NOT_RUN
    # "verify" never lied and never touched the host: no tool_spawn events
    assert "tool_spawn" not in [x["event"] for x in _events(audit)]


def test_dead_sandbox_records_block_never_disproof(tmp_path):
    """ok=False spawns: sandbox/runtime failure — not_run with reason,
    no host fallback possible (the subagent only spawns via the sandbox
    it was given)."""
    graph = _finding_graph()

    class DeadSandbox:
        def spawn(self, argv):
            return SpawnResult(ok=False, exit_code=-1, stdout="",
                               error="curl failed")

    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    VerifySubagent(cfg, graph, audit, "target-corp.com", DeadSandbox()).run()

    node = graph.by_type("verify_attempt")[0]
    assert verification_status(node) == VERIFICATION_NOT_RUN
    assert node["properties"]["reason"] == "probe run failed"
    assert "verify_skipped" in [x["event"] for x in _events(audit)]


# ---- graph save/load + duplicate edges --------------------------------------

def test_lineage_edges_survive_save_load(tmp_path):
    graph = _finding_graph()
    finding = graph.by_type("finding")[0]
    attempt = graph.by_type("exploit_attempt")[0]
    from kryonsec.purple.lineage import link
    edge = link(graph, "verified_by", finding, attempt,
                provenance={"agent": "VERIFY", "source_type": "tool"},
                properties={"finding_id": "H1"})
    assert edge is not None

    reloaded = EngagementGraph.from_dict(graph.to_dict())
    assert len(reloaded.edges) == len(graph.edges) == 1
    e = reloaded.edges[0]
    assert e["id"] == edge["id"]
    assert e["source_node_id"] == finding["id"]
    assert e["target_node_id"] == attempt["id"]
    assert e["properties"]["finding_id"] == "H1"


def test_links_are_idempotent_and_refused_when_dangling():
    from kryonsec.purple.lineage import link

    graph = _finding_graph()
    finding = graph.by_type("finding")[0]
    attempt = next(n for n in graph.by_type("exploit_attempt")
                   if n["label"] == "H1:sqlmap")

    # first link creates, second returns the same edge (no duplicate).
    # Refs are node dicts/ids — anything else (a label) must not resolve.
    first = link(graph, "verified_by", finding, attempt,
                 provenance={"agent": "VERIFY", "source_type": "tool"})
    second = link(graph, "verified_by", finding, attempt)
    assert first["id"] == second["id"]
    assert first["provenance"] == {"agent": "VERIFY", "source_type": "tool"}
    assert second["provenance"] == first["provenance"]  # first wins, untouched
    assert len(graph.find_edges("verified_by")) == 1

    refused = []
    # a label that names nothing real can never become one end
    assert link(graph, "verified_by", finding, "H-missing",
                on_refuse=refused.append) is None
    assert refused and "not a node in engagement" in refused[0]
    # an unregistered relationship name is a programming error, refused
    assert link(graph, "magically_proves", finding, finding,
                on_refuse=refused.append) is None
    assert refused  # each refusal reached the caller for auditing
    assert len(graph.edges) == 1  # nothing bogus was stored


# ---- capability verification/approval separation schema ---------------------

def test_capability_schema_separates_verification_from_gate_status():
    record = build_record(
        capability="shell", tool="sqlmap", attempt_id="a",
        attempt_label="H1:sqlmap", hypothesis_id="H1",
        target_host="target-corp.com", finding_id="H1",
        evidence="os-shell session", status="claimed")
    # a claimed record is, by construction, not independently verified
    assert record.verification == "not_run"

    unknown = build_record(
        capability="shell", tool="t", attempt_id="a", attempt_label="l",
        hypothesis_id="h", target_host="t", evidence="e",
        status="approved", verification="yes")
    assert unknown is None  # verification is a validated vocabulary too
