"""Batch 5D: the verification_support specialist — evidence analysis only.

What these tests lock down:
- the specialist READS the VERIFY state's records
  (finding_verification_detail + evidence_quality) and files an honest
  deliverable: the DERIVED standing, the counterevidence verbatim, the
  deterministic unresolved questions;
- it never probes: no sandbox spawn, no tool_spawn events — the probes
  stay with the VERIFY subagent and its registered contract; a
  specialist that could probe would be a second, uncontracted path to
  target contact;
- no model text can move the standing: a finding whose properties
  shout ``verified`` with no attempt records reads ``not_run``;
- tasks are derived only from registered read-only
  ``verification_analysis`` records at the VERIFY boundary, capped and
  identity-deduped, and survive checkpoint/resume like every other
  read-only specialist task.
"""

import json
import uuid
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.coordinator import HandoffCoordinator
from kryonsec.purple.handoff import (
    TASK_TYPES,
    TaskAssignment,
    new_message_id,
    task_safety,
)
from kryonsec.purple.orchestrator import BudgetTracker
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.runner import (
    checkpoint_handoffs,
    persist_handoffs,
    resume_specialists,
)
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.specialist import (
    EXECUTORS,
    SPECIALIST_ROLES,
    SpecialistScheduler,
    SpecialistTask,
    role_of,
)
from kryonsec.storage import get_purple_session, init_purple_db, reset_engine
from kryonsec.purple.verify import VerifySubagent
from kryonsec.purple.handoff_store import load_handoffs, load_scheduler_payload

ENGAGEMENT = "e-vs"


def _scratch_audit(name: str | None = None) -> AuditLog:
    return AuditLog(
        Path("/tmp") / f"vsupport-audit-{name or uuid.uuid4().hex[:10]}.jsonl")


def _events(audit: AuditLog) -> list[dict]:
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _only(events: list[dict], name: str) -> list[dict]:
    return [e for e in events if e.get("event") == name]


def _is_probe(url: str) -> bool:
    return "1%3D1" in url or "1%3D2" in url


class DiffSandbox:
    """The clean signature: true == baseline, false differs."""

    def spawn(self, argv):
        url = argv[-1]
        if not _is_probe(url):
            return SpawnResult(ok=True, exit_code=0, stdout="full page")
        is_true = "1%3D1" in url or "+AND+1%3D1" in url
        return SpawnResult(
            ok=True, exit_code=0,
            stdout="full page" if is_true else "empty result")


class RotatingBaselineSandbox:
    """The contested signature: the baseline itself moves."""

    def __init__(self):
        self.n = 0

    def spawn(self, argv):
        url = argv[-1]
        self.n += 1
        if not _is_probe(url):
            page = "page A" if self.n <= 3 else f"page B-{self.n}"
            return SpawnResult(ok=True, exit_code=0, stdout=page)
        is_true = "1%3D1" in url or "+AND+1%3D1" in url
        return SpawnResult(
            ok=True, exit_code=0,
            stdout="page A" if is_true else "page B-false")


def _finding_graph(engagement: str = ENGAGEMENT, tool: str = "sqlmap",
                   asset: str = "/showthread.asp?id=1",
                   labels: "tuple[str, ...]" = ("H1",)) -> EngagementGraph:
    """Target + one hypothesis/exploit-attempt/finding triple per label."""
    graph = EngagementGraph(engagement_id=engagement)
    graph.add_node("target", "target-corp.com", {})
    for label in labels:
        graph.add_node("hypothesis", label, {
            "title": f"SQLi on thread {label}", "target_asset": asset,
            "rationale": "evidence", "cvss_vector": "",
            "tools": [tool], "confidence": 0.8, "approved": True,
        })
        graph.add_node("exploit_attempt", f"{label}:{tool}", {
            "tool": tool, "ok": True, "exit_code": 0, "confirmed": True,
            "argv": [tool], "output_excerpt": "is vulnerable",
        })
        graph.add_node("finding", label, {
            "tool": tool, "confirmed_by": f"sandbox {tool} output",
            "excerpt": "is vulnerable",
        })
    return graph


def _graph_with_verification(engagement: str = ENGAGEMENT,
                             sandbox: object | None = None,
                             tool: str = "sqlmap",
                             labels: "tuple[str, ...]" = ("H1",),
                             ) -> EngagementGraph:
    """A graph whose findings have REAL verify_attempt records, produced
    by running the VERIFY subagent against the given sandbox fake."""
    graph = _finding_graph(engagement, tool=tool, labels=labels)
    audit = _scratch_audit()
    VerifySubagent(
        KryonsecConfig(home=Path("/tmp") / f"vs-{uuid.uuid4().hex[:8]}"),
        graph, audit, "target-corp.com",
        sandbox if sandbox is not None else DiffSandbox(),
    ).run()
    return graph


def _assignment(engagement: str = ENGAGEMENT, **kw) -> TaskAssignment:
    base = dict(
        engagement_id=engagement,
        message_id=new_message_id(),
        source="VERIFY",
        destination="specialist",
        task_type="verification_analysis",
        subject_ref="H1",
        content="analyze the verification records for H1",
    )
    base.update(kw)
    return TaskAssignment(**base)


def _coordinator(engagement: str = ENGAGEMENT,
                 graph: EngagementGraph | None = None,
                 audit: AuditLog | None = None) -> HandoffCoordinator:
    return HandoffCoordinator(
        engagement_id=engagement,
        graph=graph if graph is not None else _finding_graph(engagement),
        audit=audit if audit is not None else _scratch_audit(),
    )


def _scheduler(coordinator: HandoffCoordinator, audit: AuditLog,
               budget: BudgetTracker | None = None) -> SpecialistScheduler:
    return SpecialistScheduler(coordinator, audit, budget=budget)


def _submit_task(scheduler: SpecialistScheduler, task_id: str,
                 stage: str = "VERIFY") -> SpecialistTask:
    task = SpecialistTask(
        engagement_id=scheduler.coordinator.engagement_id,
        task_id=task_id, role="verification_support", stage=stage)
    scheduler.submit(task)
    return task


# ---- the role and its boundary ------------------------------------------------

def test_the_role_is_read_only_evidence_analysis():
    role = role_of("verification_support")
    assert role.task_type == "verification_analysis"
    assert task_safety(role.task_type) == "read_only"
    assert role.stages == {"VERIFY"}
    assert role.executor == "verification_support"
    assert role.llm is False
    assert "verification_analysis" in TASK_TYPES
    assert TASK_TYPES["verification_analysis"] == "read_only"
    assert EXECUTORS["verification_support"] is not None


def test_the_executor_never_probes_and_never_spawns():
    """The hard boundary: a specialist that could probe would be a
    second, uncontracted path to target contact."""
    graph = _finding_graph()
    coord = _coordinator(graph=graph)
    audit = _scratch_audit()

    class ExplodesIfSpawned:
        def spawn(self, argv):  # pragma: no cover — must never happen
            raise AssertionError("the specialist spawned a tool")

    budget = BudgetTracker(max_tokens=100_000)
    scheduler = _scheduler(coord, audit, budget=budget)
    task_id = coord.register(_assignment()).record.message_id
    _submit_task(scheduler, task_id)
    scheduler.run_ready("VERIFY")

    events = [e["event"] for e in _events(audit)]
    assert "tool_spawn" not in events
    ok, reason = audit.verify()
    assert ok, reason


# ---- the analysis ----------------------------------------------------------

def test_a_verified_finding_reads_verified(tmp_path):
    graph = _graph_with_verification(sandbox=DiffSandbox())
    coord = _coordinator(graph=graph)
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment()).record.message_id
    _submit_task(scheduler, task_id)

    summary = scheduler.run_ready("VERIFY")
    assert summary["ran"] == 1

    task = scheduler.get(task_id)
    assert task.deliverable["status"] == "completed"
    assert task.deliverable["standing"] == "verified"
    assert any("independent test ran and agreed" in c["note"]
               for c in task.deliverable["claims"])
    # the limitation is the honest boundary, on the record
    assert any("runs no probe" in line
               for line in task.deliverable["limitations"])


def test_counterevidence_is_carried_verbatim_never_discarded(tmp_path):
    graph = _graph_with_verification(sandbox=RotatingBaselineSandbox())
    coord = _coordinator(graph=graph)
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment()).record.message_id
    _submit_task(scheduler, task_id)
    scheduler.run_ready("VERIFY")

    task = scheduler.get(task_id)
    d = task.deliverable
    assert d["standing"] == "unresolved"
    ce_claims = [c for c in d["claims"] if "counterevidence" in c["note"]]
    assert ce_claims and any("rotat" in c["note"] for c in ce_claims)
    # the failed quality check becomes a deterministic open question
    assert any("baseline_control" in q for q in d["unresolved"])


def test_a_never_ran_finding_reads_not_run_with_its_block_reason(tmp_path):
    """A nikto finding (no verification contract for web_scan) keeps its
    honest not_run standing and its real blocking reason."""
    graph = _graph_with_verification(sandbox=DiffSandbox(), tool="nikto")
    coord = _coordinator(graph=graph)
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment()).record.message_id
    _submit_task(scheduler, task_id)
    scheduler.run_ready("VERIFY")

    task = scheduler.get(task_id)
    d = task.deliverable
    assert d["standing"] == "not_run"
    assert any("never ran" in q for q in d["unresolved"])
    assert any("reachability" in c["note"] for c in d["claims"])


def test_model_text_cannot_move_the_standing():
    """A finding whose properties shout verified, with no attempt
    records, reads not_run — the derivation is the only basis."""
    graph = _finding_graph()
    graph.by_type("finding")[0]["properties"].update({
        "verified": True, "status": "verified",
        "confirmed_by": "trust me, totally verified",
    })
    coord = _coordinator(graph=graph)
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment()).record.message_id
    _submit_task(scheduler, task_id)
    scheduler.run_ready("VERIFY")

    task = scheduler.get(task_id)
    assert task.deliverable["standing"] == "not_run"
    assert any("never ran" in q for q in task.deliverable["unresolved"])


def test_missing_finding_is_blocked_not_completed():
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(
        _assignment(subject_ref="H-GONE")).record.message_id
    _submit_task(scheduler, task_id)
    summary = scheduler.run_ready("VERIFY")
    assert summary["ran"] == 1
    record = coord.get(task_id)
    assert record.status == "blocked"          # never a fake "completed"
    task = scheduler.get(task_id)
    assert task.deliverable["status"] == "blocked"
    assert task.deliverable["standing"] == "unresolved"
    assert "no finding" in task.outcome_note


# ---- derivation: the VERIFY boundary's own records ----------------------------

def test_derivation_schedules_each_analysis_assignment():
    coord = _coordinator(graph=_graph_with_verification())
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    first = coord.register(_assignment(subject_ref="H1")).record.message_id
    second = coord.register(_assignment(subject_ref="H2")).record.message_id

    assert scheduler.derive_from_records("VERIFY") == 2
    assert sorted(t.task_id for t in scheduler.tasks()) == sorted(
        [first, second])
    assert all(t.role == "verification_support" for t in scheduler.tasks())
    assert all(t.stage == "VERIFY" for t in scheduler.tasks())
    # identity dedup: the same boundary again derives nothing new
    assert scheduler.derive_from_records("VERIFY") == 0


def test_derivation_refuses_other_states_and_other_types():
    coord = _coordinator(graph=_graph_with_verification())
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    # each type derives at ITS OWN boundary only
    coord.register(_assignment(content="verification analysis"))
    coord.register(_assignment(
        task_type="evidence_assessment", source="HYPOTHESIZE",
        content="hypothesis assessment"))
    at_verify = scheduler.derive_from_records("VERIFY")
    assert at_verify == 1
    assert [t.role for t in scheduler.tasks()] == ["verification_support"]
    at_hyp = scheduler.derive_from_records("HYPOTHESIZE")
    assert at_hyp == 1
    assert sorted(t.role for t in scheduler.tasks()) == [
        "evidence_assessment", "verification_support"]


def test_derivation_is_capped_at_twelve():
    coord = _coordinator(graph=_graph_with_verification())
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    for i in range(1, 14):
        coord.register(_assignment(subject_ref=f"H{i}"))
    created = scheduler.derive_from_records("VERIFY")
    assert created == 12
    assert any(e["event"] == "specialist_derivation_capped"
               for e in _events(audit))


def test_proposal_path_accepts_the_read_only_analysis():
    """verification_analysis is read-only: a proposal for it schedules.
    verify_check stays state-changing: a proposal for it is refused."""
    coord = _coordinator(graph=_graph_with_verification())
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)

    decision = scheduler.submit_proposal(
        "verification_analysis", subject_ref="H1",
        source="VERIFY", content="analyze the records")
    assert decision.record is not None
    assert [t.role for t in scheduler.tasks()] == ["verification_support"]

    from kryonsec.purple.specialist import SpecialistError
    with pytest.raises(SpecialistError):
        scheduler.submit_proposal(
            "verify_check", subject_ref="H1",
            source="VERIFY", content="state-changing work")


# ---- persistence and recovery --------------------------------------------------

@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = None
    yield config
    reset_engine()


def test_checkpoint_writes_the_verification_support_task(cfg):
    audit = _scratch_audit()
    coord = _coordinator(graph=_graph_with_verification(), audit=audit)
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment()).record.message_id
    _submit_task(scheduler, task_id)

    assert checkpoint_handoffs(
        cfg, ENGAGEMENT, coord, audit, "VERIFY", scheduler=scheduler) is True
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        restored = load_handoffs(session, ENGAGEMENT).records()
        payload = load_scheduler_payload(session, ENGAGEMENT)
    assert [r.message_id for r in restored] == [task_id]
    assert [t["task_id"] for t in payload["tasks"]] == [task_id]
    assert [t["role"] for t in payload["tasks"]] == ["verification_support"]


def test_resume_reopens_interrupted_analysis_and_keeps_completed(cfg):
    """An interrupted (claimed) verification_analysis task reopens as
    blocked — claimable again at its own boundary, its result
    recomputed, never assumed; a completed one stays completed."""
    audit = _scratch_audit()
    coord = _coordinator(graph=_graph_with_verification(labels=("H1", "H2")),
                         audit=audit)
    first = coord.register(_assignment(subject_ref="H1")).record.message_id
    second = coord.register(_assignment(subject_ref="H2")).record.message_id
    scheduler = _scheduler(coord, audit)
    _submit_task(scheduler, first)
    _submit_task(scheduler, second)
    scheduler.run_ready("VERIFY")               # completes both analyses

    # simulate an interruption mid-flight of a third analysis task —
    # same subject as the first, distinguished by its own target asset
    third = coord.register(_assignment(target_asset="/other/?id=9")
                           ).record.message_id
    scheduler2 = _scheduler(coord, audit)
    _submit_task(scheduler2, third)
    coord.claim(third)                          # claimed, never finished
    assert persist_handoffs(
        cfg, ENGAGEMENT, coord, audit, scheduler=scheduler2) is True

    fresh_coord = _coordinator(engagement=ENGAGEMENT,
                               graph=_graph_with_verification())
    fresh_audit = _scratch_audit()
    restored_coord, resumed = resume_specialists(
        cfg, ENGAGEMENT, fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))

    restored = {r.message_id: r for r in restored_coord.records()}
    statuses = {mid: r.status for mid, r in restored.items()}
    assert statuses[third] == "blocked"
    assert "reopened" in restored[third].blocked_reason
    assert restored[third].attempts == 1        # attempts preserved
    assert statuses[first] == "completed"       # never re-run
    assert statuses[second] == "completed"      # never re-run
    resumed_ids = [t.task_id for t in resumed.tasks()]
    assert third in resumed_ids
    assert first not in resumed_ids
    assert second not in resumed_ids


def test_replay_after_resume_derives_nothing_new(cfg):
    """Identity dedup across a resume: replaying the VERIFY boundary
    cannot double-record analysis work."""
    audit = _scratch_audit()
    coord = _coordinator(graph=_graph_with_verification(), audit=audit)
    task_id = coord.register(_assignment()).record.message_id
    scheduler = _scheduler(coord, audit)
    _submit_task(scheduler, task_id)
    assert persist_handoffs(
        cfg, ENGAGEMENT, coord, audit, scheduler=scheduler) is True

    fresh_coord = _coordinator(engagement=ENGAGEMENT,
                               graph=_graph_with_verification())
    fresh_audit = _scratch_audit()
    restored_coord, resumed = resume_specialists(
        cfg, ENGAGEMENT, fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))
    assert resumed.derive_from_records("VERIFY") == 0
    assert [t.task_id for t in resumed.tasks()] == [task_id]
