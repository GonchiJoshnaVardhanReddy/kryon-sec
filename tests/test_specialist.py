"""Batch 4A/4B/4C: bounded specialist scheduling, task context, budgets.

What this file pins down, in the repo's outside-in style:

* **Roles are honest.** Six roles exist; exactly one has a deterministic
  executor (the Batch-4 evidence assessment); the LLM-backed roles say so
  and are deferred, never improvised.
* **The task schema refuses malformation.** Priority, timeout, dependency
  and id bounds are enforced at the schema; extra fields are forbidden.
* **Submission is validated and deduplicated.** A task must cite a known
  task-assignment record of its role's type, in its role's stage, in the
  coordinator's engagement — and a second submission of the same task is
  suppressed, not re-run.
* **Proposals are review-as-data.** A model suggestion can only become
  READ-ONLY scheduled work through the coordinator's dedup identity; a
  state-changing proposal is refused at the door.
* **Derivation is deterministic and capped.** Only registered
  evidence-assessment assignments derive tasks, at most twelve per
  boundary, and re-deriving is free.
* **Claims are atomic and bounded.** The coordinator's transition table
  owns the claim; attempts are capped; a timed-out claim parks as
  ``blocked`` and may be re-claimed within the cap.
* **Results are engine words only.** The end-to-end assessment grades the
  graph (never model prose), links its evidence, answers honestly when
  the subject does not exist, and its token figure is an estimate all the
  way into the shared budget.
* **Budgets count once.** The engagement BudgetTracker's reservations,
  commits, releases, snapshots and restores — with an estimate never
  halting the loop and a replay never double-counting.
* **Context is bounded, redacted, untrusted-marked.** The task-context
  builder (4B) carries what one task may see, marks target/model text,
  redacts secrets and refuses unknown tasks.

SQLite is used where storage is touched; PostgreSQL paths are NOT RUN
(no PostgreSQL environment in this workspace).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

import pytest
from pydantic import ValidationError
from rich.console import Console

from kryonsec.purple.audit import AuditLog
from kryonsec.purple.coordinator import (
    HandoffCoordinator,
    HandoffTransitionError,
)
from kryonsec.purple.deliverables import (
    STANDING_WORDS,
    BudgetUsage,
    DeliverableClaim,
    SpecialistDeliverable,
)
from kryonsec.purple.handoff import (
    TaskAssignment,
    TaskResult,
    new_message_id,
    task_identity,
    utc_now_iso,
)
from kryonsec.purple.orchestrator import BudgetTracker
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.specialist import (
    EXECUTORS,
    SPECIALIST_ROLES,
    EvidenceAssessmentSpecialist,
    SpecialistBudget,
    SpecialistError,
    SpecialistEventLedger,
    SpecialistScheduler,
    SpecialistTask,
    evidence_questions,
    recover_for_resume,
    role_of,
)
from kryonsec.purple.task_context import (
    MAX_OBSERVATIONS,
    TASK_CONTEXT_FORMAT_VERSION,
    ContextLine,
    TaskContext,
    TaskContextError,
    build_task_context,
)
from kryonsec.purple.ui import PurpleUI
from kryonsec.purple.views import asset_key, hypothesis_engine_view

ENGAGEMENT = "e-1"  # every test runs inside one engagement id by default


# ---- fixtures ---------------------------------------------------------------


def _scratch_audit(name: str | None = None) -> AuditLog:
    """A scratch audit chain. Unique per call, so two tests never share a
    file and never read each other's events."""
    return AuditLog(
        Path("/tmp") / f"specialist-audit-{name or uuid.uuid4().hex[:10]}.jsonl")


def _events(audit: AuditLog) -> list[dict]:
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _only(events: list[dict], name: str) -> list[dict]:
    return [e for e in events if e.get("event") == name]


ASSET = "/ListProducts.asp?artist=1"


def _graph(engagement: str = ENGAGEMENT, hypotheses: tuple = ("H1",),
           *, asset_observed: bool = True) -> EngagementGraph:
    """Target + (optionally) the observed asset + hypothesis nodes."""
    graph = EngagementGraph(engagement_id=engagement)
    graph.add_node("target", "example.com", {})
    if asset_observed:
        graph.add_node("path", ASSET, {})
    for label in hypotheses:
        graph.add_node("hypothesis", label, {
            "title": f"SQL injection check {label}",
            "target_asset": ASSET,
            "rationale": "recon shows a query parameter",
            "tools": ["sqlmap"],
            "confidence": 0.5,
            "approved": True,
        })
    return graph


def _assignment(engagement: str = ENGAGEMENT, **kw) -> TaskAssignment:
    base = dict(
        engagement_id=engagement,
        message_id=new_message_id(),
        source="HYPOTHESIZE",
        destination="specialist",
        task_type="evidence_assessment",
        subject_ref="H1",
        content="assess the recorded evidence for H1",
    )
    base.update(kw)
    return TaskAssignment(**base)


def _coordinator(engagement: str = ENGAGEMENT,
                 graph: EngagementGraph | None = None,
                 audit: AuditLog | None = None) -> HandoffCoordinator:
    return HandoffCoordinator(
        engagement_id=engagement,
        graph=graph if graph is not None else _graph(engagement),
        audit=audit if audit is not None else _scratch_audit(),
    )


def _scheduler(coordinator: HandoffCoordinator, audit: AuditLog,
               budget: BudgetTracker | None = None,
               policy: SpecialistBudget | None = None) -> SpecialistScheduler:
    return SpecialistScheduler(coordinator, audit, budget=budget,
                               policy=policy)


def _submit_task(scheduler: SpecialistScheduler, task_id: str,
                 stage: str = "HYPOTHESIZE", **kw) -> SpecialistTask:
    task = SpecialistTask(
        engagement_id=scheduler.coordinator.engagement_id,
        task_id=task_id,
        role=kw.pop("role", "evidence_assessment"),
        stage=stage,
        **kw,
    )
    scheduler.submit(task)
    return task


def _complete(coord: HandoffCoordinator, task_id: str,
              subject: str = "H1") -> None:
    """Claim + complete an assignment through the coordinator's own
    transitions — the honest lifecycle any result takes."""
    coord.claim(task_id)
    coord.record_result(task_id, TaskResult(
        engagement_id=coord.engagement_id, message_id=new_message_id(),
        source="specialist.evidence_assessment", destination="specialist",
        result_status="completed", subject_ref=subject,
        content="done", correlation_id=task_id))


# ---- roles ------------------------------------------------------------------


def test_roles_are_honest_about_what_runs():
    """Six roles; two deterministic executors (Batch 5D added the
    verification-support one, read-only analysis); LLM roles deferred."""
    assert set(SPECIALIST_ROLES) == {
        "recon_analysis", "hypothesis_analysis", "evidence_assessment",
        "verification_support", "defensive_recommendation", "reporting",
    }
    executors = {r.name: r.executor for r in SPECIALIST_ROLES.values()}
    assert executors["evidence_assessment"] == "evidence_assessment"
    assert executors["verification_support"] == "verification_support"
    assert all(
        v is None for k, v in executors.items()
        if k not in ("evidence_assessment", "verification_support"))
    assert set(EXECUTORS) == {"evidence_assessment", "verification_support"}
    llm_roles = {r.name for r in SPECIALIST_ROLES.values() if r.llm}
    assert llm_roles == {"hypothesis_analysis", "defensive_recommendation"}


def test_unknown_role_lookup_raises_specialist_error():
    with pytest.raises(SpecialistError):
        role_of("no_such_role")


# ---- the task schema ----------------------------------------------------------


def test_task_schema_bounds():
    with pytest.raises(ValidationError):
        SpecialistTask(engagement_id=ENGAGEMENT, task_id=new_message_id(),
                       role="evidence_assessment", stage="HYPOTHESIZE",
                       priority=101)
    with pytest.raises(ValidationError):
        SpecialistTask(engagement_id=ENGAGEMENT, task_id=new_message_id(),
                       role="evidence_assessment", stage="HYPOTHESIZE",
                       priority=-1)
    with pytest.raises(ValidationError):
        SpecialistTask(engagement_id=ENGAGEMENT, task_id=new_message_id(),
                       role="evidence_assessment", stage="HYPOTHESIZE",
                       timeout_s=9)
    with pytest.raises(ValidationError):
        SpecialistTask(engagement_id=ENGAGEMENT, task_id=new_message_id(),
                       role="evidence_assessment", stage="HYPOTHESIZE",
                       timeout_s=3601)
    with pytest.raises(ValidationError):
        SpecialistTask(engagement_id=ENGAGEMENT, task_id="not a message id",
                       role="evidence_assessment", stage="HYPOTHESIZE")
    with pytest.raises(ValidationError):
        SpecialistTask(engagement_id=ENGAGEMENT, task_id=new_message_id(),
                       role="evidence_assessment", stage="HYPOTHESIZE",
                       smuggled="field")


def test_task_priority_accepts_the_whole_range_and_rejects_bool():
    task = SpecialistTask(engagement_id=ENGAGEMENT, task_id=new_message_id(),
                          role="evidence_assessment", stage="HYPOTHESIZE",
                          priority=0)
    assert task.priority == 0
    with pytest.raises(ValidationError):
        SpecialistTask(engagement_id=ENGAGEMENT, task_id=new_message_id(),
                       role="evidence_assessment", stage="HYPOTHESIZE",
                       priority=True)


def test_task_dependency_list_is_bounded_and_deduplicated():
    ids = [new_message_id() for _ in range(10)]
    task = SpecialistTask(
        engagement_id=ENGAGEMENT, task_id=new_message_id(),
        role="evidence_assessment", stage="HYPOTHESIZE",
        depends_on=ids[:8] + [ids[0], "junk id with spaces"],
    )
    assert task.depends_on == ids[:8]  # first eight valid ids win, dupes drop


def test_task_stage_must_be_a_lifecycle_name():
    with pytest.raises(ValidationError):
        SpecialistTask(engagement_id=ENGAGEMENT, task_id=new_message_id(),
                       role="evidence_assessment", stage="NOWHERE")


# ---- submission -------------------------------------------------------------


def test_submit_refuses_unknown_record():
    scheduler = _scheduler(_coordinator(), _scratch_audit())
    with pytest.raises(SpecialistError):
        scheduler.submit(SpecialistTask(
            engagement_id=ENGAGEMENT, task_id=new_message_id(),
            role="evidence_assessment", stage="HYPOTHESIZE"))


def test_submit_refuses_non_assignment_record():
    coord = _coordinator()
    scheduler = _scheduler(coord, _scratch_audit())
    result = TaskResult(
        engagement_id=ENGAGEMENT, message_id=new_message_id(),
        source="specialist.evidence_assessment", destination="specialist",
        result_status="completed", subject_ref="H1",
        content="a prior answer")
    result_record = coord.register(result).record
    assert result_record.kind == "task_result"
    with pytest.raises(SpecialistError):
        scheduler.submit(SpecialistTask(
            engagement_id=ENGAGEMENT, task_id=result_record.message_id,
            role="evidence_assessment", stage="HYPOTHESIZE"))


def test_submit_refuses_role_stage_mismatch():
    coord = _coordinator()
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    with pytest.raises(SpecialistError):
        scheduler.submit(SpecialistTask(
            engagement_id=ENGAGEMENT, task_id=task_id,
            role="evidence_assessment", stage="VERIFY"))


def test_submit_refuses_cross_engagement():
    coord = _coordinator(ENGAGEMENT)
    scheduler = _scheduler(coord, _scratch_audit())
    other = _assignment(engagement="e-2", subject_ref="H1")
    with pytest.raises(SpecialistError):
        scheduler.submit(SpecialistTask(
            engagement_id="e-2", task_id=other.message_id,
            role="evidence_assessment", stage="HYPOTHESIZE"))


def test_submit_refuses_task_type_mismatch():
    coord = _coordinator()
    scheduler = _scheduler(coord, _scratch_audit())
    exploit_id = coord.register(
        _assignment(task_type="exploit_test", destination="EXPLOIT",
                    subject_ref="H1")).record.message_id
    with pytest.raises(SpecialistError):
        scheduler.submit(SpecialistTask(
            engagement_id=ENGAGEMENT, task_id=exploit_id,
            role="evidence_assessment", stage="HYPOTHESIZE"))


def test_duplicate_submission_is_suppressed_not_rerun():
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    second = SpecialistTask(
        engagement_id=ENGAGEMENT, task_id=task_id,
        role="evidence_assessment", stage="HYPOTHESIZE")
    assert scheduler.submit(second) == "already_submitted"
    assert len(scheduler.tasks()) == 1
    events = _events(audit)
    assert len(_only(events, "specialist_duplicate_suppressed")) == 1


# ---- proposals --------------------------------------------------------------


def test_proposal_refuses_state_changing_work():
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    with pytest.raises(SpecialistError):
        scheduler.submit_proposal(
            "exploit_test", "H1", "please test the login form",
            source="model")
    refused = _only(_events(audit), "specialist_proposal_refused")
    assert refused and "state-changing" in refused[0]["reason"]


def test_proposal_refuses_unknown_task_type():
    scheduler = _scheduler(_coordinator(), _scratch_audit())
    with pytest.raises(SpecialistError):
        scheduler.submit_proposal(
            "hack_the_planet", "H1", "do it", source="model")


def test_proposal_is_deduplicated_into_one_task():
    """A re-filed proposal schedules the dedup'd record's id — never a
    second task for work that already exists."""
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    first = scheduler.submit_proposal(
        "evidence_assessment", "H1", "assess H1", source="model")
    second = scheduler.submit_proposal(
        "evidence_assessment", "H1", "assess H1", source="model")
    assert second.outcome != "new"
    assert second.record.message_id == first.record.message_id
    assert len(scheduler.tasks()) == 1
    assert scheduler.tasks()[0].task_id == first.record.message_id


# ---- derivation ---------------------------------------------------------------


def test_derivation_schedules_each_assessment_assignment():
    from kryonsec.purple.coordinator import StageBoundaryRecorder

    coord = _coordinator(graph=_graph(hypotheses=("H1", "H2")))
    scheduler = _scheduler(coord, _scratch_audit())
    # the boundary recorder's Batch-4 rule: one assignment per hypothesis
    StageBoundaryRecorder(coord).on_state_complete("HYPOTHESIZE")
    derived = scheduler.derive_from_records("HYPOTHESIZE")
    assert derived == 2
    assert len(scheduler.tasks()) == 2
    assert scheduler.derive_from_records("HYPOTHESIZE") == 0  # idempotent


def test_derivation_refuses_other_states():
    scheduler = _scheduler(_coordinator(), _scratch_audit())
    assert scheduler.derive_from_records("VERIFY") == 0
    assert scheduler.tasks() == []


def test_derivation_is_capped_at_twelve():
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    for i in range(1, 15):
        coord.register(_assignment(subject_ref=f"H{i}"))
    created = scheduler.derive_from_records("HYPOTHESIZE")
    assert created == 12
    assert len(scheduler.tasks()) == 12
    capped = _only(_events(audit), "specialist_derivation_capped")
    assert capped and capped[0]["cap"] == 12


def test_boundary_recorder_caps_hypothesis_flood():
    """The recorder derives at most 12 assignments from a 14-hypothesis
    graph and says so once."""
    from kryonsec.purple.coordinator import StageBoundaryRecorder

    audit = _scratch_audit()
    coord = _coordinator(
        graph=_graph(hypotheses=tuple(f"H{i}" for i in range(1, 15))),
        audit=audit)
    StageBoundaryRecorder(coord).on_state_complete("HYPOTHESIZE")
    assignments = [
        r for r in coord.records()
        if r.kind == "task_assignment" and r.task_type == "evidence_assessment"
    ]
    assert len(assignments) == 12
    capped = _only(_events(audit), "handoff_derivation_capped")
    assert capped and capped[0]["derived"] == 12 and capped[0]["total"] == 14


# ---- readiness, ordering, claims ---------------------------------------------


def test_readiness_of_unknown_task():
    scheduler = _scheduler(_coordinator(), _scratch_audit())
    assert scheduler.readiness(new_message_id()) == (False, "not scheduled")


def test_dependency_gates_readiness():
    coord = _coordinator()
    scheduler = _scheduler(coord, _scratch_audit())
    first = coord.register(_assignment(subject_ref="H1")).record.message_id
    second = coord.register(_assignment(subject_ref="H2")).record.message_id
    _submit_task(scheduler, first)
    _submit_task(scheduler, second, depends_on=[first])

    ok, reason = scheduler.readiness(second)
    assert not ok and "registered" in reason  # dependency not completed
    _complete(coord, first, subject="H1")
    ok, reason = scheduler.readiness(second)
    assert ok and reason == "ready"
    # an unknown dependency is a named refusal, never a crash
    third = coord.register(_assignment(subject_ref="H3")).record.message_id
    _submit_task(scheduler, third, depends_on=[new_message_id()])
    ok, reason = scheduler.readiness(third)
    assert not ok and "unknown" in reason


def test_attempts_cap_closes_reclaiming():
    coord = _coordinator()
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    # two interrupted claims (the legal blocked->in_progress reclaim),
    # and the cap then refuses a third
    for _ in range(2):
        coord.claim(task_id)
        coord.block(task_id, "interrupted")
    ok, reason = scheduler.readiness(task_id)
    assert not ok and "attempts exhausted (2)" in reason


def test_ready_orders_by_priority_then_age():
    coord = _coordinator(graph=_graph(hypotheses=("H1", "H2", "H3")))
    scheduler = _scheduler(coord, _scratch_audit())
    a = coord.register(_assignment(subject_ref="H1")).record.message_id
    b = coord.register(_assignment(subject_ref="H2")).record.message_id
    c = coord.register(_assignment(subject_ref="H3")).record.message_id
    _submit_task(scheduler, a, priority=10)
    _submit_task(scheduler, b, priority=90)
    _submit_task(scheduler, c, priority=50)
    ready = scheduler.ready("HYPOTHESIZE")
    assert [t.task_id for t in ready] == [b, c, a]
    # another boundary's work is simply not ready here
    assert scheduler.ready("VERIFY") == []


def test_manual_claim_makes_task_not_ready_and_nothing_runs():
    """Lost claim race: the scheduler sees in_progress, runs nothing,
    crashes nowhere."""
    coord = _coordinator()
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    coord.claim(task_id)
    ok, reason = scheduler.readiness(task_id)
    assert not ok and reason == "already in progress"
    summary = scheduler.run_ready("HYPOTHESIZE")
    assert summary["ran"] == 0


def test_double_claim_refused_by_the_transition_table():
    coord = _coordinator()
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    coord.claim(task_id)
    with pytest.raises(HandoffTransitionError):
        coord.claim(task_id)


# ---- cancellation -------------------------------------------------------------


def test_cancel_withdraws_scheduled_work():
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    record = scheduler.cancel(task_id, "operator asked")
    assert record.status == "cancelled"
    ok, reason = scheduler.readiness(task_id)
    assert not ok and reason == "record is cancelled"
    assert scheduler.ready("HYPOTHESIZE") == []
    assert _only(_events(audit), "specialist_cancelled")


def test_cancel_unknown_task_raises():
    scheduler = _scheduler(_coordinator(), _scratch_audit())
    with pytest.raises(SpecialistError):
        scheduler.cancel(new_message_id())


# ---- timeouts -------------------------------------------------------------------


def _stamp(seconds_ago: int) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


def test_expired_claim_parks_as_blocked_and_reopens():
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    task = _submit_task(scheduler, task_id, timeout_s=10)
    coord.claim(task_id)
    task.last_claimed_at = _stamp(60)
    assert scheduler.check_timeouts("HYPOTHESIZE") == 1
    record = coord.get(task_id)
    assert record.status == "blocked"
    assert "timeout" in record.blocked_reason
    assert task.last_claimed_at == ""  # the stale stamp is cleared
    assert _only(_events(audit), "specialist_timeout")
    # blocked -> in_progress is legal: it may re-claim within the cap
    ok, reason = scheduler.readiness(task_id)
    assert ok and reason == "ready"


def test_fresh_claim_is_not_timed_out():
    coord = _coordinator()
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    task = _submit_task(scheduler, task_id, timeout_s=600)
    coord.claim(task_id)
    task.last_claimed_at = utc_now_iso()   # claimed moments ago
    assert scheduler.check_timeouts("HYPOTHESIZE") == 0


# ---- the end-to-end assessment -------------------------------------------------


def test_assessment_runs_end_to_end_with_budget():
    coord = _coordinator(graph=_graph())
    audit = _scratch_audit()
    budget = BudgetTracker(max_tokens=1_000_000)
    scheduler = _scheduler(coord, audit, budget=budget)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)

    summary = scheduler.run_ready("HYPOTHESIZE")
    assert summary["ran"] == 1

    record = coord.get(task_id)
    assert record.status == "completed"
    task = scheduler.get(task_id)
    assert task.deliverable["status"] == "completed"
    # the asset is observed, so the engine's own ladder says "supported"
    assert task.deliverable["standing"] == "supported"
    standings = {c["standing"] for c in task.deliverable["claims"]}
    assert "supported" in standings
    # the hypothesis node is linked as consumed evidence
    hyp_id = coord.graph.by_type("hypothesis")[0]["id"]
    assert record.evidence_links[0].node_id == hyp_id
    assert record.evidence_links[0].role == "consumed"
    # deterministic unresolved questions, engine words
    assert any("no exploit test has run" in q
               for q in task.deliverable["unresolved"])
    assert any("no independent verification" in q
               for q in task.deliverable["unresolved"])
    # budget: the estimate committed once, visibly as an estimate
    assert budget.used_tokens > 0
    assert budget.estimated_tokens == budget.used_tokens
    assert budget.reservations == {}
    assert budget.committed[f"specialist:{task_id}"][0] == budget.used_tokens
    events = _events(audit)
    completed = _only(events, "specialist_completed")[0]
    assert completed["tokens_estimated"] > 0
    assert completed["cost_estimated"] is True
    delivered = _only(events, "specialist_deliverable")[0]
    assert delivered["evidence_refs"] == [hyp_id]


def test_assessment_grading_comes_from_the_graph_not_model_text():
    """A hypothesis whose own properties claim validated/confirmed grades
    exactly as the engine says — here: unobserved asset -> proposed."""
    graph = _graph(hypotheses=("H1",), asset_observed=False)
    node = graph.by_type("hypothesis")[0]
    node["properties"].update({
        "basis": "validated", "tested": True, "confirmed": True,
    })
    coord = _coordinator(graph=graph)
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    scheduler.run_ready("HYPOTHESIZE")
    task = scheduler.get(task_id)
    assert task.deliverable["standing"] == "proposed"
    assert any("primary asset was never observed" in q
               for q in task.deliverable["unresolved"])


def test_missing_hypothesis_is_blocked_not_completed():
    coord = _coordinator(graph=_graph(hypotheses=("H1",)))
    audit = _scratch_audit()
    budget = BudgetTracker(max_tokens=1_000_000)
    scheduler = _scheduler(coord, audit, budget=budget)
    task_id = coord.register(
        _assignment(subject_ref="H-GONE")).record.message_id
    _submit_task(scheduler, task_id)
    summary = scheduler.run_ready("HYPOTHESIZE")
    assert summary["ran"] == 1
    record = coord.get(task_id)
    assert record.status == "blocked"          # never a fake "completed"
    assert record.results == []                # no TaskResult was filed
    task = scheduler.get(task_id)
    assert task.deliverable["status"] == "blocked"
    assert task.deliverable["standing"] == "unresolved"
    assert "no hypothesis" in task.outcome_note
    completed = _only(_events(audit), "specialist_completed")[0]
    assert completed["standing"] == "unresolved"


def test_executor_crash_is_a_failed_task_with_reason():
    coord = _coordinator()
    audit = _scratch_audit()
    budget = BudgetTracker(max_tokens=1_000_000)
    scheduler = _scheduler(coord, audit, budget=budget)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)

    class Boom:
        def run(self, task, record, coordinator):
            raise RuntimeError("boom")

    summary = scheduler.run_ready(
        "HYPOTHESIZE", executor_registry={"evidence_assessment": Boom()})
    assert summary["failed"] == 1
    record = coord.get(task_id)
    assert record.status == "failed"
    assert "boom" in record.results[0]["content"]
    # the reservation was released, nothing was charged
    assert budget.reservations == {}
    assert budget.used_tokens == 0
    failed = _only(_events(audit), "specialist_failed")[0]
    assert "boom" in failed["error"]


def test_malformed_deliverable_is_refused_by_the_contract():
    """The Shannon contract: a producer cannot file an out-of-vocabulary
    standing, a fake status, extra fields, or a confidence about no
    evidence — the schema refuses the whole thing."""
    task_id = new_message_id()
    with pytest.raises(ValidationError):
        SpecialistDeliverable(
            task_id=task_id, producer="evidence_assessment",
            source_stage="HYPOTHESIZE", status="completed",
            standing="banana")
    with pytest.raises(ValidationError):
        SpecialistDeliverable(
            task_id=task_id, producer="evidence_assessment",
            source_stage="HYPOTHESIZE", status="done")
    with pytest.raises(ValidationError):
        SpecialistDeliverable(
            task_id=task_id, producer="evidence_assessment",
            source_stage="HYPOTHESIZE", status="completed",
            smuggled=True)
    with pytest.raises(ValidationError):
        SpecialistDeliverable(
            task_id=task_id, producer="evidence_assessment",
            source_stage="HYPOTHESIZE", status="completed",
            confidence=0.9)
    with pytest.raises(ValidationError):
        SpecialistDeliverable(
            task_id=task_id, producer="evidence_assessment",
            source_stage="HYPOTHESIZE", status="completed", version=2)
    # a deliverable with evidence may carry a confidence
    ok = SpecialistDeliverable(
        task_id=task_id, producer="evidence_assessment",
        source_stage="HYPOTHESIZE", status="completed",
        confidence=0.9, evidence_refs=["node-1"])
    assert ok.confidence == 0.9
    # the standing vocabulary is the engine's union, closed
    assert "proposed" in STANDING_WORDS and "unresolved" in STANDING_WORDS
    with pytest.raises(ValidationError):
        DeliverableClaim(subject_ref="H1", standing="celebrated")


def test_malformed_deliverable_from_executor_fails_the_task():
    """A custom registry executor that tries to hand back an invalid
    deliverable raises inside run() — and the task is recorded FAILED,
    honestly, with the reason."""
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)

    class ForgedStanding:
        def run(self, task, record, coordinator):
            return (SpecialistDeliverable(
                task_id=task.task_id, producer="evidence_assessment",
                source_stage="HYPOTHESIZE", status="completed",
                standing="celebrated"), BudgetUsage(tokens=10))

    summary = scheduler.run_ready(
        "HYPOTHESIZE",
        executor_registry={"evidence_assessment": ForgedStanding()})
    assert summary["failed"] == 1
    assert coord.get(task_id).status == "failed"
    failed = _only(_events(audit), "specialist_failed")[0]
    assert "standing" in failed["error"]


# ---- budgets ---------------------------------------------------------------------


def test_budget_reservation_holds_headroom_without_halting():
    budget = BudgetTracker(max_tokens=1_000)
    budget.record_usage(800, estimate=False)
    assert budget.reserve("specialist:a", 300) is False   # would pass ceiling
    assert budget.reserve("specialist:a", 150) is True
    assert budget.reserved_tokens == 150
    # a reservation NEVER trips the loop's guard — only real usage does
    assert budget.exhausted() is False
    budget.record_usage(200, estimate=False)
    assert budget.exhausted() is True
    budget.release("specialist:a")
    assert budget.reservations == {}


def test_budget_reservation_is_idempotent_per_key():
    budget = BudgetTracker(max_tokens=10_000)
    assert budget.reserve("k", 100) is True
    assert budget.reserve("k", 100) is True
    assert budget.reserved_tokens == 100
    # a committed key re-reserves True without counting again
    budget.commit("k", 100, estimate=True)
    assert budget.reserve("k", 100) is True
    assert budget.used_tokens == 100
    assert budget.reserved_tokens == 0


def test_budget_commit_is_first_commit_wins():
    budget = BudgetTracker(max_tokens=10_000)
    budget.commit("specialist:x", 120, 0.0, estimate=True)
    budget.commit("specialist:x", 999, 0.0, estimate=True)  # replay: ignored
    assert budget.used_tokens == 120
    assert budget.estimated_tokens == 120
    assert budget.committed["specialist:x"] == (120, 0.0)


def test_budget_commit_converts_the_reservation():
    budget = BudgetTracker(max_tokens=10_000)
    budget.reserve("specialist:y", 400)
    budget.commit("specialist:y", 150, estimate=True)
    assert budget.reservations == {}          # headroom released
    assert budget.used_tokens == 150          # actual, not the held 400
    assert budget.committed["specialist:y"] == (150, 0.0)


def test_budget_usage_accounting_clamps_and_labels():
    budget = BudgetTracker(max_tokens=10_000)
    budget.record_usage(-50, -1.0)            # clamped to zero
    assert budget.used_tokens == 0 and budget.used_cost_usd == 0.0
    budget.record_usage(30, 0.2, estimate=False)
    assert budget.estimated_tokens == 0       # provider usage is not an estimate
    assert budget.estimated_cost_usd == 0.0
    budget.record_usage(10, estimate=True)
    assert budget.estimated_tokens == 10


def test_budget_snapshot_roundtrip_and_refusals():
    budget = BudgetTracker(max_tokens=10_000)
    budget.record_usage(500, 0.25, estimate=False)
    budget.record_usage(70, estimate=True)
    budget.reserve("specialist:pending", 300)
    budget.commit("specialist:done", 500, 0.25, estimate=False)
    snapshot = budget.budget_snapshot()
    # used = the two record_usage calls + the committed one
    assert snapshot["used_tokens"] == 1_070
    assert snapshot["used_cost_usd"] == 0.5
    assert snapshot["estimated_tokens"] == 70

    fresh = BudgetTracker(max_tokens=10_000)
    fresh.restore_budget(snapshot)
    assert fresh.used_tokens == 1_070
    assert fresh.used_cost_usd == 0.5
    assert fresh.estimated_tokens == 70
    assert fresh.reservations == {"specialist:pending": (300, 0.0)}
    assert fresh.committed["specialist:done"] == (500, 0.25)

    with pytest.raises(ValueError):
        fresh.restore_budget("not a dict")
    with pytest.raises(ValueError):
        fresh.restore_budget({"used_tokens": "x"})
    with pytest.raises(ValueError):
        fresh.restore_budget({"used_tokens": -5})
    with pytest.raises(ValueError):
        fresh.restore_budget({"committed": {"k": "no"}})


def test_scheduler_budget_defers_by_engagement_bound():
    coord = _coordinator()
    audit = _scratch_audit()
    budget = BudgetTracker(max_tokens=100)  # task estimate ~4000 exceeds it
    scheduler = _scheduler(coord, audit, budget=budget)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    summary = scheduler.run_ready("HYPOTHESIZE")
    assert summary["ran"] == 0
    assert summary["deferred_budget"] == 1
    assert coord.get(task_id).status == "registered"   # stays for later
    deferred = _only(_events(audit), "specialist_budget_deferred")[0]
    assert deferred["reason"] == "engagement budget bound reached"


def test_scheduler_role_bound_defers_after_cap():
    coord = _coordinator(graph=_graph(hypotheses=("H1", "H2", "H3")))
    audit = _scratch_audit()
    scheduler = _scheduler(
        coord, audit, budget=BudgetTracker(max_tokens=1_000_000),
        policy=SpecialistBudget(
            max_tokens_per_task=200, max_tokens_per_role=250))

    class FixedEstimate(EvidenceAssessmentSpecialist):
        def _estimate(self, coordinator, task, summary):
            return 150

    for label in ("H1", "H2", "H3"):
        task_id = coord.register(
            _assignment(subject_ref=label)).record.message_id
        _submit_task(scheduler, task_id)
    summary = scheduler.run_ready(
        "HYPOTHESIZE",
        executor_registry={"evidence_assessment": FixedEstimate()})
    assert summary["ran"] == 2
    assert summary["deferred_budget"] == 1
    deferred = _only(_events(audit), "specialist_budget_deferred")
    assert any("role budget exhausted" in d["reason"] for d in deferred)
    assert scheduler.progress()["tokens_estimated"] == 300


def test_scheduler_without_budget_still_runs():
    coord = _coordinator()
    scheduler = _scheduler(coord, _scratch_audit(), budget=None)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    summary = scheduler.run_ready("HYPOTHESIZE")
    assert summary["ran"] == 1


# ---- the event ledger ---------------------------------------------------------------


def test_ledger_marks_each_fact_once():
    ledger = SpecialistEventLedger()
    key = SpecialistEventLedger.fact_key("task_completed", "ho_abc")
    ledger.mark(key)
    ledger.mark(key)
    assert ledger.seen(key) and len(ledger.to_dict()) == 1


def test_ledger_is_bounded():
    ledger = SpecialistEventLedger()
    for i in range(600):
        ledger.mark(f"k{i}")
    data = ledger.to_dict()
    assert len(data) <= SpecialistEventLedger.MAX_LEDGER
    assert "k599" in data                    # newest kept
    assert "k0" not in data                  # oldest dropped


def test_ledger_roundtrip_filters_garbage():
    ledger = SpecialistEventLedger.from_dict(
        {"a": "2026-01-01T00:00:00Z", 7: "x", "b": 9})
    assert ledger.seen("a")
    assert not ledger.seen("b") and not ledger.seen("7")
    assert SpecialistEventLedger.from_dict(None).to_dict() == {}
    with pytest.raises(SpecialistError):
        SpecialistEventLedger.from_dict("nope")


# ---- the scheduler snapshot (4C) ------------------------------------------------


def test_scheduler_snapshot_roundtrip():
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    task = _submit_task(scheduler, task_id)
    scheduler.ledger.mark("some-fact")
    data = scheduler.to_dict()
    assert data["version"] == 1
    assert data["engagement_id"] == ENGAGEMENT

    restored = SpecialistScheduler.from_dict(
        data, coordinator=coord, audit=audit)
    assert [t.model_dump() for t in restored.tasks()] == [task.model_dump()]
    assert restored.ledger.seen("some-fact")


def test_scheduler_snapshot_carries_the_budget():
    coord = _coordinator()
    audit = _scratch_audit()
    budget = BudgetTracker(max_tokens=10_000)
    budget.record_usage(444, estimate=True)
    scheduler = _scheduler(coord, audit, budget=budget)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    data = scheduler.to_dict()
    assert data["budget"]["used_tokens"] == 444

    fresh_budget = BudgetTracker(max_tokens=10_000)
    restored = SpecialistScheduler.from_dict(
        data, coordinator=coord, audit=audit, budget=fresh_budget)
    assert fresh_budget.used_tokens == 444  # restored, never reset
    assert restored.tasks()


def test_scheduler_snapshot_refusals():
    coord = _coordinator()
    audit = _scratch_audit()
    scheduler = _scheduler(coord, audit)
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    data = scheduler.to_dict()

    with pytest.raises(SpecialistError):
        SpecialistScheduler.from_dict("nope", coordinator=coord, audit=audit)
    with pytest.raises(SpecialistError):
        SpecialistScheduler.from_dict(
            dict(data, version=99), coordinator=coord, audit=audit)
    with pytest.raises(SpecialistError):
        SpecialistScheduler.from_dict(
            dict(data, engagement_id="e-other"), coordinator=coord,
            audit=audit)
    with pytest.raises(SpecialistError):
        SpecialistScheduler.from_dict(
            dict(data, tasks=[data["tasks"][0], data["tasks"][0]]),
            coordinator=coord, audit=audit)
    with pytest.raises(SpecialistError):
        SpecialistScheduler.from_dict(
            dict(data, tasks="nope"), coordinator=coord, audit=audit)
    with pytest.raises(ValueError):
        SpecialistScheduler.from_dict(
            dict(data, budget={"used_tokens": "x"}),
            coordinator=coord, audit=audit,
            budget=BudgetTracker(max_tokens=10_000))


# ---- recovery pass (4C) -----------------------------------------------------------


def test_recovery_pass_reopens_and_gates():
    coord = _coordinator()
    audit = _scratch_audit()
    read_only = coord.register(_assignment(subject_ref="H1")).record.message_id
    state_changing = coord.register(
        _assignment(task_type="exploit_test", destination="EXPLOIT",
                    subject_ref="H1")).record.message_id
    finished = coord.register(_assignment(subject_ref="H2")).record.message_id
    coord.claim(read_only)
    coord.claim(state_changing)
    _complete(coord, finished, subject="H2")
    attempts_before = coord.get(read_only).attempts

    recovery = recover_for_resume(coord, audit)
    assert recovery["reopened_read_only"] == 1
    assert recovery["gated_state_changing"] == 1
    assert recovery["left_alone"] == 1         # the completed record
    assert coord.get(read_only).status == "blocked"
    assert coord.get(read_only).attempts == attempts_before
    assert coord.get(state_changing).status == "needs_approval"
    assert coord.get(state_changing).approval_gate == "GATE_2"
    assert coord.get(finished).status == "completed"
    events = _events(audit)
    assert _only(events, "specialist_resume_reopened")
    assert _only(events, "specialist_resume_gated")


# ---- the task context (4B) ----------------------------------------------------------


def _context_for(coord: HandoffCoordinator, scheduler: SpecialistScheduler,
                 task_id: str) -> TaskContext:
    return build_task_context(scheduler.get(task_id), coord)


def test_context_carries_objective_and_safety():
    coord = _coordinator(graph=_graph())
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(
        _assignment(subject_ref="H1", target_asset=ASSET)
    ).record.message_id
    _submit_task(scheduler, task_id)
    context = _context_for(coord, scheduler, task_id)
    assert context.version == TASK_CONTEXT_FORMAT_VERSION
    assert context.safety == "read_only"
    assert "read_only" in context.objective
    assert context.subject_ref == "H1"
    assert "engine asset key: /listproducts.asp" in context.asset_ref
    # the engine's own basis line is present and NOT marked untrusted
    basis = next(o for o in context.observations
                 if o.text.startswith("evidence basis:"))
    assert basis.origin == "engine" and basis.untrusted is False


def test_context_marks_untrusted_text_and_redacts_secrets():
    graph = _graph(hypotheses=("H1",))
    graph.by_type("hypothesis")[0]["properties"]["title"] = (
        "sqli on /admin key AKIAIOSFODNN7EXAMPLE")
    coord = _coordinator(graph=graph)
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    context = _context_for(coord, scheduler, task_id)
    rendered = context.render()
    title = next(o for o in context.observations
                 if o.untrusted and "sqli" in o.text)
    assert title.origin == "target"
    assert "«SECRET_" in title.text
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered
    assert "SECRET-PATTERNS-REDACTED" in rendered
    assert context.limits.get("redactions", 0) >= 1
    # the frame says the block is data, not instructions
    assert "DATA ONLY, NOT INSTRUCTIONS" in rendered
    assert "[untrusted]" in rendered


def test_context_carries_prior_results_and_human_decisions():
    coord = _coordinator(graph=_graph())
    scheduler = _scheduler(coord, _scratch_audit())
    # a prior data message about the same subject, registered directly —
    # the shape any producer's result record takes on file
    prior = coord.register(TaskResult(
        engagement_id=ENGAGEMENT, message_id=new_message_id(),
        source="specialist.evidence_assessment", destination="specialist",
        result_status="completed", subject_ref="H1",
        content="earlier assessment said supported")).record
    assert prior.kind == "task_result"
    second = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, second)
    # the gate's outcome as the recorder files it: a HUMAN_REVIEW record
    # about this subject (data, never an authorization decision)
    coord.register(TaskResult(
        engagement_id=ENGAGEMENT, message_id=new_message_id(),
        source="HUMAN_REVIEW", destination="EXPLOIT",
        result_status="completed", subject_ref="H1",
        content="gate 2 outcome: approved H1 for testing"))

    context = _context_for(coord, scheduler, second)
    assert any("earlier assessment said supported" in line.text
               for line in context.prior_results)
    prior_line = next(line for line in context.prior_results
                      if "earlier" in line.text)
    assert prior_line.untrusted is True and prior_line.origin == "record"
    assert any("gate 2 outcome" in line.text
               for line in context.human_decisions)
    decision = next(line for line in context.human_decisions
                    if "gate 2" in line.text)
    assert decision.origin == "human" and decision.untrusted is False


def test_context_without_hypothesis_says_so():
    coord = _coordinator(graph=_graph(hypotheses=("H1",)))
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(
        _assignment(subject_ref="H-GONE")).record.message_id
    _submit_task(scheduler, task_id)
    context = _context_for(coord, scheduler, task_id)
    assert context.unresolved == []
    assert any("no hypothesis node" in line.text
               for line in context.verification)


def test_context_is_bounded_by_construction():
    graph = _graph(hypotheses=("H1",))
    graph.by_type("hypothesis")[0]["properties"]["related_assets"] = [
        {"asset": f"/p{i}"} for i in range(20)
    ]
    coord = _coordinator(graph=graph)
    scheduler = _scheduler(coord, _scratch_audit())
    task_id = coord.register(_assignment(subject_ref="H1")).record.message_id
    _submit_task(scheduler, task_id)
    context = _context_for(coord, scheduler, task_id)
    assert len(context.observations) <= MAX_OBSERVATIONS
    # related assets are capped at six references
    asset_lines = [o for o in context.observations if "(role:" in o.text]
    assert len(asset_lines) == 6
    assert len(context.render()) <= 6_000


def test_context_refuses_unknown_task():
    coord = _coordinator()
    with pytest.raises(TaskContextError):
        build_task_context(
            SpecialistTask(engagement_id=ENGAGEMENT,
                           task_id=new_message_id(),
                           role="evidence_assessment", stage="HYPOTHESIZE"),
            coord)


def test_context_schema_refuses_malformation():
    with pytest.raises(ValidationError):
        TaskContext(
            version=TASK_CONTEXT_FORMAT_VERSION, engagement_id=ENGAGEMENT,
            task_id=new_message_id(), role="evidence_assessment",
            stage="HYPOTHESIZE", task_type="evidence_assessment",
            safety="read_only", objective="x", subject_ref="H1",
            smuggled=True)
    with pytest.raises(ValidationError):
        ContextLine(text="x", origin="model")   # not a known origin
    with pytest.raises(ValidationError):
        TaskContext(
            version=99, engagement_id=ENGAGEMENT, task_id=new_message_id(),
            role="evidence_assessment", stage="HYPOTHESIZE",
            task_type="evidence_assessment", safety="read_only",
            objective="x", subject_ref="H1")
    # unresolved questions are capped at eight, first-wins
    context = TaskContext(
        engagement_id=ENGAGEMENT, task_id=new_message_id(),
        role="evidence_assessment", stage="HYPOTHESIZE",
        task_type="evidence_assessment", safety="read_only",
        objective="x", subject_ref="H1",
        unresolved=[f"question {i}" for i in range(12)])
    assert len(context.unresolved) == 8


def test_evidence_questions_use_engine_words():
    graph = _graph(hypotheses=("H1",))
    view = hypothesis_engine_view(graph.by_type("hypothesis")[0], graph)
    questions = evidence_questions(view, "H1")
    assert any("no exploit test has run" in q for q in questions)
    assert any("no independent verification" in q for q in questions)
    assert len(questions) <= 6


def test_asset_normalization_is_not_identity_with_a_host():
    """The dedup identity normalizes scheme/query/fragment/case of the
    asset a task names — but a host-qualified URL is a DIFFERENT asset,
    never silently merged with the bare path."""
    assert asset_key(ASSET) == asset_key("/LISTPRODUCTS.asp/")
    assert asset_key(ASSET) != asset_key("http://example.com" + ASSET)
    assert task_identity(ENGAGEMENT, "evidence_assessment", ASSET, "H1") == \
        task_identity(ENGAGEMENT, "evidence_assessment",
                      "/LISTPRODUCTS.asp/", "H1")
    assert task_identity(ENGAGEMENT, "evidence_assessment", ASSET, "H1") != \
        task_identity(ENGAGEMENT, "evidence_assessment", ASSET, "H2")


def test_coordinator_dedups_identical_proposal_identities():
    """Two assignments with the same identity never become two records."""
    coord = _coordinator()
    first = coord.register(_assignment(subject_ref="H1"))
    second = coord.register(_assignment(subject_ref="H1"))
    assert second.outcome != "new"
    assert second.record.message_id == first.record.message_id


# ---- UI progress (read-only, from the scheduler's own audit events) ---------------


def _ui() -> PurpleUI:
    console = Console(file=StringIO(), force_terminal=False, width=100)
    return PurpleUI(console, target="t.com", engagement_id="e-ui",
                    clock=(lambda: 1000.0), utf8=True)


def test_ui_counters_follow_specialist_events():
    ui = _ui()
    ui.on_audit({"event": "specialist_submitted", "role":
                 "evidence_assessment", "stage": "HYPOTHESIZE"})
    ui.on_audit({"event": "specialist_completed", "role":
                 "evidence_assessment", "standing": "supported",
                 "tokens_estimated": 123, "cost_estimated": True})
    assert ui.specialist_scheduled == 1
    assert ui.specialist_done == 1
    assert any("supported" in n for n in ui.notices)
    assert any("123 tokens" in n or "~123" in n for n in ui.notices)


def test_ui_renders_deferral_and_resume_notices():
    ui = _ui()
    ui.on_audit({"event": "specialist_budget_deferred",
                 "reason": "engagement budget bound reached"})
    ui.on_audit({"event": "specialist_resume_gated"})
    ui.on_audit({"event": "specialist_timeout", "role":
                 "evidence_assessment"})
    assert any("budget" in n for n in ui.notices)
    assert any("Gate 2" in n for n in ui.notices)
    assert ui.specialist_blocked == 1


def test_ui_progress_event_updates_estimates():
    ui = _ui()
    ui.on_audit({"event": "specialist_progress", "state": "HYPOTHESIZE",
                 "scheduled": 3, "tokens_estimated": 640,
                 "by_status": {"completed": 1, "blocked": 2}})
    assert ui.specialist_tokens == 640
    assert ui.specialist_blocked == 2


def test_ui_never_crashes_on_specialist_garbage():
    ui = _ui()
    ui.on_audit({"event": "specialist_completed"})   # no fields at all
    ui.on_audit({"event": "specialist_progress", "tokens_estimated": "x",
                 "by_status": "not a dict"})
    assert ui.specialist_done == 1
    assert ui.specialist_tokens == 0


# ---- module surface ----------------------------------------------------------------


def test_specialist_module_exposes_the_public_surface():
    import kryonsec.purple.specialist as mod

    for name in ("SPECIALIST_ROLES", "SpecialistTask", "SpecialistScheduler",
                 "SpecialistBudget", "SpecialistEventLedger",
                 "SpecialistError", "EXECUTORS", "evidence_questions",
                 "recover_for_resume"):
        assert hasattr(mod, name)
