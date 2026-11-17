"""Batch 4C: specialist resume — checkpoints, recovery, budget persistence.

What this file pins down:

* **One transaction, one moment.** The scheduler snapshot is written in
  the SAME transaction as the handoff records, so the two always
  describe the same instant; saving twice replaces the row, never
  duplicates it.
* **Resume restores, never repeats.** A reused engagement id restores
  its records, its scheduler (tasks, ledger) and its budget consumption;
  recovery then reopens interrupted read-only work, parks interrupted
  state-changing work behind Gate 2, and leaves finished work alone.
* **A corrupt checkpoint is refused, not half-read.** Wrong version,
  wrong engagement, unreadable rows — each is refused loudly, audited as
  ``specialist_resume_failed``, and the engagement continues with a
  FRESH scheduler over the records that did restore.
* **A fresh engagement stays quiet.** No prior rows means no resume
  events at all.

SQLite only; PostgreSQL paths are NOT RUN (no PostgreSQL environment in
this workspace).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.coordinator import HandoffCoordinator
from kryonsec.purple.handoff import TaskAssignment, new_message_id
from kryonsec.purple.handoff_store import (
    load_handoffs,
    load_scheduler_payload,
    save_handoffs,
)
from kryonsec.purple.orchestrator import BudgetTracker
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.runner import (
    checkpoint_handoffs,
    persist_handoffs,
    resume_specialists,
    start_engagement,
)
from kryonsec.purple.specialist import SpecialistScheduler, SpecialistTask
from kryonsec.storage import get_purple_session, init_purple_db, reset_engine
from kryonsec.storage.models import HandoffSchedulerRow


@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = None
    yield config
    reset_engine()


def _scratch_audit(name: str | None = None) -> AuditLog:
    return AuditLog(
        Path("/tmp") / f"resume-audit-{name or uuid.uuid4().hex[:10]}.jsonl")


def _events(audit: AuditLog) -> list[dict]:
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _only(events: list[dict], name: str) -> list[dict]:
    return [e for e in events if e.get("event") == name]


def _assignment(engagement: str = "e-1", **kw) -> TaskAssignment:
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


def _coordinator(engagement: str = "e-1", audit: AuditLog | None = None,
                 graph: EngagementGraph | None = None) -> HandoffCoordinator:
    return HandoffCoordinator(
        engagement_id=engagement,
        graph=graph if graph is not None else EngagementGraph(engagement),
        audit=audit if audit is not None else _scratch_audit(),
    )


def _one_task(coord: HandoffCoordinator, audit: AuditLog,
              budget: BudgetTracker | None = None) -> tuple[
                  SpecialistScheduler, str]:
    scheduler = SpecialistScheduler(coord, audit, budget=budget)
    task_id = coord.register(_assignment(engagement=coord.engagement_id)
                             ).record.message_id
    scheduler.submit(SpecialistTask(
        engagement_id=coord.engagement_id, task_id=task_id,
        role="evidence_assessment", stage="HYPOTHESIZE"))
    return scheduler, task_id


# ---- the checkpoint -----------------------------------------------------------


def test_checkpoint_writes_records_and_scheduler_in_one_moment(cfg):
    audit = _scratch_audit()
    coord = _coordinator("e-ck", audit=audit)
    budget = BudgetTracker(max_tokens=10_000)
    budget.record_usage(123, estimate=True)
    scheduler, task_id = _one_task(coord, audit, budget=budget)

    assert checkpoint_handoffs(
        cfg, "e-ck", coord, audit, "VERIFY", scheduler=scheduler) is True
    written = _only(_events(audit), "handoff_checkpoint_written")[0]
    assert written["records"] == 1

    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        restored = load_handoffs(session, "e-ck")
        payload = load_scheduler_payload(session, "e-ck")
    assert [r.message_id for r in restored.records()] == [task_id]
    assert payload["version"] == 1
    assert payload["engagement_id"] == "e-ck"
    assert [t["task_id"] for t in payload["tasks"]] == [task_id]
    assert payload["budget"]["used_tokens"] == 123


def test_saving_twice_replaces_the_scheduler_row(cfg):
    audit = _scratch_audit()
    coord = _coordinator("e-replace", audit=audit)
    scheduler, _ = _one_task(coord, audit)
    for _ in range(2):
        assert checkpoint_handoffs(
            cfg, "e-replace", coord, audit, "VERIFY",
            scheduler=scheduler) is True
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        rows = session.query(HandoffSchedulerRow).filter(
            HandoffSchedulerRow.engagement_id == "e-replace").all()
    assert len(rows) == 1


def test_checkpoint_without_scheduler_leaves_no_row(cfg):
    audit = _scratch_audit()
    coord = _coordinator("e-bare", audit=audit)
    coord.register(_assignment(engagement="e-bare"))
    assert checkpoint_handoffs(cfg, "e-bare", coord, audit, "HYPOTHESIZE") \
        is True
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        assert load_scheduler_payload(session, "e-bare") is None


# ---- the resume flow ------------------------------------------------------------


def test_resume_restores_records_tasks_and_budget(cfg):
    """The full resume: prior rows restore the coordinator, the scheduler
    re-creates its tasks, and the budget continues — never resets."""
    audit = _scratch_audit()
    coord = _coordinator("e-resume", audit=audit)
    budget = BudgetTracker(max_tokens=10_000)
    budget.record_usage(444, estimate=True)
    scheduler, task_id = _one_task(coord, audit, budget=budget)
    assert persist_handoffs(
        cfg, "e-resume", coord, audit, scheduler=scheduler) is True

    fresh_coord = _coordinator("e-resume")
    fresh_audit = _scratch_audit()
    fresh_budget = BudgetTracker(max_tokens=10_000)
    resumed_coord, resumed = resume_specialists(
        cfg, "e-resume", fresh_coord, fresh_audit, fresh_budget)

    assert [r.message_id for r in resumed_coord.records()] == [task_id]
    assert [t.task_id for t in resumed.tasks()] == [task_id]
    assert fresh_budget.used_tokens == 444        # restored, not reset
    assert fresh_budget.estimated_tokens == 444
    events = _events(fresh_audit)
    detected = _only(events, "specialist_resume_detected")[0]
    assert detected["records"] == 1
    resumed_event = _only(events, "specialist_resumed")[0]
    assert resumed_event["budget_used_tokens"] == 444
    assert resumed_event["recovered"]["reopened_read_only"] == 0


def test_resume_reopens_read_only_and_gates_state_changing(cfg):
    """The recovery pass, end to end through storage: interrupted
    read-only work reopens; interrupted state-changing work is parked
    behind Gate 2 — never automatically re-run."""
    audit = _scratch_audit()
    coord = _coordinator("e-recover", audit=audit)
    read_only = coord.register(
        _assignment(engagement="e-recover", subject_ref="H1")
    ).record.message_id
    state_changing = coord.register(
        _assignment(engagement="e-recover", task_type="exploit_test",
                    destination="EXPLOIT", subject_ref="H1")
    ).record.message_id
    coord.claim(read_only)
    coord.claim(state_changing)
    scheduler = SpecialistScheduler(coord, audit)
    scheduler.submit(SpecialistTask(
        engagement_id="e-recover", task_id=read_only,
        role="evidence_assessment", stage="HYPOTHESIZE"))
    assert persist_handoffs(
        cfg, "e-recover", coord, audit, scheduler=scheduler) is True

    fresh_audit = _scratch_audit()
    fresh_coord = _coordinator("e-recover")
    restored_coord, resumed = resume_specialists(
        cfg, "e-recover", fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))

    restored = {r.message_id: r for r in restored_coord.records()}
    assert restored[read_only].status == "blocked"
    assert restored[read_only].attempts == 1     # attempts preserved
    assert "reopened" in restored[read_only].blocked_reason
    assert restored[state_changing].status == "needs_approval"
    assert restored[state_changing].approval_gate == "GATE_2"
    assert [t.task_id for t in resumed.tasks()] == [read_only]
    events = _events(fresh_audit)
    assert _only(events, "specialist_resume_reopened")
    assert _only(events, "specialist_resume_gated")


def test_resume_without_scheduler_checkpoint_is_partial_and_fresh(cfg):
    """Records without a scheduler snapshot: the records are the identity
    base, restored; the scheduler starts fresh (and re-derivation is
    identity-deduped, so nothing re-runs)."""
    audit = _scratch_audit()
    coord = _coordinator("e-partial", audit=audit)
    task_id = coord.register(
        _assignment(engagement="e-partial")).record.message_id
    assert persist_handoffs(cfg, "e-partial", coord, audit) is True

    fresh_audit = _scratch_audit()
    fresh_coord = _coordinator("e-partial")
    restored_coord, resumed = resume_specialists(
        cfg, "e-partial", fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))
    assert [r.message_id for r in restored_coord.records()] == [task_id]
    assert resumed.tasks() == []
    partial = _only(_events(fresh_audit), "specialist_resume_partial")[0]
    assert partial["reason"] == "no scheduler checkpoint"


def test_fresh_engagement_is_quiet(cfg):
    """No prior rows: a genuinely fresh engagement — nothing restored,
    nothing announced."""
    audit = _scratch_audit()
    audit.write({"event": "test_marker"})   # the chain exists, then nothing
    coord = _coordinator("e-fresh", audit=audit)
    _, resumed = resume_specialists(
        cfg, "e-fresh", coord, audit, BudgetTracker(max_tokens=10_000))
    assert resumed.tasks() == []
    assert coord.records() == []
    events = _events(audit)
    assert not [e for e in events
                if e.get("event", "").startswith("specialist_resume")]


def test_replay_after_resume_is_free(cfg):
    """Resume then checkpoint again: the same rows, the same snapshot —
    replaying the save cannot duplicate or drift."""
    audit = _scratch_audit()
    coord = _coordinator("e-replay", audit=audit)
    scheduler, task_id = _one_task(coord, audit)
    assert persist_handoffs(
        cfg, "e-replay", coord, audit, scheduler=scheduler) is True

    fresh_coord = _coordinator("e-replay")
    fresh_audit = _scratch_audit()
    restored_coord, resumed = resume_specialists(
        cfg, "e-replay", fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))
    assert persist_handoffs(
        cfg, "e-replay", restored_coord, fresh_audit,
        scheduler=resumed) is True

    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        reloaded = load_handoffs(session, "e-replay")
        payload = load_scheduler_payload(session, "e-replay")
    assert [r.message_id for r in reloaded.records()] == [task_id]
    assert [t["task_id"] for t in payload["tasks"]] == [task_id]


# ---- corrupt / incompatible checkpoints ------------------------------------------


def _row_payload(cfg, engagement_id: str, payload: dict) -> None:
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        session.query(HandoffSchedulerRow).filter(
            HandoffSchedulerRow.engagement_id == engagement_id
        ).delete(synchronize_session=False)
        session.add(HandoffSchedulerRow(
            engagement_id=engagement_id, payload=payload))
        session.commit()


def test_wrong_version_scheduler_payload_is_refused_audited_and_fresh(cfg):
    audit = _scratch_audit()
    coord = _coordinator("e-version", audit=audit)
    coord.register(_assignment(engagement="e-version"))
    assert persist_handoffs(cfg, "e-version", coord, audit) is True
    _row_payload(cfg, "e-version", {"version": 99})

    fresh_audit = _scratch_audit()
    fresh_coord = _coordinator("e-version")
    restored_coord, resumed = resume_specialists(
        cfg, "e-version", fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))
    # the records restored; the scheduler snapshot did not
    assert len(restored_coord.records()) == 1
    assert resumed.tasks() == []
    failed = _only(_events(fresh_audit), "specialist_resume_failed")[0]
    assert failed["reason"] == "scheduler_checkpoint_unusable"
    assert "version" in failed["error"]


def test_cross_engagement_scheduler_payload_is_refused(cfg):
    audit = _scratch_audit()
    coord = _coordinator("e-cross", audit=audit)
    coord.register(_assignment(engagement="e-cross"))
    assert persist_handoffs(cfg, "e-cross", coord, audit) is True
    _row_payload(cfg, "e-cross", {
        "version": 1, "engagement_id": "e-other", "tasks": [],
    })

    fresh_audit = _scratch_audit()
    fresh_coord = _coordinator("e-cross")
    restored_coord, resumed = resume_specialists(
        cfg, "e-cross", fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))
    assert len(restored_coord.records()) == 1
    assert resumed.tasks() == []
    failed = _only(_events(fresh_audit), "specialist_resume_failed")[0]
    assert failed["reason"] == "scheduler_checkpoint_unusable"
    assert "e-other" in failed["error"]


def test_unreadable_scheduler_row_is_refused(cfg):
    audit = _scratch_audit()
    coord = _coordinator("e-unreadable", audit=audit)
    coord.register(_assignment(engagement="e-unreadable"))
    assert persist_handoffs(cfg, "e-unreadable", coord, audit) is True
    _row_payload(cfg, "e-unreadable", "not a dict")

    fresh_audit = _scratch_audit()
    fresh_coord = _coordinator("e-unreadable")
    restored_coord, resumed = resume_specialists(
        cfg, "e-unreadable", fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))
    assert len(restored_coord.records()) == 1
    assert resumed.tasks() == []
    failed = _only(_events(fresh_audit), "specialist_resume_failed")[0]
    assert failed["reason"] == "scheduler_checkpoint_unusable"


def test_corrupt_record_row_refuses_the_whole_resume(cfg):
    """A handoff row this build cannot read refuses the records too —
    never half-interpreted: audited, fresh, the engagement continues."""
    audit = _scratch_audit()
    coord = _coordinator("e-badrow", audit=audit)
    coord.register(_assignment(engagement="e-badrow"))
    assert persist_handoffs(cfg, "e-badrow", coord, audit) is True

    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        from kryonsec.storage.models import HandoffRecordRow

        row = session.query(HandoffRecordRow).filter(
            HandoffRecordRow.engagement_id == "e-badrow").one()
        row.payload = {"version": 999, "record": {}}
        session.commit()

    fresh_audit = _scratch_audit()
    fresh_coord = _coordinator("e-badrow")
    _, resumed = resume_specialists(
        cfg, "e-badrow", fresh_coord, fresh_audit,
        BudgetTracker(max_tokens=10_000))
    assert fresh_coord.records() == []
    assert resumed.tasks() == []
    failed = _only(_events(fresh_audit), "specialist_resume_failed")[0]
    assert failed["reason"] == "storage_unreadable"


# ---- the full runner integration ----------------------------------------------


def test_start_engagement_twice_restores_specialist_state(cfg):
    """The runner-level resume: a second start_engagement on the SAME id
    restores the prior scheduler, its tasks and the budget spend."""
    orch, audit, _ = start_engagement(cfg, "e-twice", target="example.com")
    coord = orch.handoff_coordinator
    budget = orch.specialist_scheduler.budget
    budget.record_usage(222, estimate=True)
    scheduler, task_id = _one_task(coord, audit, budget=budget)
    assert persist_handoffs(
        cfg, "e-twice", coord, audit, scheduler=scheduler) is True

    orch2, audit2, _ = start_engagement(cfg, "e-twice", target="example.com")
    assert [t.task_id for t in orch2.specialist_scheduler.tasks()] == \
        [task_id]
    assert [r.message_id for r in orch2.handoff_coordinator.records()] == \
        [task_id]
    assert orch2.specialist_scheduler.budget.used_tokens == 222
    resumed = _only(_events(audit2), "specialist_resumed")
    assert resumed and resumed[-1]["budget_used_tokens"] == 222
