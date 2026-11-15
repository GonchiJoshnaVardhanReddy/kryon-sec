"""Bounded specialist scheduling (Batch 4A/4C, ARTEX-inspired coordination).

The Batch-3 coordinator records and de-duplicates handoffs. This module is
the layer above it that *runs* bounded specialist work — deterministically,
inside the same single-threaded state-boundary the graph checkpoint uses,
with no new authority:

* **The orchestrator stays the only lifecycle authority.** A specialist
  task runs in the boundary AFTER a state completed (the graph is
  quiescent, nothing is mid-write) and can never trigger the next state,
  enter EXPLOIT/POST_EXPLOIT, launch a tool or touch the network. Every
  executor in :data:`EXECUTORS` is a read-only graph analysis; a role
  whose real implementation is an LLM state is described honestly and
  *deferred*, never improvised.
* **Roles are capability descriptions, not agents.** A role entry says
  which lifecycle stage the work belongs to and what existing
  implementation covers it. Describing a role does not create an
  executable LLM agent — the executor registry is the only thing that
  runs.
* **Tasks are typed and validated.** :class:`SpecialistTask` references a
  coordinator ``TaskAssignment`` record by message id, carries a role,
  stage, priority, dependencies and a bounded timeout. Malformed tasks are
  refused at the schema.
* **Claims are atomic.** Claiming goes through the coordinator's own
  transition table (``registered -> in_progress``), so a second claim of
  the same task is refused loudly, and an attempts cap bounds retries —
  read-only work only; a failed state-changing task never re-runs this
  way at all.
* **Duplicate work stays impossible.** Task creation flows through the
  coordinator's content-addressed dedup, and this layer's event ledger
  (:class:`SpecialistEventLedger`) de-duplicates *notifications* so
  repeated boundaries cannot loop: a rule that fired once never fires
  again for the same fact, and no rule creates tasks — only
  :meth:`SpecialistScheduler.derive_from_records` does, identity-deduped.
* **Timeouts are checked, not assumed.** A claimed task past its bounded
  deadline is moved to ``blocked`` with the reason kept; recovery rules in
  Batch 4C turn an interrupted read-only task back into claimable work
  and an interrupted state-changing task into ``needs_approval`` — the
  human gate, never an automatic re-run.

Nothing here reads the sandbox, the allowlists, the LLM client or the
Copilot database.
"""

from __future__ import annotations

import logging

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .audit import AuditLog
from .coordinator import HandoffCoordinator, HandoffError
from .deliverables import BudgetUsage, DeliverableClaim, SpecialistDeliverable
from .handoff import (
    _ID_RE,
    _STAGE_RE,
    MAX_NOTE_CHARS,
    TASK_TYPES,
    DispatchDecision,
    HandoffRecord,
    TaskAssignment,
    TaskResult,
    _one_line,
    new_message_id,
    task_safety,
    utc_now_iso,
)
from .handoff_store import SCHEDULER_FORMAT_VERSION
from .orchestrator import STATES
from .views import claim_text, hypothesis_engine_view

log = logging.getLogger(__name__)

__all__ = [
    "SPECIALIST_ROLES",
    "SpecialistRole",
    "SpecialistTask",
    "SpecialistScheduler",
    "SpecialistBudget",
    "SpecialistEventLedger",
    "EvidenceAssessmentSpecialist",
    "EXECUTORS",
    "SpecialistError",
    "evidence_questions",
    "recover_for_resume",
]


class SpecialistError(Exception):
    """A scheduling failure that is the caller's bug, not task data."""


# ---- the roles --------------------------------------------------------------
#
# Typed capability descriptions. ``implements`` is the honest mapping to
# what EXISTS in this codebase today — a role with no deterministic
# executor is deferred, and its description says exactly that.

class SpecialistRole(BaseModel):
    """One specialist capability, mapped to existing implementations."""

    model_config = ConfigDict(extra="forbid", validate_default=True)

    name: str
    task_type: str          # a registered TASK_TYPES entry (safety derives)
    stages: frozenset[str]  # lifecycle states this role may run in
    implements: str         # what actually covers this role today
    llm: bool = False       # whether the real implementation calls an LLM
    executor: str | None = None  # the deterministic executor's name, if any

    @field_validator("name", "implements", mode="before")
    @classmethod
    def _clean_names(cls, value):
        return _one_line(value, 120)

    @field_validator("task_type")
    @classmethod
    def _valid_task_type(cls, value: str) -> str:
        if value not in TASK_TYPES:
            raise ValueError(
                f"role task_type {value!r} is not a registered task type")
        return value

    @field_validator("stages", mode="before")
    @classmethod
    def _clean_stages(cls, value):
        if isinstance(value, str):
            return frozenset({value})
        return frozenset(entry for entry in value if isinstance(entry, str))


SPECIALIST_ROLES: dict[str, SpecialistRole] = {r.name: r for r in [
    SpecialistRole(
        name="recon_analysis",
        task_type="recon_passive",
        stages={"RECON_PASSIVE", "RECON_ACTIVE"},
        implements=(
            "deterministic summarization over graph asset nodes "
            "(views.observed_assets); no executor wired in Batch 4 — "
            "the recon states themselves cover it"),
        executor=None,
    ),
    SpecialistRole(
        name="hypothesis_analysis",
        task_type="hypothesize",
        stages={"HYPOTHESIZE"},
        implements=(
            "the HYPOTHESIZE subagent (LLM, runs in its own lifecycle "
            "state); deterministic support via views.hypothesis_engine_view"),
        llm=True,
        executor=None,
    ),
    SpecialistRole(
        name="evidence_assessment",
        task_type="evidence_assessment",
        stages={"HYPOTHESIZE"},
        implements=(
            "deterministic engine-view assessment of one hypothesis's "
            "evidence standing (views.hypothesis_engine_view) — the "
            "Batch 4 end-to-end specialist"),
        executor="evidence_assessment",
    ),
    SpecialistRole(
        name="verification_support",
        task_type="verify_check",
        stages={"VERIFY"},
        implements=(
            "the VERIFY state's boolean probes (sandbox, runs in its own "
            "lifecycle state); deterministic support via "
            "views.verification_status"),
        executor=None,
    ),
    SpecialistRole(
        name="defensive_recommendation",
        task_type="blue_team_scan",
        stages={"BLUE_TEAM"},
        implements=(
            "the BLUE_TEAM subagent (LLM) plus the static scanners, both "
            "running in their own lifecycle state"),
        llm=True,
        executor=None,
    ),
    SpecialistRole(
        name="reporting",
        task_type="report_compile",
        stages={"REPORT"},
        implements=(
            "the deterministic report compiler (purple.report), running "
            "in its own lifecycle state"),
        executor=None,
    ),
]}


def role_of(name: str) -> SpecialistRole:
    try:
        return SPECIALIST_ROLES[name]
    except KeyError:
        raise SpecialistError(
            f"unknown specialist role {name!r}; registered roles: "
            + ", ".join(sorted(SPECIALIST_ROLES))) from None


# ---- the task schema ---------------------------------------------------------

class SpecialistTask(BaseModel):
    """One bounded unit of specialist work, referencing a coordinator task.

    ``task_id`` is the message id of an existing ``TaskAssignment`` record —
    the specialist layer never invents work; it schedules what the
    engagement's records already describe. The safety class comes from the
    task type via :func:`task_safety`, never from the submitter.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    engagement_id: str
    task_id: str
    role: str
    stage: str
    priority: int = 50
    depends_on: list[str] = Field(default_factory=list)
    timeout_s: int = 600
    created_at: str = ""
    last_claimed_at: str = ""
    outcome_note: str = ""
    deliverable: dict | None = None   # the last SpecialistDeliverable, as data

    @field_validator("engagement_id", "task_id", "role", "stage",
                     mode="before")
    @classmethod
    def _clean_names(cls, value):
        return _one_line(value, 64)

    @field_validator("task_id")
    @classmethod
    def _valid_task_id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError("task_id must be a handoff message id")
        return value

    @field_validator("stage")
    @classmethod
    def _valid_stage(cls, value: str) -> str:
        if not _STAGE_RE.match(value):
            raise ValueError("stage must be a lifecycle state name")
        if value not in STATES:
            raise ValueError(
                f"stage {value!r} is not a lifecycle state "
                f"(the loop's states: {', '.join(STATES)})")
        return value

    @field_validator("priority", mode="before")
    @classmethod
    def _valid_priority(cls, value) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("priority must be an int")
        if not 0 <= value <= 100:
            raise ValueError("priority must be 0-100")
        return value

    @field_validator("timeout_s", mode="before")
    @classmethod
    def _valid_timeout(cls, value) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("timeout_s must be an int")
        if not 10 <= value <= 3600:
            raise ValueError("timeout_s must be 10-3600 seconds")
        return value

    @field_validator("depends_on", mode="before")
    @classmethod
    def _clean_deps(cls, value):
        if not isinstance(value, (list, tuple)):
            return []
        kept: list[str] = []
        for entry in value:
            text = _one_line(entry, 64)
            if not text or not _ID_RE.match(text) or text in kept:
                continue
            kept.append(text)
            if len(kept) == 8:
                break
        return kept

    @field_validator("created_at", "last_claimed_at", mode="before")
    @classmethod
    def _clean_times(cls, value):
        if value in (None, ""):
            return utc_now_iso() if value is not None else ""
        return _one_line(value, 40)

    @field_validator("outcome_note", mode="before")
    @classmethod
    def _clean_note(cls, value):
        return _one_line(value, MAX_NOTE_CHARS)


# ---- the budget policy --------------------------------------------------------

class SpecialistBudget(BaseModel):
    """The bounds specialist work may consume, as honest token estimates.

    The engagement-wide ceiling lives on the orchestrator's
    :class:`~orchestrator.BudgetTracker` — the LLM states accrue there and
    the loop's guard reads it. The specialist layer reserves against the
    SAME tracker, so specialist context reads and LLM work compete for one
    budget instead of two. ``max_tokens_per_task`` and
    ``max_tokens_per_role`` are this layer's own bounds, applied before a
    reservation is attempted.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    max_tokens_per_task: int = 4_000
    max_tokens_per_role: int = 24_000

    @field_validator("max_tokens_per_task", "max_tokens_per_role")
    @classmethod
    def _positive(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError("budget bounds must be positive ints")
        return value

    @model_validator(mode="after")
    def _sane_order(self) -> "SpecialistBudget":
        if self.max_tokens_per_task > self.max_tokens_per_role:
            raise ValueError(
                "max_tokens_per_task cannot exceed max_tokens_per_role")
        return self


# ---- the event ledger (4C, ARTEX-inspired) ------------------------------------

class SpecialistEventLedger:
    """De-duplicated notifications about engagement facts.

    ARTEX wakes its planner on events; here the same idea is reduced to
    what a deterministic engine may do with them: **write an audit line,
    once per fact**. Rules never create tasks (task creation is the
    identity-deduped derivation only), never authorize anything, never
    widen scope — so a repeated notification cannot loop or accumulate
    work. The processed set is bounded (oldest entries are dropped) and
    persists with the scheduler so a restored run cannot re-notify.
    """

    MAX_LEDGER = 500

    def __init__(self, processed: dict[str, str] | None = None):
        self._processed: dict[str, str] = dict(processed or {})

    @staticmethod
    def fact_key(event: str, *parts: str) -> str:
        """A stable key for one fact. Caller-provided parts are ids this
        layer already trusts (message ids, node ids) — never free text."""
        return event + ":" + "|".join(parts)

    def seen(self, key: str) -> bool:
        return key in self._processed

    def mark(self, key: str) -> None:
        if len(self._processed) >= self.MAX_LEDGER:
            # drop the oldest — bounded memory, and the audit chain keeps
            # the full history anyway
            for old in list(self._processed)[: self.MAX_LEDGER // 4]:
                self._processed.pop(old, None)
        self._processed[key] = utc_now_iso()

    def to_dict(self) -> dict[str, str]:
        return dict(self._processed)

    @classmethod
    def from_dict(cls, data: dict | None) -> "SpecialistEventLedger":
        if data is None:
            return cls()
        if not isinstance(data, dict):
            raise SpecialistError("event ledger payload must be an object")
        ledger = cls()
        for key, ts in data.items():
            if isinstance(key, str) and isinstance(ts, str):
                ledger._processed[key] = ts
        return ledger


# ---- the deterministic executors ----------------------------------------------
#
# One executor per role that can actually run today. Everything here is a
# read-only graph analysis: no LLM, no sandbox, no network, no tool.

class EvidenceAssessmentSpecialist:
    """Assesses one hypothesis's evidence standing — the Batch 4 specialist.

    The analysis path is the one the report and the memory browser already
    read: :func:`views.hypothesis_engine_view`. What it produces is the
    engine's own grading of the hypothesis — proposed / supported / tested /
    validated, the exploit status and the verification status — plus the
    deterministic unresolved questions. No model text can move the result:
    a hypothesis whose prose says ``confirmed`` assesses exactly like one
    that says nothing.
    """

    role_name = "evidence_assessment"

    def run(
        self,
        task: SpecialistTask,
        record: HandoffRecord,
        coordinator: HandoffCoordinator,
    ) -> tuple[SpecialistDeliverable, BudgetUsage]:
        engagement = coordinator.engagement_id
        subject = record.subject_ref
        hypothesis = next(
            (n for n in coordinator.graph.by_type("hypothesis")
             if n.get("label") == subject),
            None,
        )
        errors: list[str] = []
        claims: list[DeliverableClaim] = []

        if hypothesis is None:
            # The hypothesis this task is about does not exist in THIS
            # engagement's graph. That is a fact about the task, not a
            # failure to paper over.
            status = "blocked"
            standing = "unresolved"
            summary = f"no hypothesis {subject!r} in this engagement's graph"
            unresolved = [
                f"hypothesis {subject} was not found in the engagement graph"
            ]
            tokens = self._estimate(coordinator, task, "")
            return self._deliverable(
                task, engagement, status, standing, summary,
                claims, [], unresolved, errors,
                BudgetUsage(tokens=tokens), record,
            ), BudgetUsage(tokens=tokens)

        view = hypothesis_engine_view(hypothesis, coordinator.graph)
        status = "completed"
        standing = view["basis"]
        summary = (
            f"evidence standing of {subject}: {view['basis']} "
            f"(exploit: {view['exploit_status']}, verification: "
            f"{view['verification_status']})")
        claims.append(DeliverableClaim(
            subject_ref=subject,
            standing=standing,
            note=claim_text(view["basis_note"], MAX_NOTE_CHARS),
        ))
        if view["tested"]:
            claims.append(DeliverableClaim(
                subject_ref=subject,
                standing=view["exploit_status"],
                note=claim_text(view["exploit_note"], MAX_NOTE_CHARS),
            ))
        claims.append(DeliverableClaim(
            subject_ref=subject,
            standing=view["verification_status"],
            note=claim_text(view["verification_note"], MAX_NOTE_CHARS),
        ))

        unresolved = self._unresolved_questions(view, subject)
        tokens = self._estimate(coordinator, task, summary)

        return self._deliverable(
            task, engagement, status, standing, summary,
            claims, [hypothesis["id"]], unresolved, errors,
            BudgetUsage(tokens=tokens), record,
        ), BudgetUsage(tokens=tokens)

    def _unresolved_questions(self, view: dict, subject: str) -> list[str]:
        return evidence_questions(view, subject)

    def _estimate(
        self, coordinator: HandoffCoordinator, task: SpecialistTask,
        summary: str,
    ) -> int:
        """Honest estimate of the tokens this task's context + output size.

        Marked as an estimate everywhere it is recorded — a deterministic
        read has no provider usage to report, so its number must never be
        presented as a charge.
        """
        from ..llm import count_tokens

        nodes = len(coordinator.graph.nodes)
        return count_tokens(
            f"{task.role} {task.task_id} {summary} nodes={nodes}") + 24

    def _deliverable(
        self,
        task: SpecialistTask,
        engagement: str,
        status: str,
        standing: str,
        summary: str,
        claims: list[DeliverableClaim],
        evidence_refs: list[str],
        unresolved: list[str],
        errors: list[str],
        usage: BudgetUsage,
        record: HandoffRecord,
    ) -> SpecialistDeliverable:
        return SpecialistDeliverable(
            task_id=task.task_id,
            producer=self.role_name,
            source_stage=task.stage,
            status=status,
            standing=standing,
            summary=summary,
            evidence_refs=evidence_refs,
            claims=claims,
            limitations=[
                "deterministic engine-view assessment — it grades what the "
                "engagement recorded, it does not test anything",
            ],
            unresolved=unresolved,
            errors=errors,
            budget=usage,
        )


EXECUTORS: dict[str, object] = {
    "evidence_assessment": EvidenceAssessmentSpecialist(),
}


# ---- the scheduler --------------------------------------------------------------

class SpecialistScheduler:
    """Submits, orders, claims, runs and accounts for specialist tasks.

    Runs inside the state boundary (single-threaded), deterministic, and
    bounded in every direction that matters: attempts per task, tokens per
    task and role, timeout per claim, ledger size, tasks derived per
    boundary.
    """

    MAX_ATTEMPTS = 2
    MAX_TASKS_PER_BOUNDARY = 12
    ROLE = "evidence_assessment"  # the derivation's role

    def __init__(
        self,
        coordinator: HandoffCoordinator,
        audit: AuditLog,
        budget: object | None = None,
        policy: SpecialistBudget | None = None,
        ledger: SpecialistEventLedger | None = None,
    ):
        self.coordinator = coordinator
        self.audit = audit
        self.budget = budget
        self.policy = policy or SpecialistBudget()
        self.ledger = ledger or SpecialistEventLedger()
        self._tasks: dict[str, SpecialistTask] = {}
        # per-role token consumption this session has committed — the
        # role-level bound
        self._role_tokens: dict[str, int] = {}

    # -- submission -------------------------------------------------------

    def submit(self, task: SpecialistTask) -> str:
        """Register one specialist task against its coordinator record.

        Refused (loudly) when the task is malformed, names an unknown
        role, points at a record this coordinator does not hold, or a
        task with this id is already scheduled. The task's stage must be
        one of its role's stages and the record's task type must match
        the role's — a specialist cannot be scheduled for work its role
        does not describe.
        """
        if not isinstance(task, SpecialistTask):
            raise SpecialistError("submit() takes a SpecialistTask")
        if task.engagement_id != self.coordinator.engagement_id:
            raise SpecialistError(
                f"task {task.task_id} belongs to engagement "
                f"{task.engagement_id!r}, not "
                f"{self.coordinator.engagement_id!r}")
        role = role_of(task.role)
        record = self.coordinator.get(task.task_id)
        if record is None:
            raise SpecialistError(
                f"task {task.task_id} cites no known handoff record")
        if record.kind != "task_assignment":
            raise SpecialistError(
                f"task {task.task_id} cites a {record.kind!r} record; "
                "only task assignments are schedulable")
        if record.task_type != role.task_type:
            raise SpecialistError(
                f"role {role.name!r} covers task type {role.task_type!r}, "
                f"not {record.task_type!r}")
        if task.stage not in role.stages:
            raise SpecialistError(
                f"role {role.name!r} does not run in stage "
                f"{task.stage!r} (its stages: {sorted(role.stages)})")
        if task.task_id in self._tasks:
            self.audit.write({
                "event": "specialist_duplicate_suppressed",
                "task_id": task.task_id,
                "role": task.role,
            })
            return "already_submitted"

        for dep in task.depends_on:
            if dep == task.task_id:
                raise SpecialistError("a task cannot depend on itself")
        self._tasks[task.task_id] = task
        self.audit.write({
            "event": "specialist_submitted",
            "task_id": task.task_id,
            "role": task.role,
            "stage": task.stage,
            "priority": task.priority,
            "depends_on": task.depends_on,
            "timeout_s": task.timeout_s,
        })
        return "new"

    def submit_proposal(
        self,
        task_type: str,
        subject_ref: str,
        content: str,
        source: str,
        target_asset: str = "",
        depends_on: list[str] | None = None,
        priority: int = 50,
    ) -> DispatchDecision:
        """File a PROPOSED task for review-as-data, then schedule it.

        This is the only door a model suggestion gets, and it is a
        proposal, not an instruction: the suggestion is registered as a
        TaskAssignment through the coordinator (so engagement, evidence
        refs and the dedup identity all apply), and it is scheduled only
        if it names a registered READ-ONLY task type. A state-changing
        proposal is refused at the door — no agent may talk new target
        work into existence.
        """
        try:
            safety = task_safety(task_type)
        except ValueError as e:
            self.audit.write({
                "event": "specialist_proposal_refused",
                "reason": str(e)[:200],
                "task_type": claim_text(task_type, 32),
            })
            raise SpecialistError(str(e)) from None
        if safety != "read_only":
            self.audit.write({
                "event": "specialist_proposal_refused",
                "reason": "proposals cannot create state-changing work",
                "task_type": claim_text(task_type, 32),
            })
            raise SpecialistError(
                f"{task_type!r} is state-changing: a proposal cannot "
                "create target-affecting work — that stays with the "
                "lifecycle gates")
        role = next(
            (r for r in SPECIALIST_ROLES.values()
             if r.task_type == task_type and r.executor),
            None,
        )
        if role is None:
            self.audit.write({
                "event": "specialist_proposal_refused",
                "reason": "no deterministic executor covers this task type",
                "task_type": claim_text(task_type, 32),
            })
            raise SpecialistError(
                f"no deterministic executor covers {task_type!r}")
        decision = self.coordinator.register(TaskAssignment(
            engagement_id=self.coordinator.engagement_id,
            message_id=new_message_id(),
            source=claim_text(source, 64) or "specialist_proposal",
            destination="specialist",
            task_type=task_type,
            subject_ref=claim_text(subject_ref, 80),
            target_asset=claim_text(target_asset, 300),
            content=claim_text(content, 400),
        ))
        # Dedup returns the record the identity already has — schedule by
        # ITS id, so a re-filed proposal can never become a second task
        # for work that is already scheduled (or already finished).
        record = decision.record
        if record is not None and record.message_id not in self._tasks:
            self.submit(SpecialistTask(
                engagement_id=self.coordinator.engagement_id,
                task_id=record.message_id,
                role=role.name,
                stage=sorted(role.stages)[0],
                priority=priority,
                depends_on=depends_on or [],
            ))
        return decision

    # -- derivation ---------------------------------------------------------

    def derive_from_records(self, state: str) -> int:
        """Schedule specialist tasks for this boundary's own records.

        The deterministic rule, stated once: every ``evidence_assessment``
        TaskAssignment registered during the ``HYPOTHESIZE`` boundary
        becomes one ``evidence_assessment`` specialist task (identity
        dedup keeps re-derivations free). Nothing else derives tasks —
        this is why repeated notifications cannot create endless work.
        """
        if state != "HYPOTHESIZE":
            return 0
        created = 0
        for record in self.coordinator.records():
            if record.kind != "task_assignment":
                continue
            if record.task_type != "evidence_assessment":
                continue
            if record.message_id in self._tasks:
                continue
            if created >= self.MAX_TASKS_PER_BOUNDARY:
                self.audit.write({
                    "event": "specialist_derivation_capped",
                    "state": state,
                    "cap": self.MAX_TASKS_PER_BOUNDARY,
                })
                break
            self.submit(SpecialistTask(
                engagement_id=self.coordinator.engagement_id,
                task_id=record.message_id,
                role=self.ROLE,
                stage=state,
            ))
            created += 1
        return created

    # -- readiness ------------------------------------------------------------

    def readiness(self, task_id: str) -> tuple[bool, str]:
        """Whether a task may be claimed now, and why not.

        The checks, in order: known task; the record is registered; its
        stage is eligible for the CURRENT lifecycle state (specialists
        only ever run inside the boundary of their own state); the
        dependencies completed; attempts under the cap.
        """
        task = self._tasks.get(task_id)
        if task is None:
            return False, "not scheduled"
        record = self.coordinator.get(task_id)
        if record is None:
            return False, "record vanished"
        if record.status in ("registered", "blocked"):
            # blocked work may be re-claimed within the attempts cap —
            # ``blocked -> in_progress`` is a legal coordinator transition,
            # and a timed-out claim is exactly what deserves one
            pass
        elif record.status == "in_progress":
            return False, "already in progress"
        elif record.status in ("needs_approval", "cancelled"):
            return False, f"record is {record.status}"
        elif record.status in ("failed", "inconclusive"):
            return False, f"record is {record.status} (retries go through "
            "the coordinator's rules)"
        else:  # completed — the dedup ladder already says so
            return False, "already completed"
        if record.attempts >= self.MAX_ATTEMPTS:
            return False, f"attempts exhausted ({record.attempts})"
        for dep in task.depends_on:
            dep_record = self.coordinator.get(dep)
            if dep_record is None:
                return False, f"dependency {dep} unknown"
            if dep_record.status != "completed":
                return False, f"dependency {dep} is {dep_record.status}"
        return True, "ready"

    def ready(self, current_state: str) -> list[SpecialistTask]:
        """Claimable tasks for this boundary, best first.

        Priority descending, then oldest first, then task id — a total
        order so the same state of the world always schedules the same
        way. A task whose role has no deterministic executor IS included:
        :meth:`run_ready` defers it with an audit line (once per task, via
        the ledger) rather than silently pretending it was never there.
        """
        eligible: list[tuple[int, str, str, SpecialistTask]] = []
        for task in self._tasks.values():
            ok, reason = self.readiness(task.task_id)
            if not ok:
                self._note_not_ready(task, reason)
                continue
            if task.stage != current_state:
                continue  # not this boundary's work — simply not ready here
            eligible.append((-task.priority, task.created_at,
                             task.task_id, task))
        eligible.sort()
        return [entry[3] for entry in eligible]

    def _note_not_ready(self, task: SpecialistTask, reason: str) -> None:
        """One audit line per (task, reason) — the ARTEX information-need
        signal, deduplicated so it cannot loop."""
        key = SpecialistEventLedger.fact_key(
            "specialist_not_ready", task.task_id, reason)
        if self.ledger.seen(key):
            return
        self.ledger.mark(key)
        self.audit.write({
            "event": "specialist_not_ready",
            "task_id": task.task_id,
            "role": task.role,
            "reason": reason[:200],
        })

    # -- execution --------------------------------------------------------------

    def run_ready(
        self,
        current_state: str,
        *,
        executor_registry: dict | None = None,
    ) -> dict:
        """Claim and execute every ready task for this boundary.

        For each ready task, in order: reserve budget; claim (atomic — a
        concurrent claim of the same task raises in the coordinator's
        transition table); run the role's executor; record the result
        back through the coordinator (``record_result`` with the task id
        as correlation); link the evidence the deliverable cites;
        commit or release the reservation. A task whose role has no
        deterministic executor is deferred honestly — described, never
        improvised. Budget exhaustion defers rather than blocks: the
        work stays registered and a later boundary may claim it.
        """
        registry = EXECUTORS if executor_registry is None else executor_registry
        summary = {"ran": 0, "failed": 0, "deferred_budget": 0,
                   "deferred_no_executor": 0, "blocked_timeout": 0}
        for task in self.ready(current_state):
            role = role_of(task.role)
            executor = registry.get(role.executor) if role.executor else None
            if executor is None:
                if self._defer_no_executor(task, role):
                    summary["deferred_no_executor"] += 1
                continue
            record = self.coordinator.get(task.task_id)
            if record is None or record.status != "registered":
                continue
            if not self._reserve(task):
                summary["deferred_budget"] += 1
                continue
            try:
                self.coordinator.claim(task.task_id)
            except HandoffError as e:
                # lost the claim race (or the attempts cap): the
                # reservation goes back, the task stays for later
                self._release(task.task_id)
                self.audit.write({
                    "event": "specialist_claim_refused",
                    "task_id": task.task_id,
                    "error": str(e)[:200],
                })
                continue
            task.last_claimed_at = utc_now_iso()
            self.audit.write({
                "event": "specialist_started",
                "task_id": task.task_id,
                "role": task.role,
                "stage": task.stage,
            })
            try:
                deliverable, usage = executor.run(task, record,
                                                  self.coordinator)
            except Exception as exc:
                usage = BudgetUsage(tokens=0)
                self._fail(task, record, exc)
                self._commit(task.task_id, usage)
                summary["failed"] += 1
                continue
            self._complete(task, deliverable, usage)
            summary["ran"] += 1
        return summary

    def _defer_no_executor(self, task: SpecialistTask, role: SpecialistRole
                           ) -> bool:
        key = SpecialistEventLedger.fact_key(
            "specialist_deferred", task.task_id)
        if self.ledger.seen(key):
            return False
        self.ledger.mark(key)
        self.audit.write({
            "event": "specialist_deferred_no_executor",
            "task_id": task.task_id,
            "role": role.name,
            "implements": role.implements[:200],
        })
        return True

    def _reserve(self, task: SpecialistTask) -> bool:
        """Reserve the estimate against the engagement budget.

        A refusal defers, never blocks: budget exhaustion means new
        specialist work waits, exactly like the spec's budget guard.
        """
        if self.budget is None:
            return True
        role_used = self._role_tokens.get(task.role, 0)
        if role_used >= self.policy.max_tokens_per_role:
            self.audit.write({
                "event": "specialist_budget_deferred",
                "task_id": task.task_id,
                "role": task.role,
                "reason": "role budget exhausted",
                "role_tokens_estimated": role_used,
            })
            return False
        reserve = getattr(self.budget, "reserve", None)
        if reserve is None:
            return True
        ok = bool(reserve(f"specialist:{task.task_id}",
                          self.policy.max_tokens_per_task, 0.0))
        if not ok:
            # the tracker refused the reservation: say why the task did
            # not start — deferral is only honest if it is visible
            self.audit.write({
                "event": "specialist_budget_deferred",
                "task_id": task.task_id,
                "role": task.role,
                "reason": "engagement budget bound reached",
            })
        return ok

    def _commit(self, task_id: str, usage: BudgetUsage) -> None:
        if self.budget is None:
            return
        commit = getattr(self.budget, "commit", None)
        if commit is not None:
            commit(f"specialist:{task_id}", usage.tokens, usage.cost_usd,
                   estimate=usage.estimated)

    def _release(self, task_id: str) -> None:
        if self.budget is None:
            return
        release = getattr(self.budget, "release", None)
        if release is not None:
            release(f"specialist:{task_id}")

    def _complete(
        self,
        task: SpecialistTask,
        deliverable: SpecialistDeliverable,
        usage: BudgetUsage,
    ) -> None:
        record = self.coordinator.get(task.task_id)
        if record is None:
            return
        # A deliverable whose status is ``blocked`` is an honest answer —
        # the work could not be carried out — and the record says so the
        # same way a timeout does, through the coordinator's own table,
        # never with a fabricated "completed".
        try:
            if deliverable.status == "blocked":
                self.coordinator.block(
                    task.task_id, claim_text(deliverable.summary, 200))
            else:
                result = TaskResult(
                    engagement_id=self.coordinator.engagement_id,
                    message_id=new_message_id(),
                    source=f"specialist.{deliverable.producer}",
                    destination=record.destination,
                    result_status="completed",
                    subject_ref=record.subject_ref,
                    content=claim_text(deliverable.summary, 400),
                    correlation_id=task.task_id,
                )
                self.coordinator.record_result(task.task_id, result)
        except HandoffError as exc:
            # the task's lifecycle refused the result (e.g. it was
            # cancelled mid-run): the deliverable is still recorded as
            # data, but never over a terminal record
            self.audit.write({
                "event": "specialist_result_refused",
                "task_id": task.task_id,
                "error": str(exc)[:200],
            })
            self._release(task.task_id)
            return
        for node_id in deliverable.evidence_refs:
            try:
                self.coordinator.link_evidence(
                    task.task_id, node_id, "consumed")
            except HandoffError as exc:
                # an evidence ref the graph does not hold is refused
                # loudly — the same rule the coordinator applies at
                # registration
                self.audit.write({
                    "event": "specialist_evidence_refused",
                    "task_id": task.task_id,
                    "node_id": node_id,
                    "error": str(exc)[:200],
                })
        task.outcome_note = claim_text(deliverable.summary, MAX_NOTE_CHARS)
        task.deliverable = deliverable.model_dump()
        self._role_tokens[task.role] = (
            self._role_tokens.get(task.role, 0) + usage.tokens)
        self._commit(task.task_id, usage)
        self.audit.write({
            "event": "specialist_completed",
            "task_id": task.task_id,
            "role": task.role,
            "standing": deliverable.standing,
            "unresolved": len(deliverable.unresolved),
            "tokens_estimated": usage.tokens,
            "cost_estimated": usage.estimated,
        })
        self.audit.write({
            "event": "specialist_deliverable",
            "task_id": task.task_id,
            "producer": deliverable.producer,
            "status": deliverable.status,
            "standing": deliverable.standing,
            "summary": deliverable.summary,
            "claims": len(deliverable.claims),
            "evidence_refs": deliverable.evidence_refs[:8],
            "budget_tokens_estimated": usage.tokens,
        })
        # the event ledger hears the completion (once) — dependents' next
        # readiness check will find them satisfied, no push needed
        self.ledger.mark(SpecialistEventLedger.fact_key(
            "task_completed", task.task_id))

    def _fail(
        self,
        task: SpecialistTask,
        record: HandoffRecord,
        exc: Exception,
    ) -> None:
        """An executor crash is a FAILED task result — honestly, with the
        reason kept, and the reservation released."""
        detail = f"{type(exc).__name__}: {exc}"
        try:
            self.coordinator.record_result(
                task.task_id,
                TaskResult(
                    engagement_id=self.coordinator.engagement_id,
                    message_id=new_message_id(),
                    source=f"specialist.{task.role}",
                    destination=record.destination,
                    result_status="failed",
                    subject_ref=record.subject_ref,
                    content=claim_text(detail, 400),
                    correlation_id=task.task_id,
                ))
        except HandoffError:
            # terminal record (cancelled): the failure is audited, the
            # record untouched
            pass
        task.outcome_note = claim_text(detail, MAX_NOTE_CHARS)
        self._release(task.task_id)
        self.audit.write({
            "event": "specialist_failed",
            "task_id": task.task_id,
            "role": task.role,
            "error": detail[:200],
        })
        self.ledger.mark(SpecialistEventLedger.fact_key(
            "task_failed", task.task_id))

    # -- timeout & cancellation ------------------------------------------------

    def check_timeouts(self, current_state: str) -> int:
        """Claimed work past its deadline goes to ``blocked``, reason kept.

        ``blocked -> in_progress`` is a legal transition, so a later
        boundary may re-claim within the attempts cap; the timeout is
        never a completion and never a failure of the underlying work —
        it is the scheduler saying it stopped waiting.
        """
        now = utc_now_iso()
        timed_out = 0
        for task in self._tasks.values():
            if not task.last_claimed_at:
                continue
            record = self.coordinator.get(task.task_id)
            if record is None or record.status != "in_progress":
                continue
            if _seconds_between(task.last_claimed_at, now) < task.timeout_s:
                continue
            try:
                self.coordinator.block(
                    task.task_id, f"specialist timeout after "
                    f"{task.timeout_s}s")
            except HandoffError:
                continue  # terminal meanwhile — nothing to do
            self._release(task.task_id)
            task.last_claimed_at = ""
            timed_out += 1
            self.audit.write({
                "event": "specialist_timeout",
                "task_id": task.task_id,
                "role": task.role,
                "timeout_s": task.timeout_s,
            })
            self.ledger.mark(SpecialistEventLedger.fact_key(
                "task_timeout", task.task_id))
        if timed_out:
            _ = current_state  # timeouts are checked at every boundary
        return timed_out

    def cancel(self, task_id: str, reason: str = "") -> HandoffRecord:
        """Withdraw scheduled work that has not finished."""
        task = self._tasks.get(task_id)
        if task is None:
            raise SpecialistError(f"task {task_id} is not scheduled")
        record = self.coordinator.cancel(task_id)
        self._release(task_id)
        task.outcome_note = claim_text(reason or "cancelled", MAX_NOTE_CHARS)
        self.audit.write({
            "event": "specialist_cancelled",
            "task_id": task_id,
            "role": task.role,
            "reason": task.outcome_note,
        })
        self.ledger.mark(SpecialistEventLedger.fact_key(
            "task_cancelled", task_id))
        return record

    # -- boundary entry point ----------------------------------------------------

    def on_boundary(self, state: str) -> dict:
        """Everything the scheduler does at one state boundary.

        In order: derive this boundary's tasks (deterministic,
        identity-deduped), check timeouts of older claims, run what is
        ready, announce progress. Deterministic throughout — no LLM, no
        tool, no transition input.
        """
        derived = self.derive_from_records(state)
        timed_out = self.check_timeouts(state)
        summary = self.run_ready(state)
        summary["derived"] = derived
        summary["timed_out"] = timed_out
        self.audit.write({
            "event": "specialist_progress",
            "state": state,
            **self.progress(),
        })
        return summary

    # -- inspection ------------------------------------------------------------

    def tasks(self) -> list[SpecialistTask]:
        return list(self._tasks.values())

    def get(self, task_id: str) -> SpecialistTask | None:
        return self._tasks.get(task_id)

    def progress(self) -> dict:
        """The counts the UI/event stream needs — nothing more."""
        by_status: dict[str, int] = {}
        for task in self._tasks.values():
            record = self.coordinator.get(task.task_id)
            status = record.status if record else "unknown"
            by_status[status] = by_status.get(status, 0) + 1
        return {
            "scheduled": len(self._tasks),
            "by_status": by_status,
            "tokens_estimated": sum(self._role_tokens.values()),
            "events_processed": len(self.ledger.to_dict()),
        }

    # -- persistence ---------------------------------------------------------------

    def to_dict(self) -> dict:
        """A JSON-safe snapshot: the scheduler's half of the checkpoint.

        When the shared engagement budget is attached and knows how to
        snapshot itself, its consumption rides along — so a restored run
        reinstates what was already spent instead of silently resetting
        it (Batch 4C).
        """
        data: dict = {
            "version": SCHEDULER_FORMAT_VERSION,
            "engagement_id": self.coordinator.engagement_id,
            "tasks": [t.model_dump() for t in self._tasks.values()],
            "role_tokens": dict(self._role_tokens),
            "event_ledger": self.ledger.to_dict(),
        }
        snapshot = getattr(self.budget, "budget_snapshot", None)
        if callable(snapshot):
            data["budget"] = snapshot()
        return data

    @classmethod
    def from_dict(
        cls,
        data: dict,
        *,
        coordinator: HandoffCoordinator,
        audit: AuditLog,
        budget: object | None = None,
    ) -> "SpecialistScheduler":
        if not isinstance(data, dict):
            raise SpecialistError("scheduler payload must be an object")
        version = data.get("version")
        if version != SCHEDULER_FORMAT_VERSION:
            raise SpecialistError(
                f"scheduler format version {version!r} is not supported "
                f"(this build writes {SCHEDULER_FORMAT_VERSION})")
        engagement_id = data.get("engagement_id")
        if engagement_id != coordinator.engagement_id:
            raise SpecialistError(
                f"scheduler payload names engagement {engagement_id!r}, "
                f"not {coordinator.engagement_id!r}")
        raw_tasks = data.get("tasks") or []
        if not isinstance(raw_tasks, list):
            raise SpecialistError("scheduler tasks must be a list")
        scheduler = cls(
            coordinator, audit, budget=budget,
            ledger=SpecialistEventLedger.from_dict(data.get("event_ledger")),
        )
        # The budget snapshot, when there is one, is reinstated BEFORE any
        # task is accepted: a restored run starts from what was actually
        # spent, never from a clean slate.
        restore = getattr(scheduler.budget, "restore_budget", None)
        if callable(restore) and isinstance(data.get("budget"), dict):
            restore(data["budget"])
        for raw in raw_tasks:
            try:
                task = SpecialistTask.model_validate(raw)
            except Exception as e:
                raise SpecialistError(
                    f"scheduler task failed validation: {e}") from e
            if task.engagement_id != engagement_id:
                raise SpecialistError(
                    f"scheduler task {task.task_id} names engagement "
                    f"{task.engagement_id!r}")
            if task.task_id in scheduler._tasks:
                raise SpecialistError(
                    f"scheduler payload repeats task {task.task_id}")
            scheduler._tasks[task.task_id] = task
        raw_role_tokens = data.get("role_tokens") or {}
        if not isinstance(raw_role_tokens, dict):
            raise SpecialistError("role_tokens must be an object")
        for role, tokens in raw_role_tokens.items():
            if (isinstance(role, str) and isinstance(tokens, int)
                    and not isinstance(tokens, bool) and tokens >= 0):
                scheduler._role_tokens[role] = tokens
        return scheduler


# ---- helpers -----------------------------------------------------------------

def evidence_questions(view: dict, subject: str) -> list[str]:
    """The deterministic unresolved questions one hypothesis's engine view
    raises (Batch 4B).

    One source of truth: the evidence-assessment executor puts these in
    its deliverable's ``unresolved``, and the task-context builder puts
    them in a context's ``unresolved`` — the two surfaces can never
    disagree about what a subject still owes. Engine words only.
    """
    questions: list[str] = []
    if not view["tested"]:
        questions.append(
            f"no exploit test has run for {subject} — nothing here is "
            "a finding yet")
    elif not view["confirmed"]:
        questions.append(
            f"the test(s) for {subject} did not confirm it — a test "
            "that found nothing is not evidence it is absent")
    if view["verification_status"] == "not_run":
        questions.append(
            f"no independent verification has run for {subject}")
    elif view["verification_status"] == "inconclusive":
        questions.append(
            f"the independent verification of {subject} could not "
            "establish either way")
    if not view["primary_asset_observed"]:
        questions.append(
            f"{subject}'s primary asset was never observed by this "
            "engagement")
    return questions[:6]


def recover_for_resume(coordinator: HandoffCoordinator, audit: AuditLog) -> dict:
    """The resume recovery pass (Batch 4C) — one deterministic decision
    per prior record, through the coordinator's own transition table.

    * ``in_progress`` read-only work: the outcome is unknown (the process
      died mid-task), so the work REOPENS — ``blocked`` with the reason
      kept — claimable again at its own stage, recomputed from the graph
      rather than assumed. Read-only re-running is exactly what resume
      exists for.
    * ``in_progress`` state-changing work: the same unknown outcome, but
      re-running it is out of the question — it goes behind Gate 2 via
      the coordinator's ``request_approval`` (the existing human
      mechanism), attempts preserved.
    * everything else (completed, cancelled, failed, inconclusive,
      blocked, needs_approval): left exactly as it was — finished work is
      never repeated, and identity/attempt state is never reset.

    Deterministic and data-driven only: no LLM, no tool, no transition
    decision. The audit events it writes are the resume trail.
    """
    recovered = {
        "reopened_read_only": 0,
        "gated_state_changing": 0,
        "left_alone": 0,
    }
    for record in coordinator.records():
        if record.kind != "task_assignment":
            recovered["left_alone"] += 1
            continue
        if record.status != "in_progress":
            recovered["left_alone"] += 1
            continue
        safety = (
            task_safety(record.task_type)
            if record.task_type else "read_only"
        )
        if safety == "read_only":
            coordinator.block(
                record.message_id,
                "interrupted mid-run; reopened for re-assessment",
            )
            recovered["reopened_read_only"] += 1
            audit.write({
                "event": "specialist_resume_reopened",
                "task_id": record.message_id,
                "task_type": record.task_type,
                "attempts": record.attempts,
            })
        else:
            coordinator.request_approval(
                record.message_id,
                "GATE_2",
                "interrupted mid-run with unknown outcome; human "
                "authorization required before it runs again",
            )
            recovered["gated_state_changing"] += 1
            audit.write({
                "event": "specialist_resume_gated",
                "task_id": record.message_id,
                "task_type": record.task_type,
                "gate": "GATE_2",
                "attempts": record.attempts,
            })
    return recovered


def _seconds_between(iso_a: str, iso_b: str) -> float:
    """Wall-clock seconds between two ISO stamps; 0.0 when unparseable.

    Timeouts are best-effort by design: an unparseable stamp defers the
    check rather than timing out work that may have just started.
    """
    from datetime import datetime

    def _parse(value: str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    a, b = _parse(iso_a), _parse(iso_b)
    if a is None or b is None:
        return 0.0
    return (b - a).total_seconds()
