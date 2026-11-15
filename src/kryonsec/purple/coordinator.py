"""The deterministic handoff coordinator (Phase 3A / tool expansion Batch 3).

One place records the structured exchange between the engagement's
specialist stages, de-duplicates work before it is dispatched twice, and
refuses every lifecycle change that is not on its transition table.

Three boundaries it must never cross, all tested in
``tests/test_handoff.py``:

* **It never decides a transition.** The ten-state orchestrator
  (``purple.orchestrator``) remains the sole transition authority. The
  coordinator runs *inside* the ``on_state_complete`` boundary — after a
  state's subagent has returned, before the next state is chosen — so a
  record it writes can describe what just finished, but cannot trigger
  EXPLOIT, POST_EXPLOIT, a network request or a tool launch. It imports no
  sandbox, no allowlist and no LLM client.
* **It never grants approval.** ``approve`` is the only door out of
  ``needs_approval``, and it exists to *record* a decision a human gate
  already made (Gate 2's reviewer output, the post-exploit approver) —
  the decision itself stays in the audit chain and the graph's
  ``approved`` flags, exactly where they were.
* **It never copies evidence.** Evidence links are node ids plus a
  produced/consumed role. The node's payload stays in the engagement
  graph — the one shared evidence store — and every lookup goes back to
  the graph, refused for anything belonging to another engagement.

Dedup is deterministic and content-addressed: the identity
(:func:`handoff.task_identity` / :func:`handoff.message_identity`) covers
engagement, task type, normalized target, subject and (for data messages)
the content itself. A re-dispatch of a known identity never creates a
second record and never re-runs state-changing work on its own — it
returns a :class:`handoff.DispatchDecision` whose outcome says exactly
what the known record means for the attempt: already completed, in
progress, safe to retry, needing another approval, blocked, failed,
inconclusive.
"""

from __future__ import annotations

import logging

from pydantic import ValidationError

from .audit import AuditLog
from .handoff import (
    DISPATCH_OUTCOMES,
    HANDOFF_FORMAT_VERSION,
    BlockedTask,
    CompletionSummary,
    DispatchDecision,
    EvidenceLink,
    EvidenceRef,
    HandoffMessage,
    HandoffRecord,
    HumanApprovalRequest,
    Observation,
    TaskAssignment,
    TaskResult,
    VerificationResult,
    message_identity,
    new_message_id,
    task_identity,
    task_safety,
    utc_now_iso,
)
from .recon_passive import (
    CrossEngagementError,
    EngagementGraph,
    GraphError,
)
from .views import (
    ATTEMPT_CONFIRMED,
    ATTEMPT_INCONCLUSIVE,
    attempt_outcome,
    claim_text,
    verification_status,
)

log = logging.getLogger(__name__)

__all__ = [
    "HandoffCoordinator",
    "HandoffError",
    "HandoffTransitionError",
    "MissingEvidenceError",
    "StageBoundaryRecorder",
    "UnknownHandoffError",
]


# ---- errors ----------------------------------------------------------------

class HandoffError(Exception):
    """Base class for coordinator failures."""


class UnknownHandoffError(HandoffError):
    """A message id the coordinator does not hold."""


class HandoffTransitionError(HandoffError):
    """A status change the transition table refuses.

    Raised, audited by the coordinator, and never swallowed: an invalid
    transition is a caller bug or an attempted replay of finished work,
    and both must be loud.
    """


class MissingEvidenceError(HandoffError):
    """An evidence reference names a node this engagement does not hold.

    Refused rather than stored: a record that points at nothing real is
    the exact shape a fabricated finding takes.
    """


# cross-engagement refusals reuse recon_passive.CrossEngagementError, the
# graph's own word for it, so one exception type covers the boundary.


# ---- the transition table ---------------------------------------------------
#
# The closed set of status changes. Anything else is refused — the table is
# the authority, not the caller's intention. Transitions INTO a status are
# listed; leaving a terminal status is impossible by construction.
#
# needs_approval -> registered is the ONE recovery from waiting, and it is
# approve(): a human decision recorded, never a message's word.

TRANSITIONS: dict[str, frozenset[str]] = {
    "registered": frozenset({
        "in_progress", "blocked", "needs_approval", "cancelled"}),
    "in_progress": frozenset({
        "completed", "failed", "inconclusive", "blocked",
        "needs_approval", "cancelled"}),
    "needs_approval": frozenset({
        "registered", "in_progress", "cancelled"}),
    "blocked": frozenset({
        "in_progress", "needs_approval", "cancelled"}),
    # A failed/inconclusive attempt may be retried (read-only work) or
    # parked behind a human gate (state-changing work) — never silently
    # re-run by anything else.
    "failed": frozenset({"in_progress", "needs_approval", "cancelled"}),
    "inconclusive": frozenset({"in_progress", "needs_approval", "cancelled"}),
    "completed": frozenset(),
    "cancelled": frozenset(),
}


def _redespatch_outcome(record: HandoffRecord) -> str:
    """What a re-dispatch of an already-known TASK identity means.

    The one rule that keeps repeated dispatch from re-running dangerous
    work: a read-only task that ended unsure or failed may be retried;
    state-changing work may not — not until a human approves again.
    Nothing here invents an outcome the record does not carry.
    """
    status = record.status
    if status == "registered":
        return "already_registered"
    if status in ("completed", "in_progress", "blocked", "needs_approval"):
        return status if status != "completed" else "already_completed"
    # failed / inconclusive / cancelled: safety decides whether a retry
    # is even askable
    safety = task_safety(record.task_type) if record.task_type else "read_only"
    if status in ("failed", "inconclusive", "cancelled"):
        if safety == "read_only":
            return "safe_retry"
        # state-changing work: a silent re-run is out of the question —
        # a failed attempt stays failed, an unsure one stays inconclusive,
        # and cancelled work needs a human yes before it goes again
        return {"cancelled": "needs_approval"}.get(status, status)
    return "blocked"  # unreachable over the closed status set; fails closed


# ---- the coordinator ---------------------------------------------------------

class HandoffCoordinator:
    """Records, de-duplicates and lifecycle-tracks handoff messages."""

    def __init__(
        self,
        engagement_id: str,
        graph: EngagementGraph,
        audit: AuditLog,
    ):
        self.engagement_id = engagement_id
        self.graph = graph
        self.audit = audit
        self._by_id: dict[str, HandoffRecord] = {}
        self._by_identity: dict[str, HandoffRecord] = {}

    # -- registration ------------------------------------------------------

    def register(self, message: HandoffMessage) -> DispatchDecision:
        """Record a handoff message, de-duplicated by identity.

        Task assignments get the dispatch ladder; every other kind is
        recorded as data. A known identity never creates a second record —
        the decision names what the existing one means. Before anything is
        recorded the message must belong to THIS engagement and every
        evidence reference it carries must resolve in this engagement's
        graph.
        """
        if not isinstance(message, HandoffMessage):
            raise HandoffError(
                "register() takes a validated handoff message, not "
                f"{type(message).__name__}")
        if message.engagement_id != self.engagement_id:
            raise CrossEngagementError(
                f"handoff {message.message_id!r} belongs to engagement "
                f"{message.engagement_id!r}, not {self.engagement_id!r}")
        self._require_evidence(message)

        identity = self._identity_of(message)
        existing = self._by_identity.get(identity)
        if existing is not None:
            if isinstance(message, TaskAssignment):
                outcome = _redespatch_outcome(existing)
            else:
                outcome = "already_recorded"
            self.audit.write({
                "event": "handoff_duplicate_suppressed",
                "message_id": message.message_id,
                "existing_id": existing.message_id,
                "outcome": outcome,
            })
            return DispatchDecision(outcome=outcome, record=existing)

        if message.message_id in self._by_id:
            raise HandoffError(
                f"message_id {message.message_id!r} is already on file "
                "with different content")

        now = utc_now_iso()
        record = HandoffRecord(
            engagement_id=self.engagement_id,
            message_id=message.message_id,
            identity_key=identity,
            kind=message.kind,
            status=message.status,
            source=message.source,
            destination=message.destination,
            created_at=message.created_at,
            updated_at=now,
            task_type=(
                message.task_type if isinstance(message, TaskAssignment)
                else ""),
            subject_ref=message.subject_ref,
            attempts=0,
            message=message.model_dump(),
        )
        self._by_id[record.message_id] = record
        self._by_identity[identity] = record
        self.audit.write({
            "event": "handoff_registered",
            "message_id": record.message_id,
            "kind": record.kind,
            "task_type": record.task_type,
            "source": record.source,
            "destination": record.destination,
            "outcome": "new",
        })
        return DispatchDecision(outcome="new", record=record)

    # -- task lifecycle ------------------------------------------------------

    def claim(self, message_id: str) -> HandoffRecord:
        """Take a registered task: registered -> in_progress."""
        record = self._get(message_id)
        record = self._transition(record, "in_progress")
        record.attempts += 1
        self.audit.write({
            "event": "handoff_claimed",
            "message_id": message_id,
            "attempts": record.attempts,
        })
        return record

    def record_result(
        self, message_id: str, result: TaskResult,
    ) -> HandoffRecord:
        """Record the outcome of claimed work.

        The record must be in progress. Replay of the SAME result against
        a completed record is a no-op (idempotent, nothing re-written); a
        different result after completion is refused — finished work
        cannot be quietly re-decided.
        """
        if not isinstance(result, TaskResult):
            raise HandoffError("record_result() takes a TaskResult")
        record = self._get(message_id)
        if result.correlation_id and result.correlation_id != message_id:
            raise HandoffError(
                f"result {result.message_id!r} cites correlation "
                f"{result.correlation_id!r}, not {message_id!r}")

        dump = result.model_dump()
        if record.status == "completed":
            if dump in record.results:
                self.audit.write({
                    "event": "handoff_replay_ignored",
                    "message_id": message_id,
                    "result_id": result.message_id,
                })
                return record
            raise HandoffTransitionError(
                f"task {message_id!r} is completed; a different result "
                "cannot be recorded over it")

        record = self._transition(record, result.result_status)
        record.results.append(dump)
        record.updated_at = utc_now_iso()
        self.audit.write({
            "event": "handoff_result_recorded",
            "message_id": message_id,
            "result_status": result.result_status,
        })
        return record

    def block(self, message_id: str, reason: str = "") -> HandoffRecord:
        """A task could not run — with the real reason kept."""
        record = self._get(message_id)
        record = self._transition(record, "blocked")
        record.blocked_reason = claim_text(reason, 200)
        record.updated_at = utc_now_iso()
        self.audit.write({
            "event": "handoff_blocked",
            "message_id": message_id,
            "reason": record.blocked_reason,
        })
        return record

    def request_approval(
        self, message_id: str, gate: str, request: str = "",
    ) -> HandoffRecord:
        """Park a task behind a human gate."""
        if gate not in ("GATE_2", "GATE_3", "GATE_POST_EXPLOIT"):
            raise ValueError(f"unknown approval gate {gate!r}")
        record = self._get(message_id)
        record = self._transition(record, "needs_approval")
        record.approval_gate = gate
        record.updated_at = utc_now_iso()
        self.audit.write({
            "event": "handoff_approval_requested",
            "message_id": message_id,
            "gate": gate,
            "request": claim_text(request, 400),
        })
        return record

    def approve(
        self, message_id: str, approved_by: str,
    ) -> HandoffRecord:
        """Record that a human gate said yes — needs_approval -> registered.

        This is a bookkeeping door, not an approval: ``approved_by`` names
        the human decision already made (the Gate 2 reviewer's output, the
        post-exploit approver's). No message, no agent and no record can
        call this into being by itself — the audit chain holds the real
        decision this entry is pointing back at.
        """
        record = self._get(message_id)
        record = self._transition(record, "registered")
        record.approval_gate = ""
        record.updated_at = utc_now_iso()
        self.audit.write({
            "event": "handoff_approval_recorded",
            "message_id": message_id,
            "approved_by": claim_text(approved_by, 64),
        })
        return record

    def cancel(self, message_id: str) -> HandoffRecord:
        """Withdraw work that has not finished."""
        record = self._get(message_id)
        record = self._transition(record, "cancelled")
        record.updated_at = utc_now_iso()
        self.audit.write({
            "event": "handoff_cancelled",
            "message_id": message_id,
        })
        return record

    def retry(self, message_id: str) -> HandoffRecord:
        """Run work again — failed/inconclusive -> in_progress.

        Refused outright for state-changing work: a failed exploit or
        verification probe must not re-run because a dispatcher asked
        twice. That path goes through a human approval first
        (:meth:`request_approval` then :meth:`approve`).
        """
        record = self._get(message_id)
        if record.task_type and task_safety(record.task_type) != "read_only":
            if record.status in ("failed", "inconclusive"):
                raise HandoffTransitionError(
                    f"task {message_id!r} is {record.status} and "
                    f"{record.task_type!r} is state-changing — re-running "
                    "it needs a human approval, not a retry")
        record = self._transition(record, "in_progress")
        record.attempts += 1
        record.updated_at = utc_now_iso()
        self.audit.write({
            "event": "handoff_retried",
            "message_id": message_id,
            "attempts": record.attempts,
        })
        return record

    # -- retrieval -----------------------------------------------------------

    def eligible(self) -> list[HandoffRecord]:
        """Registered task assignments: the work ready to be claimed."""
        return [
            r for r in self.records()
            if r.kind == "task_assignment" and r.status == "registered"
        ]

    def records(self) -> list[HandoffRecord]:
        """Every record, in registration order."""
        return list(self._by_id.values())

    def get(self, message_id: str) -> HandoffRecord | None:
        """The record with this message id, or None. Never raises."""
        return self._by_id.get(message_id)

    def progress(self) -> dict:
        """The counts the UI/event stream needs — nothing more."""
        by_status: dict[str, int] = {}
        by_task_type: dict[str, int] = {}
        for record in self.records():
            by_status[record.status] = by_status.get(record.status, 0) + 1
            if record.task_type:
                by_task_type[record.task_type] = (
                    by_task_type.get(record.task_type, 0) + 1)
        return {
            "total": len(self._by_id),
            "by_status": by_status,
            "by_task_type": by_task_type,
            "evidence_links": sum(
                len(r.evidence_links) for r in self.records()),
        }

    # -- evidence ------------------------------------------------------------

    def link_evidence(
        self,
        message_id: str,
        node_id: str,
        role: str,
    ) -> EvidenceLink | None:
        """Attach a produced/consumed evidence link to a record.

        The node must exist in THIS engagement's graph — a reference to
        nothing is refused (MissingEvidenceError) and a reference to
        another engagement's evidence is refused
        (CrossEngagementError). Relinking the same node with the same
        role is idempotent. Only the id and the role are stored: the
        payload stays in the graph, so sharing a reference can never
        become copying raw output.
        """
        record = self._get(message_id)
        if role not in ("produced", "consumed"):
            raise HandoffError(
                f"evidence role must be 'produced' or 'consumed', "
                f"got {role!r}")
        node = self.graph.get_node(node_id)
        if node is None:
            self.audit.write({
                "event": "handoff_evidence_refused",
                "message_id": message_id,
                "node_id": node_id,
                "reason": "no such node in this engagement's graph",
            })
            raise MissingEvidenceError(
                f"evidence node {node_id!r} does not exist in engagement "
                f"{self.engagement_id!r}")
        node_engagement = node.get("engagement_id")
        if node_engagement is not None and node_engagement != self.engagement_id:
            self.audit.write({
                "event": "handoff_evidence_refused",
                "message_id": message_id,
                "node_id": node_id,
                "reason": f"node belongs to engagement {node_engagement!r}",
            })
            raise CrossEngagementError(
                f"evidence node {node_id!r} belongs to engagement "
                f"{node_engagement!r}, not {self.engagement_id!r}")

        for link in record.evidence_links:
            if link.node_id == node_id and link.role == role:
                return link  # idempotent: the link is already on file

        link = EvidenceLink(
            node_id=node_id,
            node_type=node.get("node_type", ""),
            role=role,
            by=record.source,
            at=utc_now_iso(),
        )
        record.evidence_links.append(link)
        record.updated_at = utc_now_iso()
        self.audit.write({
            "event": "handoff_evidence_linked",
            "message_id": message_id,
            "node_id": node_id,
            "node_type": link.node_type,
            "role": role,
        })
        return link

    def evidence(self, node_id: str) -> dict | None:
        """Look up evidence by node id — THIS engagement's graph only.

        There is no path to another engagement's evidence: the graph is
        per-engagement, and the coordinator holds exactly one.
        """
        return self.graph.get_node(node_id)

    # -- serialization ---------------------------------------------------------

    def to_dict(self) -> dict:
        """A JSON-safe snapshot (the checkpoint's write shape)."""
        return {
            "version": HANDOFF_FORMAT_VERSION,
            "engagement_id": self.engagement_id,
            "records": [r.model_dump() for r in self.records()],
        }

    @classmethod
    def from_dict(
        cls,
        data: dict,
        *,
        graph: EngagementGraph | None = None,
        audit: AuditLog | None = None,
    ) -> "HandoffCoordinator":
        """Rebuild a coordinator from ``to_dict`` output.

        Refuses a version it does not understand, an engagement mismatch,
        and a payload that repeats an identity or message id — a corrupt
        or hand-edited checkpoint fails loudly instead of silently
        de-duplicating records that were different.
        """
        if not isinstance(data, dict):
            raise HandoffError("handoff payload must be an object")
        version = data.get("version")
        if version != HANDOFF_FORMAT_VERSION:
            raise HandoffError(
                f"handoff format version {version!r} is not supported "
                f"(this build writes {HANDOFF_FORMAT_VERSION})")
        engagement_id = data.get("engagement_id")
        if not isinstance(engagement_id, str) or not engagement_id:
            raise HandoffError("handoff payload has no engagement_id")
        raw_records = data.get("records") or []
        if not isinstance(raw_records, list):
            raise HandoffError("handoff records must be a list")

        coordinator = cls(engagement_id, graph, audit)  # type: ignore[arg-type]
        for raw in raw_records:
            try:
                record = HandoffRecord.model_validate(raw)
            except ValidationError as e:
                raise HandoffError(
                    f"handoff record failed validation: {e}") from e
            if record.engagement_id != engagement_id:
                raise CrossEngagementError(
                    f"handoff record {record.message_id!r} belongs to "
                    f"engagement {record.engagement_id!r}, not "
                    f"{engagement_id!r}")
            if record.message_id in coordinator._by_id:
                raise HandoffError(
                    f"handoff payload repeats message_id "
                    f"{record.message_id!r}")
            if record.identity_key in coordinator._by_identity:
                raise HandoffError(
                    f"handoff payload repeats identity of "
                    f"{record.message_id!r}")
            coordinator._by_id[record.message_id] = record
            coordinator._by_identity[record.identity_key] = record
        return coordinator

    # -- internals ---------------------------------------------------------------

    def _get(self, message_id: str) -> HandoffRecord:
        record = self._by_id.get(message_id)
        if record is None:
            raise UnknownHandoffError(
                f"no handoff record {message_id!r} in engagement "
                f"{self.engagement_id!r}")
        return record

    def _transition(self, record: HandoffRecord, to_status: str) -> HandoffRecord:
        allowed = TRANSITIONS.get(record.status, frozenset())
        if to_status not in allowed:
            self.audit.write({
                "event": "handoff_invalid_transition",
                "message_id": record.message_id,
                "from_status": record.status,
                "to_status": to_status,
            })
            raise HandoffTransitionError(
                f"task {record.message_id!r}: {record.status} -> "
                f"{to_status} is not a registered transition")
        record.status = to_status
        record.updated_at = utc_now_iso()
        return record

    def _identity_of(self, message: HandoffMessage) -> str:
        if isinstance(message, TaskAssignment):
            return task_identity(
                message.engagement_id, message.task_type,
                message.target_asset, message.subject_ref)
        return message_identity(
            message.engagement_id, message.kind, message.source,
            message.subject_ref, message.content)

    def _require_evidence(self, message: HandoffMessage) -> None:
        """Every evidence reference must name a node this graph holds.

        A handoff's references are validated pointers, not free text:
        pointing at evidence that does not exist is refused at the door,
        which is what keeps a record from citing a finding nobody saw.
        """
        for node_id in message.evidence_refs:
            node = self.graph.get_node(node_id)
            if node is None:
                self.audit.write({
                    "event": "handoff_evidence_refused",
                    "message_id": message.message_id,
                    "node_id": node_id,
                    "reason": "no such node in this engagement's graph",
                })
                raise MissingEvidenceError(
                    f"{message.kind} {message.message_id!r} cites evidence "
                    f"node {node_id!r}, which does not exist in engagement "
                    f"{self.engagement_id!r}")


# ---- the stage boundary recorder ---------------------------------------------
#
# The integration point with the running engagement. Wired in
# ``purple.runner.start_engagement`` onto ``orch.on_state_complete`` — the
# same quiescent boundary the graph checkpoint uses — it derives handoff
# records from the graph the state just produced. Deterministic, read-only
# over the graph, no LLM call, no tool call: it runs AFTER the subagent
# returned, so it can describe the state that finished but cannot trigger
# the next one. The orchestrator alone chooses that.

class StageBoundaryRecorder:
    """Derives handoff records at each state boundary.

    Every handler is best-effort: a derivation problem is audited
    (``stage_boundary_failed``) and never fatal — the loop's transition
    decision is not this module's to make, and a record is never worth an
    engagement.
    """

    def __init__(self, coordinator: HandoffCoordinator):
        self.coordinator = coordinator
        self.graph = coordinator.graph
        self.audit = coordinator.audit
        self._engagement = coordinator.engagement_id

    def on_state_complete(self, state: str) -> None:
        handler = self._HANDLERS.get(state)
        if handler is None:
            return
        try:
            handler(self)
        except GraphError as e:
            # a graph-shaped refusal is a data problem: audited, not fatal
            self.audit.write({
                "event": "stage_boundary_failed",
                "state": state,
                "error": str(e)[:200],
            })
            log.warning("stage boundary %s refused: %s", state, e)
        except Exception as e:
            self.audit.write({
                "event": "stage_boundary_failed",
                "state": state,
                "error": str(e)[:200],
            })
            log.warning("stage boundary %s failed: %s", state, e,
                        exc_info=True)
        finally:
            # the progress line, every boundary, whatever happened above
            self._announce_progress(state)

    def _announce_progress(self, state: str) -> None:
        try:
            self.audit.write({
                "event": "handoff_progress",
                "state": state,
                **self.coordinator.progress(),
            })
        except Exception:
            # presentation must never break the boundary either
            log.warning("handoff progress could not be audited",
                        exc_info=True)

    # -- the handlers --------------------------------------------------------

    def _summary(
        self, state: str, destination: str, content: str,
        evidence_node_ids: list[str],
    ) -> None:
        self.coordinator.register(CompletionSummary(
            engagement_id=self._engagement,
            message_id=new_message_id(),
            source=state,
            destination=destination,
            content=content,
            evidence_refs=evidence_node_ids[:8],
            outcome="completed",
            states_completed=[state],
        ))

    def _on_RECON_PASSIVE(self) -> None:
        subs = self.graph.by_type("subdomain")
        paths = self.graph.by_type("path")
        targets = self.graph.by_type("target")
        evidence = [n["id"] for n in targets] + [n["id"] for n in subs]
        self._summary(
            "RECON_PASSIVE", "HYPOTHESIZE",
            f"observed {len(subs)} subdomains, {len(paths)} paths",
            evidence)

    def _on_RECON_ACTIVE(self) -> None:
        services = self.graph.by_type("service")
        endpoints = self.graph.by_type("web_endpoint")
        self._summary(
            "RECON_ACTIVE", "HYPOTHESIZE",
            f"observed {len(services)} services, "
            f"{len(endpoints)} web endpoints",
            [n["id"] for n in services] + [n["id"] for n in endpoints])

    # Batch 4: at most this many evidence-assessment assignments are
    # derived per HYPOTHESIZE boundary. The cap is what keeps a
    # hypothesis flood from becoming an unbounded task list; the
    # scheduler audits what it did not derive.
    MAX_ASSESSMENT_TASKS = 12

    def _on_HYPOTHESIZE(self) -> None:
        hypotheses = self.graph.by_type("hypothesis")
        for node in hypotheses:
            props = node.get("properties") or {}
            self.coordinator.register(Observation(
                engagement_id=self._engagement,
                message_id=new_message_id(),
                source="HYPOTHESIZE",
                destination="HUMAN_REVIEW",
                status="proposed",
                subject_ref=node["label"],
                content=claim_text(
                    props.get("title") or node["label"], 400),
                hypothesis_refs=[node["label"]],
                evidence_refs=[node["id"]],
            ))
        # Batch 4A: one READ-ONLY evidence-assessment assignment per
        # proposed hypothesis. Registering the assignment is as far as
        # this boundary goes — scheduling and running it is the
        # specialist scheduler's decision, and nothing here authorizes
        # any target contact. Identity-deduped by content, so a repeated
        # boundary re-derives the same records, not new ones.
        for node in hypotheses[: self.MAX_ASSESSMENT_TASKS]:
            props = node.get("properties") or {}
            self.coordinator.register(TaskAssignment(
                engagement_id=self._engagement,
                message_id=new_message_id(),
                source="HYPOTHESIZE",
                destination="specialist",
                task_type="evidence_assessment",
                subject_ref=node["label"],
                target_asset=claim_text(props.get("target_asset") or "", 300),
                content=claim_text(
                    props.get("title") or node["label"], 400),
                hypothesis_refs=[node["label"]],
                evidence_refs=[node["id"]],
            ))
        if len(hypotheses) > self.MAX_ASSESSMENT_TASKS:
            self.audit.write({
                "event": "handoff_derivation_capped",
                "state": "HYPOTHESIZE",
                "derived": self.MAX_ASSESSMENT_TASKS,
                "total": len(hypotheses),
            })

    def _on_HUMAN_REVIEW(self) -> None:
        hypotheses = self.graph.by_type("hypothesis")
        approved = [
            n for n in hypotheses
            if (n.get("properties") or {}).get("approved") is True
        ]
        # One stage result: the gate's outcome, as it happened. It is
        # recorded here because the state has ALREADY completed — the
        # orchestrator has already routed on approved_count — so this
        # record describes the decision and never makes it.
        self.coordinator.register(TaskResult(
            engagement_id=self._engagement,
            message_id=new_message_id(),
            source="HUMAN_REVIEW",
            destination="EXPLOIT" if approved else "BLUE_TEAM",
            result_status="completed",
            subject_ref="human_review",
            content=(
                f"gate 2 outcome: approved {len(approved)} of "
                f"{len(hypotheses)} hypotheses"),
            evidence_refs=[n["id"] for n in approved],
        ))
        # One assignment per approved hypothesis — the structured form of
        # what Gate 2 authorized. Registered AFTER the transition, as data
        # for the record, never as the reason EXPLOIT runs.
        for node in approved:
            props = node.get("properties") or {}
            self.coordinator.register(TaskAssignment(
                engagement_id=self._engagement,
                message_id=new_message_id(),
                source="HUMAN_REVIEW",
                destination="EXPLOIT",
                task_type="exploit_test",
                subject_ref=node["label"],
                target_asset=claim_text(
                    props.get("target_asset") or "", 300),
                content=claim_text(
                    props.get("title") or node["label"], 400),
                hypothesis_refs=[node["label"]],
                evidence_refs=[node["id"]],
            ))

    def _on_EXPLOIT(self) -> None:
        for node in self.graph.by_type("exploit_attempt"):
            outcome = attempt_outcome(node)
            if outcome == ATTEMPT_CONFIRMED:
                result_status = "completed"
            elif outcome == ATTEMPT_INCONCLUSIVE:
                result_status = "inconclusive"
            else:
                # not-run / unrecorded: no record is invented for work
                # that never produced an outcome
                continue
            props = node.get("properties") or {}
            decision = self.coordinator.register(TaskResult(
                engagement_id=self._engagement,
                message_id=new_message_id(),
                source="EXPLOIT",
                destination="VERIFY",
                result_status=result_status,
                subject_ref=node["label"],
                content=claim_text(
                    props.get("title") or node["label"], 400),
                evidence_refs=[node["id"]],
            ))
            # what the attempt produced, by id only
            for edge in self.graph.find_edges(
                    relationship="produced", source=node["id"]):
                self.coordinator.link_evidence(
                    decision.record.message_id,
                    edge["target_node_id"], "produced")

    def _on_VERIFY(self) -> None:
        for node in self.graph.by_type("verify_attempt"):
            vs = verification_status(node)
            props = node.get("properties") or {}
            decision = self.coordinator.register(VerificationResult(
                engagement_id=self._engagement,
                message_id=new_message_id(),
                source="VERIFY",
                destination="BLUE_TEAM",
                verification_status=vs,
                subject_ref=node["label"],
                method=claim_text(props.get("method") or "independent probe", 200),
                content=claim_text(props.get("title") or node["label"], 400),
                evidence_refs=[node["id"]],
            ))
            # the finding this check examined, by id only
            for edge in self.graph.find_edges(
                    relationship="verified_by", target=node["id"]):
                self.coordinator.link_evidence(
                    decision.record.message_id,
                    edge["source_node_id"], "consumed")

    def _on_POST_EXPLOIT(self) -> None:
        notes = self.graph.by_type("engagement_note")
        self._summary(
            "POST_EXPLOIT", "VERIFY",
            f"post-exploit enumeration recorded ({len(notes)} notes)",
            [])

    def _on_BLUE_TEAM(self) -> None:
        findings = self.graph.by_type("finding")
        self._summary(
            "BLUE_TEAM", "REPORT",
            f"defensive guidance recorded for {len(findings)} findings",
            [n["id"] for n in findings])

    def _on_REPORT(self) -> None:
        self._summary("REPORT", "operator", "engagement report written", [])

    _HANDLERS = {
        "RECON_PASSIVE": _on_RECON_PASSIVE,
        "RECON_ACTIVE": _on_RECON_ACTIVE,
        "HYPOTHESIZE": _on_HYPOTHESIZE,
        "HUMAN_REVIEW": _on_HUMAN_REVIEW,
        "EXPLOIT": _on_EXPLOIT,
        "POST_EXPLOIT": _on_POST_EXPLOIT,
        "VERIFY": _on_VERIFY,
        "BLUE_TEAM": _on_BLUE_TEAM,
        "REPORT": _on_REPORT,
    }
