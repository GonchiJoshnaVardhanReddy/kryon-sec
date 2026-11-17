"""Structured agent handoff contracts (Phase 3A / tool expansion Batch 3).

The typed data the ten-state engagement exchanges between its specialist
stages. Three rules shape every schema here:

* **Data, never authority.** A handoff message is a record about work, not
  an instruction the loop must obey. Nothing in this module drives a state
  transition, calls a tool, touches the network or answers a gate — the
  orchestrator (``purple.orchestrator``) stays the sole transition
  authority, and Gate 2 / Gate 3 approval stays exactly where it was.
* **No human impersonation.** There is no approval-*decision* message. The
  one approval-shaped kind (``HumanApprovalRequest``) can only *ask* the
  human: its ``requested_of`` is pinned to ``"human"``, it carries no
  ``approved`` field, and ``extra="forbid"`` on every model means a
  producer cannot smuggle one in. Only ``human_review`` / the post-exploit
  approver can turn a hypothesis into ``approved`` state — on the graph,
  as before.
* **Bounded, sanitized content.** Every free-text field passes through the
  same single-line treatment the hypothesis claim uses
  (:func:`views.claim_text`) and the project's secret redaction, with
  explicit caps. Untrusted scanner output and prompt-like text stay data:
  they are stored, never obeyed, and can never widen past their bound.

The status vocabulary is deliberately assembled from the vocabularies the
engagement already speaks — task lifecycle words, the graph's own node
statuses (:data:`recon_passive.NODE_STATUSES`), the verification statuses
(:mod:`views`) — so a handoff can never invent a standing the graph has no
word for.

Nothing here touches the sandbox, the allowlists, the audit chain or the
database: this module is contracts only. The coordinator that records and
de-duplicates them lives in :mod:`kryonsec.purple.coordinator`, its
persistence in :mod:`kryonsec.purple.handoff_store`.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from ..secrets import redact
from .recon_passive import NODE_STATUSES
from .views import (
    VERIFICATION_DISAGREED,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_NOT_RUN,
    VERIFICATION_VERIFIED,
    claim_text,
)

__all__ = [
    "HANDOFF_FORMAT_VERSION",
    "MESSAGE_KINDS",
    "MESSAGE_STATUSES",
    "TASK_STATUSES",
    "TASK_TYPES",
    "TASK_SAFETY",
    "DISPATCH_OUTCOMES",
    "APPROVAL_GATES",
    "BlockedTask",
    "CompletionSummary",
    "DispatchDecision",
    "EvidenceLink",
    "HandoffMessage",
    "HandoffRecord",
    "HumanApprovalRequest",
    "MAX_CONTENT_CHARS",
    "MAX_REFS",
    "MAX_STAGE_CHARS",
    "Observation",
    "TaskAssignment",
    "TaskResult",
    "VerificationResult",
    "task_identity",
    "task_safety",
    "utc_now_iso",
    "new_message_id",
]

HANDOFF_FORMAT_VERSION = 1

# ---- bounds ---------------------------------------------------------------
# Free text is sanitized, not rejected (the hypothesize rule: a model that
# writes something useful in a badly-shaped way still gets to say it) — but
# it is *bounded*, so no message can carry an unbounded payload.

MAX_STAGE_CHARS = 64       # source / destination stage names
MAX_CONTENT_CHARS = 400    # the main bounded content of any message
MAX_NOTE_CHARS = 200       # secondary notes (reasons, methods)
MAX_REFS = 8               # referenced ids per list, first-wins

# ---- vocabularies ---------------------------------------------------------

# Task lifecycle (the coordinator's transitions live in
# purple.coordinator.TRANSITIONS; this set is what a message may claim).
TASK_STATUSES: frozenset[str] = frozenset({
    "registered",       # created, not started
    "in_progress",      # claimed by a stage
    "completed",
    "blocked",          # could not run (scope, sandbox, gate) — reason kept
    "failed",
    "inconclusive",     # ran; could not establish either way
    "needs_approval",   # waiting on a human gate
    "cancelled",
})

# The one-word answer a re-dispatch (or re-recording) gets. The task
# categories are exactly the ones the Batch-3 contract asks to be
# distinguishable; the last two are the data-message equivalents — precise
# words for "this identity is already known", because an outcome invented
# for a record that says something else would be worse than the extra word.
DISPATCH_OUTCOMES: frozenset[str] = frozenset({
    "new",               # first sighting: registered
    "already_registered",  # known task identity, slot open — claim it, do not re-create it
    "already_completed", # the work is done — never re-run
    "already_recorded",  # a data message with this identity is already on file
    "in_progress",       # someone is on it
    "safe_retry",        # read-only work that may run again
    "needs_approval",    # state-changing work needs a human yes again
    "blocked",
    "failed",            # state-changing work failed: no silent re-run
    "inconclusive",      # state-changing work ended unsure: no silent re-run
})

# Registered task types and their re-run safety. The safety class is
# DERIVED, never agent-supplied: a task cannot claim to be read-only.
TASK_TYPES: dict[str, str] = {
    "recon_passive":    "read_only",       # third-party lookups only
    "recon_active":     "read_only",       # sends packets; mutates nothing on the target
    "hypothesize":      "read_only",       # LLM proposal, no target contact
    "exploit_test":     "state_changing",
    "post_exploit_enum": "state_changing",
    "verify_check":     "state_changing",
    "blue_team_scan":   "read_only",       # static analysis of /code
    "report_compile":   "read_only",
    "evidence_assessment": "read_only",    # Batch 4: deterministic graph analysis of
                                           # evidence quality — no target contact
    "verification_analysis": "read_only",  # Batch 5D: deterministic analysis of
                                           # verification records — no target
                                           # contact; the PROBES stay with the
                                           # VERIFY state (verify_check)
}

# Message kinds — the closed set the Batch-3 contract names.
MESSAGE_KINDS: frozenset[str] = frozenset({
    "task_assignment",
    "evidence_ref",
    "observation",
    "task_result",
    "blocked",
    "human_approval_request",
    "verification_result",
    "completion_summary",
})

# Approval gates a request can point at — the gates that actually exist.
APPROVAL_GATES = Literal["GATE_2", "GATE_3", "GATE_POST_EXPLOIT"]

# Re-run safety for a task type. Raises for an unknown type: a task that
# names no registered type is a bug in the caller, not data to guess about.
def task_safety(task_type: str) -> str:
    try:
        return TASK_TYPES[task_type]
    except KeyError:
        raise ValueError(
            f"unknown task type {task_type!r}; registered types: "
            + ", ".join(sorted(TASK_TYPES))
        ) from None


# The full status vocabulary a message may carry: the task lifecycle, the
# graph's node statuses (evidence standing), the verification outcomes and
# the engagement outcomes. One set, so a handoff can never mint a standing
# the rest of the engine has no word for.
MESSAGE_STATUSES: frozenset[str] = (
    TASK_STATUSES
    | NODE_STATUSES
    | frozenset({
        VERIFICATION_VERIFIED,
        VERIFICATION_DISAGREED,
        VERIFICATION_INCONCLUSIVE,
        VERIFICATION_NOT_RUN,
        "halted", "interrupted",  # engagement outcomes (runner.OUTCOMES)
    })
)

# ---- identity (duplicate-work prevention) ---------------------------------

_IDENTITY_CANON = {"sort_keys": True, "separators": (",", ":")}


def _identity(payload: dict) -> str:
    """A stable, bounded identity over the scope fields.

    Canonical JSON (sorted keys, tight separators — the audit chain's own
    serialization rule) so the same scope always hashes the same, on every
    process and every platform.
    """
    blob = json.dumps(payload, **_IDENTITY_CANON)
    return hashlib.sha256(blob.encode()).hexdigest()


def task_identity(
    engagement_id: str,
    task_type: str,
    target_asset: str,
    subject_ref: str,
) -> str:
    """The dedup identity of one unit of specialist work.

    Scope fields per the Batch-3 contract: engagement, task type, target
    (normalized through :func:`views.asset_key` — scheme, query, fragment
    and case are not identity), and the specific subject the task is about
    (hypothesis / finding / node id, "" for stage-level work).
    """
    from .views import asset_key

    return _identity({
        "scope": "task",
        "engagement_id": engagement_id,
        "task_type": task_type,
        "target_asset": asset_key(target_asset),
        "subject_ref": subject_ref,
    })


def message_identity(
    engagement_id: str,
    kind: str,
    source: str,
    subject_ref: str,
    content: str,
) -> str:
    """The dedup identity of a data-bearing message.

    Data messages (observations, results, summaries) are de-duplicated on
    what they say, not on a dispatch slot: the same stage saying the same
    thing about the same subject twice is one message, however many times
    the boundary that produces it replays.
    """
    return _identity({
        "scope": "message",
        "engagement_id": engagement_id,
        "kind": kind,
        "source": source,
        "subject_ref": subject_ref,
        "content": content,
    })


# ---- helpers --------------------------------------------------------------

def utc_now_iso() -> str:
    """ISO-8601 UTC, matching the graph's timestamp form."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def new_message_id() -> str:
    """``ho_`` + 16 hex characters — an identifier by construction, short
    enough for a status cell, and never derived from user or model text."""
    return f"ho_{uuid.uuid4().hex[:16]}"


# ---- field patterns -------------------------------------------------------

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")       # ids: no colon
_STAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_HYPOTHESIS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,49}\Z")  # Hypothesis.id
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,78}\Z")    # findings may join with ':'
_NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")  # graph node ids


def _one_line(value: object, limit: int) -> str:
    """Sanitized bounded single-line text: redaction + the claim treatment.

    Order matters here too: redact FIRST, so a secret is replaced whole
    and the length cap can never cut one into a fragment that no longer
    matches a pattern — then normalize to one bounded line.
    """
    if not isinstance(value, str):
        # a non-string names nothing: dropped, not guessed at
        return claim_text(value, limit)
    return claim_text(redact(value)[0], limit)


# ---- the base contract ----------------------------------------------------

class HandoffMessage(BaseModel):
    """One record exchanged between stages. Base of all eight kinds.

    ``extra="forbid"`` is the impersonation control: a producer cannot
    attach an ``approved`` field, an executable shape or any other key the
    contract does not name — the record is exactly its schema.
    ``validate_default`` is what makes defaulted fields (``created_at``,
    ``subject_ref``) still pass through their validators.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    engagement_id: str
    message_id: str
    kind: str
    source: str
    destination: str
    # Optional in the schema on purpose: a producer that says nothing is
    # given "now" (the validator below) rather than being refused — the
    # record's own clock is the engine's, not the producer's.
    created_at: str = ""
    status: str = "registered"
    content: str = ""
    subject_ref: str = ""
    hypothesis_refs: list[str] = Field(default_factory=list)
    finding_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    correlation_id: str | None = None

    @field_validator("engagement_id", mode="before")
    @classmethod
    def _clean_engagement(cls, value):
        return _one_line(value, MAX_STAGE_CHARS)

    @field_validator("engagement_id")
    @classmethod
    def _valid_engagement(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError(
                "engagement_id must be 1-64 chars of letters/digits/._-")
        return value

    @field_validator("message_id", "correlation_id", mode="before")
    @classmethod
    def _clean_id(cls, value):
        if value is None:
            return None
        return _one_line(value, MAX_STAGE_CHARS)

    @field_validator("message_id")
    @classmethod
    def _valid_message_id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError(
                "message_id must be 1-64 chars of letters/digits/._-")
        return value

    @field_validator("correlation_id")
    @classmethod
    def _valid_correlation(cls, value: str | None) -> str | None:
        if value is not None and not _ID_RE.match(value):
            raise ValueError(
                "correlation_id must be 1-64 chars of letters/digits/._-")
        return value

    @field_validator("source", "destination", mode="before")
    @classmethod
    def _clean_stage(cls, value):
        return _one_line(value, MAX_STAGE_CHARS)

    @field_validator("source", "destination")
    @classmethod
    def _valid_stage(cls, value: str) -> str:
        if not _STAGE_RE.match(value):
            raise ValueError(
                "source/destination must be a non-empty stage name "
                "(1-64 chars of letters/digits/._-)")
        return value

    @field_validator("kind", mode="before")
    @classmethod
    def _clean_kind(cls, value):
        return _one_line(value, 32)

    @field_validator("kind")
    @classmethod
    def _valid_kind(cls, value: str) -> str:
        if value not in MESSAGE_KINDS:
            raise ValueError(
                f"unknown message kind {value!r}; registered kinds: "
                + ", ".join(sorted(MESSAGE_KINDS)))
        return value

    @field_validator("created_at", mode="before")
    @classmethod
    def _clean_created_at(cls, value):
        if value in (None, ""):
            return utc_now_iso()
        return _one_line(value, 40)

    @field_validator("created_at")
    @classmethod
    def _valid_created_at(cls, value: str) -> str:
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("created_at must be an ISO-8601 timestamp") from None
        return value

    @field_validator("status", mode="before")
    @classmethod
    def _clean_status(cls, value):
        return _one_line(value, 32)

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        if value not in MESSAGE_STATUSES:
            raise ValueError(
                f"unknown message status {value!r}; the vocabulary is the "
                "task lifecycle, the graph node statuses and the "
                "verification outcomes")
        return value

    @field_validator("content", mode="before")
    @classmethod
    def _clean_content(cls, value):
        return _one_line(value, MAX_CONTENT_CHARS)

    @field_validator("subject_ref", mode="before")
    @classmethod
    def _clean_subject(cls, value):
        return _one_line(value, 80)

    @field_validator("subject_ref")
    @classmethod
    def _valid_subject(cls, value: str) -> str:
        if value and not _LABEL_RE.match(value):
            raise ValueError(
                "subject_ref must be empty or a 1-79 char label "
                "(letters/digits/_.:-)")
        return value

    @field_validator("hypothesis_refs", mode="before")
    @classmethod
    def _clean_hypothesis_refs(cls, value):
        return _bounded_refs(value, _HYPOTHESIS_RE, "hypothesis_refs")

    @field_validator("finding_refs", mode="before")
    @classmethod
    def _clean_finding_refs(cls, value):
        return _bounded_refs(value, _LABEL_RE, "finding_refs")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _clean_evidence_refs(cls, value):
        return _bounded_refs(value, _NODE_ID_RE, "evidence_refs")


def _bounded_refs(value: object, pattern: re.Pattern, what: str) -> list[str]:
    """At most :data:`MAX_REFS` well-shaped refs, first-wins.

    Sanitizing, not rejecting: a ref that names nothing (or is not shaped
    like a ref at all) is dropped rather than failing the message, and a
    long list is capped — a producer cannot push junk past the bound.
    """
    if not isinstance(value, (list, tuple)):
        return []
    kept: list[str] = []
    for entry in value:
        text = _one_line(entry, 80)
        if not text or not pattern.match(text):
            continue
        if text in kept:
            continue
        kept.append(text)
        if len(kept) == MAX_REFS:
            break
    return kept


# ---- the eight kinds -------------------------------------------------------

class TaskAssignment(HandoffMessage):
    """Work assigned to a stage. The only dispatchable kind.

    ``task_safety`` is derived from ``task_type``, never trusted from the
    producer, and ``requires_approval`` is re-derived from it — a task
    cannot declare itself safe to re-run or approval-free.
    """

    kind: Literal["task_assignment"] = "task_assignment"
    task_type: str
    target_asset: str = ""
    requires_approval: bool = False

    @field_validator("task_type", mode="before")
    @classmethod
    def _clean_task_type(cls, value):
        return _one_line(value, 32)

    @field_validator("task_type")
    @classmethod
    def _valid_task_type(cls, value: str) -> str:
        if value not in TASK_TYPES:
            raise ValueError(
                f"unknown task type {value!r}; registered types: "
                + ", ".join(sorted(TASK_TYPES)))
        return value

    @field_validator("target_asset", mode="before")
    @classmethod
    def _clean_asset(cls, value):
        return _one_line(value, 300)

    @model_validator(mode="after")
    def _derive_safety(self) -> "TaskAssignment":
        # The safety class and the approval requirement are the engine's
        # words, not the producer's: overwritten here whatever came in.
        self.requires_approval = task_safety(self.task_type) == "state_changing"
        return self


class EvidenceRef(HandoffMessage):
    """A pointer to evidence that already exists in the engagement graph.

    Carries the node's identity and standing — never the node's payload.
    The status is the graph's own vocabulary, asserted by the producer and
    re-checked by the coordinator against the node it points at.
    """

    kind: Literal["evidence_ref"] = "evidence_ref"
    node_id: str
    node_type: str
    node_status: str = "observed"

    @field_validator("node_id", mode="before")
    @classmethod
    def _clean_node_id(cls, value):
        return _one_line(value, 64)

    @field_validator("node_id")
    @classmethod
    def _valid_node_id(cls, value: str) -> str:
        if not _NODE_ID_RE.match(value):
            raise ValueError(
                "node_id must be a 1-64 char graph node id "
                "(letters/digits/_.:-)")
        return value

    @field_validator("node_type", mode="before")
    @classmethod
    def _clean_node_type(cls, value):
        return _one_line(value, 32)

    @field_validator("node_type")
    @classmethod
    def _valid_node_type(cls, value: str) -> str:
        if not value:
            raise ValueError("node_type must be a non-empty node type")
        return value

    @field_validator("node_status")
    @classmethod
    def _valid_node_status(cls, value: str) -> str:
        if value not in NODE_STATUSES:
            raise ValueError(
                f"node_status {value!r} is not a graph status")
        return value

    @model_validator(mode="after")
    def _mirror_status(self) -> "EvidenceRef":
        self.status = self.node_status
        # the node is the subject: its id is the dedup identity's subject
        # slot, so two evidence refs about different nodes never collide
        if not self.subject_ref:
            self.subject_ref = self.node_id
        return self


class Observation(HandoffMessage):
    """Something a stage wants the next stage to see.

    Its standing can only ever be ``observed`` (the stage saw it) or
    ``proposed`` (a model suggested it). Anything stronger — tested,
    confirmed, independently verified — is not a message's word to give:
    it comes from execution evidence and verification, via the graph.
    """

    kind: Literal["observation"] = "observation"
    status: Literal["observed", "proposed"] = "proposed"


class TaskResult(HandoffMessage):
    """The outcome of one task, addressed back to the coordinator.

    ``status`` is forced to equal ``result_status`` — the message cannot
    say one thing in its status and another in its payload.
    """

    kind: Literal["task_result"] = "task_result"
    result_status: Literal["completed", "failed", "inconclusive"]
    outcome_note: str = ""

    @field_validator("outcome_note", mode="before")
    @classmethod
    def _clean_note(cls, value):
        return _one_line(value, MAX_NOTE_CHARS)

    @model_validator(mode="after")
    def _mirror_status(self) -> "TaskResult":
        self.status = self.result_status
        return self


class BlockedTask(HandoffMessage):
    """A task that could not run, with the real reason kept.

    The reason is carried, not laundered: a scope refusal is never
    described as a pass or a fail.
    """

    kind: Literal["blocked"] = "blocked"
    blocked_by: str = "unknown"
    block_reason: str = ""
    status: Literal["blocked"] = "blocked"

    @field_validator("blocked_by", mode="before")
    @classmethod
    def _clean_blocked_by(cls, value):
        return _one_line(value, MAX_STAGE_CHARS)

    @field_validator("blocked_by")
    @classmethod
    def _valid_blocked_by(cls, value: str) -> str:
        if not _STAGE_RE.match(value):
            raise ValueError("blocked_by must be a non-empty reason name")
        return value

    @field_validator("block_reason", mode="before")
    @classmethod
    def _clean_reason(cls, value):
        return _one_line(value, MAX_NOTE_CHARS)


class HumanApprovalRequest(HandoffMessage):
    """A *request* addressed to the human operator.

    There is deliberately no approved field and no approval-decision kind:
    an agent can ask, only the operator can answer, and the answer lands
    in the audit chain via ``human_review`` / the post-exploit approver —
    never in a handoff record.
    """

    kind: Literal["human_approval_request"] = "human_approval_request"
    requested_of: Literal["human"] = "human"
    gate: APPROVAL_GATES
    request: str = ""
    status: Literal["needs_approval"] = "needs_approval"

    @field_validator("request", mode="before")
    @classmethod
    def _clean_request(cls, value):
        return _one_line(value, MAX_CONTENT_CHARS)


class VerificationResult(HandoffMessage):
    """What an independent check concluded about a finding.

    The status words are the engine's own verification vocabulary
    (:mod:`views`) — verified / disagreed / inconclusive / not_run — and
    are forced onto the message status, so a result cannot call itself
    confirmed in one field and verified in another.
    """

    kind: Literal["verification_result"] = "verification_result"
    verification_status: Literal[
        "verified", "disagreed", "inconclusive", "not_run"]
    method: str = ""

    @field_validator("method", mode="before")
    @classmethod
    def _clean_method(cls, value):
        return _one_line(value, MAX_NOTE_CHARS)

    @model_validator(mode="after")
    def _mirror_status(self) -> "VerificationResult":
        self.status = self.verification_status
        return self


class CompletionSummary(HandoffMessage):
    """What a stage finished with, addressed to the next one."""

    kind: Literal["completion_summary"] = "completion_summary"
    outcome: Literal["completed", "halted", "failed", "interrupted"] = "completed"
    states_completed: list[str] = Field(default_factory=list)
    status: Literal["completed", "halted", "failed", "interrupted"] = "completed"

    @field_validator("states_completed", mode="before")
    @classmethod
    def _clean_states(cls, value):
        if not isinstance(value, (list, tuple)):
            return []
        kept: list[str] = []
        for entry in value:
            text = _one_line(entry, 32)
            if not text:
                continue
            kept.append(text)
            if len(kept) == 12:
                break
        return kept

    @model_validator(mode="after")
    def _mirror_status(self) -> "CompletionSummary":
        self.status = self.outcome
        return self


# ---- the coordinator's record ----------------------------------------------

class EvidenceLink(BaseModel):
    """One producer/consumer edge between a record and a graph node.

    Ids and roles only — a link never carries the node's payload, so
    sharing a reference can never become copying raw scanner output.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    node_id: str
    node_type: str = ""
    role: Literal["produced", "consumed"]
    by: str = ""
    at: str = ""

    @field_validator("node_id", mode="before")
    @classmethod
    def _clean_node_id(cls, value):
        return _one_line(value, 64)

    @field_validator("node_id")
    @classmethod
    def _valid_node_id(cls, value: str) -> str:
        if not _NODE_ID_RE.match(value):
            raise ValueError("node_id must be a graph node id")
        return value

    @field_validator("by", "node_type", mode="before")
    @classmethod
    def _clean_bounded(cls, value, info):
        return _one_line(value, MAX_STAGE_CHARS if info.field_name == "by" else 32)

    @field_validator("at", mode="before")
    @classmethod
    def _clean_at(cls, value):
        if value in (None, ""):
            return utc_now_iso()
        return _one_line(value, 40)


class HandoffRecord(BaseModel):
    """The coordinator's durable record of one handoff message.

    Holds the originating message (as data), the lifecycle status of the
    work it represents, the results recorded against it, and the evidence
    links it declared. Serialized whole into ``handoff_records.payload`` —
    one row per record, one transaction per save.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    engagement_id: str
    message_id: str
    identity_key: str
    kind: str
    status: str
    source: str
    destination: str
    created_at: str
    updated_at: str
    task_type: str = ""
    subject_ref: str = ""
    attempts: int = 0
    message: dict = Field(default_factory=dict)  # the origin message, as data
    results: list[dict] = Field(default_factory=list)
    evidence_links: list[EvidenceLink] = Field(default_factory=list)
    blocked_reason: str = ""
    approval_gate: str = ""

    @field_validator("attempts")
    @classmethod
    def _valid_attempts(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("attempts must be a non-negative int")
        return value


class DispatchDecision(BaseModel):
    """The answer to "should this work run, again or at all?".

    ``outcome`` is one of :data:`DISPATCH_OUTCOMES`; ``record`` is the
    existing record when the identity was already known, else the newly
    created one. Missing records are never invented — a decision about
    work the coordinator has no record of is ``new``.
    """

    model_config = ConfigDict(extra="forbid")

    outcome: str
    record: HandoffRecord | None = None

    @field_validator("outcome")
    @classmethod
    def _valid_outcome(cls, value: str) -> str:
        if value not in DISPATCH_OUTCOMES:
            raise ValueError(f"unknown dispatch outcome {value!r}")
        return value
