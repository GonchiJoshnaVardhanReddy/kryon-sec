"""Validated output contracts for specialist work (Batch 4D, Shannon-inspired).

One deliverable is one specialist's structured answer: what task it belongs
to, who produced it, what standing the result has, which evidence it is
backed by, what it could not establish, and what the work cost. Shannon's
lesson is adopted here: **validators are code, not prompts** — a malformed
deliverable is refused at the schema, never repaired into something that
looks right.

Two vocabularies, and the difference between them is the point:

* ``status`` — the *task* outcome words (``completed`` / ``failed`` /
  ``inconclusive`` / ``blocked``). What happened to the work.
* ``standing`` — the *evidence* words the engine itself derives
  (:data:`~recon_passive.NODE_STATUSES` plus the verification outcomes).
  No producer may claim a standing: the specialist layer derives it from
  the graph via :mod:`views` before the deliverable is built, and an LLM
  that says ``verified`` without the independent-verification contract
  behind it produces a deliverable whose standing says what the engine
  recorded — which is ``not_run``, not ``verified``.

Every free-text field is bounded and redacted on the way in (the handoff
treatment), ``extra="forbid"`` is the impersonation control, and the budget
fields are *labelled* as estimates unless the producer marks them actual —
a deterministic specialist never has provider usage data, so its numbers
must never be presented as charges.
"""

from __future__ import annotations

from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .handoff import (
    _ID_RE,
    _LABEL_RE,
    _NODE_ID_RE,
    _STAGE_RE,
    MAX_NOTE_CHARS,
    _bounded_refs,
    _one_line,
)
from .views import (
    VERIFICATION_DISAGREED,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_NOT_RUN,
    VERIFICATION_UNRESOLVED,
    VERIFICATION_VERIFIED,
)

__all__ = [
    "DELIVERABLE_FORMAT_VERSION",
    "RESULT_STATUSES",
    "BudgetUsage",
    "SpecialistDeliverable",
    "DeliverableClaim",
]

DELIVERABLE_FORMAT_VERSION = 1

# The task-outcome words a deliverable may carry — the same words the
# coordinator's TaskResult vocabulary uses, so a deliverable and the record
# it is filed under can never disagree about what happened.
RESULT_STATUSES: frozenset[str] = frozenset({
    "completed", "failed", "inconclusive", "blocked",
})

# The evidence-standing words. These are the engine's, not the producer's:
# a deliverable's standing is *derived* by the specialist layer from the
# graph, and a model-supplied word cannot raise it (a hypothesis's prose
# claiming ``confirmed`` renders as ``proposed`` — the A13 rule, carried
# here so a deliverable cannot relapse). Every word below is one of three
# engine vocabularies the executor reads: the graph node statuses, the
# verification outcomes and the exploit-attempt outcomes — plus the basis
# levels ``views.relationship_basis`` grades a hypothesis with, and
# ``unresolved`` for a subject the engine can derive nothing about.
STANDING_WORDS: frozenset[str] = frozenset({
    # graph node statuses (recon_passive.NODE_STATUSES)
    "observed", "inferred", "proposed", "validated", "confirmed", "rejected",
    # independent-verification outcomes (views.VERIFICATION_*):
    # unresolved is the contested word — an agreeing difference with
    # counterevidence standing — and shares the spelling of the basis
    # level ``unresolved`` below (both mean: the engine settles nothing)
    VERIFICATION_VERIFIED, VERIFICATION_DISAGREED, VERIFICATION_UNRESOLVED,
    VERIFICATION_INCONCLUSIVE, VERIFICATION_NOT_RUN,
    # exploit-attempt outcomes (views.ATTEMPT_*): what a test recorded,
    # which is not what a model claimed and not a finding
    "none", "not-run", "unrecorded", "inconclusive",
    # engine basis levels (views.BASIS_*): proposed is above, these two
    # grade how much of the hypothesis the engine's own records support
    "supported", "tested",
    "unresolved",
})


class BudgetUsage(BaseModel):
    """What one specialist task consumed, honestly labelled.

    ``estimated`` exists so a number can never pretend to be a charge: the
    deterministic specialists have no provider usage object, so their token
    figures are estimates of the context they read and the output they
    wrote, and their cost is zero. An LLM-backed specialist that receives
    provider-reported usage records it here with ``estimated=False``.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    tokens: int = 0
    cost_usd: float = 0.0
    estimated: bool = True
    source: Literal["none", "provider_usage", "token_estimate"] = (
        "token_estimate")

    @field_validator("tokens")
    @classmethod
    def _valid_tokens(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("tokens must be a non-negative int")
        return value

    @field_validator("cost_usd")
    @classmethod
    def _valid_cost(cls, value: float) -> float:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError("cost_usd must be a number")
        if value < 0:
            raise ValueError("cost_usd must be non-negative — a refund is "
                             "not a budget consumption")
        return float(value)

    @model_validator(mode="after")
    def _align_source(self) -> "BudgetUsage":
        # A provider-usage figure is actual by definition; an estimate is
        # not provider data. The two fields cannot disagree.
        if self.source == "provider_usage":
            self.estimated = False
        elif self.source == "token_estimate":
            self.estimated = True
        if self.estimated and self.source == "provider_usage":
            self.source = "token_estimate"
        return self


class DeliverableClaim(BaseModel):
    """One claim inside a deliverable, with its engine-derived standing.

    ``standing`` is filled by the specialist layer from :mod:`views` — the
    producer never writes it. A claim without a standing the engine can
    derive stays ``unresolved``: carried, visible, never promoted.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    subject_ref: str = ""
    standing: str = "unresolved"
    note: str = ""

    @field_validator("subject_ref", mode="before")
    @classmethod
    def _clean_subject(cls, value):
        return _one_line(value, 80)

    @field_validator("subject_ref")
    @classmethod
    def _valid_subject(cls, value: str) -> str:
        if value and not _LABEL_RE.match(value):
            raise ValueError(
                "subject_ref must be empty or a bounded label")
        return value

    @field_validator("standing")
    @classmethod
    def _valid_standing(cls, value: str) -> str:
        if value not in STANDING_WORDS:
            raise ValueError(
                f"standing {value!r} is not an engine-derived evidence "
                "word; the producer cannot invent a standing")
        return value

    @field_validator("note", mode="before")
    @classmethod
    def _clean_note(cls, value):
        return _one_line(value, MAX_NOTE_CHARS)


class SpecialistDeliverable(BaseModel):
    """The validated output contract for one specialist task.

    Rejected, never repaired, when a required field is missing or a
    vocabulary word is wrong: the schema is the whole contract, and a
    deliverable that does not validate means the task failed — it is
    recorded as one, with the reason kept.
    """

    model_config = ConfigDict(extra="forbid", validate_default=True)

    version: int = DELIVERABLE_FORMAT_VERSION
    task_id: str
    producer: str          # the specialist role
    source_stage: str      # the lifecycle stage it ran in
    status: str            # RESULT_STATUSES
    standing: str = "unresolved"
    summary: str = ""      # the one-line answer
    evidence_refs: list[str] = Field(default_factory=list)
    claims: list[DeliverableClaim] = Field(default_factory=list)
    confidence: float | None = None
    rationale: str = ""
    limitations: list[str] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    budget: BudgetUsage = Field(default_factory=BudgetUsage)

    @field_validator("version")
    @classmethod
    def _valid_version(cls, value: int) -> int:
        if value != DELIVERABLE_FORMAT_VERSION:
            raise ValueError(
                f"deliverable format version {value!r} is not supported "
                f"(this build writes {DELIVERABLE_FORMAT_VERSION})")
        return value

    @field_validator("task_id")
    @classmethod
    def _valid_task(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError("task_id must be a handoff message id")
        return value

    @field_validator("producer", "source_stage", mode="before")
    @classmethod
    def _clean_names(cls, value):
        return _one_line(value, 64)

    @field_validator("producer", "source_stage")
    @classmethod
    def _valid_names(cls, value: str) -> str:
        if not _STAGE_RE.match(value):
            raise ValueError("producer/source_stage must be non-empty names")
        return value

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        if value not in RESULT_STATUSES:
            raise ValueError(
                f"status {value!r} is not a task-outcome word "
                f"({', '.join(sorted(RESULT_STATUSES))})")
        return value

    @field_validator("standing")
    @classmethod
    def _valid_standing(cls, value: str) -> str:
        if value not in STANDING_WORDS:
            raise ValueError(
                f"standing {value!r} is not an engine-derived word")
        return value

    @field_validator("summary", "rationale", mode="before")
    @classmethod
    def _clean_text(cls, value):
        return _one_line(value, 400)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _clean_evidence(cls, value):
        return _bounded_refs(value, _NODE_ID_RE, "evidence_refs")

    @field_validator("limitations", "unresolved", "errors", mode="before")
    @classmethod
    def _clean_lines(cls, value):
        return _bounded_lines(value)

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: float | None) -> float | None:
        if value is None:
            return None
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError("confidence must be a number or None")
        if not 0.0 <= value <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        return float(value)

    @model_validator(mode="after")
    def _no_unbacked_confidence(self) -> "SpecialistDeliverable":
        # Confidence is a number ABOUT evidence. A deliverable that names
        # no evidence cannot carry one — it would be a feeling with a
        # decimal point.
        if self.confidence is not None and not self.evidence_refs:
            raise ValueError(
                "confidence requires evidence_refs: a number about "
                "nothing is not a measurement")
        return self


def _bounded_lines(value: object, limit: int = 6,
                   chars: int = MAX_NOTE_CHARS) -> list[str]:
    """At most ``limit`` bounded single-line entries, first-wins."""
    if not isinstance(value, (list, tuple)):
        return []
    kept: list[str] = []
    for entry in value:
        text = _one_line(entry, chars)
        if not text:
            continue
        kept.append(text)
        if len(kept) == limit:
            break
    return kept
