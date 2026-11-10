"""Capability evidence for the EXPLOIT -> POST_EXPLOIT handoff (Phase 1B).

A capability starts life as ``claimed`` — parsed from one exploit
attempt's own execution evidence by a registered parser — and reaches
``approved`` or ``rejected`` exclusively through the Gate 3 decision in
``exploit.py``. The POST_EXPLOIT subagent consumes ``approved`` records
and nothing else, and fails closed when there is none, when the record
is malformed, when it was rejected, or when its target host is outside
engagement scope.

Honest limitation, unchanged: the parser registry is deliberately EMPTY.
No tool in the current inventory yields trustworthy, independently
verifiable shell evidence, so nothing ever claims a capability and the
POST_EXPLOIT state stays dormant — the engagement routes EXPLOIT ->
VERIFY exactly as it did before Phase 1B. Add a registry entry only for
a tool whose shell artifacts can be parsed deterministically, and write
its test; the registry — never an LLM, never a generic success message,
never an exit code alone — decides what counts as capability evidence.
"""

from __future__ import annotations

from typing import Callable, Literal

from pydantic import BaseModel, ValidationError, field_validator

from ..secrets import redact
from .views import ATTEMPT_CONFIRMED, attempt_outcome

#: A parsed evidence excerpt is bounded at the record level: whatever a
#: parser returns, the stored evidence is at most this many characters,
#: secret-redacted.
MAX_EVIDENCE_CHARS = 600
#: Gate 3 presentation: at most this many records, this many characters
#: in total.
MAX_GATE_RECORDS = 3
MAX_GATE_CHARS = 1500

#: Tool name -> parser(output_excerpt) -> shell-evidence text or None.
#:. Deliberately empty (see module docstring): an empty registry keeps
#: POST_EXPLOIT dormant — the safe pre-Phase-1B behavior.
CAPABILITY_PARSERS: dict[str, Callable[[str], "str | None"]] = {}


def _clean(text: str) -> str:
    """Bound + secret-redact a piece of capability evidence."""
    return redact(text[:MAX_EVIDENCE_CHARS])[0]


class CapabilityRecord(BaseModel):
    """One structured, validated capability claim.

    Exactly the ``properties`` of a ``capability`` graph node. The
    lifecycle is one-way: a parser may only ever write ``claimed``;
    only the Gate 3 decision writes ``approved``/``rejected``;
    ``verified`` is reserved for Phase 1C independent verification —
    nothing grants it implicitly.
    """

    capability: Literal["shell"]
    tool: str
    #: exploit_attempt node id + label the claim derives from
    attempt_id: str
    attempt_label: str
    hypothesis_id: str
    #: in-scope host the capability is established on
    target_host: str
    #: finding node label the attempt confirmed ("" when unconfirmed-but-run)
    finding_id: str = ""
    #: Gate 3 lifecycle (approval decision) — written only by the gate:
    #: claimed -> approved | rejected. Phase 1C: the model no longer
    #: conflates approval with independent verification; a record whose
    #: status is ``verified`` here is legacy shape and reads as
    #: not-approved (fail closed).
    status: Literal["claimed", "verified", "approved", "rejected"]
    #: Phase 1C — INDEPENDENT verification of the claimed shell evidence
    #: itself. Written ONLY by the Phase 1D verifier
    #: (:mod:`capability_verify`) when the record's producer has a
    #: registered verification contract AND the contract's bounded probe
    #: reproduces its marker inside the Mode B sandbox — never by Gate 3
    #: and never implicitly. Eligibility for post-exploitation requires
    #: ``status == "approved"`` AND ``verification == "verified"``;
    #: approval alone is never enough.
    verification: Literal["not_run", "verified"] = "not_run"
    #: bounded, secret-redacted supporting evidence
    evidence: str
    #: machine-produced, never LLM-authored
    recorded_by: Literal["EXPLOIT_PROGRAM"] = "EXPLOIT_PROGRAM"

    @field_validator(
        "tool", "attempt_id", "attempt_label", "hypothesis_id", "target_host"
    )
    @classmethod
    def _non_empty(cls, value: str) -> str:
        """A record without a traceable source field is malformed — and a
        malformed record must never be able to hand the subagent a
        target or an attempt to hang off."""
        if not (value or "").strip():
            raise ValueError("capability record source fields cannot be empty")
        return value

    @field_validator("evidence")
    @classmethod
    def _evidence_bounded(cls, value: str) -> str:
        return _clean(value)


def build_record(
    *,
    capability: str,
    tool: str,
    attempt_id: str,
    attempt_label: str,
    hypothesis_id: str,
    target_host: str,
    finding_id: str = "",
    evidence: str,
    status: str = "claimed",
    verification: str = "not_run",
) -> "CapabilityRecord | None":
    """Build + validate a record — a wrong field means None, never a
    half-valid record (fail closed). Anything claiming a capability the
    schema does not know, an unknown status, or empty source fields is
    refused here. ``verification`` defaults to ``not_run`` and only the
    Phase 1D verifier may pass ``verified`` — no Gate 3 decision can set
    it."""
    try:
        record = CapabilityRecord(
            capability=capability,  # type: ignore[arg-type]
            tool=tool,
            attempt_id=attempt_id,
            attempt_label=attempt_label,
            hypothesis_id=hypothesis_id,
            target_host=target_host,
            finding_id=finding_id,
            status=status,  # type: ignore[arg-type]
            verification=verification,  # type: ignore[arg-type]
            evidence=evidence,
        )
    except ValidationError:
        return None
    return record


def claim_from_attempt(
    attempt: dict,
    target_host: str,
    findings_by_label: "dict[str, dict] | None" = None,
) -> "CapabilityRecord | None":
    """Derive a capability claim from one exploit_attempt node — or None.

    Every gate must pass, in order:
    1. the attempt's tool must have a parser in ``CAPABILITY_PARSERS``
       (empty by default — the dormant state),
    2. the attempt must be CONFIRMED by the authoritative read-time
       derivation (:func:`views.attempt_outcome`), which reads only the
       producer's execution evidence — never the stored outcome word,
       never an LLM claim, never a bare exit code,
    3. the parser must extract usable shell evidence from the attempt's
       own bounded, redacted output excerpt.
    """
    props = attempt.get("properties", {})
    tool = props.get("tool", "")
    parser = CAPABILITY_PARSERS.get(tool)
    if parser is None:
        return None
    if attempt_outcome(attempt) != ATTEMPT_CONFIRMED:
        return None
    parsed = parser(_clean(str(props.get("output_excerpt", ""))))
    if not parsed:
        return None
    label = str(attempt.get("label", ""))
    hyp_id = label.split(":", 1)[0]
    finding = (findings_by_label or {}).get(hyp_id)
    return build_record(
        capability="shell",
        tool=tool,
        attempt_id=str(attempt.get("id", "")),
        attempt_label=label,
        hypothesis_id=hyp_id,
        target_host=target_host,
        finding_id=(finding or {}).get("label", ""),
        evidence=str(parsed),
    )


def host_in_scope(host: str, target: str) -> bool:
    """The record's host is the engagement target or a subdomain of it."""
    h = (host or "").strip().lower().rstrip(".")
    t = (target or "").strip().lower().rstrip(".")
    return bool(h) and bool(t) and (h == t or h.endswith("." + t))


def capability_gate_text(
    records: "list[CapabilityRecord]",
    max_records: int = MAX_GATE_RECORDS,
    max_chars: int = MAX_GATE_CHARS,
) -> str:
    """The bounded Gate 3 presentation text — the reviewer sees the real
    capability evidence (already redacted at the record level), not a
    stub string."""
    lines: list[str] = []
    for record in records[:max_records]:
        lines.append(
            f"{record.capability} on {record.target_host} via {record.tool} "
            f"(hypothesis {record.hypothesis_id}, "
            f"finding {record.finding_id or 'none'}, "
            f"attempt {record.attempt_label})"
        )
        if record.evidence:
            lines.append(f"  evidence: {record.evidence}")
    return "\n".join(lines)[:max_chars]
