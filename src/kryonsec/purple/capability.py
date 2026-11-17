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

Phase 6A completes the record's lifecycle: records are BOUND to the
engagement that claimed them (never portable across engagements),
STAMPED with the moment they were recorded (they expire — a capability
is a statement about a shell that existed, never a standing
authorization), and REVOCABLE through an audited, append-only kill
switch. :func:`capability_eligibility` is the ONE ordered check every
consumer runs before acting on a record; it re-derives freshness and
staleness from the graph at consumption time instead of trusting the
record's stored words.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Literal

from pydantic import BaseModel, ValidationError, field_validator

from ..secrets import redact
from .handoff import utc_now_iso
from .views import ATTEMPT_CONFIRMED, attempt_outcome

#: A parsed evidence excerpt is bounded at the record level: whatever a
#: parser returns, the stored evidence is at most this many characters,
#: secret-redacted.
MAX_EVIDENCE_CHARS = 600
#: Gate 3 presentation: at most this many records, this many characters
#: in total.
MAX_GATE_RECORDS = 3
MAX_GATE_CHARS = 1500

#: Phase 6A — the longest a record stays eligible after it was recorded.
#: A claimed+approved+verified capability describes a shell that existed
#: at a moment in time; after this window the record is stale and the
#: subagent must refuse (a fresh claim from fresh evidence is the only
#: way back). Deliberately short: hours, not days.
CAPABILITY_MAX_AGE_S = 6 * 3600
#: Phase 6A — bounded producer names in the parser registry.
MAX_TOOL_NAME_CHARS = 64

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
    #: not-approved (fail closed). Phase 6A: ``revoked`` is the one-way
    #: terminal state the audited kill switch writes (revocation is
    #: RECORDED, never deleted); a revoked record is refused everywhere.
    status: Literal["claimed", "verified", "approved", "rejected", "revoked"]
    #: Phase 1C — INDEPENDENT verification of the claimed shell evidence
    #: itself. Written ONLY by the Phase 1D verifier
    #: (:mod:`capability_verify`) when the record's producer has a
    #: registered verification contract AND the contract's bounded probe
    #: reproduces its marker inside the Mode B sandbox — never by Gate 3
    #: and never implicitly. Eligibility for post-exploitation requires
    #: ``status == "approved"`` AND ``verification == "verified"``;
    #: approval alone is never enough.
    verification: Literal["not_run", "verified"] = "not_run"
    #: Phase 6A — the engagement that claimed this record. Empty only on
    #: legacy (pre-6A) records; eligibility refuses an unbound record, so
    #: a capability can never be consumed by an engagement other than the
    #: one whose exploit claimed it.
    engagement_id: str = ""
    #: Phase 6A — when the claim was recorded (ISO-8601 UTC). Drives
    #: expiration at consumption time; a missing or unparseable stamp
    #: reads as unusable and is refused (fail closed), never as fresh.
    recorded_at: str = ""
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
    engagement_id: str = "",
    recorded_at: str = "",
) -> "CapabilityRecord | None":
    """Build + validate a record — a wrong field means None, never a
    half-valid record (fail closed). Anything claiming a capability the
    schema does not know, an unknown status, or empty source fields is
    refused here. ``verification`` defaults to ``not_run`` and only the
    Phase 1D verifier may pass ``verified`` — no Gate 3 decision can set
    it. ``engagement_id``/``recorded_at`` default empty (legacy shape);
    production claims (:func:`claim_from_attempt`) always set both."""
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
            engagement_id=engagement_id,
            recorded_at=recorded_at,
            evidence=evidence,
        )
    except ValidationError:
        return None
    return record


def claim_from_attempt(
    attempt: dict,
    target_host: str,
    findings_by_label: "dict[str, dict] | None" = None,
    engagement_id: str = "",
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

    Phase 6A: every record written here is BOUND to ``engagement_id``
    (the caller passes the graph's engagement id — a claim is never
    portable) and STAMPED with the moment it was recorded (``recorded_at``
    — expiration is computed from the record's own stamp at consumption
    time, not from a wall-clock read there).
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
        engagement_id=engagement_id,
        recorded_at=utc_now_iso(),
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


# ---- Phase 6A: registration, revocation, eligibility ------------------------


def register_capability_parser(
    tool: str, parser: "Callable[[str], str | None]",
) -> None:
    """The reviewed-configuration entry point for the producer registry
    (Phase 6A).

    The shipped registry stays deliberately EMPTY — nothing in the
    current inventory yields shell evidence that survives independent
    verification, and this function is how a reviewed tool would EVER
    be added, never a way to sneak one in at runtime. It is strict:
    an empty, overlong (``MAX_TOOL_NAME_CHARS``) or control-charactered
    tool name, or a non-callable parser, is REFUSED — never half-
    registered. Re-registering a tool's name OVERWRITES the previous
    parser (registration is reviewed configuration applied by a human
    decision, not runtime data), mirroring the verification-contract
    registry's overwrite semantics.
    """
    name = (tool or "").strip()
    if not name:
        raise ValueError("capability parser registration needs a tool name")
    if len(name) > MAX_TOOL_NAME_CHARS:
        raise ValueError(
            f"capability parser tool name too long "
            f"({len(name)} > {MAX_TOOL_NAME_CHARS} chars)")
    if any(ord(c) < 32 or c == "\x7f" for c in name):
        raise ValueError(
            "capability parser tool name has control characters")
    if not callable(parser):
        raise ValueError("capability parser must be callable")
    CAPABILITY_PARSERS[name] = parser


def record_age_s(recorded_at: str, now: datetime) -> "float | None":
    """The record's age in seconds, from its own ``recorded_at`` stamp.

    None means UNUSABLE, never "fresh": a missing stamp, an unparseable
    one, or one claiming to be from the future (clock skew or a forged
    record) is not read as a young record — the caller must refuse.
    Pure: no clock reads of its own; ``now`` comes from the caller so
    expiration is testable deterministically.
    """
    try:
        ts = datetime.fromisoformat(
            (recorded_at or "").strip().replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age = (now - ts).total_seconds()
    if age < 0:
        return None  # the future is not a valid record time
    return age


def capability_eligibility(
    record: "CapabilityRecord",
    node: dict,
    graph,
    *,
    engagement_id: str,
    target: str,
    now: datetime,
) -> "tuple[bool, str]":
    """The ONE ordered eligibility check every consumer runs before
    acting on a capability record (Phase 6A).

    Ordered checks, each fail-closed:
    1. the node is still a capability node on this graph
    2. consumed — a record an earlier run already consumed is refused
       (the consumption guard: after a crash or interruption the state
       never silently replays state-changing enumeration on a stale
       capability; recovery is a fresh claim from fresh evidence)
    3. revoked — a revoked record stays revoked (revocation is recorded,
       never deleted)
    4. approval — only ``approved`` status is consumable
    5. verification — independent verification, not approval alone
    6. binding — the record belongs to THIS engagement (unbound legacy
       records are refused, not grandfathered)
    7. scope — the record's host is in engagement scope
    8. freshness — the record carries a usable stamp and has not expired
    9. staleness — its attempt still exists on the graph, is still the
       same tool, and still confirms the capability

    Pure: mutates nothing, reads no clock (``now`` is a parameter),
    writes no audit — the caller decides what a refusal means and
    records it. Returns ``(ok, reason)``; the reason strings are a
    stable, asserted contract.
    """
    if not isinstance(node, dict) or node.get("node_type") != "capability":
        return False, "capability node is missing or retyped on the graph"
    if (node.get("properties") or {}).get("consumed_at"):
        return False, ("capability record was already consumed by an "
                       "earlier run — refused (never replayed)")
    if record.status == "revoked":
        return False, "capability record is revoked"
    if record.status != "approved":
        return False, "capability record is not approved"
    if record.verification != "verified":
        return False, ("capability evidence is not independently "
                       "verified (approval alone is not eligibility)")
    if not record.engagement_id:
        return False, "capability record is not bound to an engagement"
    if record.engagement_id != engagement_id:
        return False, (f"capability record belongs to engagement "
                       f"{record.engagement_id!r}, not "
                       f"{engagement_id!r} — refused (cross-engagement)")
    if not host_in_scope(record.target_host, target):
        return False, "capability host is outside engagement scope"

    age = record_age_s(record.recorded_at, now)
    if age is None:
        return False, "capability record has no usable recorded_at stamp"
    if age > CAPABILITY_MAX_AGE_S:
        return False, (f"capability record expired "
                       f"({int(age)}s old > {CAPABILITY_MAX_AGE_S}s)")

    attempt = graph.get_node(record.attempt_id) if graph is not None else None
    if attempt is None:
        return False, ("capability record's attempt is missing from the "
                       "graph — invalidated")
    attempt_props = attempt.get("properties") or {}
    if str(attempt_props.get("tool", "")) != record.tool:
        return False, ("capability record's attempt tool no longer "
                       "matches the record — invalidated")
    try:
        still_confirms = attempt_outcome(attempt) == ATTEMPT_CONFIRMED
    except Exception:  # a read-time derivation bug can never approve
        still_confirms = False
    if not still_confirms:
        return False, ("capability record's attempt no longer confirms "
                       "the capability — invalidated")
    return True, "eligible"


def revoke_capability(graph, audit, node_id: str) -> bool:
    """The audited kill switch for one capability record (Phase 6A).

    Revocation is a RECORDED terminal state, never a deletion: the node
    stays on the graph with ``status`` flipped to ``revoked`` — the same
    direct write the Gate 3 decision uses — and the audit chain gains a
    ``capability_revoked`` event. Refuses (and audits the refusal) when
    the node does not exist, is not a capability node, or carries a
    record the schema no longer accepts. Re-revoking an already-revoked
    record is an idempotent no-op success. Returns whether the record
    ends revoked.
    """
    node = graph.get_node(node_id) if graph is not None else None
    if node is None or node.get("node_type") != "capability":
        audit.write({
            "event": "capability_revoked",
            "node_id": node_id,
            "revoked": False,
            "reason": "no capability node with this id",
        })
        return False
    try:
        record = CapabilityRecord.model_validate(node["properties"])
    except ValidationError:
        audit.write({
            "event": "capability_revoked",
            "node_id": node_id,
            "revoked": False,
            "reason": "malformed capability record",
        })
        return False
    if record.status == "revoked":
        audit.write({
            "event": "capability_revoked",
            "node_id": node_id,
            "revoked": True,
            "already_revoked": True,
            "attempt_label": record.attempt_label,
            "capability": record.capability,
        })
        return True
    node["properties"]["status"] = "revoked"
    audit.write({
        "event": "capability_revoked",
        "node_id": node_id,
        "revoked": True,
        "attempt_label": record.attempt_label,
        "capability": record.capability,
        "previous_status": record.status,
    })
    return True
