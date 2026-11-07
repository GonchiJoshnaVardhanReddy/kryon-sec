"""Independent capability verification (Phase 1D).

Phase 1B lets a REGISTERED parser turn one exploit attempt's own
execution evidence into a ``claimed`` capability record; Phase 1C
reserves the record's ``verification`` field for an independent check
and makes approval alone never eligible for post-exploitation. This
module is that separate, deterministic verification mechanism.

Contract model
--------------
* A producer is trusted ONLY if it is explicitly registered TWICE:
  once as an evidence parser (``capability.CAPABILITY_PARSERS``) and
  once with a :class:`VerificationContract` here. Both registries are
  deliberately EMPTY in production — no current tool can claim a shell
  with evidence that survives an independent probe, so verification is
  dormant exactly like claiming is (fail closed by emptiness).
* A contract binds the producer to ONE bounded, deterministic probe:
  a fixed argv run INSIDE the Mode B sandbox (the same
  ``KaliSandbox`` the engagement uses — gVisor + the pinned egress
  policy that each spawn re-verifies), whose stdout must contain the
  contract's exact marker. The verdict is derived from the probe's
  execution evidence alone — never from the claimed evidence string,
  never from a stored status word, never from an exit code alone.
* Every attempt, result and refusal is recorded: a
  ``capability_verification`` graph node linked to its originating
  capability node by ``verified_by`` lineage, plus audit events
  (``capability_verification_attempted`` then
  ``capability_verified`` / ``_refused`` / ``_failed``).

Fail-closed surfaces (each audited, none crash the run): unregistered
producer, stale/missing attempt references, a record whose lifecycle
already moved past ``claimed``, an out-of-scope host, a malformed or
contradictory record, an allowlist-violating probe, and sandbox or
probe failure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, field_validator

from ..secrets import redact
from . import capability
from .allowlist import AllowlistViolation, ToolAllowlist
from .lineage import link
from .views import ATTEMPT_CONFIRMED, attempt_outcome

log = logging.getLogger(__name__)

#: Bounds for the probe and the recorded verdict evidence (defence in
#: depth: a contract cannot smuggle an unbounded command or marker).
MAX_PROBE_TOKENS = 12
MAX_PROBE_TOKEN_CHARS = 200
MAX_MARKER_CHARS = 64
MAX_REASON_CHARS = 200

#: producer tool -> its mutually-approved verification contract.
#: Deliberately EMPTY (production): both halves of producer trust
#: (parser + contract) must be explicitly registered, tested and
#: reviewed before any capability can ever be verified.
CAPABILITY_VERIFICATION_CONTRACTS: "dict[str, VerificationContract]" = {}


@dataclass(frozen=True)
class VerificationContract:
    """The ONE bounded verification method a producer is trusted with.

    ``probe_argv`` is the exact static argv the verifier runs inside
    the Mode B sandbox; ``expect_marker`` is the exact stdout token the
    probe must emit for the capability to confirm — the probe's OWN
    evidence, independent of the claimed evidence string. Contracts are
    reviewed configuration (never runtime/LLM input) and are fully
    static: no templating, no environmental interpolation.

    Binding requirements (fail closed at verify time): the probe argv
    MUST reference the claimed target — a marker-only probe that never
    touches the engagement target cannot demonstrate an ON-TARGET
    capability and is refused — and the contract names the one
    ``capability`` class it may verify, which must equal the record's.
    """

    producer: str
    #: short machine label of the method, e.g. "sandbox_marker_probe"
    method: str
    probe_argv: "tuple[str, ...]"
    expect_marker: str
    #: the capability class this contract may verify (kept narrow:
    #: a shell contract must not verify a file-read record)
    capability: str = "shell"

    def probe_args(self) -> "tuple[str, ...]":
        """The exact argv for the probe — a static contract argv."""
        return tuple(self.probe_argv)


def register_contract(contract: "VerificationContract") -> None:
    """Explicit producer registration (trusted configuration, never
    LLM/operator runtime input). A bad contract raises instead of
    registering — the registry shape is itself fail closed."""
    if not (contract.producer or "").strip():
        raise ValueError("verification contract needs a producer")
    if not (contract.method or "").strip():
        raise ValueError("verification contract needs a method")
    argv = tuple(contract.probe_argv)
    if not argv or len(argv) > MAX_PROBE_TOKENS:
        raise ValueError(
            "verification contract probe must have 1.."
            f"{MAX_PROBE_TOKENS} argv tokens")
    if any(len(t) > MAX_PROBE_TOKEN_CHARS for t in argv):
        raise ValueError(
            f"probe tokens are bounded at {MAX_PROBE_TOKEN_CHARS} chars")
    if any("\n" in t or "{" in t or "}" in t for t in argv):
        raise ValueError(
            "probe tokens are fully static: no newlines or placeholders")
    if not contract.expect_marker or \
            len(contract.expect_marker) > MAX_MARKER_CHARS:
        raise ValueError(
            f"expect_marker must be 1..{MAX_MARKER_CHARS} chars")
    if not (contract.capability or "").strip():
        raise ValueError("verification contract needs a capability class")
    CAPABILITY_VERIFICATION_CONTRACTS[contract.producer] = contract


def contracts_ready() -> bool:
    """True when at least one trusted producer has a verification
    contract. Production stays False — verification is dormant — and
    the exploit flow skips the whole phase, producing ZERO nodes and
    ZERO events, exactly the pre-Phase-1D behavior."""
    return bool(CAPABILITY_VERIFICATION_CONTRACTS)


class CapabilityVerificationResult(BaseModel):
    """The typed verdict of one independent verification attempt.

    ``status`` is derived: ``verified`` only when a registered
    producer's contract probe succeeded INSIDE the sandbox; every
    other path is ``refused`` (never attempted: trust/scope/lifecycle
    problems) or ``failed`` (attempted, not reproducible). Fail
    closed — eligibility needs exactly this ``verified``.
    """

    capability_node_id: str
    attempt_node_id: str
    tool: str
    target_host: str
    method: str
    status: Literal["verified", "refused", "failed"]
    reasons: "list[str]" = []
    probe_exit_code: "int | None" = None
    marker_seen: bool = False

    @field_validator("reasons", mode="before")
    @classmethod
    def _reasons_bounded(cls, value):
        out = []
        for item in (value or []):
            out.append(redact(str(item)[:MAX_REASON_CHARS])[0])
        return out


class CapabilityVerifier:
    """Deterministic, independent verification of claimed capability
    records. Shares the engagement sandbox (Mode B execution, egress
    policy enforced per spawn by KaliSandbox) and writes every outcome
    to the evidence graph and the audit chain."""

    def __init__(self, graph, audit, target: str, sandbox,
                 allowlist: "ToolAllowlist | None" = None):
        self.graph = graph
        self.audit = audit
        self.target = target
        self.sandbox = sandbox
        # Gate choice: when no explicit allowlist is handed in, build a
        # strict one from the registered contracts ONLY — the probe
        # template is the contract argv itself, so nothing outside the
        # mutual registration can ever pass Layer 2.
        if allowlist is None:
            allowlist = ToolAllowlist(templates={
                f"capif:{c.producer}": list(c.probe_argv)
                for c in CAPABILITY_VERIFICATION_CONTRACTS.values()
            })
        self.allowlist = allowlist

    # -- entry point -------------------------------------------------------

    def verify(self, node: dict, record: capability.CapabilityRecord,
               ) -> CapabilityVerificationResult:
        """Verify one claimed record. Returns the typed verdict and has
        already written this attempt + its outcome to the graph and
        audit chain."""
        self.audit.write({
            "event": "capability_verification_attempted",
            "record_id": node["id"],
            "attempt_id": record.attempt_id,
            "tool": record.tool,
            "target_host": record.target_host,
        })
        result = self._verify_checked(node, record)
        self._record(node, record, result)
        return result

    # -- the deterministic checks + probe ----------------------------------

    def _verify_checked(self, node, record) -> CapabilityVerificationResult:
        def verdict(status: str, *reasons: str,
                    method: str = "") -> CapabilityVerificationResult:
            return CapabilityVerificationResult(
                capability_node_id=node["id"],
                attempt_node_id=record.attempt_id,
                tool=record.tool,
                target_host=record.target_host,
                method=method,
                status=status,
                reasons=[r for r in reasons if r],
            )

        # Contradictory lifecycle: verification happens BEFORE the gate,
        # so the record must still be exactly "claimed"; any decided or
        # legacy shape means we are verifying the wrong record.
        if record.status != "claimed":
            return verdict("refused",
                           f"record lifecycle is {record.status!r}; "
                           "verification applies only to claimed records "
                           "(contradictory — fail closed)")
        if record.verification == "verified":
            return verdict("refused",
                           "record already verified (verification is "
                           "one-way, never re-run)")
        if record.capability != "shell":
            return verdict("refused",
                           f"capability {record.capability!r} has no "
                           "verification contract")

        # Producer trust: BOTH halves must be explicitly registered —
        # the evidence parser that produced the claim and the contract
        # that defines the one allowed verification method.
        if record.tool not in capability.CAPABILITY_PARSERS:
            return verdict("refused",
                           "evidence producer is not registered in the "
                           "capability parser registry (untrusted)")
        contract = CAPABILITY_VERIFICATION_CONTRACTS.get(record.tool)
        if contract is None:
            return verdict("refused",
                           "no verification contract is registered for "
                           "this producer (untrusted)")

        # The claimed attempt must still exist, be the producer's own
        # attempt, and STILL confirm at read time (exactly how the
        # claim was derived) — a stale or contrived record cannot.
        attempt = self.graph.get_node(record.attempt_id)
        if attempt is None or \
                attempt.get("node_type") != "exploit_attempt":
            return verdict("refused",
                           "claimed attempt is missing from the graph "
                           "(stale reference)")
        if str(attempt.get("properties", {}).get("tool", "")) != record.tool:
            return verdict("refused",
                           "claimed attempt was produced by a different "
                           "tool (contradictory)")
        if attempt_outcome(attempt) != ATTEMPT_CONFIRMED:
            return verdict("refused",
                           "claimed attempt no longer confirms at read "
                           "time (stale evidence)")

        # Scope: the capability must sit on the engagement target.
        if not capability.host_in_scope(record.target_host, self.target):
            return verdict("refused",
                           "capability host is outside engagement scope")

        # Probe binding (fail closed): the probe's static argv MUST
        # reference the engagement target. A marker-only probe that
        # never touches the target cannot demonstrate an ON-TARGET
        # capability — coupling target and capability is what makes the
        # independent check meaningful.
        if not any(self.target in token or record.target_host in token
                   for token in contract.probe_argv):
            return verdict(
                "refused",
                "verification contract probe is not bound to the "
                "engagement target — a marker-only probe is not "
                "independent evidence of an on-target capability",
                method=contract.method)
        # Capability binding: the contract names the capability class it
        # may verify and it must be exactly the claimed one.
        if str(contract.capability or "").strip() != record.capability:
            return verdict(
                "refused",
                f"verification contract binds capability "
                f"{contract.capability!r}, not {record.capability!r} "
                "(contradictory)",
                method=contract.method)

        # The one allowed probe, exactly as contracted, through the
        # Mode B sandbox (gVisor; the egress policy is re-verified per
        # spawn by KaliSandbox itself).
        argv = list(contract.probe_args())
        try:
            self.allowlist.validate(f"capif:{record.tool}", argv)
            self.allowlist.check_blocklist(argv)
        except AllowlistViolation as e:
            return verdict("refused",
                           f"probe rejected by the Layer-2 gate: {e}")

        try:
            spawn = self.sandbox.spawn(argv)
        except Exception as e:  # sandbox/egress failure — fail loudly
            return verdict("failed",
                           f"sandbox refused or crashed the probe: "
                           f"{str(e)[:MAX_REASON_CHARS]}",
                           method=contract.method)
        if not spawn.ok:
            return verdict("failed",
                           "sandbox could not start the verification "
                           "probe", f"exit={spawn.exit_code}",
                           spawn.error[:MAX_REASON_CHARS],
                           method=contract.method)
        if spawn.exit_code != 0:
            return verdict(
                "failed", f"probe exit={spawn.exit_code}",
                (spawn.stdout or "")[:MAX_REASON_CHARS],
                method=contract.method)
        if contract.expect_marker not in (spawn.stdout or ""):
            return verdict(
                "failed",
                "probe did not reproduce the contracted marker — the "
                "claimed capability is not independently verifiable",
                method=contract.method)

        result = CapabilityVerificationResult(
            capability_node_id=node["id"],
            attempt_node_id=record.attempt_id,
            tool=record.tool,
            target_host=record.target_host,
            method=contract.method,
            status="verified",
            reasons=["contract probe reproduced the marker inside the "
                     "sandbox"],
            probe_exit_code=spawn.exit_code,
            marker_seen=True,
        )
        # The only writer of ``verification = "verified"`` anywhere —
        # and only ever on the probe's independent evidence (a record
        # whose Gate 3 status is not "claimed" can never get here).
        node["properties"]["verification"] = "verified"
        return result

    # -- graph + audit recording --------------------------------------------

    def _record(self, node, record, result: CapabilityVerificationResult,
                ) -> None:
        """Every attempt, result and refusal lands in the evidence
        graph (a capability_verification node + verified_by lineage
        when anything was attempted at all) and the audit chain."""
        v_node = self.graph.add_node(
            node_type="capability_verification",
            label=f"capif-check:{node.get('label', '')}",
            properties=result.model_dump(),
            provenance={"agent": "CAPABILITY_VERIFIER",
                        "source_type": "tool"},
        )
        refused: "list[str]" = []
        link(
            self.graph, "verified_by", node, v_node,
            provenance={"agent": "CAPABILITY_VERIFIER",
                        "source_type": "tool"},
            properties={"status": result.status},
            on_refuse=refused.append,
        )
        if refused:
            self.audit.write({
                "event": "lineage_refused",
                "relationship": "verified_by",
                "record_id": node["id"],
                "reason": refused[0],
            })
        event = {
            "verified": "capability_verified",
            "refused": "capability_verification_refused",
            "failed": "capability_verification_failed",
        }.get(result.status, "capability_verification_failed")
        self.audit.write({
            "event": event,
            "record_id": node["id"],
            "verification_id": v_node["id"],
            "attempt_id": record.attempt_id,
            "tool": record.tool,
            "method": result.method,
            "status": result.status,
            "reasons": result.reasons[:5],
            "probe_exit_code": result.probe_exit_code,
            "marker_seen": result.marker_seen,
        })


def verify_claimed_records(graph, audit, target: str, sandbox,
                           records: "list[tuple[dict, capability.CapabilityRecord]]",
                           allowlist: "ToolAllowlist | None" = None,
                           ) -> "dict[str, CapabilityVerificationResult]":
    """Verify every claimed record in one go (skip entirely when no
    contract is registered — production dormancy, zero side effects).
    Returns results keyed by capability node id."""
    if not contracts_ready():
        return {}
    verifier = CapabilityVerifier(graph, audit, target, sandbox,
                                  allowlist)
    return {
        node["id"]: verifier.verify(node, record)
        for node, record in records
    }
