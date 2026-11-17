"""A production Mode B tool adapter: dnsx-probe (Tool Expansion Batch 1).

Target: Kali's bundled dnsx (verified in the pinned sandbox image:
executable ``dnsx``, entrypoint-allowlisted) for authorized DNS
resolution of the engagement target, in the RECON_ACTIVE stage only,
through the Phase 2B.2 adapter framework — the SAME engine, sandbox,
allowlist, egress boundary, scope checks, audit chain and evidence
graph as every other tool. This module adds NO general-purpose command
interface: the executable is the fixed ``dnsx`` binary and the argv
template is fixed and Layer-2 validated.

WHY AN ADAPTER AT ALL (Batch 1 evaluation):
    - The legacy discovery entry treats dnsx as a bare stdout pipe: its
      resolution never carries run provenance (which request produced
      it), no bounded per-line parsing, and a crash inside the parse
      loop would be unattributed. The adapter runs the SAME binary with
      the SAME fixed argv shape and produces the SAME legacy-shape
      ``dns_resolution`` node — with the adapter_attempt run record,
      structured failure classification (2B.7) and per-IP defensive
      parsing that the legacy path cannot carry.
    - TEXT output contract, NOT ``-json``: the shipped Layer-2
      ``dnsx`` template in allowlist.py (the one the legacy plan also
      runs) is the fixed
      ``-l {target} -r {resolver} -resp-only -silent -duc -nc`` shape
      the registry-compiled allowlist must stay in lockstep with.
      ``-resp-only -silent`` lines are bare IPv4 addresses — verified
      live against the real 1.3.1 binary through the gate (plain
      ``-silent`` prints the bare DOMAIN, ``-resp`` brackets the IP,
      and default output carries ANSI colors; all three unparseable,
      hence the flags). The ``{resolver}`` value is the egress
      policy's pinned DNS resolver, derived by product code — never
      caller-invented. "text parsing as actually verified".

DUPLICATE AVOIDANCE: one probe per check. The registered dnsx-probe
adapter REPLACES the legacy ``dnsx`` discovery entry (deterministic
either/or in ReconActiveSubagent, the same rule as the 2B.3 httpx
rule): when the adapter runs, the legacy entry is omitted from the
plan — the two never both resolve the same domain in one state.

NO NEW AGGRESSION: the template is exactly the shipped legacy shape —
no brute-force lists (``-d`` is refused at Layer 2 since 1.3.1 made it
brute-force input), no record-type iteration, no OOB callbacks. The
``-duc``/``-nc`` flags remove an update phone-home and color escapes
the gate would not carry anyway. The egress boundary stays
target-scope: DNS reaches ONLY the policy's pinned resolver.

Every parse is DEFENSIVE: a line that is not a bare IPv4 or the
annotated ``host [TYPE] ip`` shape is skipped and counted; octets are
range-checked; malformed output can never become an observation; and a
resolved address is recon evidence, NEVER a vulnerability claim
(verification stays ``not_verified`` everywhere).

Registration is explicit: :func:`production_registry` is the shipped
registry for this adapter; :func:`recon_active_registry` in
adapter_whatweb.py is the combined RECON_ACTIVE registry the runner
injects. Anything not registered stays disabled.
"""

from __future__ import annotations

import logging
import re

from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLog
from .adapters import AdapterRunRecord
from .lineage import link
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

ADAPTER_ID = "dnsx-probe"
#: the canonical id under the name recon_active's lane getter imports
#: (the same export pattern as the nuclei/tls/api adapter modules)
DNSX_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "dnsx"

#: the fixed argv template — EXACTLY the shipped ``dnsx`` entry in
#: allowlist.py ACTIVE_RECON_TEMPLATES, so the adapter argv and the
#: legacy plan entry are byte-identical. Lockstep is asserted by tests
#: that render the adapter argv against the SHIPPED Layer-2 template.
#:
#: ``{resolver}`` is REQUIRED and carries the egress policy's pinned
#: DNS resolver (comma-joined when several) — the caller derives it
#: from ``sandbox.egress_policy.dns_resolvers``; a caller cannot invent
#: a resolver any more than a target (the {resolver} charset admits
#: only IP-ish text). Verified live against the real dnsx 1.3.1 binary
#: through the gate (Phase-4 lab, 2026-11-16): without ``-r`` the tool
#: queries a hardcoded public-resolver list the gate drops; with
#: ``-resp-only -nc`` the output is bare-IP lines the parser reads.
DNSX_PROBE_TEMPLATE: tuple[str, ...] = (
    "-l", "{target}",
    "-r", "{resolver}",
    "-resp-only", "-silent", "-duc", "-nc",
)


def make_dnsx_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere.
    """
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="dnsx DNS resolution probe",
        purpose=(
            "Authorized DNS resolution of the engagement target via "
            "dnsx: resolved A records as recon evidence. RECON_ACTIVE "
            "only; a resolved address is a fact about the domain, "
            "never a vulnerability claim."
        ),
        category="recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=DNSX_PROBE_TEMPLATE,
        target_kind="domain",
        max_seconds=120,
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy dnsx plan entry
        evidence_kind="text_excerpt",
    )


def production_registry():
    """The shipped Mode B adapter registry for the dnsx-probe adapter:
    EXPLICITLY contains this one vetted production adapter and nothing
    else. Unknown adapters remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_dnsx_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class DnsxObservation(BaseModel):
    """ONE parsed dnsx resolution — exactly one resolved IPv4 address.

    Honest fields only: what dnsx reported, bounded, octet-checked. No
    confirmed / vulnerability / severity field exists — a DNS answer is
    a fact about the domain, not a finding.
    """

    model_config = ConfigDict(frozen=True)

    ip: str = Field(min_length=7, max_length=15,
                    pattern=r"^(?:\d{1,3}\.){3}\d{1,3}$")
    excerpt: str = Field(min_length=1, max_length=300)


# ``-silent`` output lines: bare "1.2.3.4", or the annotated shape some
# builds print: "domain [A] 1.2.3.4"
_IPV4_LINE_RE = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$")
_ANNOTATED_LINE_RE = re.compile(
    r"^(?P<host>\S+)\s+\[[A-Za-z0-9]+\]\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$",
)


def _plausible_ipv4(ip: str) -> bool:
    """Octet range check — a regex-shaped string like ``999.1.1.1`` is
    malformed tool output, never an address."""
    try:
        return all(0 <= int(octet) <= 255 for octet in ip.split("."))
    except ValueError:
        return False


def parse_dnsx_lines(
    stdout: str,
    *,
    max_observations: int = 50,
) -> "tuple[list[DnsxObservation], int]":
    """Parse bounded resolutions from a dnsx run.

    Returns ``(observations, malformed_lines)``. A line counts as
    malformed when it is non-empty and is neither a bare IPv4 nor the
    annotated ``host [TYPE] ip`` shape — banner output, resolver errors
    and half-written tails are all malformed, never interpreted, never
    labelled evidence. Impossible octets are malformed too. The count
    is capped at ``max_observations``; anything over the cap is left
    unparsed (bounded output, honest and deterministic). Within the
    cap, the FIRST observation for an address wins — one address, one
    observation.
    """
    observations: list[DnsxObservation] = []
    malformed = 0
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        if len(observations) >= max_observations:
            break
        line = line.strip()
        if not line:
            continue
        m = _IPV4_LINE_RE.match(line) or _ANNOTATED_LINE_RE.match(line)
        if not m:
            malformed += 1
            continue
        ip = m.group("ip")
        if ip in seen or not _plausible_ipv4(ip):
            malformed += 1
            continue
        seen.add(ip)
        try:
            observations.append(DnsxObservation(
                ip=ip,
                excerpt=line[:300],
            ))
        except Exception:  # defensive: a bad line is data, never a crash
            malformed += 1
    return observations, malformed


# ---- evidence recording -------------------------------------------------------


def find_adapter_attempt_node(graph: EngagementGraph,
                              request_id: str) -> "dict | None":
    """The ``adapter_attempt`` node this run produced (by request_id —
    stable across node hunting). None when the run never produced one
    (refusals are audit-only by the 2B.2 design)."""
    for node in graph.by_type("adapter_attempt"):
        props = node.get("properties") or {}
        if props.get("request_id") == request_id:
            return node
    return None


def record_dnsx_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    observations: "list[DnsxObservation]",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one dnsx adapter run onto the evidence graph.

    LEGACY-SHAPE evidence: ONE ``dns_resolution`` node (the SAME node
    type the legacy discovery path produces), labelled by the queried
    domain, carrying ALL resolved addresses in one ``ips`` property —
    the legacy path also folds the whole run into one node, so
    HYPOTHESIZE reads one uniform surface. The node additionally
    carries the adapter provenance and request id the legacy excerpt
    cannot. A duplicate (a ``dns_resolution`` node for the same label
    already on the graph) is SKIPPED — first observation wins, matching
    the graph's own idempotence rule. Refusal to link is AUDITED, never
    silent and never fatal. A successful run that resolved nothing is
    an honest INCONCLUSIVE result: no node, audited with ``resolved:0``,
    never a negative claim.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no observation nodes: a refusal must never
        # leave fabricated resolution evidence behind
        audit.write({
            "event": "dnsx_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "observations_offered": len(observations),
        })
        return []
    ips = [o.ip for o in observations]
    if ips:
        label = run_record.target[:300]
        existing = [n for n in graph.by_type("dns_resolution")
                    if n.get("label") == label]
        if not existing:
            try:
                node = graph.add_node(
                    node_type="dns_resolution",
                    label=label,
                    properties={
                        "ips": ips,
                        "source": TOOL_EXECUTABLE,
                        "adapter": ADAPTER_ID,
                        "request_id": run_record.request_id,
                        "untrusted": True,
                        "verification": "not_verified",
                    },
                    provenance={
                        "agent": "ADAPTER",
                        "source_type": "tool",
                        "tool": TOOL_EXECUTABLE,
                        "adapter": ADAPTER_ID,
                    },
                )
            except Exception as e:  # graph validation: audited, not fatal
                audit.write({
                    "event": "dnsx_adapter_evidence_refused",
                    "request_id": run_record.request_id,
                    "reason": f"dns_resolution node refused: {e}"[:200],
                    "label": label,
                })
                node = None
            if node is not None:
                created.append(node["id"])
                link(
                    graph, "produced", attempt["id"], node["id"],
                    provenance={
                        "agent": "ADAPTER", "source_type": "tool",
                        "adapter": ADAPTER_ID,
                    },
                    on_refuse=lambda reason, _nid=node["id"]: audit.write({
                        "event": "dnsx_adapter_evidence_refused",
                        "request_id": run_record.request_id,
                        "node_id": _nid,
                        "reason": str(reason)[:200],
                    }),
                )
    audit.write({
        "event": "dnsx_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "resolved_ips": ips,
        "malformed_lines": malformed_lines,
        "dns_resolution_nodes": len(created),
        "duplicate_or_refused": (1 if ips else 0) - len(created),
    })
    return created
