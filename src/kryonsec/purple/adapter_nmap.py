"""A production Mode B tool adapter: nmap-probe (Tool Expansion Batch 2).

Target: Kali's bundled nmap (verified in the pinned sandbox image:
executable ``nmap``, entrypoint-allowlisted) for the authoritative
service scan against the engagement target, in the RECON_ACTIVE stage
only, through the Phase 2B.2 adapter framework — the SAME engine,
sandbox, allowlist, egress boundary, scope checks, audit chain and
evidence graph as every other tool. This module adds NO
general-purpose command interface: the executable is the fixed
``nmap`` binary and the argv template is fixed and Layer-2 validated.

WHY AN ADAPTER AT ALL (Batch 2 evaluation):
    - The legacy discovery entry treats nmap as a bare stdout pipe:
      its service nodes never carry run provenance (which request
      produced them), and a crash inside the parse loop would be
      unattributed. The adapter runs the SAME binary with the SAME
      fixed argv shape and produces the SAME legacy-shape ``service``
      nodes — with the adapter_attempt run record, structured failure
      classification (2B.7) and bounded parsing that the legacy path
      cannot carry.
    - TEXT output contract, NOT ``-oX/-oJ``: the shipped Layer-2
      ``nmap`` template in allowlist.py (the one the legacy discovery
      plan also runs) is the fixed ``-Pn/-sT/-sV/-sC`` shape the
      registry-compiled allowlist must stay in lockstep with, and the
      XML/JSON field shapes could not be verified against the real
      binary from this development environment. ``-sV`` report lines
      are the long-standing parseable contract the legacy parse already
      relies on: "text parsing as actually supported".

NO NEW AGGRESSION: the discovery lane pins ``params`` to the SAME
constants the legacy plan entry uses — ``ports=RECON_PORTS`` (the
bounded 18-port list, NOT a full-range scan: spec §9.1) and
``rate="100"``. The adapter never widens either: a different port list,
rate or scan type would be a conscious code change in the lane,
auditable in git, never caller input. ``-sT`` is not a choice either:
gVisor grants no raw sockets, so a SYN scan is impossible in the
sandbox in the first place.

DUPLICATE AVOIDANCE: one probe per check. The registered nmap-probe
adapter REPLACES the legacy ``nmap`` discovery entry (deterministic
either/or in ReconActiveSubagent, the same rule as the Batch 1
naabu/dnsx rule): when the adapter runs, the legacy entry is omitted
from the plan — the two never both scan the target in one state.
Unlike naabu, the legacy nmap entry DOES add graph nodes (``service``
nodes, the authoritative service evidence HYPOTHESIZE reads), so the
adapter produces the SAME nodes — legacy shape, plus the adapter
provenance the legacy parse cannot carry.

Every parse is DEFENSIVE and REUSES the legacy TEXT parser
(:func:`recon_active.parse_nmap_services` — the SAME regex the legacy
discovery entry uses, lockstep by construction, no second
implementation to drift): lines that are not ``port/proto state
service`` service lines are simply not services, and the observation
count is capped; malformed or banner output can never become a
service; and an open service is recon evidence, NEVER a vulnerability
claim (verification stays ``not_verified`` everywhere).

Registration is explicit: :func:`production_registry` is the shipped
registry for this adapter; :func:`recon_active_registry` in
adapter_whatweb.py is the combined RECON_ACTIVE registry the runner
injects. Anything not registered stays disabled.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLog
from .adapters import AdapterRunRecord
from .lineage import link
from .recon_passive import EngagementGraph
from .recon_active import parse_nmap_services

log = logging.getLogger(__name__)

ADAPTER_ID = "nmap-probe"
#: the canonical id under the name recon_active's lane getter imports
#: (the same export pattern as the naabu/dnsx adapter modules)
NMAP_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "nmap"

#: the fixed argv template — EXACTLY the shipped ``nmap`` entry in
#: allowlist.py ACTIVE_RECON_TEMPLATES (``-Pn/-sT/-sV/-sC/--max-rate/-p``
#: plus the positional target), so the adapter argv and the legacy
#: discovery entry are byte-identical once the discovery lane fills
#: ``{ports}`` and ``{rate}`` with the SAME pinned constants the legacy
#: entry uses. Lockstep is asserted by tests that render the adapter
#: argv against the SHIPPED Layer-2 template.
NMAP_PROBE_TEMPLATE: tuple[str, ...] = (
    "-Pn", "-sT", "-sV", "-sC", "--max-rate", "{rate}", "-p", "{ports}",
    "{target}",
)

#: the pinned scan rate the lane passes (the legacy entry's
#: ``--max-rate 100``). A constant here makes the pin explicit and
#: testable; the port list is the lane's own RECON_PORTS constant.
PINNED_RATE = "100"

#: a bounded cap on parsed services (nmap -sV on a bounded 18-port list
#: cannot realistically exceed this; the cap keeps a hostile banner
#: flood from flooding the graph).
MAX_SERVICES = 100


def make_nmap_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere. ``{ports}`` and
    ``{rate}`` are the template's placeholders; the discovery lane is
    the deterministic caller that pins them.
    """
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="nmap service scan probe",
        purpose=(
            "Authorized service discovery against the engagement "
            "target via nmap (-Pn -sT -sV -sC, bounded port list, "
            "bounded rate): open services as recon evidence. "
            "RECON_ACTIVE only; an open service is a fact about the "
            "host, never a vulnerability claim."
        ),
        category="recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=NMAP_PROBE_TEMPLATE,
        target_kind="domain",
        max_seconds=300,        # <= the sandbox's own 330s ceiling
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy nmap discovery entry
        evidence_kind="text_excerpt",
    )


def production_registry():
    """The shipped Mode B adapter registry for the nmap-probe adapter:
    EXPLICITLY contains this one vetted production adapter and nothing
    else. Unknown adapters remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_nmap_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class NmapServiceObservation(BaseModel):
    """ONE parsed nmap service line — exactly one open service.

    Honest fields only: what nmap reported, bounded. No confirmed /
    vulnerability / severity field exists — an open service is a fact
    about the host, not a finding.
    """

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    proto: str = Field(min_length=2, max_length=8)
    service: str = Field(min_length=1, max_length=100)
    version: str = Field(default="", max_length=200)

    def properties(self, *, target: str, request_id: str) -> dict:
        """The ``service`` node properties — the SAME shape the legacy
        nmap parse produces (port/proto/service/version/source), with
        the adapter provenance the legacy excerpt cannot carry."""
        return {
            "port": self.port,
            "proto": self.proto,
            "service": self.service,
            "version": self.version,
            "source": TOOL_EXECUTABLE,
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }


def parse_nmap_service_lines(
    stdout: str,
    *,
    max_observations: int = MAX_SERVICES,
) -> "tuple[list[NmapServiceObservation], int]":
    """Parse bounded open-service observations from an nmap -sV run.

    REUSES :func:`recon_active.parse_nmap_services` — the legacy TEXT
    parser, lockstep by construction (there is no second regex to
    drift). Returns ``(observations, malformed_lines)`` where
    ``malformed_lines`` counts parse failures the legacy parser would
    have swallowed silently: a non-empty line that LOOKS like a
    service line (starts with ``port/proto``) but failed the open/state
    filter is malformed — skipped banners, headers and blank lines are
    simply not service lines and are not counted (nmap prints a
    multi-line REPORT, not a flat result stream like naabu -silent).
    The count is capped at ``max_observations``; anything over the cap
    is left unparsed (bounded output, honest and deterministic).
    """
    from .recon_active import _PORT_RE

    observations: list[NmapServiceObservation] = []
    malformed = 0
    for line in (stdout or "").splitlines():
        if len(observations) >= max_observations:
            break
        stripped = line.strip()
        if not stripped or not _PORT_RE.match(stripped):
            continue          # not a service line at all — nmap report text
        services = parse_nmap_services(stripped)
        if not services:
            # a port-shaped line that the legacy parser rejected
            # (closed/filtered state, unparsable service) — counted,
            # never interpreted
            malformed += 1
            continue
        for svc in services:
            try:
                observations.append(NmapServiceObservation(
                    port=svc["port"],
                    proto=svc["proto"][:8],
                    service=svc["service"][:100],
                    version=svc["version"][:200],
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


def record_nmap_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    observations: "list[NmapServiceObservation]",
) -> "list[str]":
    """Map one nmap adapter run onto the evidence graph.

    For each observation: ONE legacy-shape ``service`` node (the SAME
    node type the legacy nmap parse produces and HYPOTHESIZE reads,
    labelled ``target:port/proto``), with a ``produced`` lineage edge
    from the run's ``adapter_attempt`` node and the adapter provenance
    the legacy parse cannot carry. Duplicate service labels (already on
    the graph — first-wins) are SKIPPED, so a repeat scan adds no node.
    Refusal to link is AUDITED, never silent and never fatal.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no service nodes: a refusal must never leave
        # fabricated service evidence behind
        audit.write({
            "event": "nmap_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "observations_offered": len(observations),
        })
        return []
    for observation in observations:
        label = f"{run_record.target}:{observation.port}/" \
                f"{observation.proto}"
        existing = [n for n in graph.by_type("service")
                    if n.get("label") == label]
        if existing:
            continue
        try:
            node = graph.add_node(
                node_type="service",
                label=label,
                properties=observation.properties(
                    target=run_record.target,
                    request_id=run_record.request_id),
                provenance={
                    "agent": "ADAPTER",
                    "source_type": "tool",
                    "tool": TOOL_EXECUTABLE,
                    "adapter": ADAPTER_ID,
                },
            )
        except Exception as e:  # graph validation: audited, not fatal
            audit.write({
                "event": "nmap_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"service node refused: {e}"[:200],
                "label": label[:300],
            })
            continue
        created.append(node["id"])
        link(
            graph, "produced", attempt["id"], node["id"],
            provenance={
                "agent": "ADAPTER", "source_type": "tool",
                "adapter": ADAPTER_ID,
            },
            on_refuse=lambda reason, _nid=node["id"]: audit.write({
                "event": "nmap_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "nmap_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "target": run_record.target[:300],
        "services": len(observations),
        "service_nodes": len(created),
        "duplicate_or_refused": len(observations) - len(created),
    })
    return created
