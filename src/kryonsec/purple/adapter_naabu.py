"""A production Mode B tool adapter: naabu-probe (Tool Expansion Batch 1).

Target: Kali's bundled naabu (verified in the pinned sandbox image:
executable ``naabu``, entrypoint-allowlisted) for authorized TCP port
discovery against the engagement target, in the RECON_ACTIVE stage
only, through the Phase 2B.2 adapter framework — the SAME engine,
sandbox, allowlist, egress boundary, scope checks, audit chain and
evidence graph as every other tool. This module adds NO
general-purpose command interface: the executable is the fixed
``naabu`` binary and the argv template is fixed and Layer-2 validated.

WHY AN ADAPTER AT ALL (Batch 1 evaluation):
    - The legacy discovery entry treats naabu as a bare stdout pipe:
      its ports never carry run provenance (which request produced
      them), no bounded per-line parsing, and a crash inside the parse
      loop would be unattributed. The adapter runs the SAME binary
      with the SAME fixed argv shape and feeds the SAME merged port
      set the legacy parse produced — with the adapter_attempt run
      record, structured failure classification (2B.7) and bounded
      per-line parsing that the legacy path cannot carry.
    - TEXT output contract, NOT ``-json``: the shipped Layer-2
      ``naabu`` template in allowlist.py (the one the legacy plan also
      runs) is the fixed ``-host/-p/-rate/-silent`` shape the
      registry-compiled allowlist must stay in lockstep with, and the
      field shapes of naabu's JSON could not be verified against the
      real binary from this development environment. ``-silent`` lines
      are ``host:port`` pairs — deterministic and parseable with a
      strict, defensive parser: "text parsing as actually supported".

NO NEW AGGRESSION: the discovery lane pins ``params`` to the SAME
constants the legacy plan entry uses — ``ports=RECON_PORTS`` (the
bounded 18-port list, NOT a full-range scan: spec §9.1) and
``rate="100"`` (the legacy rate). The adapter never widens either: a
different port list or rate would be a conscious code change in the
lane, auditable in git, never caller input. (The whatweb-probe
precedent pins its aggression level in the template; here the pinned
values stay in the lane because the template must stay byte-identical
to the shipped Layer-2 entry both paths validate against.)

DUPLICATE AVOIDANCE: one probe per check. The registered naabu-probe
adapter REPLACES the legacy ``naabu`` discovery entry (deterministic
either/or in ReconActiveSubagent, the same rule as the 2B.3 httpx
rule): when the adapter runs, the legacy entry is omitted from the
plan — the two never both scan the same host in one state. NO graph
nodes of its own: parity with the legacy path, whose ports merge into
the shared ``open_ports`` set (the run's ``adapter_attempt`` node is
the graph evidence that the scan happened).

Every parse is DEFENSIVE: a line that is not ``host:port`` is skipped
and counted; ports are range-checked (1-65535); malformed output can
never become a port; and an open port is recon evidence, NEVER a
vulnerability claim (verification stays ``not_verified`` everywhere).

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
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

ADAPTER_ID = "naabu-probe"
#: the canonical id under the name recon_active's lane getter imports
#: (the same export pattern as the nuclei/tls/api adapter modules)
NAABU_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "naabu"

#: the fixed argv template — EXACTLY the shipped ``naabu`` entry in
#: allowlist.py ACTIVE_RECON_TEMPLATES (``-host/-p/-rate/-silent``), so
#: the adapter argv and the legacy plan entry are byte-identical once
#: the discovery lane fills ``{ports}`` and ``{rate}`` with the SAME
#: pinned constants the legacy entry uses. Lockstep is asserted by
#: tests that render the adapter argv against the SHIPPED Layer-2
#: template.
NAABU_PROBE_TEMPLATE: tuple[str, ...] = (
    "-host", "{target}", "-p", "{ports}", "-rate", "{rate}", "-silent",
)


def make_naabu_probe_adapter():
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
        title="naabu port discovery probe",
        purpose=(
            "Authorized TCP port discovery against the engagement "
            "target via naabu: open ports as recon evidence. "
            "RECON_ACTIVE only, bounded port list, bounded rate; an "
            "open port is a fact about the host, never a "
            "vulnerability claim."
        ),
        category="recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=NAABU_PROBE_TEMPLATE,
        target_kind="domain",
        max_seconds=120,
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy naabu plan entry
        evidence_kind="text_excerpt",
    )


def production_registry():
    """The shipped Mode B adapter registry for the naabu-probe adapter:
    EXPLICITLY contains this one vetted production adapter and nothing
    else. Unknown adapters remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_naabu_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class NaabuObservation(BaseModel):
    """ONE parsed naabu line — exactly one reported ``host:port``.

    Honest fields only: what naabu reported, bounded. No confirmed /
    vulnerability / severity field exists — an open port is a fact
    about the host, not a finding.
    """

    model_config = ConfigDict(frozen=True)

    host: str = Field(min_length=1, max_length=300)
    port: int = Field(ge=1, le=65535)
    excerpt: str = Field(min_length=1, max_length=300)


# naabu -silent lines: "host:port" (the same shape the legacy parser
# in recon_active.py accepts)
_NAABU_LINE_RE = re.compile(r"^(?P<host>[A-Za-z0-9._-]+):(?P<port>\d{1,5})$")


def parse_naabu_lines(
    stdout: str,
    *,
    max_observations: int = 100,
) -> "tuple[list[NaabuObservation], int]":
    """Parse bounded open-port observations from a naabu run.

    Returns ``(observations, malformed_lines)``. A line counts as
    malformed when it is non-empty and is not a ``host:port`` pair —
    banner output, connection errors and half-written tails are all
    malformed, never interpreted, never labelled evidence. Out-of-range
    ports are malformed too. The count is capped at
    ``max_observations``; anything over the cap is left unparsed
    (bounded output, honest and deterministic). Within the cap, the
    FIRST observation for a port wins — one port, one observation —
    and the returned list is SORTED BY PORT, the same order the legacy
    ``parse_naabu`` produces (``sorted(ports)``): deterministic parity
    with the lane it replaces, independent of naabu's line order.
    """
    observations: list[NaabuObservation] = []
    malformed = 0
    seen: set[int] = set()
    for line in (stdout or "").splitlines():
        if len(observations) >= max_observations:
            break
        line = line.strip()
        if not line:
            continue
        m = _NAABU_LINE_RE.match(line)
        if not m:
            malformed += 1
            continue
        port = int(m.group("port"))
        if not (1 <= port <= 65535) or port in seen:
            malformed += 1
            continue
        seen.add(port)
        try:
            observations.append(NaabuObservation(
                host=m.group("host")[:300],
                port=port,
                excerpt=line[:300],
            ))
        except Exception:  # defensive: a bad line is data, never a crash
            malformed += 1
    observations.sort(key=lambda o: o.port)
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


def record_naabu_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    observations: "list[NaabuObservation]",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one naabu adapter run onto the evidence graph — WITHOUT
    adding nodes of its own.

    LEGACY-SHAPE behavior: the legacy naabu discovery entry adds NO
    graph nodes — its ports merge into the shared ``open_ports`` set
    the state builds. The adapter keeps exactly that parity: the run's
    ``adapter_attempt`` node (created by execute_adapter for every
    successful run) is the graph evidence that the scan happened, with
    the full record (argv, exit code, excerpts, ``not_verified``) as
    its properties; the parsed ports flow back to the caller's port
    set. This function exists to keep the lane shape uniform with the
    other adapters and to audit the parse outcome honestly
    (observations found, malformed lines skipped, zero observations =
    an INCONCLUSIVE scan, never a "no open ports" claim).

    Returns an empty list — always (no node of its own is created).
    """
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node: a refusal must never leave fabricated port
        # evidence behind — audited, then nothing (there are no nodes)
        audit.write({
            "event": "naabu_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "observations_offered": len(observations),
        })
        return []
    audit.write({
        "event": "naabu_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "ports": sorted(o.port for o in observations),
        "malformed_lines": malformed_lines,
        "graph_nodes": 0,
    })
    return []
