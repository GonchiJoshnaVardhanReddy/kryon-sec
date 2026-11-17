"""A production Mode B tool adapter: feroxbuster-probe (Tool Expansion
Batch 2).

Target: Kali's bundled feroxbuster (verified in the pinned sandbox
image: executable ``feroxbuster``, entrypoint-allowlisted) for
authorized content discovery against in-scope web endpoints, in the
RECON_ACTIVE stage only, through the Phase 2B.2 adapter framework —
the SAME engine, sandbox, allowlist, egress boundary, scope checks,
audit chain and evidence graph as every other tool. This module adds
NO general-purpose command interface: the executable is the fixed
``feroxbuster`` binary and the argv template is fixed and Layer-2
validated.

WHY AN ADAPTER AT ALL (Batch 2 evaluation):
    - The legacy web-plan entry treats feroxbuster as a bare stdout
      pipe: its discovered paths never carry run provenance (which
      request produced them), no bounded per-line parsing, and a crash
      inside the parse loop would be unattributed. The adapter runs the
      SAME binary with the SAME fixed argv shape and produces the SAME
      legacy-shape ``path`` nodes — with the adapter_attempt run
      record, structured failure classification (2B.7) and bounded
      per-line parsing that the legacy path cannot carry.
    - TEXT output contract, NOT ``-o <file>/json``: the shipped
      Layer-2 ``feroxbuster`` template in allowlist.py (the one the
      legacy plan also runs) is the fixed ``-u/-w/-t/--timeout`` shape
      the registry-compiled allowlist must stay in lockstep with, and
      feroxbuster's JSON output mode is a different flag set that
      could not be verified against the real binary from this
      development environment. The status/URL result lines are
      deterministic and parseable with the strict regex the legacy
      parse already relies on (one that was FIXED against real
      feroxbuster shapes — see ``_FEROX_RE``): "text parsing as
      actually supported".

NO NEW AGGRESSION: the template is byte-identical to the shipped
Layer-2 entry — the SAME baked seclists wordlist, 5 threads, 30s
per-request timeout. No recursion switch, no extensions, no
wordlist/threads/depth knobs: anything else is a conscious code change
in the repo, auditable in git, never caller input. The FUZZ-marker URL
is composed DETERMINISTICALLY by the adapter framework from the
scope-validated base (``base.rstrip('/') + '/FUZZ'`` — the exact
composition the legacy entry performs); the lane can never point the
fuzzing at a different origin than the base it was given.

DUPLICATE AVOIDANCE: one probe per check. The registered
feroxbuster-probe adapter REPLACES the legacy ``feroxbuster`` web-plan
entry (deterministic either/or in ReconActiveSubagent, the same rule
as the Batch 1 katana rule): when the adapter runs, the legacy entry
is omitted from the plan — the two never both bust directories on the
same base in one state.

Every parse is DEFENSIVE and reuses the legacy regex objects
(``recon_active._FEROX_RE`` / ``_FEROX_STATUS`` — lockstep by
construction, no second implementation to drift): a line that is not a
status/URL result line is skipped and counted — banner output,
progress lines and half-written tails are all malformed, never
interpreted, never labelled evidence. Statuses outside the legacy
interest set are skipped exactly as the legacy parse skips them. A
discovered path is recon evidence, NEVER a vulnerability claim
(verification stays ``not_verified`` everywhere).

Registration is explicit: :func:`production_registry` is the shipped
registry for this adapter; :func:`recon_active_registry` in
adapter_whatweb.py is the combined RECON_ACTIVE registry the runner
injects. Anything not registered stays disabled.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, ConfigDict, Field

from .allowlist import SECLISTS_WEB
from .audit import AuditLog
from .adapters import AdapterRunRecord
from .lineage import link
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

ADAPTER_ID = "feroxbuster-probe"
#: the canonical id under the name recon_active's lane getter imports
#: (the same export pattern as the katana adapter module)
FEROXBUSTER_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "feroxbuster"

#: the fixed argv template — EXACTLY the shipped ``feroxbuster`` entry
#: in allowlist.py ACTIVE_RECON_TEMPLATES (``-u/{urlfuzz}`` + the baked
#: seclists wordlist + 5 threads + 30s timeout), so the adapter argv
#: and the legacy plan entry are byte-identical once the framework
#: composes ``{urlfuzz}`` from the scope-validated base. Lockstep is
#: asserted by tests that render the adapter argv against the SHIPPED
#: Layer-2 template.
FEROXBUSTER_PROBE_TEMPLATE: tuple[str, ...] = (
    "-u", "{urlfuzz}", "-w", SECLISTS_WEB, "-t", "5", "--timeout", "30",
)


def make_feroxbuster_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere. ``{urlfuzz}`` is
    the template's only placeholder; the adapter framework composes it
    from the scope-validated URL (never caller input).
    """
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="feroxbuster content discovery probe",
        purpose=(
            "Authorized content discovery against in-scope web "
            "endpoints via feroxbuster (baked seclists wordlist, 5 "
            "threads, 30s per-request timeout): discovered paths as "
            "recon evidence. RECON_ACTIVE only; a discovered path is "
            "a fact about the site, never a vulnerability claim."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=FEROXBUSTER_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=300,        # <= the sandbox's own 330s ceiling
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy feroxbuster plan entry
        evidence_kind="text_excerpt",
    )


def production_registry():
    """The shipped Mode B adapter registry for the feroxbuster-probe
    adapter: EXPLICITLY contains this one vetted production adapter
    and nothing else. Unknown adapters remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_feroxbuster_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class FeroxBusterObservation(BaseModel):
    """ONE parsed feroxbuster result line — exactly one discovered path
    and the HTTP status it was found with.

    Honest fields only: what feroxbuster reported, bounded. No
    confirmed / vulnerability / severity field exists — a discovered
    path is a fact about the site, not a finding.
    """

    model_config = ConfigDict(frozen=True)

    path: str = Field(min_length=1, max_length=300)
    status: int = Field(ge=100, le=599)

    def properties(self, *, request_id: str) -> dict:
        """The ``path`` node properties — the SAME shape the legacy
        feroxbuster parse produces (``status`` + ``source``), with the
        adapter provenance the legacy excerpt cannot carry."""
        return {
            "status": self.status,
            "source": TOOL_EXECUTABLE,
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }


MAX_OBSERVATIONS = 100


def parse_feroxbuster_lines(
    stdout: str,
    *,
    max_observations: int = MAX_OBSERVATIONS,
) -> "tuple[list[FeroxBusterObservation], int]":
    """Parse bounded discovered-path observations from a feroxbuster
    run.

    Uses the SAME regex objects the legacy parse uses
    (``recon_active._FEROX_RE`` / ``_FEROX_STATUS``) — lockstep by
    construction, no second implementation to drift. Returns
    ``(observations, malformed_lines)``. A line counts as malformed
    when it is non-empty and does not match the result-line shape
    (banner output, progress lines, crawl errors, half-written tails)
    or when its status is outside the legacy interest set (the legacy
    parse silently skips both — the adapter counts them instead). The
    count is capped at ``max_observations``; anything over the cap is
    left unparsed (bounded output, honest and deterministic).
    """
    from urllib.parse import urlsplit

    from .recon_active import _FEROX_RE, _FEROX_STATUS

    observations: list[FeroxBusterObservation] = []
    malformed = 0
    for line in (stdout or "").splitlines():
        if len(observations) >= max_observations:
            break
        stripped = line.strip()
        if not stripped:
            continue
        m = _FEROX_RE.match(stripped)
        if not m:
            malformed += 1
            continue
        status = int(m.group("status"))
        if status not in _FEROX_STATUS:
            malformed += 1
            continue
        raw = m.group("url")
        if raw.startswith(("http://", "https://")):
            parts = urlsplit(raw)
            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"
        else:
            path = raw  # bare-path build (legacy parity)
        try:
            observations.append(FeroxBusterObservation(
                path=path[:300], status=status))
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


def record_feroxbuster_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    observations: "list[FeroxBusterObservation]",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one feroxbuster adapter run onto the evidence graph.

    For each observation: ONE legacy-shape ``path`` node (the SAME node
    type the legacy feroxbuster parse produces and HYPOTHESIZE reads,
    labelled by the discovered path), a ``produced`` lineage edge from
    the run's ``adapter_attempt`` node, with provenance kept verbatim.
    Duplicate paths (same label already on the graph — including paths
    other sources like katana or the passive Wayback source produced)
    are SKIPPED — first observation wins, so a repeat bust adds no node
    and no duplicate surface. Refusal to link is AUDITED, never silent
    and never fatal.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no path nodes: a refusal must never leave
        # fabricated path evidence behind
        audit.write({
            "event": "feroxbuster_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "observations_offered": len(observations),
        })
        return []
    for observation in observations:
        existing = [n for n in graph.by_type("path")
                    if n.get("label") == observation.path]
        if existing:
            continue
        try:
            node = graph.add_node(
                node_type="path",
                label=observation.path,
                properties=observation.properties(
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
                "event": "feroxbuster_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"path node refused: {e}"[:200],
                "path": observation.path[:300],
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
                "event": "feroxbuster_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "feroxbuster_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "observations": len(observations),
        "malformed_lines": malformed_lines,
        "path_nodes": len(created),
        "duplicate_or_refused": len(observations) - len(created),
    })
    return created
