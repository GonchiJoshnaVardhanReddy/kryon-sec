"""A production Mode B tool adapter: katana-probe (Tool Expansion
Batch 1).

Target: Kali's bundled katana (verified in the pinned sandbox image:
executable ``katana``, entrypoint-allowlisted) for authorized
non-destructive web crawling of in-scope web endpoints, in the
RECON_ACTIVE stage only, through the Phase 2B.2 adapter framework —
the SAME engine, sandbox, allowlist, egress boundary, scope checks,
audit chain and evidence graph as every other tool. This module adds
NO general-purpose command interface: the executable is the fixed
``katana`` binary and the argv template is fixed and Layer-2
validated.

WHY AN ADAPTER AT ALL (Batch 1 evaluation):
    - The legacy web-plan entry treats katana as a bare stdout pipe:
      its crawled URLs never carry run provenance (which request
      produced them), no bounded per-line parsing, and a crash inside
      the parse loop would be unattributed. The adapter runs the SAME
      binary with the SAME fixed argv shape and produces the SAME
      legacy-shape ``path`` nodes — with the adapter_attempt run
      record, structured failure classification (2B.7) and bounded
      per-line parsing that the legacy path cannot carry.
    - TEXT output contract, NOT ``-json``: the shipped Layer-2
      ``katana`` template in allowlist.py (the one the legacy plan
      also runs) is the fixed ``-u/-d/-silent`` shape the
      registry-compiled allowlist must stay in lockstep with, and the
      field shapes of katana's JSON stream could not be verified
      against the real binary from this development environment.
      ``-silent`` lines are bare URLs — deterministic and parseable
      with a strict, defensive parser: "text parsing as actually
      supported".

NO NEW AGGRESSION: the lane pins ``params={"depth": "2"}`` — the SAME
crawl depth the legacy plan entry uses (``-d 2``). The adapter never
widens it: a deeper crawl would be a conscious code change in the
lane, auditable in git, never caller input. No forms are submitted, no
headers fuzzed — katana runs as the plain crawler it is in the legacy
plan.

DUPLICATE AVOIDANCE: one probe per check. The registered katana-probe
adapter REPLACES the legacy ``katana`` web-plan entry (deterministic
either/or in ReconActiveSubagent, the same rule as the 2B.3 httpx
rule): when the adapter runs, the legacy entry is omitted from the
plan — the two never both crawl the same base in one state. hakrawler
(duplicate of katana) stays out of the plan as before.

Every parse is DEFENSIVE: a line that is not an ``http(s)://`` URL is
skipped and counted — banner output, crawl errors and half-written
tails are all malformed, never interpreted, never labelled evidence.
Paths are derived the SAME way the legacy parse derives them (split on
the engagement target, query kept, bounded to 300 chars) and capped at
a bounded number of observations; malformed output can never become an
observation, and a crawled path is recon evidence, NEVER a
vulnerability claim (verification stays ``not_verified`` everywhere).

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

log = logging.getLogger(__name__)

ADAPTER_ID = "katana-probe"
#: the canonical id under the name recon_active's lane getter imports
#: (the same export pattern as the nuclei/tls/api adapter modules)
KATANA_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "katana"

#: the fixed argv template — EXACTLY the shipped ``katana`` entry in
#: allowlist.py ACTIVE_RECON_TEMPLATES (``-u/-d/-silent``), so the
#: adapter argv and the legacy plan entry are byte-identical once the
#: lane fills ``{depth}`` with the SAME pinned constant (``2``) the
#: legacy entry uses. Lockstep is asserted by tests that render the
#: adapter argv against the SHIPPED Layer-2 template.
KATANA_PROBE_TEMPLATE: tuple[str, ...] = (
    "-u", "{url}", "-d", "{depth}", "-silent",
)

#: the pinned crawl depth the lane passes (the legacy plan entry's
#: ``-d 2``). A constant here makes the pin explicit and testable.
PINNED_DEPTH = "2"


def make_katana_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere. ``{depth}`` is the
    template's placeholder; the lane is the deterministic caller that
    pins it.
    """
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="katana web crawl probe",
        purpose=(
            "Authorized non-destructive web crawling of in-scope web "
            "endpoints via katana: discovered paths as recon "
            "evidence. RECON_ACTIVE only, pinned depth 2; a crawled "
            "path is a fact about the site, never a vulnerability "
            "claim."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=KATANA_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=180,
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy katana plan entry
        evidence_kind="text_excerpt",
    )


def production_registry():
    """The shipped Mode B adapter registry for the katana-probe
    adapter: EXPLICITLY contains this one vetted production adapter
    and nothing else. Unknown adapters remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_katana_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class KatanaObservation(BaseModel):
    """ONE parsed katana line — exactly one crawled URL and the path
    it maps to on the graph.

    Honest fields only: what katana reported, bounded. No confirmed /
    vulnerability / severity field exists — a crawled path is a fact
    about the site, not a finding.
    """

    model_config = ConfigDict(frozen=True)

    url: str = Field(min_length=1, max_length=500)
    path: str = Field(min_length=1, max_length=300)

    def properties(self, *, request_id: str) -> dict:
        """The ``path`` node properties — the SAME shape the legacy
        katana parse produces (``source`` + ``url``), with the adapter
        provenance the legacy excerpt cannot carry."""
        return {
            "url": self.url,
            "source": TOOL_EXECUTABLE,
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }


def derive_crawled_path(line: str, target: str) -> str:
    """The path label for a crawled URL — the SAME derivation the
    legacy katana parse uses (split on the engagement target, query
    string kept, never empty). A URL that does not contain the target
    yields the whole (bounded) URL as the path — the legacy behavior,
    kept in parity."""
    return line.split(target, 1)[-1] or "/"


def parse_katana_lines(
    stdout: str,
    *,
    target: str,
    max_observations: int = 100,
) -> "tuple[list[KatanaObservation], int]":
    """Parse bounded crawled-URL observations from a katana run.

    Returns ``(observations, malformed_lines)``. A line counts as
    malformed when it is non-empty and does not start with
    ``http://``/``https://`` — banner output, crawl errors and
    half-written tails are all malformed, never interpreted, never
    labelled evidence. The count is capped at ``max_observations``;
    anything over the cap is left unparsed (bounded output, honest and
    deterministic).
    """
    observations: list[KatanaObservation] = []
    malformed = 0
    for line in (stdout or "").splitlines():
        if len(observations) >= max_observations:
            break
        line = line.strip()
        if not line:
            continue
        if not line.startswith(("http://", "https://")):
            malformed += 1
            continue
        try:
            observations.append(KatanaObservation(
                url=line[:500],
                path=derive_crawled_path(line, target)[:300],
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


def record_katana_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    observations: "list[KatanaObservation]",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one katana adapter run onto the evidence graph.

    For each observation: one ``path`` node (the SAME node type the
    legacy katana parse produces and the investigation context reads,
    labelled by the derived path), a ``produced`` lineage edge from the
    run's ``adapter_attempt`` node, with provenance kept verbatim.
    Duplicate paths (same label already on the graph — including
    ``path`` nodes other sources like the Wayback passive source or
    feroxbuster produced) are SKIPPED — first observation wins, so a
    repeat crawl adds no node and no duplicate surface. Refusal to
    link is AUDITED, never silent and never fatal.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no observation nodes: a refusal must never
        # leave fabricated path evidence behind
        audit.write({
            "event": "katana_adapter_evidence_refused",
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
                "event": "katana_adapter_evidence_refused",
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
                "event": "katana_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "katana_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "observations": len(observations),
        "malformed_lines": malformed_lines,
        "path_nodes": len(created),
        "duplicate_or_refused": len(observations) - len(created),
    })
    return created
