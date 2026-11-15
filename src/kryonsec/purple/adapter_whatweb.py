"""The third production Mode B tool adapter: whatweb-probe (Phase 2B.5).

Target: Kali's bundled WhatWeb (verified in the pinned sandbox image:
executable ``whatweb``, version 0.6.4, entrypoint-allowlisted) for
authorized technology fingerprinting, in the RECON_ACTIVE stage only,
through the Phase 2B.2 adapter framework — the SAME engine, sandbox,
allowlist, egress boundary, scope checks, audit chain and evidence
graph as every other tool. This module adds NO general-purpose command
interface: the executable is the fixed ``whatweb`` binary and the argv
template is fixed and Layer-2 validated.

WHY AN ADAPTER AT ALL (Task 2 evaluation, verified live against the
pinned image):
    - WhatWeb fingerprint detection is materially richer than what
      httpx-toolkit's `-tech-detect` produces: it matches specific
      products down to versions (verified on a local lab:
      ``Python[3.14.7]``, ``HTTPServer[SimpleHTTP/0.6
      Python/3.14.7]``), which httpx's tech list does not carry.
    - Machine-readable JSON exists in WhatWeb 0.6.4 (``--log-json=-``
      prints a JSON array — also verified live). The adapter still
      pins the brief TEXT contract, because the shipped Layer-2
      ``whatweb`` template in allowlist.py (the one the legacy plan
      also runs) is a fixed 5-argument shape the registry-compiled
      allowlist must stay in lockstep with; adding ``--log-json=-``
      would change the shared template for both paths. The brief line
      is deterministic and parseable with a strict, defensive parser —
      "text parsing as actually supported".

NO AGGRESSION: the template pins ``-a 1`` (WhatWeb's default,
passive-style level — the same level the upstream default documents).
The legacy plan's ``-a 3`` entry predates this phase; the adapter
never emits it, and the test battery attests the adapter argv can
never carry anything but level 1.

DUPLICATE AVOIDANCE (Task 4): one probe per check. The registered
whatweb-probe adapter REPLACES the legacy ``whatweb`` plan entry for
the same base URLs (deterministic either/or in ReconActiveSubagent,
like the 2B.3 httpx rule), and the adapter's evidence lands in
``tech_fingerprint`` nodes — a DIFFERENT node type from the
``web_endpoint`` nodes the httpx-probe adapter owns — so the two
adapters enrich the same surface without duplicating each other's
evidence.

Every parse is DEFENSIVE: a line that is not a brief-format
``url [code text] plugins…`` line is skipped and counted — plugin
tokens must carry alpha-numeric names, malformed output can never
become an observation, and a fingerprint is NEVER a vulnerability
claim (verification stays ``not_verified`` everywhere).

Registration is explicit: :func:`production_registry` is the shipped
registry for this adapter; :func:`recon_active_registry` is the
combined RECON_ACTIVE registry (the five web adapters plus the three
Batch 1 discovery/crawl probes) the runner injects. Anything not
registered stays disabled.
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

ADAPTER_ID = "whatweb-probe"
TOOL_EXECUTABLE = "whatweb"

#: the fixed argv template — the brief-text contract of the shipped
#: ``whatweb`` entry in allowlist.py ACTIVE_RECON_TEMPLATES, with the
#: aggression level PINNED to 1: the adapter always runs WhatWeb's
#: default level regardless of what the alternation template would
#: also permit (keeping the shared template honest — the legacy plan
#: still validates against it — while freezing the adapter to no
#: aggression). Lockstep is asserted by tests that render the adapter
#: argv against the SHIPPED Layer-2 template.
WHATWEB_PROBE_TEMPLATE: tuple[str, ...] = (
    "-a", "1", "--no-errors", "--color=never", "{url}",
)


def make_whatweb_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere.
    """
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="whatweb technology fingerprint",
        purpose=(
            "Authorized technology fingerprinting against in-scope web "
            "endpoints: server/product fingerprints with version "
            "granularity via WhatWeb. RECON_ACTIVE only; observations "
            "are recon evidence, never vulnerability claims."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=WHATWEB_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=120,
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy whatweb plan entry
        evidence_kind="text_excerpt",
    )


def production_registry():
    """The shipped Mode B adapter registry for the whatweb-probe
    adapter: EXPLICITLY contains this one vetted production adapter and
    nothing else. Unknown adapters remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_whatweb_probe_adapter())
    return registry


def recon_active_registry():
    """The combined RECON_ACTIVE registry the runner injects: the
    EIGHT vetted production adapters — the five web adapters (httpx-probe
    2B.3, whatweb-probe 2B.5, tls-probe 2B.5, api-probe 2B.5,
    nuclei-probe 2B.4) plus the three Batch 1 discovery/crawl probes
    (dnsx-probe, naabu-probe, katana-probe — Tool Expansion Batch 1).
    One probe per check is preserved by ReconActiveSubagent's
    deterministic either/or rules, not by pretending one of the
    adapters does not exist."""
    registry = production_registry()
    from .adapter_httpx import make_httpx_probe_adapter
    from .adapter_nuclei import make_nuclei_probe_adapter
    from .adapter_tls import make_tls_probe_adapter
    from .adapter_api import make_api_probe_adapter
    from .adapter_dnsx import make_dnsx_probe_adapter
    from .adapter_naabu import make_naabu_probe_adapter
    from .adapter_katana import make_katana_probe_adapter

    registry.register(make_httpx_probe_adapter())
    registry.register(make_tls_probe_adapter())
    registry.register(make_api_probe_adapter())
    registry.register(make_nuclei_probe_adapter())
    registry.register(make_dnsx_probe_adapter())
    registry.register(make_naabu_probe_adapter())
    registry.register(make_katana_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class WhatwebObservation(BaseModel):
    """ONE parsed WhatWeb brief-format line — exactly one probed URL.

    Honest fields only: what WhatWeb reported, bounded. ``plugins``
    keeps each plugin token verbatim (``Name[v]`` or a bare ``Name``) —
    bounded. No confirmed / vulnerability / severity field exists — a
    fingerprint is a fact about the service, not a finding.
    """

    model_config = ConfigDict(frozen=True)

    url: str = Field(min_length=1, max_length=500)
    status_code: int = Field(ge=100, le=599)
    status_text: str = Field(default="", max_length=60)
    plugins: tuple[str, ...] = Field(default=(), max_length=24)
    excerpt: str = Field(max_length=500)

    def properties(self, *, request_id: str) -> dict:
        """The ``tech_fingerprint`` node properties — the ``excerpt``
        field (with the bounded raw line) is what the investigation
        context actually renders for this node type, so it is kept as
        the first-class property; the parsed fields travel alongside
        with the adapter provenance."""
        return {
            "excerpt": self.excerpt,
            "status": self.status_code,
            "status_text": self.status_text,
            "plugins": list(self.plugins),
            "source": TOOL_EXECUTABLE,
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }


# the brief-format header: "http://host:port/ [200 OK] Country[...], ..."
# (verified live against WhatWeb 0.6.4 in the pinned sandbox image)
_BRIEF_RE = re.compile(
    r"^(?P<url>\S+)\s+\[(?P<status>\d{3})\s+(?P<status_text>[^\]]*)\]"
    r"(?:\s+(?P<rest>.+))?$",
)

# one plugin token: a name (no brackets — bracketed values never start a
# token) optionally followed by bracketed value groups
_PLUGIN_RE = re.compile(
    r"^(?P<name>[^,\[\]]+?)\s*(?P<vals>(?:\[[^\]\[]*\])*)$",
)


def _split_tool_tokens(rest: str) -> "list[str]":
    """Split ``rest`` on top-level commas only — commas inside bracketed
    plugin values (e.g. ``Title[a, b]``) belong to the value, not the
    token boundary."""
    tokens: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in rest:
        if ch == "[":
            depth += 1
            current.append(ch)
        elif ch == "]":
            depth = max(depth - 1, 0)
            current.append(ch)
        elif ch == "," and depth == 0:
            tokens.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tokens.append("".join(current).strip())
    return [t for t in tokens if t]


def _render_plugin_token(token: str) -> str | None:
    """A plugin token verbatim, or None when it is not recognisably a
    plugin token. Bare names (``HTML5``) pass through; unknown shapes
    return None — never guessed into an observation."""
    m = _PLUGIN_RE.match(token)
    if not m:
        return None
    name = m.group("name").strip()
    values = re.findall(r"\[([^\]\[]*)\]", m.group("vals") or "")
    if not name:
        return None
    rendered = name
    for value in values[:6]:
        rendered = f"{rendered}[{value}]"
    return rendered[:300]


def parse_whatweb_lines(
    stdout: str,
    *,
    max_observations: int = 20,
) -> "tuple[list[WhatwebObservation], int]":
    """Parse bounded brief-format observations from a whatweb run.

    Returns ``(observations, malformed_lines)``. A line counts as
    malformed when it is non-empty and does NOT match the brief
    ``url [code] plugins…`` shape — banner/version output, connection
    errors that slip through and half-written tails are all malformed,
    never interpreted, never labelled evidence. Within a matching line
    a plugin token that does not parse is dropped (never invented as a
    plugin). The count is capped at ``max_observations``; anything over
    the cap is left unparsed (bounded output, honest and deterministic).
    """
    observations: list[WhatwebObservation] = []
    malformed = 0
    for line in (stdout or "").splitlines():
        if len(observations) >= max_observations:
            break
        line = line.strip()
        if not line:
            continue
        m = _BRIEF_RE.match(line)
        if not m:
            malformed += 1
            continue
        plugins: list[str] = []
        raw = m.group("rest") or ""
        for token in _split_tool_tokens(raw)[:40]:
            rendered = _render_plugin_token(token)
            if rendered is not None:
                plugins.append(rendered)
        try:
            observations.append(WhatwebObservation(
                url=m.group("url")[:500],
                status_code=int(m.group("status")),
                status_text=(m.group("status_text") or "")[:60],
                plugins=tuple(plugins[:24]),
                excerpt=line[:500],
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


def record_whatweb_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    observations: "list[WhatwebObservation]",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one whatweb adapter run onto the evidence graph.

    For each observation: one ``tech_fingerprint`` node (the SAME node
    type the legacy whatweb path produces and the investigation
    context renders, labelled by the probed base URL), a ``produced``
    lineage edge from the run's ``adapter_attempt`` node, with
    provenance kept verbatim. Duplicate fingerprints (same label
    already on the graph) are skipped — first observation wins,
    matching the graph's own idempotence rule; this is ALSO the layer
    that keeps the httpx-probe and whatweb-probe adapters from
    duplicating each other's evidence (they use different node types,
    and a repeat whatweb run against the same base adds no node).
    Refusal to link is AUDITED, never silent and never fatal.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no observation nodes: a refusal must never
        # leave fabricated fingerprint evidence behind
        audit.write({
            "event": "whatweb_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "observations_offered": len(observations),
        })
        return []
    for observation in observations:
        existing = [n for n in graph.by_type("tech_fingerprint")
                    if n.get("label") == observation.url]
        if existing:
            continue
        try:
            node = graph.add_node(
                node_type="tech_fingerprint",
                label=observation.url,
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
                "event": "whatweb_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"tech_fingerprint node refused: {e}"[:200],
                "url": observation.url[:300],
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
                "event": "whatweb_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "whatweb_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "observations": len(observations),
        "malformed_lines": malformed_lines,
        "tech_fingerprint_nodes": len(created),
        "duplicate_or_refused": len(observations) - len(created),
    })
    return created
