"""The first production Mode B tool adapter: httpx-probe (Phase 2B.3).

Target: ProjectDiscovery httpx for authorized HTTP service
reconnaissance, in the RECON_ACTIVE stage only, through the Phase 2B.2
adapter framework — the SAME engine, sandbox, allowlist, egress
boundary, scope checks, audit chain and evidence graph as every other
tool. This module adds NO general-purpose command interface: the
executable is the fixed ``httpx-toolkit`` binary (Kali's package name
for upstream httpx — ``debian/rules`` installs it ONLY as
``httpx-toolkit``; a plain ``httpx`` command does not exist in this
image), and the argv template is fixed and Layer-2 validated.

OUTPUT CONTRACT (verified against upstream httpx flags):
    -json          JSONL — one JSON object per line (stable contract)
    -status-code   include HTTP status
    -title         include page title
    -tech-detect   include detected technologies
    -no-color      no ANSI (JSONL stays clean)
    -duc           no update check (offline-deterministic)

Every parse is DEFENSIVE: a line that is not a JSON object carrying a
url + integer status_code is skipped and counted — malformed output can
never become an observation, ordinary text is never labelled JSON, and
an HTTP 200 / exit 0 / detected technology is NEVER a vulnerability
claim (verification stays ``not_verified`` everywhere).

Registration is explicit: :func:`production_registry` is the shipped
registry; anything not registered stays disabled (the Phase 2B.2
registry default).
"""

from __future__ import annotations

import json
import logging

from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLog
from .adapters import AdapterRunRecord
from .lineage import link
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

ADAPTER_ID = "httpx-probe"
TOOL_EXECUTABLE = "httpx-toolkit"

#: the fixed argv template — identical token sequence as the
#: ``httpx-toolkit`` entry in allowlist.py ACTIVE_RECON_TEMPLATES
#: (kept honest by tests that compare both).
HTTPX_PROBE_TEMPLATE: tuple[str, ...] = (
    "-u", "{url}", "-silent", "-json", "-status-code", "-title",
    "-tech-detect", "-no-color", "-duc",
)


def make_httpx_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere.
    """
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="httpx web probe",
        purpose=(
            "Authorized HTTP service reconnaissance against in-scope web "
            "endpoints: status, title and technology fingerprint via "
            "ProjectDiscovery httpx. RECON_ACTIVE only; observations are "
            "recon evidence, never vulnerability claims."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=HTTPX_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=120,
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model (egress+scope), the
        risk="active",           # SAME standing as the legacy httpx probe
        evidence_kind="json_report",
    )


def production_registry():
    """The shipped Mode B adapter registry: EXPLICITLY contains the one
    vetted production adapter and nothing else. Unknown adapters remain
    disabled elsewhere — this registry only AUTHORIZES what is here."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_httpx_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class HttpxObservation(BaseModel):
    """ONE parsed httpx JSONL line — exactly one in-scope web endpoint.

    Honest fields only: what httpx reported, bounded. No confirmed /
    vulnerability / severity field exists — a 200 or a technology name
    is a fact about the service, not a finding.
    """

    model_config = ConfigDict(frozen=True)

    url: str = Field(min_length=1, max_length=500)
    status_code: int = Field(ge=100, le=599)
    title: str = Field(default="", max_length=300)
    tech: tuple[str, ...] = Field(default=(), max_length=10)
    webserver: str = Field(default="", max_length=200)

    def properties(self, *, request_id: str) -> dict:
        """The ``web_endpoint`` node properties — the SAME key shape as
        the legacy parse_httpx records (``status``/``title``/``tech``/
        ``source``) so HYPOTHESIZE reads both paths identically, plus
        the adapter provenance the legacy text parse cannot carry."""
        return {
            "status": self.status_code,
            "title": self.title,
            "tech": list(self.tech),
            "source": TOOL_EXECUTABLE,
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }


def parse_httpx_json_lines(
    stdout: str,
    *,
    max_observations: int = 50,
) -> "tuple[list[HttpxObservation], int]":
    """Parse bounded JSONL observations from a httpx run.

    Returns ``(observations, malformed_lines)``. A line counts as
    malformed when it is non-empty and NOT a strict JSON object carrying
    a string ``url`` and an integer ``status_code`` — httpx's own
    non-JSON chatter, error lines and half-written tails are all
    malformed, never interpreted, never labelled JSON. The count is
    capped at ``max_observations``; anything over the cap is left
    unparsed (oversized-output bound, honest and deterministic).
    """
    observations: list[HttpxObservation] = []
    malformed = 0
    for line in (stdout or "").splitlines():
        if len(observations) >= max_observations:
            break
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(raw, dict):
            malformed += 1
            continue
        url = raw.get("url")
        status = raw.get("status_code")
        if not isinstance(url, str) or not url.strip() \
                or not isinstance(status, int):
            malformed += 1
            continue
        tech = raw.get("tech")
        if isinstance(tech, str):
            tech_items = [t for t in
                          (part.strip() for part in tech.split(",")) if t]
        elif isinstance(tech, list):
            tech_items = []
            for item in tech:
                text = str(item).strip()
                if text and text != "None":
                    tech_items.append(text)
        else:
            tech_items = []
        webserver = raw.get("webserver")
        try:
            observations.append(HttpxObservation(
                url=url.strip()[:500],
                status_code=status,
                title=str(raw.get("title") or "")[:300],
                tech=tuple(t[:120] for t in tech_items[:10]),
                webserver=str(webserver or "")[:200]
                if webserver is not None else "",
            ))
        except Exception:   # defensive: a bad line is data, never a crash
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


def record_httpx_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    observations: "list[HttpxObservation]",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one httpx adapter run onto the evidence graph.

    For each observation: one ``web_endpoint`` node (same node type and
    key shape the legacy httpx path produces), a ``produced`` lineage
    edge from the run's ``adapter_attempt`` node (the chain: attempt ->
    observations), with provenance kept verbatim. Duplicate endpoints
    (same label already on the graph) are skipped — first observation
    wins, matching the graph's own idempotence rule. Refusal to link is
    AUDITED, never silent and never fatal to the run.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no observation nodes: a refusal must never
        # leave fabricated endpoint evidence behind
        audit.write({
            "event": "httpx_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "observations_offered": len(observations),
        })
        return []
    for observation in observations:
        existing = [n for n in graph.by_type("web_endpoint")
                    if n.get("label") == observation.url]
        if existing:
            continue
        try:
            node = graph.add_node(
                node_type="web_endpoint",
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
        except Exception as e:   # graph validation: audited, not fatal
            audit.write({
                "event": "httpx_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"web_endpoint node refused: {e}"[:200],
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
                "event": "httpx_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "httpx_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "observations": len(observations),
        "malformed_lines": malformed_lines,
        "web_endpoint_nodes": len(created),
        "duplicate_or_refused": len(observations) - len(created),
    })
    return created
