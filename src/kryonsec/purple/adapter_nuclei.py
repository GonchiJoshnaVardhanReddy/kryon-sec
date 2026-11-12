"""The fourth production Mode B tool adapter: nuclei-probe (Phase 2B.4).

Target: the sandbox image's bundled Nuclei (verified in the pinned
image: executable ``nuclei``, engine v3.11.1, entrypoint-allowlisted)
for authorized NON-DESTRUCTIVE vulnerability checks against in-scope
web endpoints, in the RECON_ACTIVE stage only, through the Phase 2B.2
adapter framework — the SAME engine, sandbox, allowlist, egress
boundary, scope checks, audit chain and evidence graph as every other
tool. This module adds NO general-purpose command interface: the
executable is the fixed ``nuclei`` binary and the argv template is
fixed and Layer-2 validated.

TEMPLATE POLICY (the reviewed, pinned local allowlist):

- The sandbox image bakes the upstream nuclei-templates tree at build
  time (Dockerfile.kali); the image is digest-pinned, so the tree is
  IMMUTABLE for every run — no template can be uploaded, fetched or
  changed at runtime.
- The adapter's argv carries the template set as FIXED LITERALS: the
  four vetted detection sets
  ``http/exposures/configs/`` (exposed .env/.git/config files, backups),
  ``http/misconfiguration/`` (missing headers, insecure settings),
  ``http/exposed-panels/`` (admin panels and consoles),
  ``http/token-spray/`` (secrets/tokens leaked in responses).
  There is NO ``{template}`` variable: a caller cannot choose a
  template. Everything else the tree contains — cves, vulnerabilities,
  default-logins, fuzzing, credential-stuffing, takeovers, and the
  rest of exposures (measured: its scan overruns the entrypoint's
  hard 300s bound under the sandbox's caps) — is simply never
  emitted by the adapter.
- Remote template sources are structurally impossible here: the fixed
  argv never carries ``-turl``/``-wurl``/``-ut`` (remote template /
  workflow URLs, template update), and ``-duc`` additionally disables
  the update check. The sandbox's egress boundary is target-scope
  anyway.
- ``-etags intrusive`` excludes any template that declares itself
  intrusive; OAST/out-of-band callbacks are OFF via ``-ni`` (which
  also excludes OAST-based templates); local-file payload access
  (``-lfa``), self-contained templates (``-esc``), code templates
  (``-code``), fuzz/DAST templates (``-fuzz``/``-dast``) and headless
  templates (``-headless``) are NOT enabled — the defaults that refuse
  them hold, and the fixed argv can never turn them on.

BOUNDS: ``-rl 20`` requests/second, ``-c 10`` template concurrency,
``-timeout 15`` per request, ``-retries 1``, ``-mt 2m`` nuclei's own
graceful max-time (measured live through gVisor under the sandbox's
caps: the full four-dir run completes in ~175s, and the entrypoint
kills any tool at 300s hard; the adapter's max_seconds is 300).

OUTPUT CONTRACT (verified against the pinned image's nuclei v3.11.1):
    -j / -jsonl   one JSON object per match line (stable contract)
    -silent       findings only (no banners in the JSONL stream)
    -nc           no ANSI escapes
    -or           omit raw request/response pairs (bounded, and the
                  raw traffic is not evidence we need to keep)

Every parse is DEFENSIVE: a line that is not a JSON object carrying a
template id and a matched target is skipped and counted — nuclei's own
non-JSON chatter, [INF]/[WRN]/[ERR] log lines and half-written tails
are all malformed, never interpreted. A detected template match is a
CANDIDATE: its textual severity label is reported metadata, and no
exit code, severity or matcher outcome is ever a confirmed finding.
``verification`` is HARD-WIRED to ``not_verified``; only the VERIFY
subagent (independent tool, same Phase-1C rule) can upgrade anything.

DUPLICATE AVOIDANCE: the existing ``nuclei`` EXPLOIT semantics
(allowlist template, exploit.py's fixed argv + verdict-word
confirmation markers) are UNTOUCHED — this adapter does not enter the
EXPLOIT stage and produces ``vuln_candidate`` nodes, a different node
type from EXPLOIT's ``finding`` nodes, so detection can never
 masquerade as a confirmed exploit finding.

Registration is explicit: :func:`production_registry` is the shipped
registry for this adapter; :func:`recon_active_registry` is the
combined RECON_ACTIVE registry (httpx-probe 2B.3 + whatweb-probe 2B.5
+ nuclei-probe 2B.4) the runner injects. Anything not registered stays
disabled.
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

ADAPTER_ID = "nuclei-probe"
#: the id RECON_ACTIVE's wiring looks up (same identity; the whatweb
#: and httpx modules keep their ids locally — this module exposes its
#: own constant for the same lookup pattern)
NUCLEI_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "nuclei"

#: where the digest-pinned image bakes the nuclei template tree
#: (Dockerfile.kali — world-readable at build time; runtime egress to
#: template sources does not exist in the sandbox anyway)
TEMPLATE_ROOT = "/opt/nuclei-templates/http"

#: the reviewed, pinned template allowlist: four vetted detection
#: sets, FIXED LITERALS in the argv template below. Content inside
#: them is immutable (digest-pinned image).
#:
#: WHY ``exposures/configs/`` and not the whole ``exposures/`` tree
#: (measured live under the sandbox's exact resource caps): nuclei's
#: full exposures directory runs past the entrypoint's hard 300s kill
#: and ignores its own graceful max-time there, while the high-value
#: exposed-config coverage (.env, .git, backups, config files) in its
#: ``configs/`` subtree completes bounded (~30s alone; the combined
#: four-dir run measures ~175s, twice, through the egress bridge).
VETTED_TEMPLATE_DIRS: tuple[str, ...] = (
    f"{TEMPLATE_ROOT}/exposures/configs/",
    f"{TEMPLATE_ROOT}/misconfiguration/",
    f"{TEMPLATE_ROOT}/exposed-panels/",
    f"{TEMPLATE_ROOT}/token-spray/",
)

#: the fixed argv template — frozen literals everywhere except {url}.
#: Every safety flag is a LITERAL: the caller cannot add, remove or
#: reshape a single argument (the Layer-2 check re-validates the
#: rendered argv against exactly this template).
_TEMPLATE_ARGS: tuple[str, ...] = tuple(
    arg for dir_path in VETTED_TEMPLATE_DIRS for arg in ("-t", dir_path)
)
NUCLEI_PROBE_TEMPLATE: tuple[str, ...] = (
    "-u", "{url}",
    *_TEMPLATE_ARGS,
    "-etags", "intrusive",     # never run a self-declared intrusive template
    "-j",                      # JSONL output (one object per match line)
    "-silent",                 # matches only; no banners in the stream
    "-nc",                     # no ANSI escapes
    "-ni",                     # NO interactsh / OOB callbacks; OAST-based
                               # templates are excluded entirely
    "-duc",                    # no update check (offline-deterministic)
    "-or",                     # omit raw request/response pairs
    "-rl", "20",               # 20 requests/second
    "-c", "10",                # 10 templates in parallel
    "-timeout", "15",          # per-request timeout (seconds)
    "-retries", "1",           # single retry, no hammering
    "-mt", "2m",               # nuclei's own graceful max-time: the full
                               # four-dir run measures ~175s through
                               # gVisor under the sandbox's caps (and
                               # the entrypoint kills at 300s hard —
                               # measured live; 3m+ and the full
                               # exposures tree overrun that bound)
)


def make_nuclei_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere.
    """
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="nuclei non-destructive check",
        purpose=(
            "Authorized non-destructive vulnerability checks against "
            "in-scope web endpoints: Nuclei over a pinned local "
            "template allowlist (exposed configs, misconfigurations, "
            "panels, leaked tokens) — detection only, RECON_ACTIVE "
            "only. Matches are candidates, never confirmed findings."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=NUCLEI_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=300,        # <= the sandbox's own 330s ceiling
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy recon probes
        evidence_kind="json_report",
    )


def production_registry():
    """The shipped Mode B adapter registry: EXPLICITLY contains this
    one vetted production adapter and nothing else. Unknown adapters
    remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_nuclei_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class NucleiCandidate(BaseModel):
    """ONE parsed nuclei JSONL match line — one detected candidate.

    Honest fields only: what nuclei reported, bounded. There is NO
    confirmed/verified field and the severity is named
    ``severity_as_reported`` on purpose: the template author's label is
    DATA about the match, not a verdict this engine reached, and it
    must never be confused with the finding verification workflow.
    """

    model_config = ConfigDict(frozen=True)

    template_id: str = Field(min_length=1, max_length=120)
    name: str = Field(default="", max_length=300)
    severity_as_reported: str = Field(default="", max_length=20)
    matched: str = Field(min_length=1, max_length=500)
    host: str = Field(default="", max_length=300)
    tags: tuple[str, ...] = Field(default=(), max_length=12)
    template_path: str = Field(default="", max_length=300)
    #: the matcher that fired (one template can fire several — the
    #: node is the (template @ matched) candidate, first observation wins)
    matcher_name: str = Field(default="", max_length=120)
    excerpt: str = Field(max_length=600)

    def label(self) -> str:
        """The ``vuln_candidate`` node label: (template, matched
        target) — the dedupe key (a repeat run adds no node)."""
        return f"{self.template_id} @ {self.matched}"[:300]

    def properties(self, *, request_id: str) -> dict:
        """The ``vuln_candidate`` node properties — classification is
        ``detected_candidate`` and verification is ``not_verified``:
        detection is neither confirmation nor independent
        verification, whatever the matcher or severity says."""
        return {
            "classification": "detected_candidate",
            "template_id": self.template_id,
            "name": self.name,
            "severity_as_reported": self.severity_as_reported,
            "matched": self.matched,
            "host": self.host,
            "tags": list(self.tags),
            "template_path": self.template_path,
            "matcher_name": self.matcher_name,
            "excerpt": self.excerpt,
            "source": TOOL_EXECUTABLE,
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }


#: nuclei only reports a textual severity in one of these (v3.11.1);
#: anything else is not trusted into the field
_SEVERITIES = frozenset({
    "info", "low", "medium", "high", "critical", "unknown",
})


def parse_nuclei_json_lines(
    stdout: str,
    *,
    max_candidates: int = 50,
) -> "tuple[list[NucleiCandidate], int]":
    """Parse bounded JSONL candidates from a nuclei run.

    Returns ``(candidates, malformed_lines)``. A line counts as
    malformed when it is non-empty and NOT a strict JSON object
    carrying a template id and a matched target — nuclei's own log
    chatter, error lines and half-written tails are all malformed,
    never interpreted, never labelled candidates. An explicit
    ``matcher-status: false`` object (a non-result, not a detection)
    is likewise counted, never promoted. The count is capped at
    ``max_candidates``; anything over the cap is left unparsed
    (bounded output, honest and deterministic).
    """
    candidates: list[NucleiCandidate] = []
    malformed = 0
    for line in (stdout or "").splitlines():
        if len(candidates) >= max_candidates:
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
        if raw.get("matcher-status") is False:
            malformed += 1          # a non-result is not an observation
            continue
        template_id = raw.get("template-id") or raw.get("template")
        # the REAL v3.11.1 shape carries "matched-at" (verified live);
        # "matched" is the older key and "url"/"host" last resorts —
        # all are just WHERE the template matched, defensively read
        matched = (raw.get("matched-at") or raw.get("matched")
                   or raw.get("url") or raw.get("host"))
        if not isinstance(template_id, str) or not template_id.strip() \
                or not isinstance(matched, str) or not matched.strip():
            malformed += 1
            continue
        info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
        severity = info.get("severity")
        tags = info.get("tags")
        if isinstance(tags, str):
            tags = [t for t in (part.strip() for part in tags.split(","))
                    if t]
        elif not isinstance(tags, list):
            tags = []
        try:
            candidates.append(NucleiCandidate(
                template_id=template_id.strip()[:120],
                name=str(info.get("name") or "")[:300],
                severity_as_reported=(severity if isinstance(severity, str)
                                      and severity.lower() in _SEVERITIES
                                      else ""),
                matched=matched.strip()[:500],
                host=str(raw.get("host") or "")[:300],
                tags=tuple(str(t)[:60] for t in tags[:12]),
                template_path=str(raw.get("template-path")
                                  or raw.get("template-url") or "")[:300],
                matcher_name=str(raw.get("matcher-name") or "")[:120],
                excerpt=line[:600],
            ))
        except Exception:   # defensive: a bad line is data, never a crash
            malformed += 1
    return candidates, malformed


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


def record_nuclei_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    candidates: "list[NucleiCandidate]",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one nuclei adapter run onto the evidence graph.

    For each candidate: one ``vuln_candidate`` node (a node type
    RESERVED for pre-confirmation detections — never the ``finding``
    nodes EXPLOIT and VERIFY own), a ``produced`` lineage edge from the
    run's ``adapter_attempt`` node, with provenance kept verbatim.
    Duplicate candidates (same template @ matched target already on
    the graph) are skipped — first observation wins, matching the
    graph's own idempotence rule. Refusal to link is AUDITED, never
    silent and never fatal to the run.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no candidate nodes: a refusal must never
        # leave fabricated detection evidence behind
        audit.write({
            "event": "nuclei_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "candidates_offered": len(candidates),
        })
        return []
    for candidate in candidates:
        label = candidate.label()
        existing = [n for n in graph.by_type("vuln_candidate")
                    if n.get("label") == label]
        if existing:
            continue
        try:
            node = graph.add_node(
                node_type="vuln_candidate",
                label=label,
                properties=candidate.properties(
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
                "event": "nuclei_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"vuln_candidate node refused: {e}"[:200],
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
                "event": "nuclei_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "nuclei_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "candidates": len(candidates),
        "malformed_lines": malformed_lines,
        "vuln_candidate_nodes": len(created),
        "duplicate_or_refused": len(candidates) - len(created),
    })
    return created
