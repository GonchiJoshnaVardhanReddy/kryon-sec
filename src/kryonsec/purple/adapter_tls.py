"""The fifth and sixth production Mode B tool adapters (Phase 2B.5).

This module: tls-probe. (The API twin lives in adapter_api.py.)

Target: the sandbox image's REAL testssl binary — verified live in the
pinned image: the Kali package ``testssl.sh`` (3.2.4+dfsg-2) installs
its executable as ``/usr/bin/testssl``; a ``testssl.sh`` command name
does NOT exist, so the legacy ``testssl.sh`` allowlist template and
entrypoint entry silently exit-127 in this image. The adapter reaches
the tool through the baked wrapper script ``/opt/kryonsec/tls_probe.py``
(entrypoint-allowlisted, fixed argv ``[script, url]``) because testssl
can only write its machine-readable findings to a FILE, and the
sandbox captures stdout only — the wrapper owns the file lifecycle
inside the run and prints one bounded JSON payload.

POLICY (frozen — the wrapper carries it, this definition pins it):
    - ONE approved https://host:port target per run; no
      certificate-metadata-driven scanning of other hosts is possible
      (the wrapper points testssl at exactly that node);
    - every testssl flag is a literal inside the reviewed wrapper
      script: no user-selected checks, no custom scripts, no shell, no
      ``--phone-out`` (external reporting/telemetry — never set), no
      authenticated testing, no automatic downloads;
    - bounded: the wrapper kills testssl after 240s (measured live
      under the sandbox's exact caps: full run 185s/203s; the
      entrypoint kills at 300s regardless) and reads the partial
      findings testssl wrote incrementally — an overrun is marked
      ``partial`` and never padded;
    - findings are capped (120) and each finding text is bounded
      (300 chars) by the wrapper; the payload is one JSON object
      (evidence_kind json_report).

EVIDENCE SEMANTICS (the honest part):
    - one ``tls_observation`` node per run (the SAME node type the
      legacy sslscan/testssl excerpt path already produces — no new
      node type, no context churn), carrying the structured summary:
      protocol offers, certificate observations, and the tool-reported
      weaknesses (bounded);
    - every tool-reported weakness ALSO becomes a ``vuln_candidate``
      node (the pre-confirmation node type the nuclei-probe adapter
      introduced) with classification ``detected_candidate`` and
      verification HARD-WIRED ``not_verified`` — detection is never
      confirmation, whatever testssl's severity label says;
    - the adapter TRUSTS testssl's severity label only from its known
      label set; anything else is kept as text, never normalized into
      a verdict.

Registration is explicit: :func:`production_registry` carries this
one adapter; :func:`recon_active_registry` (adapter_whatweb.py) is the
combined RECON_ACTIVE registry the runner injects. Anything not
registered stays disabled.
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

ADAPTER_ID = "tls-probe"
#: the id RECON_ACTIVE's wiring looks up (same identity; the sibling
#: adapter modules keep their ids locally — each module exposes its
#: own constant for the same lookup pattern)
TLS_PROBE_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "/opt/kryonsec/tls_probe.py"

#: the fixed argv template: the wrapper script takes EXACTLY the
#: approved URL and nothing else — no flag, no option, no second
#: argument is possible (the wrapper refuses argv != 2).
TLS_PROBE_TEMPLATE: tuple[str, ...] = ("{url}",)

#: testssl's known severity labels (3.2.4); anything else stays text
_SEVERITIES = frozenset({
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN", "OK", "INFO",
})

#: severities that mean "the tool reported a weakness" — these become
#: vuln_candidate nodes. OK/INFO stay observations-only.
_WEAK_SEVERITIES = frozenset({
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN",
})

MAX_CANDIDATES = 20          # vuln_candidate nodes per run
MAX_WEAK_IN_NODE = 20        # weaknesses inside the summary node


def make_tls_probe_adapter():
    """Build the frozen adapter definition (same registry identity
    everywhere; a factory keeps the import graph light)."""
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="testssl TLS baseline",
        purpose=(
            "Authorized TLS/HTTPS baseline inspection of in-scope "
            "https endpoints: protocols, certificate validity/expiry/"
            "hostname, chain problems, weak ciphers — testssl via the "
            "baked wrapper script with a frozen flag set. Tool-"
            "reported weaknesses are candidates, never confirmations. "
            "RECON_ACTIVE only."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=TLS_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=300,        # <= the sandbox's own 330s ceiling
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy TLS plan entries
        evidence_kind="json_report",
    )


def production_registry():
    """The shipped Mode B adapter registry for tls-probe: EXPLICITLY
    contains this one vetted production adapter and nothing else."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_tls_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class TLSFinding(BaseModel):
    """ONE testssl finding, bounded, honest. ``severity_as_reported``
    is testssl's OWN label — data about the match, never a verdict
    this engine reached."""

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(min_length=1, max_length=60)
    severity_as_reported: str = Field(default="", max_length=20)
    finding: str = Field(default="", max_length=300)
    cve: str = Field(default="", max_length=60)
    port: str = Field(default="", max_length=10)


class TLSProbeRun(BaseModel):
    """The parsed tls_probe.py payload — one run against one approved
    node. ``status`` is the wrapper's own honest verdict: ``complete``
    or ``partial`` (killed at the time bound; the findings it got to
    write are kept, never padded)."""

    model_config = ConfigDict(frozen=True)

    url: str = Field(min_length=1, max_length=500)
    node: str = Field(min_length=1, max_length=300)
    tool: str = Field(default="testssl", max_length=40)
    tool_version: str = Field(default="", max_length=20)
    status: str = Field(default="", max_length=20)
    exit_code: int = Field(default=-1)
    started_at: str = Field(default="", max_length=32)
    findings: tuple[TLSFinding, ...] = Field(default=(), max_length=120)
    truncated: bool = Field(default=False)
    argv_reference: tuple[str, ...] = Field(default=(), max_length=12)

    @property
    def weak_findings(self) -> "tuple[TLSFinding, ...]":
        """The findings whose severity is in the known weakness label
        set (tool-reported weaknesses = candidates)."""
        return tuple(f for f in self.findings
                     if f.severity_as_reported in _WEAK_SEVERITIES)

    def summary_properties(self, *, request_id: str) -> dict:
        """The run-summary ``tls_observation`` node properties."""
        weak = self.weak_findings
        protocols = {
            f.finding_id: f.finding for f in self.findings
            if f.finding_id.startswith(("SSLv", "TLS1"))
        }
        certs = {
            f.finding_id: f.finding for f in self.findings
            if f.finding_id.startswith("cert_")
        }
        return {
            "classification": "tool_reported_observation",
            "tool": self.tool,
            "tool_version": self.tool_version,
            "status": self.status,
            "node": self.node,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "protocol_offers": protocols,
            "certificate_observations": certs,
            "weak_findings": [
                {
                    "id": f.finding_id,
                    "severity_as_reported": f.severity_as_reported,
                    "finding": f.finding,
                }
                for f in weak[:MAX_WEAK_IN_NODE]
            ],
            "weak_finding_count": len(weak),
            "finding_count": len(self.findings),
            "truncated": self.truncated,
            "argv_reference": list(self.argv_reference),
            "source": "testssl",
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }


def parse_tls_probe_payload(
    stdout: str,
) -> "tuple[TLSProbeRun | None, int]":
    """Parse the wrapper's ONE JSON payload defensively.

    Returns ``(run, malformed_lines)``. ``run`` is None when the
    output carries no parseable payload — chatter, usage text and
    half-written tails are all malformed, never interpreted. A
    payload missing the kind marker or its node is malformed too.
    """
    malformed = 0
    run = None
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(raw, dict) \
                or raw.get("kind") != "kryonsec_tls_probe":
            malformed += 1
            continue
        url = raw.get("url")
        node = raw.get("node")
        if not isinstance(url, str) or not url.strip() \
                or not isinstance(node, str) or not node.strip():
            malformed += 1
            continue
        findings: list[TLSFinding] = []
        for entry in raw.get("findings") or []:
            if not isinstance(entry, dict):
                continue
            fid = entry.get("id")
            if not isinstance(fid, str) or not fid.strip():
                continue     # an idless blob is skipped, not guessed
            try:
                findings.append(TLSFinding(
                    finding_id=fid.strip()[:60],
                    severity_as_reported=str(
                        entry.get("severity_as_reported") or "")[:20],
                    finding=str(entry.get("finding") or "")[:300],
                    cve=str(entry.get("cve") or "")[:60],
                    port=str(entry.get("port") or "")[:10],
                ))
            except Exception:   # defensive: bad entry is data
                malformed += 1
        try:
            run = TLSProbeRun(
                url=url.strip()[:500],
                node=node.strip()[:300],
                tool=str(raw.get("tool") or "testssl")[:40],
                tool_version=str(raw.get("tool_version") or "")[:20],
                status=str(raw.get("status") or "")[:20],
                exit_code=int(raw.get("exit_code") or -1),
                started_at=str(raw.get("started_at") or "")[:32],
                findings=tuple(findings[:120]),
                truncated=bool(raw.get("truncated")),
                argv_reference=tuple(
                    str(a)[:200] for a in
                    (raw.get("argv_reference") or ())[:12]),
            )
        except Exception:
            malformed += 1
            run = None
        break
    return run, malformed


# ---- evidence recording -------------------------------------------------------


def find_adapter_attempt_node(graph: EngagementGraph,
                              request_id: str) -> "dict | None":
    """The ``adapter_attempt`` node this run produced (by request_id).
    None when the run never produced one (refusals are audit-only)."""
    for node in graph.by_type("adapter_attempt"):
        props = node.get("properties") or {}
        if props.get("request_id") == request_id:
            return node
    return None


def record_tls_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    run: "TLSProbeRun | None",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one tls-probe adapter run onto the evidence graph.

    One ``tls_observation`` node per run (label = the probed node —
    the SAME node type the legacy sslscan/testssl path produces; the
    first observation of a node wins, matching the graph's own
    idempotence rule). Every tool-reported weakness ALSO becomes a
    ``vuln_candidate`` node — the pre-confirmation node type — with
    classification ``detected_candidate`` and verification
    HARD-WIRED ``not_verified``; dedupe key is
    ``(finding_id @ node)``, first observation wins. Refusal to link
    is AUDITED, never silent and never fatal to the run.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no evidence: a refusal must never leave
        # fabricated observations behind
        audit.write({
            "event": "tls_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
        })
        return []
    if run is None:
        audit.write({
            "event": "tls_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "output carried no parseable tls probe payload",
            "malformed_lines": malformed_lines,
        })
        return []
    summary_label = f"testssl {run.node}"[:300]
    existing = [n for n in graph.by_type("tls_observation")
                if n.get("label") == summary_label]
    summary_node = None
    if not existing:
        try:
            summary_node = graph.add_node(
                node_type="tls_observation",
                label=summary_label,
                properties=run.summary_properties(
                    request_id=run_record.request_id),
                provenance={
                    "agent": "ADAPTER",
                    "source_type": "tool",
                    "tool": "testssl",
                    "adapter": ADAPTER_ID,
                },
            )
            created.append(summary_node["id"])
        except Exception as e:  # graph validation: audited, not fatal
            audit.write({
                "event": "tls_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"tls_observation node refused: {e}"[:200],
                "label": summary_label,
            })
    if summary_node is not None:
        link(
            graph, "produced", attempt["id"], summary_node["id"],
            provenance={
                "agent": "ADAPTER", "source_type": "tool",
                "adapter": ADAPTER_ID,
            },
            on_refuse=lambda reason: audit.write({
                "event": "tls_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": str(reason)[:200],
            }),
        )
    for finding in run.weak_findings[:MAX_CANDIDATES]:
        label = f"testssl {finding.finding_id} @ {run.node}"[:300]
        existing = [n for n in graph.by_type("vuln_candidate")
                    if n.get("label") == label]
        if existing:
            continue
        try:
            node = graph.add_node(
                node_type="vuln_candidate",
                label=label,
                properties={
                    "classification": "detected_candidate",
                    "finding_id": finding.finding_id,
                    "severity_as_reported":
                        finding.severity_as_reported,
                    "finding": finding.finding,
                    "cve": finding.cve,
                    "node": run.node,
                    "tool": "testssl",
                    "adapter": ADAPTER_ID,
                    "request_id": run_record.request_id,
                    "untrusted": True,
                    "verification": "not_verified",
                },
                provenance={
                    "agent": "ADAPTER",
                    "source_type": "tool",
                    "tool": "testssl",
                    "adapter": ADAPTER_ID,
                },
            )
        except Exception as e:
            audit.write({
                "event": "tls_adapter_evidence_refused",
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
                "event": "tls_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "tls_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": "testssl",
        "request_id": run_record.request_id,
        "status": run.status,
        "findings": len(run.findings),
        "weak_findings": len(run.weak_findings),
        "malformed_lines": malformed_lines,
        "nodes_created": len(created),
    })
    return created
