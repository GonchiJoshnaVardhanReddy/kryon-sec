"""The sixth production Mode B tool adapter: api-probe (Phase 2B.5).

Target: the baked read-only script ``/opt/kryonsec/api_probe.py``
(entrypoint-allowlisted, fixed argv ``[script, url]``) — a bounded,
read-only API security baseline check of ONE approved http(s) base
URL: security headers, CORS configuration evidence, advertised HTTP
methods, and OpenAPI/Swagger document metadata.

WHY A NEW BAKED SCRIPT (Task 2 evaluation, verified against the
pinned image): the existing Phase-8 ``openapi_probe.py`` covers only
documentation discovery (4 well-known paths) and records no security
headers, no CORS evidence, no OPTIONS metadata — and it follows
redirects by default (urllib's default handler), which this phase
forbids. Rather than duplicate its doc logic, api_probe.py SUPERSETs
it (same four paths, same bounded endpoint enumeration) and the
registered adapter REPLACES the legacy openapi_probe plan entry
(deterministic either/or, like the 2B.3 httpx rule) — one probe per
check, never both.

REQUEST POLICY (frozen inside the reviewed script; this definition
pins the one-argument surface):
    - ONE approved base URL per run; every request stays under that
      host. Cross-host redirects are recorded and never followed; no
      secondary request to another host is possible;
    - GET and OPTIONS only — PUT/PATCH/DELETE and state-changing POST
      are structurally absent from the script;
    - no credentials/tokens/cookies are ever read, sent or stored;
    - the CORS observation uses ONE fixed inert test origin
      (``https://kryonsec-cors-probe.invalid``); reflection is
      recorded as concrete header evidence — never claimed as
      credential theft or practical exploitation;
    - OpenAPI documents: size-capped before parsing, parsed with
      ``json.loads`` only (no code execution), ``$ref``s counted
      never resolved/fetched, operations enumerated as metadata and
      NEVER invoked;
    - bounded: at most 7 requests, 10s per request, 512KiB per
      response read, 50 enumerated endpoints, bounded output.

EVIDENCE SEMANTICS (the honest part):
    - one ``api_observation`` node per run (the structured summary:
      security headers observed, CORS evidence, OPTIONS metadata,
      docs found) with verification ``not_verified`` — a missing
      header or a permissive CORS value is DATA, never an exploit;
    - OpenAPI-declared paths become ``path`` nodes (the SAME node
      type the legacy openapi_probe path produces — metadata only,
      source ``api_probe``);
    - the script's own tool-flagged weaknesses (a missing well-known
      security header on a live response, a reflected wildcard-CORS
      with credentials allowed) become ``vuln_candidate`` nodes —
      the pre-confirmation node type — classification
      ``detected_candidate``, severity capped at ``low``, and
      verification HARD-WIRED ``not_verified``. This module NEVER
      fabricates a high/critical label: header and CORS facts are
      baseline observations, not claims.

Registration is explicit: :func:`production_registry` carries this
one adapter; :func:`recon_active_registry` (adapter_whatweb.py) is
the combined RECON_ACTIVE registry the runner injects. Anything not
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

ADAPTER_ID = "api-probe"
#: the id RECON_ACTIVE's wiring looks up (same identity; the sibling
#: adapter modules keep their ids locally — each module exposes its
#: own constant for the same lookup pattern)
API_PROBE_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "/opt/kryonsec/api_probe.py"

#: the fixed argv template: the script takes EXACTLY the approved
#: base URL and nothing else (the script refuses argv != 2).
API_PROBE_TEMPLATE: tuple[str, ...] = ("{url}",)

#: the well-known security headers the baseline inspects — the SAME
#: list the baked script uses (kept in lockstep by tests)
SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "referrer-policy",
    "permissions-policy", "server", "x-powered-by",
)

MAX_CANDIDATES = 20          # vuln_candidate nodes per run


def make_api_probe_adapter():
    """Build the frozen adapter definition (same registry identity
    everywhere; a factory keeps the import graph light)."""
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="read-only API baseline",
        purpose=(
            "Authorized read-only API baseline inspection of in-scope "
            "endpoints: security headers, CORS evidence, advertised "
            "methods (OPTIONS = metadata only), OpenAPI metadata — "
            "bounded GET/OPTIONS to the approved host only. "
            "Observations are data, never exploit claims. "
            "RECON_ACTIVE only."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=API_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=120,
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy openapi_probe entry
        evidence_kind="json_report",
    )


def production_registry():
    """The shipped Mode B adapter registry for api-probe: EXPLICITLY
    contains this one vetted production adapter and nothing else."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_api_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class APIProbeRun(BaseModel):
    """The parsed api_probe.py payload — one run against one approved
    base URL. Honest fields only; every header value is bounded data
    from the server."""

    model_config = ConfigDict(frozen=True)

    url: str = Field(min_length=1, max_length=500)
    status: str = Field(default="", max_length=20)
    requests_sent: int = Field(default=0, ge=0, le=7)
    base_status: int = Field(default=0, ge=0, le=599)
    security_headers: dict[str, str] = Field(default_factory=dict)
    cors_probe: dict = Field(default_factory=dict)
    options: dict = Field(default_factory=dict)
    docs: dict = Field(default_factory=dict)
    limitations: tuple[str, ...] = Field(default=(), max_length=10)
    errors: tuple[str, ...] = Field(default=(), max_length=10)
    started_at: str = Field(default="", max_length=32)

    def summary_properties(self, *, request_id: str) -> dict:
        """The run-summary ``api_observation`` node properties."""
        present = {k: v for k, v in self.security_headers.items()
                   if k in SECURITY_HEADERS}
        missing = [h for h in SECURITY_HEADERS
                   if h not in present and h not in (
                       "server", "x-powered-by")]
        return {
            "classification": "tool_reported_observation",
            "status": self.status,
            "requests_sent": self.requests_sent,
            "base_status": self.base_status,
            "security_headers": present,
            "missing_security_headers": missing,
            "cors_probe": self.cors_probe,
            "options": self.options,
            "docs": self.docs,
            "limitations": list(self.limitations),
            "started_at": self.started_at,
            "source": "api_probe",
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }

    def weak_candidates(self) -> "list[dict]":
        """The script's own tool-flagged baseline weaknesses, as
        bounded candidate descriptors. Severity is CAPPED at ``low``:
        header/CORS facts are baseline observations, never claims —
        nothing here can read as a high/critical finding."""
        candidates: list[dict] = []
        if self.base_status in range(200, 400):
            for header in ("strict-transport-security",
                           "content-security-policy",
                           "x-frame-options",
                           "x-content-type-options",
                           "referrer-policy",
                           "permissions-policy"):
                if header not in self.security_headers:
                    candidates.append({
                        "id": f"missing-{header}",
                        "severity_as_reported": "low",
                        "finding": (f"response did not carry the "
                                    f"{header} header"),
                    })
        cors = self.cors_probe or {}
        if cors.get("origin_reflected") and \
                cors.get("access_control_allow_credentials", "").lower() \
                in ("true", "1"):
            candidates.append({
                "id": "cors-reflected-with-credentials",
                "severity_as_reported": "low",
                "finding": ("server reflected the probe test origin in "
                            "Access-Control-Allow-Origin with "
                            "Access-Control-Allow-Credentials true — "
                            "header evidence only, not a demonstrated "
                            "exposure"),
            })
        return candidates


def parse_api_probe_payload(
    stdout: str,
) -> "tuple[APIProbeRun | None, int]":
    """Parse the script's ONE JSON payload defensively.

    Returns ``(run, malformed_lines)``. ``run`` is None when the
    output carries no parseable payload — chatter, usage text and
    half-written tails are all malformed, never interpreted. A
    payload missing the kind marker or its URL is malformed too.
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
                or raw.get("kind") != "kryonsec_api_probe":
            malformed += 1
            continue
        url = raw.get("url")
        if not isinstance(url, str) or not url.strip():
            malformed += 1
            continue
        base = raw.get("base") if isinstance(raw.get("base"), dict) \
            else {}
        try:
            requests_sent = int(raw.get("requests_sent") or 0)
        except (TypeError, ValueError):
            malformed += 1
            continue
        if not 0 <= requests_sent <= 7:
            malformed += 1
            continue
        try:
            run = APIProbeRun(
                url=url.strip()[:500],
                status=str(raw.get("status") or "")[:20],
                requests_sent=requests_sent,
                base_status=int(base.get("status") or 0),
                security_headers={
                    str(k)[:200]: str(v)[:200]
                    for k, v in (base.get("security_headers") or {}).items()
                    if isinstance(k, str)
                },
                cors_probe=raw.get("cors_probe")
                if isinstance(raw.get("cors_probe"), dict) else {},
                options=raw.get("options")
                if isinstance(raw.get("options"), dict) else {},
                docs=raw.get("docs")
                if isinstance(raw.get("docs"), dict) else {},
                limitations=tuple(
                    str(x)[:300] for x in
                    (raw.get("limitations") or ())[:10]),
                errors=tuple(
                    str(x)[:300] for x in (raw.get("errors") or ())[:10]),
                started_at=str(raw.get("started_at") or "")[:32],
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


def record_api_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    run: "APIProbeRun | None",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one api-probe adapter run onto the evidence graph.

    One ``api_observation`` node per run (label = the probed URL —
    first observation of that label wins, matching the graph's
    idempotence rule). OpenAPI-declared paths become ``path`` nodes
    (the SAME node type the legacy openapi_probe path produces; a
    path the graph already carries is NOT re-added). Tool-flagged
    baseline weaknesses become ``vuln_candidate`` nodes with
    classification ``detected_candidate`` and verification
    HARD-WIRED ``not_verified``; dedupe key is the label (``id @
    url``), first observation wins. Refusal to link is AUDITED, never
    silent and never fatal.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no evidence: a refusal must never leave
        # fabricated observations behind
        audit.write({
            "event": "api_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
        })
        return []
    if run is None:
        audit.write({
            "event": "api_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "output carried no parseable api probe payload",
            "malformed_lines": malformed_lines,
        })
        return []
    existing = [n for n in graph.by_type("api_observation")
                if n.get("label") == run.url]
    summary_node = None
    if not existing:
        try:
            summary_node = graph.add_node(
                node_type="api_observation",
                label=run.url,
                properties=run.summary_properties(
                    request_id=run_record.request_id),
                provenance={
                    "agent": "ADAPTER",
                    "source_type": "tool",
                    "tool": "api_probe",
                    "adapter": ADAPTER_ID,
                },
            )
            created.append(summary_node["id"])
        except Exception as e:  # graph validation: audited, not fatal
            audit.write({
                "event": "api_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"api_observation node refused: {e}"[:200],
                "url": run.url[:300],
            })
    if summary_node is not None:
        link(
            graph, "produced", attempt["id"], summary_node["id"],
            provenance={
                "agent": "ADAPTER", "source_type": "tool",
                "adapter": ADAPTER_ID,
            },
            on_refuse=lambda reason: audit.write({
                "event": "api_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": str(reason)[:200],
            }),
        )

    # OpenAPI-declared paths: metadata-only nodes, deduped against the
    # paths the graph already carries (katana/openapi_probe/feroxbuster
    # may have found the same ones — a path is a path)
    docs = run.docs or {}
    for found in docs.get("found") or []:
        if not isinstance(found, dict) or found.get("status") != 200:
            continue
        for ep in (found.get("endpoints") or [])[:50]:
            op_path = str(ep).split(" ", 1)[-1] if " " in str(ep) \
                else str(ep)
            label = op_path[:300]
            existing = [n for n in graph.by_type("path")
                        if n.get("label") == label]
            if existing:
                continue
            try:
                node = graph.add_node(
                    node_type="path",
                    label=label,
                    properties={
                        "source": "api_probe",
                        "doc_path": found.get("path", ""),
                        "spec_version": str(found.get("spec_version")
                                            or "")[:40],
                        "methods": str(ep).split(" ", 1)[0]
                        if " " in str(ep) else "",
                        "verification": "not_verified",
                    },
                    provenance={
                        "agent": "ADAPTER",
                        "source_type": "tool",
                        "tool": "api_probe",
                        "adapter": ADAPTER_ID,
                    },
                )
            except Exception as e:
                audit.write({
                    "event": "api_adapter_evidence_refused",
                    "request_id": run_record.request_id,
                    "reason": f"path node refused: {e}"[:200],
                    "label": label,
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
                    "event": "api_adapter_evidence_refused",
                    "request_id": run_record.request_id,
                    "node_id": _nid,
                    "reason": str(reason)[:200],
                }),
            )

    # tool-flagged baseline weaknesses: pre-confirmation candidates
    for candidate in run.weak_candidates()[:MAX_CANDIDATES]:
        label = (f"api-probe {candidate['id']} @ {run.url}")[:300]
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
                    "finding_id": candidate["id"],
                    "severity_as_reported":
                        candidate["severity_as_reported"],
                    "finding": candidate["finding"],
                    "url": run.url,
                    "tool": "api_probe",
                    "adapter": ADAPTER_ID,
                    "request_id": run_record.request_id,
                    "untrusted": True,
                    "verification": "not_verified",
                },
                provenance={
                    "agent": "ADAPTER",
                    "source_type": "tool",
                    "tool": "api_probe",
                    "adapter": ADAPTER_ID,
                },
            )
        except Exception as e:
            audit.write({
                "event": "api_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"vuln_candidate node refused: {e}"[:200],
                "label": label,
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
                "event": "api_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "api_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": "api_probe",
        "request_id": run_record.request_id,
        "status": run.status,
        "requests_sent": run.requests_sent,
        "docs_found": len((run.docs or {}).get("found") or []),
        "weak_candidates": len(run.weak_candidates()),
        "malformed_lines": malformed_lines,
        "nodes_created": len(created),
    })
    return created
