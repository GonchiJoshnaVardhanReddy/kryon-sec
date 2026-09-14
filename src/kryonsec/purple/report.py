"""REPORT subagent (spec v2.1.1 §4.9).

Renders the engagement report with Jinja2, runs post-validation checks
(every finding/hypothesis appears, no duplicates), redacts secret-looking
strings, and writes report.md into the engagement directory.

Phase 6 additions: evidence normalizer (ANSI/whitespace/truncation),
hypothesis dedup, a pure-Python CVSS 3.1 base-score calculator, and the
enrichment/mapping sections in the rendered report.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..config import KryonsecConfig
from .audit import AuditLog
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)


# ---- evidence normalizer (tool expansion Phase 6) --------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def normalize_evidence(text: str, max_chars: int = 200) -> str:
    """Uniform evidence excerpt for the report: ANSI color codes stripped,
    whitespace collapsed, one truncation length. The raw tool output stays
    in the audit chain — this is only the report's view of it."""
    if not text:
        return ""
    cleaned = _ANSI_RE.sub("", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars].rstrip() + "…"
    return cleaned


# ---- CVSS 3.1 base score (tool expansion Phase 6) --------------------------
# Pure math from the CVSS v3.1 Specification, no new dependency. The vector
# comes from the HYPOTHESIZE LLM — an unparseable vector returns None, never
# a guessed score presented as a calculated one.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_SAME = {"N": 0.85, "L": 0.62, "H": 0.27}       # Scope Unchanged
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}     # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A rounding — round up to 1 decimal, with the
    intermediate value handled at 5-decimal precision (the official
    Roundup algorithm, ported)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10


def cvss_base_score(vector: str) -> float | None:
    """CVSS 3.1 base score from a vector string, e.g.
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (with or without the
    "CVSS:3.1/" prefix). None when the vector is missing or malformed."""
    if not vector:
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metrics[key.strip().upper()] = val.strip().upper()
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(m not in metrics for m in required):
        return None
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_CHANGED if metrics["S"] == "C" else _PR_SAME)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return None  # unknown metric value — not a score we computed

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if metrics["S"] == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def cvss_severity(score: float | None) -> str:
    """Qualitative severity bucket for a base score (CVSS 3.1 §5)."""
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# ---- hypothesis dedup (tool expansion Phase 6) ------------------------------

def dedup_hypotheses(graph: EngagementGraph, audit: AuditLog) -> int:
    """Merge hypotheses that propose the same (tool set, target asset) —
    the LLM regularly re-suggests the same test twice. The first
    occurrence becomes canonical; duplicates are removed from the STM
    (the audit chain keeps the full history) and every node that points
    at a merged id (remediation, finding, verify_attempt,
    exploit_attempt "H2:tool" labels) is remapped to the canonical one so
    the report joins stay correct. Returns the number merged."""
    canonical: dict[tuple, dict] = {}
    aliases: dict[str, str] = {}

    for node in list(graph.by_type("hypothesis")):
        props = node.get("properties", {})
        key = (
            tuple(sorted(str(t) for t in props.get("tools") or [])),
            str(props.get("target_asset", "")),
        )
        first = canonical.get(key)
        if first is None:
            canonical[key] = node
            continue
        # keep the strongest of each field — never lose evidence
        fprops = first["properties"]
        if (props.get("confidence") or 0) > (fprops.get("confidence") or 0):
            fprops["confidence"] = props["confidence"]
        if not fprops.get("cve") and props.get("cve"):
            fprops["cve"] = props["cve"]
        if (props.get("cvss_vector") or "") and not fprops.get("cvss_vector"):
            fprops["cvss_vector"] = props["cvss_vector"]
        if "enrichment" in props and "enrichment" not in fprops:
            fprops["enrichment"] = props["enrichment"]
        fprops.setdefault("merged_from", []).append(node["label"])
        aliases[node["label"]] = first["label"]
        graph.remove_node(node)

    if not aliases:
        return 0

    for node in graph.nodes:
        ntype, label = node["node_type"], node["label"]
        if ntype in ("remediation", "finding", "verify_attempt"):
            if label in aliases:
                node["label"] = aliases[label]
        elif ntype == "exploit_attempt" and ":" in label:
            hyp_id, rest = label.split(":", 1)
            if hyp_id in aliases:
                node["label"] = f"{aliases[hyp_id]}:{rest}"

    audit.write({
        "event": "hypotheses_merged",
        "merged": len(aliases),
        "aliases": aliases,
    })
    return len(aliases)


def _normalize_enrichment(e: dict) -> dict:
    """Fixed-shape enrichment view for the template — StrictUndefined must
    never trip on a key a failed lookup did not fill."""
    return {
        "cve": e.get("cve", ""),
        "cvss_score": e.get("cvss_score"),  # from NVD; None = unknown
        "severity": e.get("severity", ""),
        "kev": e.get("kev"),  # True/False/None (unknown — lookup failed)
        "epss": e.get("epss"),
        "epss_percentile": e.get("epss_percentile"),
        "cpes": e.get("cpes") or [],
        "cwes": e.get("cwes") or [],  # Phase 8: from the NVD record
        "exploits": e.get("exploits") or [],
        "exploit_available": bool(e.get("exploit_available")),
        # Phase 8 lookups (each empty when the fetch failed or found nothing)
        "osv_aliases": e.get("osv_aliases") or [],
        "osv_severity": e.get("osv_severity", ""),
        "affected_packages": e.get("affected_packages") or [],
        "ghsa_id": e.get("ghsa_id", ""),
        "ghsa_severity": e.get("ghsa_severity", ""),
        "patched_versions": e.get("patched_versions") or [],
        "nuclei_templates": e.get("nuclei_templates") or [],
    }


def redact_secrets(text: str) -> str:
    """Replace secret-looking strings with placeholders (§4.9).

    Delegates to the shared detector (secrets.py) so the pattern list can
    never drift from the one the LLM gates use — the report is the
    artifact most likely to be shared, and a private copy here was
    already missing AWS keys, GitHub tokens and connection strings that
    detect_secrets catches. Passwords/keys keep their label; only the
    value is replaced («SECRET_n»)."""
    from ..secrets import redact

    return redact(text)[0]


def build_timeline(audit: AuditLog) -> list[dict]:
    """Phase 8: engagement timeline from the audit chain — one row per
    milestone event (engagement_created, state_enter, report_written),
    (timestamp, event, detail). The chain's hash order (not the wall
    clock) remains the ordering guarantee; ts is presentation only."""
    milestones = []
    try:
        with open(audit.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue  # verify() reports corruption; render anyway
                event = entry.get("event", "")
                ts = str(entry.get("ts", ""))
                if event in ("engagement_created", "state_enter",
                             "report_written"):
                    detail = (entry.get("state") or entry.get("target")
                              or entry.get("engagement_id") or "")
                    milestones.append(
                        {"ts": ts, "event": event, "detail": detail})
    except OSError:
        return []
    return milestones[:100]  # bounded


def render_report(
    graph: EngagementGraph,
    audit: AuditLog,
    engagement_id: str,
    completed_states: list[str] | None = None,
    halt_reason: str | None = None,
) -> str:
    """Render the report markdown from the engagement graph."""
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        autoescape=False,
    )
    template = env.get_template("report.jinja")

    target_nodes = graph.by_type("target")
    import datetime as _dt

    # map hypothesis -> its tool-run outcome (exploit_attempt nodes are
    # labeled "H1:sqlmap"); only real Zone B execution creates them
    attempts = graph.by_type("exploit_attempt")
    tested_ids = {a["label"].split(":")[0] for a in attempts}
    confirmed_ids = {
        a["label"].split(":")[0] for a in attempts
        if a["properties"].get("confirmed")
    }
    # a finding is "verified" when VERIFY's independent probe agreed
    verified_ids = {
        n["label"] for n in graph.by_type("verify_attempt")
        if n["properties"].get("verified")
    }

    # Phase 6: enrichment + numeric CVSS score + normalized evidence per
    # hypothesis; the template renders them as the "Known risk data" rows
    hypotheses = []
    for n in graph.by_type("hypothesis"):
        props = dict(n["properties"])
        score = cvss_base_score(props.get("cvss_vector", ""))
        if score is None:
            # NVD's own score (vector missing/unparseable) — still labeled
            # as data we looked up, not something we computed
            score = (props.get("enrichment") or {}).get("cvss_score")
        hypotheses.append({
            "id": n["label"],
            **props,
            "approved": bool(props.get("approved")),
            "tested": n["label"] in tested_ids,
            "confirmed": n["label"] in confirmed_ids,
            "verified": n["label"] in verified_ids,
            "cvss_score": score,
            "cvss_qual": cvss_severity(score),
            "enrichment": _normalize_enrichment(
                (props.get("enrichment") or {})),
        })

    # Phase 6: uniform evidence excerpts (ANSI/whitespace/length) on the
    # repeatable-steps section — raw output stays in the audit chain
    norm_attempts = []
    for a in attempts:
        norm_attempts.append({
            "label": a["label"],
            "properties": {
                **a["properties"],
                "output_excerpt": normalize_evidence(
                    a["properties"].get("output_excerpt", "")),
                "argv": a["properties"].get("argv", []),
            },
        })

    # Phase 8: scanner evidence rows + an SBOM summary when syft ran
    scanners = [
        {
            "label": n["label"],
            "exit_code": n["properties"].get("exit_code", "?"),
            "findings_count": n["properties"].get("findings_count"),
            "excerpt": normalize_evidence(
                n["properties"].get("excerpt", ""), max_chars=300),
        }
        for n in graph.by_type("scanner_result")
    ]
    sbom_summary = ""
    syft_nodes = [n for n in graph.by_type("scanner_result")
                  if n["label"] == "syft"]
    if syft_nodes and syft_nodes[0]["properties"].get("packages_count"):
        sbom_summary = (
            f"SBOM: {syft_nodes[0]['properties']['packages_count']} "
            "packages identified (syft)")

    return template.render(
        engagement_id=engagement_id,
        target=target_nodes[0]["label"] if target_nodes else "(none)",
        subdomains=sorted(n["label"] for n in graph.by_type("subdomain")),
        paths=sorted(n["label"] for n in graph.by_type("path"))[:50],
        hypotheses=hypotheses,
        attempts=norm_attempts,
        scanners=scanners,
        sbom_summary=sbom_summary,
        timeline=build_timeline(audit),
        remediations=[
            # .get defaults: BLUE_TEAM nodes written before Phase 6 (and
            # test fixtures) lack cwe/owasp/attack/owasp_api — StrictUndefined
            # must never crash REPORT (the report is the only deliverable)
            {"hypothesis_id": n["label"], **n["properties"],
             "cwe": n["properties"].get("cwe", ""),
             "owasp": n["properties"].get("owasp", ""),
             "attack": n["properties"].get("attack", ""),
             "owasp_api": n["properties"].get("owasp_api", "")}
            for n in graph.by_type("remediation")
        ],
        # the report may only claim testing happened when tools really ran
        # (exploit_attempt nodes are only created by real Zone B execution)
        exploit_attempts=graph.by_type("exploit_attempt"),
        completed_states=completed_states or [],
        halt_reason=halt_reason or "",
        audit_head=audit.head_hash(),
        generated_at=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def validate_report(report: str, graph: EngagementGraph) -> list[str]:
    """§4.9 post-validation. Returns a list of problems (empty = clean)."""
    problems: list[str] = []

    # every hypothesis appears
    for h in graph.by_type("hypothesis"):
        if h["label"] not in report:
            problems.append(f"hypothesis {h['label']} missing from report")

    # every remediation's target hypothesis appears
    for r in graph.by_type("remediation"):
        if r["label"] not in report:
            problems.append(f"remediation for {r['label']} missing from report")

    # no duplicate remediation sections
    remediation_markers = report.count("### Fix for")
    if remediation_markers != len(graph.by_type("remediation")):
        problems.append(
            f"remediation count mismatch: {remediation_markers} sections, "
            f"{len(graph.by_type('remediation'))} nodes"
        )

    # Phase 6: every hypothesis that carries enrichment data must show it
    # (the CVE row) — a dropped enrichment row would hide public-risk
    # context from the reader
    for h in graph.by_type("hypothesis"):
        enrich = (h["properties"].get("enrichment") or {}).get("cve")
        if enrich and enrich not in report:
            problems.append(
                f"enrichment for {h['label']} ({enrich}) missing from report")

    # Phase 6: duplicate hypotheses (same tool set + target asset) must
    # have been merged — a dup would double-count risk in the report
    seen_keys: set[tuple] = set()
    for h in graph.by_type("hypothesis"):
        props = h["properties"]
        key = (tuple(sorted(str(t) for t in props.get("tools") or [])),
               str(props.get("target_asset", "")))
        if key in seen_keys:
            problems.append(
                f"duplicate hypothesis {h['label']} "
                f"(same tools/asset as an earlier one) was not merged")
        seen_keys.add(key)

    # Phase 6: normalized evidence must not carry ANSI codes or runs of
    # raw whitespace — the report is plain markdown
    if _ANSI_RE.search(report):
        problems.append("ANSI escape codes found in report output")

    return problems


class ReportSubagent:
    """Runs the REPORT state: render, validate, redact, write report.md."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        graph: EngagementGraph,
        audit: AuditLog,
        engagement_id: str,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        self.engagement_id = engagement_id

    def run(self) -> SubagentResult:
        self.audit.write({"event": "state_enter", "state": "REPORT"})

        # completed states / halt reason live on the orchestrator; the
        # runner passes them in via set_context before running.

        # Phase 6: merge duplicate hypotheses BEFORE rendering — after
        # this point the graph is the report's final word, and the merged
        # count lands on the audit chain
        try:
            dedup_hypotheses(self.graph, self.audit)
        except Exception as e:  # never block the deliverable on dedup
            self.audit.write({
                "event": "dedup_failed",
                "reason": str(e)[:200],
            })
            log.warning("hypothesis dedup failed: %s", e)

        # the report file itself first (it may fail — REPORT must never
        # crash, it is the engagement's only deliverable)
        report_path = self.cfg.home / "engagements" / self.engagement_id / "report.md"
        try:
            report = render_report(
                self.graph, self.audit, self.engagement_id,
                completed_states=getattr(self, "completed_states", None),
                halt_reason=getattr(self, "halt_reason", None),
            )

            problems = validate_report(report, self.graph)
            if problems:
                self.audit.write({
                    "event": "report_validation_failed",
                    "problems": problems,
                })
                # still write the report — but the audit records the gaps
                log.warning("report validation problems: %s", problems)

            report = redact_secrets(report)

            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report, encoding="utf-8")
        except Exception as e:  # render/validate/write all guarded — a
            # broken template must never leave the engagement report-less
            self.audit.write({
                "event": "report_failed",
                "reason": str(e)[:300],
            })
            log.warning("report render failed: %s", e)
            return SubagentResult(status="failed")

        # append report_written BEFORE reading head_hash, so the anchor
        # printed in the report matches the chain's FINAL head — a
        # verifier following the report's fingerprint instruction gets a
        # match on an untampered chain, and deleting the last line no
        # longer makes the truncated chain match the printed anchor
        self.audit.write({
            "event": "report_written",
            "path": str(report_path),
            "chars": len(report),
        })
        # patch the anchor to the now-final head hash (the fingerprint
        # line follows "The log's final fingerprint is:")
        final_head = self.audit.head_hash()
        if final_head and "The log's final fingerprint" in report:
            lines = report.splitlines()
            for i, line in enumerate(lines):
                if "The log's final fingerprint" in line:
                    # the hash sits on the next backtick-wrapped line
                    j = i + 1
                    while j < len(lines) and not lines[j].startswith("`"):
                        j += 1
                    if j < len(lines):
                        lines[j] = f"`{final_head}`"
                    break
            report = "\n".join(lines) + "\n"
            report_path.write_text(report, encoding="utf-8")
        return SubagentResult(status="ok")
