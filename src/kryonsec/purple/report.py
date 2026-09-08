"""REPORT subagent (spec v2.1.1 §4.9).

Renders the engagement report with Jinja2, runs post-validation checks
(every finding/hypothesis appears, no duplicates), redacts secret-looking
strings, and writes report.md into the engagement directory.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import KryonsecConfig
from .audit import AuditLog
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

# §4.9: credential/secret pattern redaction before the report is written.
# Left boundary (?<![A-Za-z0-9_-]) so ordinary hyphenated prose words
# ("risk-assessment-methodology") are never eaten by the sk- pattern.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?<![A-Za-z0-9_-])(?:sk-proj-|sk-)[A-Za-z0-9_-]{20,}"),  # API keys
    re.compile(r"(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*\S+",),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),  # JWTs
]


def redact_secrets(text: str) -> str:
    """Replace secret-looking strings with a placeholder (§4.9)."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


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

    return template.render(
        engagement_id=engagement_id,
        target=target_nodes[0]["label"] if target_nodes else "(none)",
        subdomains=sorted(n["label"] for n in graph.by_type("subdomain")),
        paths=sorted(n["label"] for n in graph.by_type("path"))[:50],
        hypotheses=[
            # .get("approved", False): HUMAN_REVIEW crashing leaves the key
            # unset — a StrictUndefined template must never crash REPORT
            # (the report is the engagement's only deliverable)
            {"id": n["label"], **n["properties"],
             "approved": bool(n["properties"].get("approved")),
             "tested": n["label"] in tested_ids,
             "confirmed": n["label"] in confirmed_ids,
             "verified": n["label"] in verified_ids}
            for n in graph.by_type("hypothesis")
        ],
        attempts=attempts,
        remediations=[
            {"hypothesis_id": n["label"], **n["properties"]}
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
