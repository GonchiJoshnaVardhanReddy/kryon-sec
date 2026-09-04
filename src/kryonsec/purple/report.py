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
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(sk-proj-|sk-)[A-Za-z0-9_-]{20,}"),           # API keys
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

    return template.render(
        engagement_id=engagement_id,
        target=target_nodes[0]["label"] if target_nodes else "(none)",
        subdomains=sorted(n["label"] for n in graph.by_type("subdomain")),
        paths=sorted(n["label"] for n in graph.by_type("path"))[:50],
        hypotheses=[
            {"id": n["label"], **n["properties"]}
            for n in graph.by_type("hypothesis")
        ],
        remediations=[
            {"hypothesis_id": n["label"], **n["properties"]}
            for n in graph.by_type("remediation")
        ],
        completed_states=completed_states or [],
        halt_reason=halt_reason or "",
        audit_head=audit.head_hash(),
        generated_at=_dt.datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
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
    remediation_markers = report.count("### Remediation for")
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

        report_path = self.cfg.home / "engagements" / self.engagement_id / "report.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")

        self.audit.write({
            "event": "report_written",
            "path": str(report_path),
            "chars": len(report),
        })
        return SubagentResult(status="ok")
