"""HUMAN_REVIEW subagent (spec v2.1.1 §4.4 Gate 2).

Blocking approval of hypotheses before EXPLOIT. Every decision is audited
and only approved hypotheses survive — the transition to EXPLOIT happens
only when approved_count > 0 (deterministic, in the orchestrator).

The reviewer is injectable so tests (and a future --yes flag) can drive
it without a terminal.
"""

from __future__ import annotations

import logging
import sys
from typing import Callable

from .audit import AuditLog
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)


def _approval_panel(index: int, total: int, hypothesis: dict):
    """One hypothesis, as a decision — not as a log line.

    The operator is being asked to authorise active testing, so this shows
    what is being tested, how confident the system is, and why, before the
    prompt. Keys are A/R only: see terminal_reviewer.
    """
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    p = hypothesis.get("properties", {})
    confidence = p.get("confidence")
    try:
        confidence_text = f"{float(confidence) * 100:.0f}%"
    except (TypeError, ValueError):
        confidence_text = "—"

    facts = Table.grid(padding=(0, 2))
    facts.add_column(style="dim", justify="right")
    facts.add_column()
    facts.add_row("Confidence", confidence_text)
    facts.add_row("Target", str(p.get("target_asset", "") or "—"))
    if p.get("cvss_vector"):
        facts.add_row("CVSS", str(p["cvss_vector"]))
    tools = ", ".join(p.get("tools", []) or []) or "none"
    facts.add_row("Tools", tools)
    rationale = str(p.get("rationale", "") or "").strip()
    if rationale:
        facts.add_row("Evidence", rationale)

    body = Group(
        Text(str(p.get("title", hypothesis.get("label", ""))), style="bold"),
        Text(""),
        facts,
        Text(""),
        Text("[A] Approve        [R] Reject", style="bold"),
    )
    return Panel(
        body,
        title=f"[bold magenta]{hypothesis.get('label', '?')}[/bold magenta]"
              f" [dim]— hypothesis {index} of {total}[/dim]",
        border_style="magenta", expand=False,
    )


def terminal_reviewer(hypotheses: list[dict]) -> set[str]:
    """Interactive terminal reviewer: show each hypothesis, ask A/R.

    Returns the set of approved hypothesis ids. Non-TTY stdin (tests,
    piped input) approves NOTHING — silence is never consent.

    Only two keys, because the engine has only two outcomes: the
    orchestrator routes on ``approved_count > 0`` alone, so a third
    disposition ("skip") would either be a lie or require changing that
    transition. It is not offered.
    """
    approved: set[str] = set()

    if not hypotheses:
        print("\n=== HUMAN_REVIEW — approve each hypothesis before exploit ===")
        print("No hypotheses to review.")
        return approved

    if not sys.stdin.isatty():
        log.warning(
            "HUMAN_REVIEW: stdin is not a terminal — approving nothing "
            "(silence is never consent)"
        )
        return approved

    total = len(hypotheses)
    for i, h in enumerate(hypotheses, start=1):
        _render_hypothesis(i, total, h)
        try:
            answer = input("    approve? [A/R] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer in ("a", "approve", "y", "yes"):
            approved.add(h["label"])
            print("    -> approved")
        else:
            print("    -> rejected")

    return approved


def _render_hypothesis(index: int, total: int, hypothesis: dict) -> None:
    """Print the approval panel, falling back to plain text.

    The reviewer may be driven from somewhere we do not own a console for,
    so a rendering failure must not take the gate down with it — an
    approval prompt that crashes is a gate failing open in the worst place.
    """
    try:
        from rich.console import Console

        Console().print(_approval_panel(index, total, hypothesis))
        return
    except Exception:  # pragma: no cover - terminal we cannot drive
        pass

    p = hypothesis.get("properties", {})
    print(f"\n  {hypothesis.get('label', '?')}: {p.get('title', '')}")
    print(f"    target:  {p.get('target_asset', '')}")
    print(f"    CVSS:    {p.get('cvss_vector', '') or '(not estimated)'}")
    print(f"    tools:   {', '.join(p.get('tools', []) or []) or 'none'}")
    print(f"    why:     {p.get('rationale', '')}")


class HumanReviewSubagent:
    """Runs the HUMAN_REVIEW state: ask the operator, audit, filter."""

    def __init__(
        self,
        graph: EngagementGraph,
        audit: AuditLog,
        reviewer: Callable[[list[dict]], set[str]] | None = None,
    ):
        self.graph = graph
        self.audit = audit
        # injectable: takes hypothesis nodes, returns approved ids
        self.reviewer = reviewer or terminal_reviewer

    def run(self) -> SubagentResult:
        hypotheses = self.graph.by_type("hypothesis")
        self.audit.write({
            "event": "state_enter",
            "state": "HUMAN_REVIEW",
            "hypotheses": len(hypotheses),
        })

        try:
            approved_ids = self.reviewer(hypotheses)
        except Exception as e:
            # A crash in the reviewer must fail the state, not halt it —
            # and never count as approval.
            self.audit.write({
                "event": "human_review_failed",
                "error": str(e)[:200],
            })
            log.warning("HUMAN_REVIEW reviewer crashed: %s", e)
            return SubagentResult(status="failed", approved_count=0)

        for h in hypotheses:
            approved = h["label"] in approved_ids
            self.audit.write({
                "event": "hypothesis_reviewed",
                "hypothesis_id": h["label"],
                "approved": approved,
            })
            h["properties"]["approved"] = approved

        approved_count = sum(1 for h in hypotheses if h["label"] in approved_ids)
        self.audit.write({
            "event": "human_review_done",
            "approved": approved_count,
            "rejected": len(hypotheses) - approved_count,
        })

        # Zero approved => the orchestrator routes to BLUE_TEAM (no EXPLOIT)
        return SubagentResult(status="ok", approved_count=approved_count)
