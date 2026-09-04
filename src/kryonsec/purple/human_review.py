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


def terminal_reviewer(hypotheses: list[dict]) -> set[str]:
    """Interactive terminal reviewer: show each hypothesis, ask y/n.

    Returns the set of approved hypothesis ids. Non-TTY stdin (tests,
    piped input) approves NOTHING — silence is never consent.
    """
    approved: set[str] = set()
    print("\n=== HUMAN_REVIEW — approve each hypothesis before exploit ===")

    if not hypotheses:
        print("No hypotheses to review.")
        return approved

    if not sys.stdin.isatty():
        log.warning(
            "HUMAN_REVIEW: stdin is not a terminal — approving nothing "
            "(silence is never consent)"
        )
        return approved

    for h in hypotheses:
        p = h["properties"]
        print(f"\n  {h['label']}: {p.get('title', '')}")
        print(f"    target:  {p.get('target_asset', '')}")
        print(f"    CVSS:    {p.get('cvss_vector', '') or '(not estimated)'}")
        print(f"    tools:   {', '.join(p.get('tools', [])) or 'none'}")
        print(f"    why:     {p.get('rationale', '')}")
        try:
            answer = input("    approve? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer in ("y", "yes"):
            approved.add(h["label"])
            print("    -> approved")
        else:
            print("    -> rejected")

    return approved


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
