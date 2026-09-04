"""Purple Team orchestrator (spec v2.1.1 §4.3).

Plain Python, no LLM involvement in state transitions.
10-state loop + terminal HALT. Deterministic transition table with the
v2.1.1 fix: HUMAN_REVIEW rejection routes through BLUE_TEAM, not REPORT.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

log = logging.getLogger(__name__)

STATES = [
    "INIT", "RECON_PASSIVE", "RECON_ACTIVE", "HYPOTHESIZE",
    "HUMAN_REVIEW", "EXPLOIT", "POST_EXPLOIT", "VERIFY",
    "BLUE_TEAM", "REPORT",  # 10 loop states...
]
HALT = "HALT"  # ...plus the terminal (absorbing) state


@dataclass
class SubagentResult:
    status: str = "ok"  # ok | failed | halted
    approved_count: int = 0
    shell_obtained: bool = False
    post_exploit_approved: bool = False
    halt_reason: str | None = None


@dataclass
class BudgetTracker:
    max_tokens: int = 100_000
    max_time_s: int = 3600
    max_cost_usd: float = 5.0
    used_tokens: int = 0
    used_cost_usd: float = 0.0
    elapsed_s: float = 0.0

    def exhausted(self) -> bool:
        return (
            self.used_tokens >= self.max_tokens
            or self.elapsed_s >= self.max_time_s
            or self.used_cost_usd >= self.max_cost_usd
        )


def next_state(state: str, result: SubagentResult) -> str:
    """Deterministic transitions (spec §4.3). The LLM never decides."""
    if state == HALT:
        return HALT
    if result.status == "halted":
        return HALT

    transitions: dict[str, str] = {
        "INIT": "RECON_PASSIVE",
        "RECON_PASSIVE": "RECON_ACTIVE",
        "RECON_ACTIVE": "HYPOTHESIZE",
        "HYPOTHESIZE": "HUMAN_REVIEW",
        # v2.1.1 fix: rejection still produces defensive recommendations —
        # never jump straight to REPORT.
        "HUMAN_REVIEW": "EXPLOIT" if result.approved_count > 0 else "BLUE_TEAM",
        "EXPLOIT": (
            "POST_EXPLOIT"
            if (result.shell_obtained and result.post_exploit_approved)
            else "VERIFY"
        ),
        "POST_EXPLOIT": "VERIFY",
        "VERIFY": "BLUE_TEAM",
        "BLUE_TEAM": "REPORT",
        "REPORT": HALT,
    }
    return transitions.get(state, HALT)


@dataclass
class PurpleOrchestrator:
    engagement_id: str
    budget: BudgetTracker = field(default_factory=BudgetTracker)
    state: str = "INIT"
    completed: list[str] = field(default_factory=list)
    # subagent loader: state name -> callable(SubagentResult)
    subagent_loader: Callable[[str], Callable[[], SubagentResult]] | None = None
    halt_reason: str | None = None
    # Set by the runtime guard: refuses to leave INIT off-Linux/off-Profile-2.
    execution_allowed: bool = True
    # Progress callback: called with the state name right before it runs.
    # Lets the CLI show which agent is working without knowing the loop.
    on_state: Callable[[str], None] | None = None

    def run(self) -> list[str]:
        """Run the loop to HALT. Returns the list of completed states."""
        while self.state != HALT:
            if not self.execution_allowed:
                self.halt_reason = "purple_team_requires_profile2 (Linux + Docker + gVisor)"
                self.state = HALT
                break
            if self.budget.exhausted():
                self.halt_reason = "budget_exhausted"
                self.state = HALT
                break

            self.completed.append(self.state)
            if self.on_state:
                try:
                    self.on_state(self.state)
                except Exception:
                    log.exception("progress callback error (ignored)")
            loader = self.subagent_loader(self.state) if self.subagent_loader else None
            if loader is None:
                # No subagent wired yet — record the gap and continue
                # deterministically so the state machine itself stays testable.
                log.warning("no subagent for state %s; using failed result", self.state)
                result = SubagentResult(status="failed")
            else:
                try:
                    result = loader()
                except Exception as e:  # subagent crash must not break determinism
                    log.exception("subagent crash in %s", self.state)
                    result = SubagentResult(status="failed")

            if result.status == "halted" and result.halt_reason:
                self.halt_reason = result.halt_reason

            self.state = next_state(self.state, result)

        return self.completed
