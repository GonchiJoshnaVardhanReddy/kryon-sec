"""Tests for the deterministic state machine (spec §4.3)."""

from kryonsec.purple.orchestrator import (
    HALT,
    BudgetTracker,
    PurpleOrchestrator,
    SubagentResult,
    next_state,
)


def test_happy_path_all_approved():
    r = SubagentResult(approved_count=3)
    assert next_state("HUMAN_REVIEW", r) == "EXPLOIT"


def test_rejection_routes_to_blue_team():
    # v2.1.1 fix: never HUMAN_REVIEW -> REPORT directly
    r = SubagentResult(approved_count=0)
    assert next_state("HUMAN_REVIEW", r) == "BLUE_TEAM"


def test_shell_without_approval_skips_post_exploit():
    r = SubagentResult(shell_obtained=True, post_exploit_approved=False)
    assert next_state("EXPLOIT", r) == "VERIFY"


def test_halt_is_absorbing():
    assert next_state(HALT, SubagentResult(approved_count=5)) == HALT


def test_full_loop_runs_to_halt():
    orch = PurpleOrchestrator(engagement_id="e1")
    # every subagent approves everything
    def loader(state):
        return lambda: SubagentResult(
            approved_count=1,
            shell_obtained=True,
            post_exploit_approved=True,
        )

    orch.subagent_loader = loader
    completed = orch.run()
    assert orch.state == HALT
    assert completed[0] == "INIT"
    assert "BLUE_TEAM" in completed and "REPORT" in completed


def test_budget_exhaustion_halts():
    orch = PurpleOrchestrator(
        engagement_id="e2",
        budget=BudgetTracker(max_tokens=0),
    )
    orch.run()
    assert orch.state == HALT
    assert orch.halt_reason == "budget_exhausted"


def test_profile_guard_blocks_execution():
    orch = PurpleOrchestrator(engagement_id="e3", execution_allowed=False)
    orch.run()
    assert orch.state == HALT
    assert "profile2" in orch.halt_reason
    assert orch.completed == []  # never left INIT
