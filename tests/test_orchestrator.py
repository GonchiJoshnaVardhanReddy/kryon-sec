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


def test_factory_crash_does_not_escape_run():
    """A raising subagent FACTORY must not kill the loop.

    Only the returned callable used to be wrapped in try/except, but
    runner.loader() does real work before returning (lazy imports,
    sandbox.copy_with, evidence mkdir). A raise there escaped run() entirely:
    no HALT, no halt_reason, no report — the CLI got a bare traceback.
    """
    def loader(state):
        if state == "RECON_ACTIVE":
            raise RuntimeError("factory blew up")
        return lambda: SubagentResult(approved_count=1)

    orch = PurpleOrchestrator(engagement_id="e-factory", subagent_loader=loader)
    completed = orch.run()

    assert orch.state == HALT          # reaches the terminal state
    assert "RECON_ACTIVE" in completed  # the gap is recorded, not fatal
    assert "REPORT" in completed


def test_subagent_crash_does_not_escape_run():
    """The callable path was already guarded — keep it that way."""
    def loader(state):
        def boom():
            raise RuntimeError("subagent blew up")
        return boom

    orch = PurpleOrchestrator(engagement_id="e-crash", subagent_loader=loader)
    completed = orch.run()
    assert orch.state == HALT
    assert "REPORT" in completed
