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
    # Batch 4C: how much of ``used_*`` is an ESTIMATE rather than
    # provider-reported usage. The LLM call sites that count tokens
    # locally accrue here too, and their figures must be visible as
    # estimates — never presented as charges.
    estimated_tokens: int = 0
    estimated_cost_usd: float = 0.0
    # Batch 4C: headroom held for pending specialist work. A reservation
    # counts against NEW reservations (so overlapping work cannot
    # over-commit the ceiling) but NOT against the loop's exhausted()
    # guard — an estimate of work not yet done must never halt an
    # engagement that has spent nothing.
    reservations: dict[str, tuple[int, float]] = field(default_factory=dict)
    # Keys whose usage has already been committed, with the amounts. A
    # replayed commit of the same key is ignored — the first outcome
    # stands — so retries and checkpoint replay can never double-count.
    committed: dict[str, tuple[int, float]] = field(default_factory=dict)
    # wall-clock accounting start — set on first check, not on __init__,
    # so a tracker built long before run() still measures the run
    _started_at: float | None = None

    def exhausted(self) -> bool:
        import time

        if self._started_at is None:
            self._started_at = time.monotonic()
        self.elapsed_s = time.monotonic() - self._started_at
        return (
            self.used_tokens >= self.max_tokens
            or self.elapsed_s >= self.max_time_s
            or self.used_cost_usd >= self.max_cost_usd
        )

    @property
    def reserved_tokens(self) -> int:
        return sum(tokens for tokens, _cost in self.reservations.values())

    @property
    def reserved_cost_usd(self) -> float:
        return sum(cost for _tokens, cost in self.reservations.values())

    def record_usage(self, tokens: int, cost_usd: float = 0.0,
                     *, estimate: bool = True) -> None:
        """LLM call sites accrue their usage here (spec §4.3 budget guard).

        ``estimate`` marks HOW the numbers were obtained: the default is
        the honest one for every current caller (they count tokens
        locally), and a provider-usage call site passes ``estimate=False``
        so its figures are not labelled as estimates.
        """
        tokens = max(0, int(tokens))
        cost_usd = max(0.0, float(cost_usd))
        self.used_tokens += tokens
        self.used_cost_usd += cost_usd
        if estimate:
            self.estimated_tokens += tokens
            self.estimated_cost_usd += cost_usd

    # -- reservations (Batch 4C) ----------------------------------------------

    def reserve(self, key: str, tokens: int = 0, cost_usd: float = 0.0) -> bool:
        """Hold headroom for pending work named by ``key``.

        Refused (False, never raised) when the committed total — actual
        usage plus existing reservations plus this request — would pass a
        ceiling. Idempotent per key: re-reserving work that already holds
        headroom (or already committed) succeeds without double-counting.
        """
        if not isinstance(key, str) or not key:
            return False
        if key in self.reservations or key in self.committed:
            return True
        tokens = max(0, int(tokens))
        cost_usd = max(0.0, float(cost_usd))
        if self.used_tokens + self.reserved_tokens + tokens > self.max_tokens:
            return False
        if (
            self.used_cost_usd + self.reserved_cost_usd + cost_usd
            > self.max_cost_usd
        ):
            return False
        self.reservations[key] = (tokens, cost_usd)
        return True

    def release(self, key: str) -> None:
        """Give back a reservation that will not convert (deferral,
        cancellation, a claim lost to a race). Committed usage is never
        touched by a release — work already accounted stays accounted.
        """
        self.reservations.pop(key, None)

    def commit(self, key: str, tokens: int = 0, cost_usd: float = 0.0,
               *, estimate: bool = False) -> None:
        """Convert a reservation into actual usage.

        Idempotent per key: the FIRST commit of a key records its usage
        and every later commit of the same key is ignored, so a retried
        task or a replayed checkpoint cannot double-count. The
        reservation's full headroom is released regardless of how much of
        it the actual usage used.

        ``estimate`` marks how the numbers were obtained (the same rule
        as :meth:`record_usage`): estimated figures are also visible in
        the estimated counters, never presented as charges.
        """
        if not isinstance(key, str) or not key:
            return
        if key in self.committed:
            return
        tokens = max(0, int(tokens))
        cost_usd = max(0.0, float(cost_usd))
        self.committed[key] = (tokens, cost_usd)
        self.reservations.pop(key, None)
        self.used_tokens += tokens
        self.used_cost_usd += cost_usd
        if estimate:
            self.estimated_tokens += tokens
            self.estimated_cost_usd += cost_usd

    # -- persistence (Batch 4C: consumption survives a restart) ----------------

    def budget_snapshot(self) -> dict:
        """A JSON-safe copy of this tracker's consumption state."""
        return {
            "used_tokens": self.used_tokens,
            "used_cost_usd": self.used_cost_usd,
            "estimated_tokens": self.estimated_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
            "reservations": {
                key: [tokens, cost]
                for key, (tokens, cost) in self.reservations.items()
            },
            "committed": {
                key: [tokens, cost]
                for key, (tokens, cost) in self.committed.items()
            },
        }

    def restore_budget(self, data: dict) -> None:
        """Reinstate persisted consumption. Refuses (loudly) a malformed
        snapshot — a corrupt budget payload is a checkpoint problem, and
        starting from zero would be the silent reset this exists to
        prevent.
        """
        if not isinstance(data, dict):
            raise ValueError("budget snapshot must be an object")

        def _num(value: object, what: str, minimum: float = 0.0) -> float:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"budget snapshot {what} must be a number")
            if value < minimum:
                raise ValueError(f"budget snapshot {what} must be >= {minimum}")
            return float(value)

        used_tokens = int(_num(data.get("used_tokens", 0), "used_tokens"))
        used_cost = _num(data.get("used_cost_usd", 0), "used_cost_usd")
        estimated_tokens = int(
            _num(data.get("estimated_tokens", 0), "estimated_tokens"))
        estimated_cost = _num(
            data.get("estimated_cost_usd", 0), "estimated_cost_usd")

        def _pairs(raw: object, what: str) -> dict[str, tuple[int, float]]:
            if raw is None:
                return {}
            if not isinstance(raw, dict):
                raise ValueError(f"budget snapshot {what} must be an object")
            pairs: dict[str, tuple[int, float]] = {}
            for key, value in raw.items():
                if not isinstance(key, str) or not key:
                    raise ValueError(
                        f"budget snapshot {what} has an invalid key")
                if (not isinstance(value, (list, tuple))
                        or len(value) != 2
                        or isinstance(value[0], bool)
                        or isinstance(value[1], bool)
                        or not isinstance(value[0], (int, float))
                        or not isinstance(value[1], (int, float))):
                    raise ValueError(
                        f"budget snapshot {what}[{key!r}] is not an "
                        "[tokens, cost] pair")
                tokens, cost = value
                if tokens < 0 or cost < 0:
                    raise ValueError(
                        f"budget snapshot {what}[{key!r}] is negative")
                pairs[key] = (int(tokens), float(cost))
            return pairs

        self.reservations = _pairs(data.get("reservations"), "reservations")
        self.committed = _pairs(data.get("committed"), "committed")
        self.used_tokens = used_tokens
        self.used_cost_usd = used_cost
        self.estimated_tokens = estimated_tokens
        self.estimated_cost_usd = estimated_cost


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
    # Called with the state name once its subagent has returned and before
    # the transition. That is the one moment the graph is quiescent — the
    # state's work is finished and nothing is mid-write — which is what
    # makes it the boundary a durable checkpoint is consistent at
    # (Phase 4.3). Notified, never consulted: it cannot influence a
    # transition, and a listener that raises is logged and ignored.
    on_state_complete: Callable[[str], None] | None = None
    # The Batch-3 handoff coordinator, when one is wired (the runner sets
    # it; tests may leave it None). Never consulted by the loop — it is
    # carried so the CLI can persist the records at the end of the run,
    # exactly like the graph. Data exchange, never transition authority.
    handoff_coordinator: object | None = None
    # Batch 4A: the specialist scheduler, when one is wired. Same contract
    # as the coordinator above: carried so the runner can checkpoint it at
    # the state boundary and the CLI can persist it at the end — and so
    # the scheduler's boundary work can be driven from ``_notify``'s
    # listener side, never from the transition decision itself.
    specialist_scheduler: object | None = None
    # Operator stop input: a pure predicate read at the top of every state,
    # never mid-state. It can only end the loop *between* states, so a tool
    # that is already running is allowed to finish and its evidence is
    # recorded before HALT. The UI sets the flag; the loop owns the decision.
    should_stop: Callable[[], bool] | None = None
    # States whose subagent returned ``failed``. The loop keeps its
    # deterministic route (a failed state is not a halt), but the terminal
    # lifecycle word must not call such a run "completed".
    failed_states: list[str] = field(default_factory=list)

    def run(self) -> list[str]:
        """Run the loop to HALT. Returns the list of completed states."""
        while self.state != HALT:
            if not self.execution_allowed:
                self.halt_reason = "purple_team_requires_profile2 (Linux + Docker + gVisor)"
                self.state = HALT
                break
            if self.should_stop is not None:
                # Read between states, never inside one: the running tool
                # finishes, its result is audited, and the checkpoint at the
                # boundary is therefore consistent. A broken predicate must
                # not stop a run, so it is logged and treated as "no".
                try:
                    stop = bool(self.should_stop())
                except Exception:
                    log.exception("stop predicate error (ignored)")
                    stop = False
                if stop:
                    self.halt_reason = "operator_interrupt"
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
            try:
                loader = (
                    self.subagent_loader(self.state)
                    if self.subagent_loader else None
                )
            except Exception:
                # Building the subagent must not break determinism either:
                # the factory does real work (lazy imports, sandbox.copy_with,
                # evidence mkdir), and a raise here used to escape run()
                # entirely — no HALT, no halt_reason, no report.
                log.exception("subagent factory error in %s", self.state)
                loader = None

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
            if result.status == "failed":
                self.failed_states.append(self.state)

            # After the state's work, before the transition. self.state still
            # names the state that just ran, and the graph it produced is
            # complete, so a listener sees a consistent boundary.
            self._notify_state_complete()

            self.state = next_state(self.state, result)

        return self.completed

    def _notify_state_complete(self) -> None:
        """Tell a listener the state finished. Never raises.

        Same contract as the ``on_state`` call above, for the same reason:
        this runs inside the deterministic loop, so a listener must not be
        able to change where the engagement goes next — or whether it gets
        there at all.
        """
        if self.on_state_complete is None:
            return
        try:
            self.on_state_complete(self.state)
        except Exception:
            log.exception("state-complete callback error (ignored)")
