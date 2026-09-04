"""Purple Team mode (Mode B): deterministic state machine, audit chain,
tool allowlist. Execution is gated on Profile 2 (Linux + Docker + gVisor)."""

from .allowlist import AllowlistViolation, ToolAllowlist
from .audit import AuditLog, canonical_json
from .orchestrator import HALT, STATES, BudgetTracker, PurpleOrchestrator, SubagentResult, next_state

__all__ = [
    "HALT",
    "STATES",
    "AllowlistViolation",
    "ToolAllowlist",
    "AuditLog",
    "canonical_json",
    "BudgetTracker",
    "PurpleOrchestrator",
    "SubagentResult",
    "next_state",
]
