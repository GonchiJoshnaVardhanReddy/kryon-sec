"""Purple Team engagement runner (spec v2.1.1 §4).

Profile-2 gated: refuses to run Purple Team anywhere except Linux with
Docker + gVisor available. The state machine and audit chain are fully
portable (testable anywhere); only tool execution needs the sandbox.
"""

from __future__ import annotations

import logging
import platform
from pathlib import Path

from ..config import KryonsecConfig
from ..purple.audit import AuditLog
from ..purple.orchestrator import PurpleOrchestrator, SubagentResult

log = logging.getLogger(__name__)


def profile2_available() -> tuple[bool, str]:
    """Check Purple Team prerequisites. Returns (ok, reason-if-not)."""
    if not platform.system() == "Linux":
        return False, f"Purple Team requires Linux (you are on {platform.system()}). Use WSL2 or a Linux VM."

    import shutil
    import subprocess

    if not shutil.which("docker"):
        return False, "docker CLI not found"

    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{join .Runtimes \",\"}}"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        return False, f"docker daemon unreachable: {e}"
    if out.returncode != 0:
        return False, "docker daemon not reachable"
    if "runsc" not in out.stdout:
        return False, "gVisor (runsc) runtime not registered with Docker"

    return True, "ok"


def start_engagement(cfg: KryonsecConfig, engagement_id: str) -> tuple[PurpleOrchestrator, AuditLog | None]:
    """Wire up an engagement. Returns (orchestrator, audit-log-or-None).

    On non-Profile-2 systems the orchestrator is created with
    execution_allowed=False, so running it deterministically HALTs at INIT.
    """
    ok, reason = profile2_available()
    audit: AuditLog | None = None

    if ok:
        audit_path = cfg.home / "engagements" / engagement_id / "audit.jsonl"
        audit = AuditLog(audit_path)
        audit.write({"event": "engagement_created", "engagement_id": engagement_id})
    else:
        log.warning("Profile 2 unavailable: %s", reason)

    orch = PurpleOrchestrator(
        engagement_id=engagement_id,
        execution_allowed=ok,
    )
    return orch, audit


def subagent_stub(state: str):
    """Placeholder subagent factory: every state reports 'not implemented'.

    Real subagents (RECON_PASSIVE Zone A modules, sandboxed Zone B tools,
    LLM HYPOTHESIZE/BLUE_TEAM, Jinja2 REPORT) replace these as they land.
    """

    def run() -> SubagentResult:
        log.info("subagent %s: stub (not implemented yet)", state)
        return SubagentResult(status="failed")

    return run
