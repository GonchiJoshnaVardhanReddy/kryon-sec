"""Purple Team engagement runner (spec v2.1.1 §4).

Two-tier gating:
- Zone A states (RECON_PASSIVE) run anywhere — they are third-party API
  calls only (zero packets to the target).
- Zone B states (RECON_ACTIVE onward) need the sandbox: Linux + Docker +
  gVisor. On other systems the engagement HALTs after RECON_PASSIVE with
  a clear reason instead of silently running un-sandboxed tools.
"""

from __future__ import annotations

import logging
import platform

from ..config import KryonsecConfig
from .audit import AuditLog
from .orchestrator import HALT, PurpleOrchestrator, SubagentResult

log = logging.getLogger(__name__)

# States that can run without the Kali sandbox (host-side, Zone A)
SANDBOX_FREE_STATES = {"INIT", "RECON_PASSIVE", "HYPOTHESIZE", "HUMAN_REVIEW"}


def _docker_runtimes() -> str | None:
    """Return Docker's registered runtime list, or None if unreachable."""
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return None
    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{join .Runtimes \",\"}}"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def _image_present(image: str) -> bool:
    """True if the pinned sandbox image exists locally (tag or digest)."""
    import subprocess

    try:
        out = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=10,
        )
        return out.returncode == 0
    except Exception:
        return False


def sandbox_available(image: str = "kryonsec/sandbox:latest") -> tuple[bool, str]:
    """Check Zone B prerequisites. Returns (ok, reason-if-not).

    Probes, in order: Linux platform, docker CLI + daemon, runsc runtime
    registered, and the pinned sandbox image present locally (spec §8.5/§8.6).
    """
    if platform.system() != "Linux":
        return False, (
            "Zone B (sandboxed tools) requires Linux — you are on "
            f"{platform.system()}. Use WSL2 or a Linux VM."
        )

    runtimes = _docker_runtimes()
    if runtimes is None:
        return False, "docker CLI not found or daemon unreachable"

    if "runsc" not in runtimes:
        return False, "gVisor (runsc) runtime not registered with Docker"

    if not _image_present(image):
        return False, f"sandbox image not found locally: {image}"

    return True, "ok"


def start_engagement(
    cfg: KryonsecConfig,
    engagement_id: str,
    target: str = "",
) -> tuple[PurpleOrchestrator, AuditLog, "object"]:
    """Wire up an engagement. Returns (orchestrator, audit, graph).

    The engagement starts on every OS. When the sandbox is unavailable,
    the orchestrator HALTs (with an audited reason) as soon as a state
    needs Zone B.
    """
    from .recon_passive import EngagementGraph, ReconPassiveSubagent

    audit_path = cfg.home / "engagements" / engagement_id / "audit.jsonl"
    audit = AuditLog(audit_path)
    audit.write({
        "event": "engagement_created",
        "engagement_id": engagement_id,
        "target": target,
    })
    graph = EngagementGraph(engagement_id=engagement_id)

    sandbox_ok, sandbox_reason = sandbox_available(cfg.sandbox_image)
    audit.write({
        "event": "sandbox_check",
        "available": sandbox_ok,
        "reason": sandbox_reason,
    })

    def loader(state: str):
        if state == "RECON_PASSIVE":
            sub = ReconPassiveSubagent(cfg=cfg, graph=graph, audit=audit, target=target)
            return sub.run

        if state == "HYPOTHESIZE":
            from .hypothesize import HypothesizeSubagent

            sub = HypothesizeSubagent(cfg=cfg, graph=graph, audit=audit)
            return sub.run

        if state in SANDBOX_FREE_STATES:
            return subagent_stub(state)

        # Zone B state without a sandbox: halt with a clear reason rather
        # than running un-sandboxed tools on the host.
        if not sandbox_ok:
            def blocked() -> SubagentResult:
                audit.write({
                    "event": "zone_b_blocked",
                    "state": state,
                    "reason": sandbox_reason,
                })
                log.warning("Zone B blocked in state %s: %s", state, sandbox_reason)
                return SubagentResult(status="halted", halt_reason=sandbox_reason)
            return blocked

        return subagent_stub(state)

    orch = PurpleOrchestrator(
        engagement_id=engagement_id,
        execution_allowed=True,
        subagent_loader=loader,
    )
    return orch, audit, graph


def subagent_stub(state: str):
    """Placeholder subagent factory: every state reports 'not implemented'.

    Real subagents (Zone A recon modules, sandboxed Zone B tools,
    LLM HYPOTHESIZE/BLUE_TEAM, Jinja2 REPORT) replace these as they land.
    """

    def run() -> SubagentResult:
        log.info("subagent %s: stub (not implemented yet)", state)
        return SubagentResult(status="failed")

    return run
