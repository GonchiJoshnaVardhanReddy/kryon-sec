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

# What each state does + which tools it may use (spec §4.2 state table).
# Display info only — the authoritative tool check is the allowlist.
STATE_INFO: dict[str, dict[str, str]] = {
    "INIT": {
        "agent": "init",
        "does": "load config, validate scope",
        "tools": "none",
        "zone": "—",
    },
    "RECON_PASSIVE": {
        "agent": "passive-recon",
        "does": "third-party lookups — zero packets to target",
        "tools": "crt.sh, Wayback, OTX, RIPEstat (whois/ASN), Shodan, "
                 "Censys (Zone A APIs; last two need keys); "
                 "subfinder/amass/assetfinder -passive in sandbox",
        "zone": "A",
    },
    "RECON_ACTIVE": {
        "agent": "active-recon",
        "does": "scan the target (packets to target)",
        "tools": "nmap, naabu, dnsx, httpx, whatweb, katana, feroxbuster, "
                 "openapi_probe, gowitness (screenshots → /evidence), "
                 "sslscan, testssl.sh",
        "zone": "B (sandbox)",
    },
    "HYPOTHESIZE": {
        "agent": "hypothesizer (LLM)",
        "does": "propose vulnerability hypotheses from recon data, then "
                "enrich with public risk data",
        "tools": "LLM proposes only; enrichment: NVD/CPE, CISA KEV, EPSS "
                 "(free APIs) + searchsploit in sandbox",
        "zone": "A (third-party APIs) + B for searchsploit",
    },
    "HUMAN_REVIEW": {
        "agent": "operator (you)",
        "does": "approve or reject each hypothesis",
        "tools": "none — blocking approval gate",
        "zone": "—",
    },
    "EXPLOIT": {
        "agent": "exploit",
        "does": "execute approved hypotheses only",
        "tools": "sqlmap, nuclei, nikto, ffuf, gobuster, wfuzz, curl, wget, "
                 "dalfox, commix, ssrfmap, arjun, tplmap, graphql-cop",
        "zone": "B (sandbox)",
    },
    "POST_EXPLOIT": {
        "agent": "post-exploit",
        "does": "enumerate inside an obtained shell (separate approval; "
                "dormant — no current tool yields a shell)",
        "tools": "linpeas, pspy, linux-exploit-suggester, baked enum "
                 "scripts (evidence collection only, never destructive)",
        "zone": "B (sandbox)",
    },
    "VERIFY": {
        "agent": "verifier",
        "does": "independently confirm findings",
        "tools": "curl, httpie, nc, openssl, dig, baked probe script",
        "zone": "B (sandbox)",
    },
    "BLUE_TEAM": {
        "agent": "blue-team (LLM)",
        "does": "generate fixes and detection rules, grounded in scanner "
                "evidence when a --code folder is provided",
        "tools": "semgrep, bandit, gitleaks, trivy, checkov, hadolint "
                 "(read-only /code mount) + LLM",
        "zone": "B for scanners (sandbox), LLM is host-side",
    },
    "REPORT": {
        "agent": "reporter",
        "does": "compile the engagement report",
        "tools": "Jinja2 templates",
        "zone": "—",
    },
}


def _docker_runtimes() -> str | None:
    """Return Docker's registered runtime list, or None if unreachable."""
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return None
    try:
        # .Runtimes is a Go map — `join` errors on it (moby#37584); range it
        out = subprocess.run(
            ["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
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
    progress: "Callable[[str], None] | None" = None,
    status_factory: "Callable[[str], object] | None" = None,
    code_folder: str | None = None,
) -> tuple[PurpleOrchestrator, AuditLog, "object"]:
    """Wire up an engagement. Returns (orchestrator, audit, graph).

    The engagement starts on every OS. When the sandbox is unavailable,
    the orchestrator HALTs (with an audited reason) as soon as a state
    needs Zone B.

    code_folder: absolute path to a user-provided code folder
    (--code). Blue-team static analyzers scan it through a read-only
    sandbox mount; without it (or without a sandbox) BLUE_TEAM stays
    pure LLM.

    progress: optional callback invoked with each state name before it
    runs (CLI uses it to show which agent is working).

    status_factory: optional — called with the state name, must return a
    context manager that is entered while the state's subagent runs (the
    CLI returns a spinner status line). Never wraps HUMAN_REVIEW: that
    state is interactive and owns the terminal.
    """
    from .recon_passive import EngagementGraph, ReconPassiveSubagent

    audit_path = cfg.home / "engagements" / engagement_id / "audit.jsonl"
    audit = AuditLog(audit_path)
    audit.write({
        "event": "engagement_created",
        "engagement_id": engagement_id,
        "target": target,
        "code_scan": bool(code_folder),
    })
    graph = EngagementGraph(engagement_id=engagement_id)

    sandbox_ok, sandbox_reason = sandbox_available(cfg.sandbox_image)
    audit.write({
        "event": "sandbox_check",
        "available": sandbox_ok,
        "reason": sandbox_reason,
    })

    # Evidence capture (Phase 8): screenshots and other artifacts land in
    # the engagement folder, mounted rw at the fixed /evidence in every
    # sandbox that produces evidence (active recon, exploit, post-exploit,
    # verify). The path is host-side Python — never from the LLM or argv.
    evidence_dir = cfg.home / "engagements" / engagement_id / "evidence"
    if sandbox_ok:
        evidence_dir.mkdir(parents=True, exist_ok=True)

    def resolve(state: str):
        """State name -> subagent run callable (or None for stubs)."""
        if state == "RECON_PASSIVE":
            from .recon_passive import (
                ReconPassiveSubagent,
                sandbox_passive_fetcher,
                zone_a_fetchers,
            )

            fetchers = zone_a_fetchers(cfg)
            if sandbox_ok:
                # passive subdomain tools in the sandbox (-passive flags;
                # zero packets to the target) — skipped cleanly elsewhere
                from .sandbox import KaliSandbox

                sandbox = KaliSandbox(cfg=cfg)
                fetchers.append(
                    sandbox_passive_fetcher(sandbox, audit))
            sub = ReconPassiveSubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                fetchers=fetchers,
            )
            return sub.run

        if state == "HYPOTHESIZE":
            from .hypothesize import HypothesizeSubagent

            # the sandbox (when present) powers ExploitDB searchsploit
            # enrichment; without it enrichment runs API-only and skips
            # searchsploit with an audited notice
            sandbox = None
            if sandbox_ok:
                from .sandbox import KaliSandbox

                sandbox = KaliSandbox(cfg=cfg)
            sub = HypothesizeSubagent(
                cfg=cfg, graph=graph, audit=audit, budget=orch.budget,
                sandbox=sandbox,
            )
            return sub.run

        if state == "HUMAN_REVIEW":
            from .human_review import HumanReviewSubagent

            sub = HumanReviewSubagent(graph=graph, audit=audit)
            return sub.run

        if state == "BLUE_TEAM":
            from .blue_team import BlueTeamSubagent

            # sandbox with the read-only /code mount for the static
            # analyzers; without a code folder (or sandbox) BLUE_TEAM
            # stays pure LLM
            sandbox = None
            if sandbox_ok and code_folder:
                from .sandbox import KaliSandbox

                sandbox = KaliSandbox(cfg=cfg, code_dir=code_folder)
            sub = BlueTeamSubagent(
                cfg=cfg, graph=graph, audit=audit, budget=orch.budget,
                sandbox=sandbox, code_folder=code_folder,
            )
            return sub.run

        if state == "REPORT":
            from .report import ReportSubagent

            sub = ReportSubagent(
                cfg=cfg, graph=graph, audit=audit, engagement_id=engagement_id,
            )

            def run_report() -> SubagentResult:
                # the report records how far the engagement actually got
                sub.completed_states = orch.completed
                sub.halt_reason = orch.halt_reason
                return sub.run()

            return run_report

        if state == "RECON_ACTIVE" and sandbox_ok:
            from .recon_active import ReconActiveSubagent
            from .sandbox import KaliSandbox

            sandbox = KaliSandbox(cfg=cfg, evidence_dir=str(evidence_dir))
            sub = ReconActiveSubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                sandbox=sandbox,
            )
            return sub.run

        if state == "EXPLOIT" and sandbox_ok:
            from .exploit import ExploitSubagent
            from .sandbox import KaliSandbox

            sandbox = KaliSandbox(cfg=cfg, evidence_dir=str(evidence_dir))
            sub = ExploitSubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                sandbox=sandbox, progress=progress,
            )
            return sub.run

        if state == "POST_EXPLOIT" and sandbox_ok:
            from .post_exploit import PostExploitSubagent
            from .sandbox import KaliSandbox

            sandbox = KaliSandbox(cfg=cfg, evidence_dir=str(evidence_dir))
            sub = PostExploitSubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                sandbox=sandbox,
            )
            return sub.run

        if state == "VERIFY" and sandbox_ok:
            from .sandbox import KaliSandbox
            from .verify import VerifySubagent

            sandbox = KaliSandbox(cfg=cfg, evidence_dir=str(evidence_dir))
            sub = VerifySubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                sandbox=sandbox,
            )
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

    def loader(state: str):
        if progress is not None:
            info = STATE_INFO.get(state, {})
            # parentheses, not square brackets: rich would eat [tools: ...]
            # as a markup tag
            progress(f"{info.get('agent', state)}: {info.get('does', '')} "
                     f"(tools: {info.get('tools', '?')} | zone {info.get('zone', '?')})")

        run_fn = resolve(state)

        if status_factory is not None and state != "HUMAN_REVIEW":
            def wrapped() -> SubagentResult:
                with status_factory(state):
                    return run_fn()
            return wrapped
        return run_fn

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
