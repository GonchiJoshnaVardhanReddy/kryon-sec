"""RECON_ACTIVE subagent (spec v2.1.1 §4.2, Zone B).

First contact with the target: an nmap service scan inside the sandbox
(the only place packets to the target are ever allowed). Results are
parsed into `service` graph nodes and become HYPOTHESIZE evidence.

The argv is fixed (build_argv in exploit.py, allowlist-validated) —
the LLM has no say in what gets scanned.
"""

from __future__ import annotations

import logging
import re

from ..config import KryonsecConfig
from .allowlist import AllowlistViolation, ToolAllowlist
from .audit import AuditLog
from .exploit import build_argv
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph
from .sandbox import KaliSandbox

log = logging.getLogger(__name__)

# nmap -sV lines look like:
# "80/tcp   open  http    Microsoft IIS httpd 8.5"
_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)"
    r"(?:\s+(?P<version>.+?))?\s*$",
    re.IGNORECASE,
)


def parse_nmap_services(stdout: str) -> list[dict]:
    """Extract open ports/services from nmap -sV output."""
    services = []
    for line in stdout.splitlines():
        m = _PORT_RE.match(line.strip())
        if m and m.group("state").lower() == "open":
            services.append({
                "port": int(m.group("port")),
                "proto": m.group("proto").lower(),
                "service": m.group("service"),
                "version": (m.group("version") or "").strip(),
            })
    return services


class ReconActiveSubagent:
    """Runs the RECON_ACTIVE state: one allowlisted nmap scan."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        graph: EngagementGraph,
        audit: AuditLog,
        target: str,
        sandbox: KaliSandbox,
        allowlist: ToolAllowlist | None = None,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        self.target = target
        self.sandbox = sandbox
        self.allowlist = allowlist or ToolAllowlist()

    def run(self) -> SubagentResult:
        self.audit.write({
            "event": "state_enter",
            "state": "RECON_ACTIVE",
            "target": self.target,
        })

        argv = build_argv("nmap", self.target, self.target)
        if argv is None:  # pragma: no cover — template exists
            return SubagentResult(status="failed")

        # Layer 2 check — the control, even though the argv is ours
        try:
            self.allowlist.validate(argv[0], argv)
            self.allowlist.check_blocklist(argv)
        except AllowlistViolation as e:
            self.audit.write({
                "event": "recon_active_rejected_by_allowlist",
                "reason": str(e)[:200],
            })
            return SubagentResult(status="failed")

        self.audit.write({
            "event": "tool_spawn",
            "state": "RECON_ACTIVE",
            "tool": "nmap",
            "argv": argv,
        })
        result = self.sandbox.spawn(argv)
        self.audit.write({
            "event": "tool_result",
            "state": "RECON_ACTIVE",
            "tool": "nmap",
            "ok": result.ok,
            "exit_code": result.exit_code,
            "output_chars": len(result.stdout),
            "truncated": result.truncated,
            "error": result.error[:200] if result.error else "",
        })

        services: list[dict] = []
        if result.ok:
            services = parse_nmap_services(result.stdout)
            for svc in services:
                label = f"{self.target}:{svc['port']}/{svc['proto']}"
                self.graph.add_node(
                    node_type="service",
                    label=label,
                    properties={
                        "port": svc["port"],
                        "proto": svc["proto"],
                        "service": svc["service"],
                        "version": svc["version"],
                        "source": "nmap",
                    },
                )
            self.audit.write({
                "event": "recon_active_done",
                "services_found": len(services),
                "services": [
                    f"{s['port']}/{s['proto']} {s['service']}" for s in services
                ],
            })
        else:
            # a failed scan fails the state — the loop still continues
            # deterministically; HYPOTHESIZE just has less evidence
            self.audit.write({
                "event": "recon_active_failed",
                "error": result.error[:200],
            })
            return SubagentResult(status="failed")

        return SubagentResult(status="ok")
