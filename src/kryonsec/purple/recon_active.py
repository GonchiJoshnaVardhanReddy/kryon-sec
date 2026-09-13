"""RECON_ACTIVE subagent (spec v2.1.1 §4.2, Zone B).

First contact with the target: a fixed, deterministic tool plan inside
the sandbox (the only place packets to the target are ever allowed):

  stage 1 (discovery):  nmap → naabu → dnsx
  stage 2 (web probes): per discovered http(s) service — httpx → whatweb
                        → katana → feroxbuster; sslscan + testssl.sh when
                        the service is TLS

Every argv is built here as a fixed constant list, validated against the
host-side ToolAllowlist (Layer 2), and audited. The LLM has no say in
what gets scanned. A failed tool never fails the state — HYPOTHESIZE
just has less evidence (each failure is audited).

rustscan is allowlisted but not in the default plan (nmap + naabu already
cover port discovery; one of them failing is not worth a third scanner's
runtime). hakrawler duplicates katana.
"""

from __future__ import annotations

import logging
import re

from ..config import KryonsecConfig
from .allowlist import AllowlistViolation, ToolAllowlist
from .audit import AuditLog
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph
from .sandbox import KaliSandbox, SpawnResult

log = logging.getLogger(__name__)

# nmap -sV lines look like:
# "80/tcp   open  http    Microsoft IIS httpd 8.5"
_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)"
    r"(?:\s+(?P<version>.+?))?\s*$",
    re.IGNORECASE,
)

# naabu -silent lines: "host:port"
_NAABU_RE = re.compile(r"^(?P<host>[A-Za-z0-9._-]+):(?P<port>\d+)$")

# dnsx -silent lines: "domain [A] 1.2.3.4" or bare "1.2.3.4"
_IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")

# httpx: "http://host:port/ [200] [title] [tech1,tech2]"
_HTTPX_RE = re.compile(
    r"^(?P<url>https?://\S+?)\s*\[(?P<status>\d{3})\]"
    r"(?:\s*\[(?P<title>[^\]]*)\])?(?:\s*\[(?P<tech>[^\]]*)\])?",
)

# feroxbuster: "200      15l      345w     /admin"
_FEROX_RE = re.compile(
    r"^(?P<status>[23]\d\d)\s+\d+[a-z]*\s+\d+[a-z]*\s+(?P<path>/\S*)\s*$"
)

# Ports the discovery stage looks at (web + common service ports — a
# full-range scan against a third party is exactly what spec §9.1 fears)
RECON_PORTS = (
    "21,22,25,53,80,110,143,443,445,1433,3306,3389,5432,6379,"
    "8080,8443,9200,27017"
)
SECLISTS_WEB = "/usr/share/seclists/Discovery/Web-Content/common.txt"
# web-ish ports: get stage-2 http probes
WEB_PORTS = {80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000}
TLS_PORTS = {443, 8443, 9443}


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


def parse_naabu(stdout: str) -> list[int]:
    """Extract open TCP ports from naabu -silent output."""
    ports = set()
    for line in stdout.splitlines():
        m = _NAABU_RE.match(line.strip())
        if m:
            ports.add(int(m.group("port")))
    return sorted(ports)


def parse_dnsx(stdout: str) -> list[str]:
    """Extract resolved IPv4 addresses from dnsx output."""
    return sorted({m.group("ip") for m in _IP_RE.finditer(stdout)})


def parse_httpx(stdout: str) -> list[dict]:
    """Extract (url, status, title, tech) from httpx output lines."""
    endpoints = []
    for line in stdout.splitlines():
        m = _HTTPX_RE.match(line.strip())
        if m:
            endpoints.append({
                "url": m.group("url"),
                "status": int(m.group("status")),
                "title": (m.group("title") or "")[:200],
                "tech": (m.group("tech") or "")[:200],
            })
    return endpoints


def parse_feroxbuster(stdout: str) -> list[dict]:
    """Extract discovered paths from feroxbuster output."""
    paths = []
    for line in stdout.splitlines():
        m = _FEROX_RE.match(line.strip())
        if m:
            paths.append({
                "path": m.group("path"),
                "status": int(m.group("status")),
            })
    return paths[:50]  # bounded — the graph doesn't need 10k directories


class ReconActiveSubagent:
    """Runs the RECON_ACTIVE state: fixed multi-tool scan plan."""

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

    # ---- plan construction (deterministic, no LLM input) -----------------

    def _discovery_plan(self) -> list[tuple[str, list[str]]]:
        """Stage 1: port/service discovery + DNS resolution."""
        return [
            ("nmap", ["nmap", "-Pn", "-sT", "-sV", "-sC", "--max-rate", "100",
                      "-p", RECON_PORTS, self.target]),
            ("naabu", ["naabu", "-host", self.target, "-p", RECON_PORTS,
                       "-rate", "100", "-silent"]),
            ("dnsx", ["dnsx", "-d", self.target, "-silent"]),
        ]

    def _web_plan(self, ports: set[int]) -> list[tuple[str, list[str]]]:
        """Stage 2: http probes on discovered web ports."""
        plan: list[tuple[str, list[str]]] = []
        web_ports = sorted(p for p in ports if p in WEB_PORTS)
        if not web_ports:
            web_ports = [80]  # nothing recognised — try the default anyway
        for port in web_ports:
            scheme = "https" if port in TLS_PORTS else "http"
            base = f"{scheme}://{self.target}:{port}/"
            plan.append(("httpx", ["httpx", "-u", base, "-silent",
                                   "-status-code", "-title", "-tech-detect"]))
            plan.append(("whatweb", ["whatweb", "-a", "3", "--no-errors",
                                     "--color=never", base]))
            plan.append(("katana", ["katana", "-u", base, "-d", "2", "-silent"]))
            plan.append(("feroxbuster",
                         ["feroxbuster", "-u", base.rstrip("/") + "/FUZZ",
                          "-w", SECLISTS_WEB, "-t", "5", "--timeout", "30"]))
            if port in TLS_PORTS:
                plan.append(("sslscan",
                             ["sslscan", "--no-failed", "--sleep", "100",
                              self.target]))
                plan.append(("testssl.sh",
                             ["testssl.sh", "--batch", "--severity=high",
                              "--no-color", base]))
        return plan

    # ---- execution --------------------------------------------------------

    def run(self) -> SubagentResult:
        self.audit.write({
            "event": "state_enter",
            "state": "RECON_ACTIVE",
            "target": self.target,
        })

        executed = 0
        # stage 1 — discovery. nmap output is authoritative for services;
        # naabu is both a second opinion and the fallback if nmap fails.
        open_ports: set[int] = set()
        for tool, argv in self._discovery_plan():
            result, ran = self._spawn(tool, argv)
            executed += ran if result.ok else 0
            if not result.ok:
                continue
            if tool == "nmap":
                services = parse_nmap_services(result.stdout)
                for svc in services:
                    open_ports.add(svc["port"])
                    self.graph.add_node(
                        node_type="service",
                        label=f"{self.target}:{svc['port']}/{svc['proto']}",
                        properties={
                            "port": svc["port"],
                            "proto": svc["proto"],
                            "service": svc["service"],
                            "version": svc["version"],
                            "source": "nmap",
                        },
                    )
                self.audit.write({
                    "event": "recon_active_nmap",
                    "services_found": len(services),
                    "services": [
                        f"{s['port']}/{s['proto']} {s['service']}" for s in services
                    ],
                })
            elif tool == "naabu":
                ports = parse_naabu(result.stdout)
                open_ports.update(ports)
                self.audit.write({
                    "event": "recon_active_naabu",
                    "open_ports": ports,
                })
            elif tool == "dnsx":
                ips = parse_dnsx(result.stdout)
                if ips:
                    self.graph.add_node(
                        node_type="dns_resolution",
                        label=self.target,
                        properties={"ips": ips, "source": "dnsx"},
                    )
                self.audit.write({
                    "event": "recon_active_dnsx",
                    "resolved_ips": ips,
                })

        # stage 2 — web probes on what stage 1 found
        for tool, argv in self._web_plan(open_ports):
            result, ran = self._spawn(tool, argv)
            executed += ran if result.ok else 0
            if not result.ok:
                continue
            if tool == "httpx":
                for ep in parse_httpx(result.stdout):
                    self.graph.add_node(
                        node_type="web_endpoint",
                        label=ep["url"],
                        properties={
                            "status": ep["status"],
                            "title": ep["title"],
                            "tech": ep["tech"],
                            "source": "httpx",
                        },
                    )
            elif tool == "whatweb":
                # one bounded excerpt node — the full fingerprint is in
                # the tool_result audit trail already
                self.graph.add_node(
                    node_type="tech_fingerprint",
                    label=self.target,
                    properties={
                        "excerpt": result.stdout[:500],
                        "source": "whatweb",
                    },
                )
            elif tool == "katana":
                # crawled URLs become candidate paths (same node type the
                # passive Wayback source produces — HYPOTHESIZE reads both)
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith(("http://", "https://")):
                        path = line.split(self.target, 1)[-1] or "/"
                        self.graph.add_node(
                            node_type="path",
                            label=path[:300],
                            properties={"source": "katana", "url": line[:500]},
                        )
            elif tool == "feroxbuster":
                for p in parse_feroxbuster(result.stdout):
                    self.graph.add_node(
                        node_type="path",
                        label=p["path"],
                        properties={"status": p["status"], "source": "feroxbuster"},
                    )
            elif tool in ("sslscan", "testssl.sh"):
                self.graph.add_node(
                    node_type="tls_observation",
                    label=self.target,
                    properties={
                        "source": tool,
                        "excerpt": result.stdout[:500],
                    },
                )

        if executed:
            self.audit.write({
                "event": "recon_active_done",
                "tools_executed": executed,
                "open_ports": sorted(open_ports),
            })
            return SubagentResult(status="ok")
        # every tool failed — the loop still continues deterministically;
        # HYPOTHESIZE just has less evidence, but say so honestly
        self.audit.write({
            "event": "recon_active_failed",
            "error": "no recon tool ran successfully",
        })
        return SubagentResult(status="failed")

    def _spawn(self, tool: str, argv: list[str]) -> tuple[SpawnResult, int]:
        """Validate + run one tool. Returns (result, 1-if-spawned).

        Layer 2 check on every spawn — the control, even though the argv
        is ours. A rejection is audited and skipped, never fatal.
        """
        try:
            self.allowlist.validate(argv[0], argv)
            self.allowlist.check_blocklist(argv)
        except AllowlistViolation as e:
            self.audit.write({
                "event": "recon_active_rejected_by_allowlist",
                "tool": tool,
                "reason": str(e)[:200],
            })
            return SpawnResult(ok=False, exit_code=-1, stdout="",
                               error=str(e)), 0

        self.audit.write({
            "event": "tool_spawn",
            "state": "RECON_ACTIVE",
            "tool": tool,
            "argv": argv,
        })
        result = self.sandbox.spawn(argv)
        self.audit.write({
            "event": "tool_result",
            "state": "RECON_ACTIVE",
            "tool": tool,
            "ok": result.ok,
            "exit_code": result.exit_code,
            "output_chars": len(result.stdout),
            "truncated": result.truncated,
            "error": result.error[:200] if result.error else "",
        })
        return result, 1
