"""RECON_ACTIVE subagent (spec v2.1.1 §4.2, Zone B).

First contact with the target: a fixed, deterministic tool plan inside
the sandbox (the only place packets to the target are ever allowed):

  stage 1 (discovery):  nmap → naabu → dnsx
  stage 2 (web probes): per discovered http(s) service — httpx → whatweb
                        → katana → feroxbuster → openapi_probe → gowitness;
                        sslscan + testssl.sh when the service is TLS

Every argv is built here as a fixed constant list, validated against the
host-side ToolAllowlist (Layer 2), and audited. The LLM has no say in
what gets scanned. A failed tool never fails the state — HYPOTHESIZE
just has less evidence (each failure is audited).

rustscan is allowlisted but not in the default plan (nmap + naabu already
cover port discovery; one of them failing is not worth a third scanner's
runtime). hakrawler duplicates katana. massdns (Phase 8) is allowlisted
but likewise not in the plan — dnsx covers resolution.
"""

from __future__ import annotations

import logging
import re

from ..config import KryonsecConfig
from .adapter_httpx import parse_httpx_json_lines, record_httpx_evidence
from .adapter_whatweb import parse_whatweb_lines, record_whatweb_evidence
from .adapters import AdapterError, AdapterRegistry, \
    execute_adapter, prepare_adapter_run
from .allowlist import AllowlistViolation, ToolAllowlist
from .audit import AuditLog
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph
from .sandbox import KaliSandbox, SpawnResult

log = logging.getLogger(__name__)

#: the one production adapter id that RECON_ACTIVE selects from an
#: injected registry (Phase 2B.3). Registration is explicit: when the
#: registry does not carry it (or no registry is injected), the legacy
#: fixed-plan httpx entries run exactly as before — DETERMINISTICALLY
#: one or the other, never both probing the same base.
HTTPX_ADAPTER_ID = "httpx-probe"
#: the second production adapter id RECON_ACTIVE selects from the
#: same injected registry (Phase 2B.5). Same rule: when the registry
#: does not carry it (or no registry is injected), the legacy
#: fixed-plan whatweb entry runs exactly as before — DETERMINISTICALLY
#: one or the other, never both probing the same base.
WHATWEB_ADAPTER_ID = "whatweb-probe"
#: the third production adapter id RECON_ACTIVE runs when registered
#: (Phase 2B.4): the vetted non-destructive nuclei checks. The legacy
#: fixed-plan nuclei entry lives in EXPLOIT and is untouched — this
#: adapter never enters that stage and never re-uses its verdict words.
NUCLEI_ADAPTER_ID = "nuclei-probe"

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

# feroxbuster result lines. The shape is:
#     status  [METHOD]  Nl  Nw  Nc  url
# e.g. "200      GET       15l       34w      345c http://host/admin"
# and on redirects "301      GET        9l       28w      317c http://host/a =>
# http://host/a/". Two variations exist in the wild: the METHOD column is
# printed by current releases but omitted by some builds, and the url is a
# full URL (never a bare path). The old pattern required
# "<status> <digits> <digits> /path" — neither shape — so every
# directory-busting result was dropped, silently losing the evidence.
_FEROX_RE = re.compile(
    r"^(?P<status>\d{3})\s+"
    r"(?:(?P<method>[A-Z]{3,7})\s+)?"      # optional METHOD column
    r"(?:\d+[lwc]\s+)+"                    # Nl Nw Nc (count may vary by build)
    r"(?P<url>\S+)"                        # full URL (or a path in older builds)
)

# Statuses that mean "something is really there". 404s are filtered by
# feroxbuster itself; everything else (2xx/3xx plus the protected-path codes)
# is worth a node in the graph.
_FEROX_STATUS = frozenset(
    list(range(200, 400)) + [401, 403, 405]
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
    """Extract discovered paths from feroxbuster output.

    feroxbuster prints the full URL; the graph wants the path, so the URL is
    split here (query string kept — it's often the interesting part).
    """
    from urllib.parse import urlsplit

    paths = []
    for line in stdout.splitlines():
        m = _FEROX_RE.match(line.strip())
        if not m:
            continue
        status = int(m.group("status"))
        if status not in _FEROX_STATUS:
            continue
        raw = m.group("url")
        if raw.startswith(("http://", "https://")):
            parts = urlsplit(raw)
            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"
        else:
            path = raw  # bare-path build
        paths.append({"path": path, "status": status})
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
        adapter_registry: "AdapterRegistry | None" = None,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        self.target = target
        self.sandbox = sandbox
        self.allowlist = allowlist or ToolAllowlist()
        # Phase 2B.3: the RECON_ACTIVE adapter registry (explicitly
        # injected by the runner). None -> the legacy fixed plan runs
        # unchanged. An injected registry that does not carry the
        # adapter is equivalent to no registry (unknown = disabled).
        self.adapter_registry = adapter_registry

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

    def _httpx_adapter(self):
        """The registered httpx-probe adapter, or None (unknown ids are
        refused everywhere by the registry — refusal here means the
        legacy path runs, deterministically)."""
        if self.adapter_registry is None:
            return None
        try:
            return self.adapter_registry.get(HTTPX_ADAPTER_ID)
        except AdapterError:
            return None

    def _whatweb_adapter(self):
        """The registered whatweb-probe adapter (Phase 2B.5), or None —
        the same explicit-registration rule as the httpx adapter: an
        injected registry without it means the legacy whatweb plan
        entry runs, deterministically (one or the other, never both)."""
        if self.adapter_registry is None:
            return None
        try:
            return self.adapter_registry.get(WHATWEB_ADAPTER_ID)
        except AdapterError:
            return None

    def _nuclei_adapter(self):
        """The registered nuclei-probe adapter (Phase 2B.4), or None —
        the same explicit-registration rule: an injected registry
        without it means RECON_ACTIVE runs exactly the fixed plan, no
        vuln checks added."""
        if self.adapter_registry is None:
            return None
        from .adapter_nuclei import NUCLEI_ADAPTER_ID
        try:
            return self.adapter_registry.get(NUCLEI_ADAPTER_ID)
        except AdapterError:
            return None

    def _web_bases(self, ports: set[int]) -> "list[str]":
        """The in-scope base URLs stage 2 probes (deterministic order)."""
        web_ports = sorted(p for p in ports if p in WEB_PORTS)
        if not web_ports:
            web_ports = [80]  # nothing recognised — try the default anyway
        bases: list[str] = []
        for port in web_ports:
            scheme = "https" if port in TLS_PORTS else "http"
            bases.append(f"{scheme}://{self.target}:{port}/")
        return bases

    def _web_plan(self, ports: set[int],
                  use_httpx_adapter: bool = False,
                  use_whatweb_adapter: bool = False
                  ) -> list[tuple[str, list[str]]]:
        """Stage 2: http probes on discovered web ports.

        ``use_httpx_adapter`` (Phase 2B.3) and ``use_whatweb_adapter``
        (Phase 2B.5) omit the corresponding legacy plan entries when
        the registered adapter probe runs instead — NO duplicate
        probing of the same check (deterministic either/or). The other
        probes (katana/feroxbuster/...) are unchanged either way.
        """
        plan: list[tuple[str, list[str]]] = []
        # same filter/order as _web_bases, so (port, base) stay paired
        web_ports = sorted(p for p in ports if p in WEB_PORTS) or [80]
        for port, base in zip(web_ports, self._web_bases(ports)):
            if not use_httpx_adapter:
                plan.append(("httpx", ["httpx", "-u", base, "-silent",
                                       "-status-code", "-title",
                                       "-tech-detect"]))
            if not use_whatweb_adapter:
                plan.append(("whatweb", ["whatweb", "-a", "3",
                                         "--no-errors", "--color=never",
                                         base]))
            plan.append(("katana", ["katana", "-u", base, "-d", "2", "-silent"]))
            plan.append(("feroxbuster",
                         ["feroxbuster", "-u", base.rstrip("/") + "/FUZZ",
                          "-w", SECLISTS_WEB, "-t", "5", "--timeout", "30"]))
            # Phase 8: API surface discovery + a screenshot per web port —
            # the PNG lands in the rw /evidence mount (engagement folder)
            plan.append(("openapi_probe",
                         ["/opt/kryonsec/openapi_probe.py", base]))
            plan.append(("gowitness",
                         ["gowitness", "scan", "website", "--url", base,
                          "--screenshot-path", "/evidence", "--no-console",
                          "--disable-db"]))
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

        # the registered httpx adapter (Phase 2B.3) REPLACES the legacy
        # httpx entries for the same base URLs — one probe per check,
        # never both. The adapter probe runs FIRST; its web_endpoint
        # nodes are the same type the legacy parse produced, so
        # HYPOTHESIZE reads one uniform surface.
        httpx_adapter = self._httpx_adapter()
        if httpx_adapter is not None:
            executed += self._run_httpx_adapter(httpx_adapter,
                                                self._web_bases(open_ports))

        # the registered whatweb adapter (Phase 2B.5) REPLACES the
        # legacy whatweb entries — same deterministic either/or as the
        # httpx rule above: the adapter probe runs against the same
        # base URLs, the legacy plan entry contributes nothing; the
        # richer tech_fingerprint nodes carry the adapter provenance.
        whatweb_adapter = self._whatweb_adapter()
        if whatweb_adapter is not None:
            executed += self._run_whatweb_adapter(whatweb_adapter,
                                                  self._web_bases(open_ports))

        # the registered nuclei adapter (Phase 2B.4) ADDS the vetted
        # non-destructive checks the fixed plan does not have (the
        # legacy plan's nuclei entry lives in EXPLOIT and stays there).
        # Detection candidates are ``vuln_candidate`` nodes — a node
        # type EXPLOIT's ``finding`` flow never reads, so a detection
        # can never pose as a confirmed finding; HYPOTHESIZE reads
        # them as candidate leads.
        nuclei_adapter = self._nuclei_adapter()
        if nuclei_adapter is not None:
            executed += self._run_nuclei_adapter(nuclei_adapter,
                                                 self._web_bases(open_ports))

        for tool, argv in self._web_plan(
                open_ports, use_httpx_adapter=httpx_adapter is not None,
                use_whatweb_adapter=whatweb_adapter is not None):
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
            elif tool == "openapi_probe":
                # JSON summary from the baked script — parse defensively;
                # found endpoints become path nodes for HYPOTHESIZE
                try:
                    import json as _json

                    payload = _json.loads(result.stdout)
                except ValueError:
                    payload = {}
                for found in payload.get("found") or []:
                    for ep in found.get("endpoints") or []:
                        self.graph.add_node(
                            node_type="path",
                            label=str(ep).split(" ", 1)[-1][:300],
                            properties={
                                "source": "openapi_probe",
                                "doc_path": found.get("path"),
                                "spec_version": found.get("spec_version", ""),
                            },
                        )
                if any(f.get("status") == 200 for f in payload.get("found") or []):
                    self.audit.write({
                        "event": "recon_active_openapi",
                        "found": [
                            f.get("path") for f in payload.get("found") or []
                            if f.get("status") == 200
                        ],
                    })
            elif tool == "gowitness":
                # the screenshot itself is the evidence — in the rw /evidence
                # mount (engagement folder), not in tool output. A graph node
                # records that it was taken (and where to find it).
                url = argv[argv.index("--url") + 1] if "--url" in argv else self.target
                self.graph.add_node(
                    node_type="screenshot",
                    label=url,
                    properties={"source": "gowitness", "dir": "/evidence"},
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

    def _run_httpx_adapter(self, adapter, bases: "list[str]") -> int:
        """Run the registered httpx-probe adapter against each stage-2
        base URL.

        Returns 1 per base whose run executed (the same count the
        legacy httpx plan entries contribute). Preparation refusals
        (out-of-scope base) and execution refusals (no egress, no
        sandbox) are AUDITED as ``recon_active_adapter_failure`` and
        skipped — an adapter refusal never fails the state, exactly
        like a tool failure. Observations become the SAME
        ``web_endpoint`` nodes the legacy parse produced, with the
        richer provenance the adapter path carries.
        """
        executed = 0
        for base in bases:
            try:
                prepared = prepare_adapter_run(
                    self.adapter_registry, adapter.adapter_id,
                    target=self.target, target_asset=base)
            except AdapterError as e:
                self.audit.write({
                    "event": "recon_active_adapter_failure",
                    "adapter": adapter.adapter_id,
                    "base": base[:300],
                    "reason": str(e)[:200],
                })
                continue
            record, output = execute_adapter(
                self.adapter_registry, prepared,
                sandbox=self.sandbox, audit=self.audit, graph=self.graph,
                full_output=True)
            if record.executed:
                observations, malformed = parse_httpx_json_lines(output)
                record_httpx_evidence(
                    self.graph, self.audit,
                    run_record=record,
                    observations=observations,
                    malformed_lines=malformed,
                )
                self.audit.write({
                    "event": "recon_active_httpx_adapter",
                    "adapter": adapter.adapter_id,
                    "request_id": record.request_id,
                    "base": base[:300],
                    "observations": len(observations),
                    "malformed_lines": malformed,
                })
                executed += 1
            else:
                self.audit.write({
                    "event": "recon_active_adapter_failure",
                    "adapter": adapter.adapter_id,
                    "request_id": record.request_id,
                    "base": base[:300],
                    "outcome": record.outcome,
                    "reason": record.error_excerpt[:200],
                })
        return executed

    def _run_whatweb_adapter(self, adapter, bases: "list[str]") -> int:
        """Run the registered whatweb-probe adapter against each
        stage-2 base URL (Phase 2B.5).

        Returns 1 per base whose run executed (the same count the
        legacy whatweb plan entries contribute). Preparation refusals
        (out-of-scope base) and execution refusals (no egress, no
        sandbox) are AUDITED as ``recon_active_adapter_failure`` and
        skipped — an adapter refusal never fails the state, exactly
        like a tool failure. Observations become ``tech_fingerprint``
        nodes (the same node type the legacy parse produced), with the
        parsed fields and the adapter provenance the legacy excerpt
        cannot carry.
        """
        executed = 0
        for base in bases:
            try:
                prepared = prepare_adapter_run(
                    self.adapter_registry, adapter.adapter_id,
                    target=self.target, target_asset=base)
            except AdapterError as e:
                self.audit.write({
                    "event": "recon_active_adapter_failure",
                    "adapter": adapter.adapter_id,
                    "base": base[:300],
                    "reason": str(e)[:200],
                })
                continue
            record, output = execute_adapter(
                self.adapter_registry, prepared,
                sandbox=self.sandbox, audit=self.audit, graph=self.graph,
                full_output=True)
            if record.executed:
                observations, malformed = parse_whatweb_lines(output)
                record_whatweb_evidence(
                    self.graph, self.audit,
                    run_record=record,
                    observations=observations,
                    malformed_lines=malformed,
                )
                self.audit.write({
                    "event": "recon_active_whatweb_adapter",
                    "adapter": adapter.adapter_id,
                    "request_id": record.request_id,
                    "base": base[:300],
                    "observations": len(observations),
                    "malformed_lines": malformed,
                })
                executed += 1
            else:
                self.audit.write({
                    "event": "recon_active_adapter_failure",
                    "adapter": adapter.adapter_id,
                    "request_id": record.request_id,
                    "base": base[:300],
                    "outcome": record.outcome,
                    "reason": record.error_excerpt[:200],
                })
        return executed

    def _run_nuclei_adapter(self, adapter, bases: "list[str]") -> int:
        """Run the registered nuclei-probe adapter against each stage-2
        base URL (Phase 2B.4).

        Returns 1 per base whose run executed. Preparation refusals
        (out-of-scope base) and execution refusals (no egress, no
        sandbox) are AUDITED as ``recon_active_adapter_failure`` and
        skipped — an adapter refusal never fails the state, exactly
        like a tool failure. Detected matches become ``vuln_candidate``
        nodes (detection, never confirmation); a clean zero-match run
        is an honest INCONCLUSIVE result, audited as its own event and
        never a negative finding.
        """
        from .adapter_nuclei import parse_nuclei_json_lines, \
            record_nuclei_evidence

        executed = 0
        for base in bases:
            try:
                prepared = prepare_adapter_run(
                    self.adapter_registry, adapter.adapter_id,
                    target=self.target, target_asset=base)
            except AdapterError as e:
                self.audit.write({
                    "event": "recon_active_adapter_failure",
                    "adapter": adapter.adapter_id,
                    "base": base[:300],
                    "reason": str(e)[:200],
                })
                continue
            record, output = execute_adapter(
                self.adapter_registry, prepared,
                sandbox=self.sandbox, audit=self.audit, graph=self.graph,
                full_output=True)
            if record.executed:
                candidates, malformed = parse_nuclei_json_lines(output)
                record_nuclei_evidence(
                    self.graph, self.audit,
                    run_record=record,
                    candidates=candidates,
                    malformed_lines=malformed,
                )
                self.audit.write({
                    "event": "recon_active_nuclei_adapter",
                    "adapter": adapter.adapter_id,
                    "request_id": record.request_id,
                    "base": base[:300],
                    "candidates": len(candidates),
                    "malformed_lines": malformed,
                    # honest classification: a zero-candidate, zero-
                    # malformed clean run is INCONCLUSIVE (nothing
                    # detected, nothing proven), never a negative
                    "outcome": ("detected_candidates"
                                if candidates else "inconclusive"),
                })
                executed += 1
            else:
                self.audit.write({
                    "event": "recon_active_adapter_failure",
                    "adapter": adapter.adapter_id,
                    "request_id": record.request_id,
                    "base": base[:300],
                    "outcome": record.outcome,
                    "reason": record.error_excerpt[:200],
                })
        return executed

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
