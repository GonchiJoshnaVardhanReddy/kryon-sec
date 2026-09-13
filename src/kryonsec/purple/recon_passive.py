"""RECON_PASSIVE subagent (spec v2.1.1 §4.2, Zone A).

Runs host-side. Zero packets to the target. Results land in the engagement
graph (stm_nodes) and every action lands in the audit chain.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from ..config import KryonsecConfig
from .audit import AuditLog
from .orchestrator import SubagentResult
from .zonea import (
    PassiveResult,
    crt_sh_subdomains,
    otx_passive_dns,
    ripestat_asn,
    ripestat_whois,
    wayback_subdomains,
)

log = logging.getLogger(__name__)


def zone_a_fetchers(cfg: KryonsecConfig) -> list[Callable[[str], PassiveResult]]:
    """The Zone A source list for a config. Keyless sources always run;
    Shodan/Censys are included even without keys — they return a skipped
    result that lands in the audit log as a visible notice."""
    def shodan(domain: str) -> PassiveResult:
        from .zonea import shodan_subdomains
        return shodan_subdomains(domain, api_key=cfg.shodan_api_key)

    def censys(domain: str) -> PassiveResult:
        from .zonea import censys_subdomains
        return censys_subdomains(
            domain, api_id=cfg.censys_api_id, api_secret=cfg.censys_api_secret)

    shodan.__name__ = "shodan"
    censys.__name__ = "censys"
    return [
        crt_sh_subdomains,
        wayback_subdomains,
        otx_passive_dns,
        ripestat_whois,
        ripestat_asn,
        shodan,
        censys,
    ]


def sandbox_passive_fetcher(
    sandbox,
    audit: AuditLog,
    allowlist=None,
) -> Callable[[str], PassiveResult]:
    """Passive subdomain enumeration INSIDE the gVisor sandbox (Phase 2):
    subfinder/amass/assetfinder with -passive flags — they query third-
    party sources, never the target. Only wired when the sandbox exists.

    Same safety pattern as every Zone B spawn: allowlist validation, argv
    lists, audited. The tools' output lines become subdomain candidates.
    """
    from .allowlist import AllowlistViolation, ToolAllowlist

    allow = allowlist or ToolAllowlist()

    def fetch(domain: str) -> PassiveResult:
        found: set[str] = set()
        for tool, argv in (
            ("subfinder", ["subfinder", "-d", domain, "-passive", "-silent"]),
            ("amass", ["amass", "enum", "-passive", "-d", domain]),
            ("assetfinder", ["assetfinder", "-silent", domain]),
        ):
            try:
                allow.validate(argv[0], argv)
                allow.check_blocklist(argv)
            except AllowlistViolation as e:  # pragma: no cover — fixed argv
                audit.write({
                    "event": "passive_sandbox_rejected_by_allowlist",
                    "tool": tool,
                    "reason": str(e)[:200],
                })
                continue
            audit.write({
                "event": "tool_spawn",
                "state": "RECON_PASSIVE",
                "tool": tool,
                "argv": argv,
            })
            result = sandbox.spawn(argv)
            audit.write({
                "event": "tool_result",
                "state": "RECON_PASSIVE",
                "tool": tool,
                "ok": result.ok,
                "exit_code": result.exit_code,
                "output_chars": len(result.stdout),
            })
            if not result.ok:
                continue
            for line in result.stdout.splitlines():
                host = line.strip().lower().rstrip(".")
                # scope by construction: only hosts under the target count
                if host.endswith("." + domain.lower()) and "." in host:
                    found.add(host)
        return PassiveResult(
            source="sandbox-passive", subdomains=sorted(found),
            notes=["enumerated by sandbox subfinder/amass/assetfinder "
                   "(-passive flags; zero packets to the target)"],
        )

    fetch.__name__ = "sandbox_passive"
    return fetch


@dataclass
class EngagementGraph:
    """In-memory engagement STM. On PostgreSQL this persists to stm_nodes;
    on the Profile-1 fallback it stays in memory (Purple Team execution is
    Profile-2 gated anyway, so the fallback path is for tests only)."""

    engagement_id: str
    nodes: list[dict] = field(default_factory=list)

    def add_node(self, node_type: str, label: str, properties: dict | None = None) -> dict:
        import json as _json

        size = len(_json.dumps(properties or {}).encode())
        node = {
            "engagement_id": self.engagement_id,
            "node_type": node_type,
            "label": label,
            "properties": properties or {},
            "size_bytes": size,  # app-layer computed (spec §4.5)
        }
        self.nodes.append(node)
        return node

    @property
    def size_bytes(self) -> int:
        return sum(n["size_bytes"] for n in self.nodes)

    def by_type(self, node_type: str) -> list[dict]:
        return [n for n in self.nodes if n["node_type"] == node_type]

    def remove_node(self, node: dict) -> None:
        """Drop a node (used for deterministic dedup — never used to
        rewrite history: the audit chain keeps the full record)."""
        try:
            self.nodes.remove(node)
        except ValueError:
            pass  # already gone


@dataclass
class ReconPassiveSubagent:
    cfg: KryonsecConfig
    graph: EngagementGraph
    audit: AuditLog
    target: str
    # injectable for tests. Two default sources so one flaky API
    # (crt.sh is regularly slow/empty) can't starve the LLM of data.
    fetchers: list[Callable[[str], PassiveResult]] = field(
        default_factory=lambda: [crt_sh_subdomains, wayback_subdomains]
    )

    def run(self) -> SubagentResult:
        self.audit.write({
            "event": "state_enter",
            "state": "RECON_PASSIVE",
            "target": self.target,
        })

        self.graph.add_node(
            node_type="target",
            label=self.target,
            properties={"source": "engagement_config"},
        )

        total_new = 0
        for fetcher in self.fetchers:
            source = getattr(fetcher, "__name__", str(fetcher))
            try:
                result = fetcher(self.target)
            except Exception as e:
                # A failed source must not kill the state — audit and continue
                self.audit.write({
                    "event": "passive_source_failed",
                    "source": source,
                    "error": str(e)[:200],
                })
                continue

            if result.skipped:
                # source didn't run (e.g. no API key) — a notice, not a
                # failure; the operator can add the key in kryonsec setup
                self.audit.write({
                    "event": "passive_source_skipped",
                    "source": source,
                    "reason": result.skipped,
                })
                continue

            known = {n["label"] for n in self.graph.by_type("subdomain")}
            # The apex domain is already the target node — not a subdomain node
            fresh = [
                s for s in result.subdomains
                if s not in known and s != self.target
            ]
            for subdomain in fresh:
                self.graph.add_node(
                    node_type="subdomain",
                    label=subdomain,
                    properties={"source": result.source},
                )
            total_new += len(fresh)

            known_paths = {n["label"] for n in self.graph.by_type("path")}
            for path in result.paths:
                if path not in known_paths:
                    self.graph.add_node(
                        node_type="path",
                        label=path,
                        properties={"source": result.source},
                    )

            if result.notes:
                self.graph.add_node(
                    node_type="osint_note",
                    label=result.source,
                    properties={"notes": result.notes},
                )

            # Audit the CALL (tool, source, counts) — never any API key
            self.audit.write({
                "event": "passive_source_ok",
                "source": source,
                "found": len(result.subdomains),
                "new": len(fresh),
                "paths": len(result.paths),
                "notes": len(result.notes),
            })

        return SubagentResult(status="ok")
