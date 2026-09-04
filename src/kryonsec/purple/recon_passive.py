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
from .zonea import PassiveResult, crt_sh_subdomains

log = logging.getLogger(__name__)


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


@dataclass
class ReconPassiveSubagent:
    cfg: KryonsecConfig
    graph: EngagementGraph
    audit: AuditLog
    target: str
    # injectable for tests
    fetchers: list[Callable[[str], PassiveResult]] = field(
        default_factory=lambda: [crt_sh_subdomains]
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

            # Audit the CALL (tool, source, counts) — never any API key
            self.audit.write({
                "event": "passive_source_ok",
                "source": source,
                "found": len(result.subdomains),
                "new": len(fresh),
            })

        return SubagentResult(status="ok")
