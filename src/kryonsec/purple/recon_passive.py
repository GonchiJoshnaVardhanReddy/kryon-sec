"""RECON_PASSIVE subagent (spec v2.1.1 §4.2, Zone A).

Runs host-side. Zero packets to the target. Results land in the in-memory
engagement graph and every action lands in the audit chain.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from ..config import KryonsecConfig
from .audit import AuditLog
from .orchestrator import SubagentResult
from .zonea import (
    PassiveResult,
    crt_sh_subdomains,
    hackertarget_hostsearch,
    otx_passive_dns,
    rdap_whois,
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

    def github(domain: str) -> PassiveResult:
        from .zonea import github_recon
        return github_recon(domain, token=cfg.github_token)

    shodan.__name__ = "shodan"
    censys.__name__ = "censys"
    github.__name__ = "github"
    return [
        crt_sh_subdomains,
        wayback_subdomains,
        otx_passive_dns,
        ripestat_whois,
        ripestat_asn,
        rdap_whois,
        github,
        hackertarget_hostsearch,
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


# --------------------------------------------------------------------------
# Security graph (Phase 1 — SECURITY_GRAPH.md)
#
# Nodes stay plain dicts. report.py, hypothesize.py, verify.py and the UI
# all read node["label"] / node["properties"] directly, and that keeps
# working: Phase 1 only *adds* keys (id, canonical_key, provenance,
# status, created_at) and an edges list next to nodes.
#
# Persistence is NOT here. This class is RAM-only; to_dict/from_dict are
# the serialization boundary and purple.graph_store moves a graph in and
# out of stm_nodes/stm_edges.
# --------------------------------------------------------------------------

GRAPH_FORMAT_VERSION = 1

# Status vocabulary (SECURITY_GRAPH.md §7). A model-produced item must
# never silently look like a verified fact, so the value is explicit on
# every node and edge.
NODE_STATUSES: frozenset[str] = frozenset({
    "observed",   # a tool or the engagement config saw it
    "inferred",   # derived deterministically from other observations
    "proposed",   # a model suggested it — never presented as fact
    "validated",  # a verification step agreed with it
    "confirmed",  # independently reproduced
    "rejected",   # tested and found false
})

# Registered relationship types — a deliberately closed set. A model may
# *suggest* a relationship, but only a registered name is ever stored
# (SECURITY_GRAPH.md §10, §12). Adding one is a one-line change here.
# Sources: SECURITY_GRAPH.md §3, TEST_PLAN.md §4, NEXT_IMPLEMENTATION_STEP.md.
RELATIONSHIP_TYPES: frozenset[str] = frozenset({
    "accepts_parameter", "affects", "authenticates", "authorizes",
    "belongs_to", "bypasses", "can_reach", "calls", "caused_by", "contains",
    "creates_session", "depends_on", "derived_from", "enables", "exposes",
    "fixed_by", "has_port", "has_role", "has_service", "has_subdomain",
    "hosts", "leads_to", "observed_by", "produced", "reads_from",
    "related_to", "resolves_to", "retests", "routes_to", "runs_service",
    "supported_by", "targets", "tested_by", "uses_credential",
    "uses_framework", "uses_technology", "verified_by", "writes_to",
})

_RELATIONSHIP_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}\Z")


class GraphError(Exception):
    """Base class for every graph validation failure."""


class DuplicateNodeError(GraphError):
    """A node id was reused inside one engagement."""


class UnknownNodeError(GraphError):
    """An edge referenced a node this graph does not hold."""


class CrossEngagementError(GraphError):
    """A node or edge from another engagement was passed in."""


class InvalidRelationshipError(GraphError):
    """The relationship name is empty, malformed, or not registered."""


class InvalidStatusError(GraphError):
    """The status is not in NODE_STATUSES."""


class UnserializablePropertiesError(GraphError, TypeError):
    """Properties/provenance could not be encoded as JSON.

    Subclasses TypeError as well: the pre-Phase-1 code let json.dumps raise
    TypeError, so any caller catching that keeps working.
    """


class GraphFormatError(GraphError):
    """A serialized graph payload was malformed or an unsupported version."""


def _utc_now_iso() -> str:
    """ISO-8601 UTC, e.g. 2026-10-02T12:00:00Z (matches SECURITY_GRAPH.md §5)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _json_size(payload: dict, what: str) -> int:
    """Validate a payload is JSON-encodable and return its byte size.

    Same accounting the graph has always used for nodes (spec §4.5):
    length of the encoded JSON, computed in the app layer.
    """
    try:
        blob = json.dumps(payload)
    except (TypeError, ValueError) as exc:
        raise UnserializablePropertiesError(
            f"{what} is not JSON-serializable: {exc}"
        ) from exc
    return len(blob.encode())


def _node_id_of(ref: dict | str | None) -> str | None:
    """Best-effort id extraction — never raises (see _resolve for that)."""
    if isinstance(ref, str):
        return ref or None
    if isinstance(ref, dict):
        node_id = ref.get("id")
        return node_id if isinstance(node_id, str) and node_id else None
    return None


def _provenance_dict(owner: dict) -> dict:
    """The provenance mapping on a node/edge, repaired if it is missing.

    Only ``merge_node`` needs this: it is the one operation that mutates
    provenance after the fact, and it must not assume the field survived a
    hand-built node or an older serialized payload.
    """
    provenance = owner.get("provenance")
    if not isinstance(provenance, dict):
        provenance = {}
        owner["provenance"] = provenance
    return provenance


def _parse_timestamp(value) -> datetime:
    """Graph timestamps are ISO strings; fall back to 'now' on anything odd."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _normalize_node(raw: dict, engagement_id: str) -> dict:
    """Validate one serialized node and fill in anything Phase 1 added.

    Rows written before Phase 1 (or hand-built dicts) have no
    canonical_key/provenance/status — those get sane defaults rather than
    failing the load. id/node_type/label are identity and must be present.
    """
    if not isinstance(raw, dict):
        raise GraphFormatError("node entries must be objects")
    node_id = raw.get("id")
    if not isinstance(node_id, str) or not node_id:
        raise GraphFormatError("node is missing a non-empty string 'id'")
    node_type = raw.get("node_type")
    if not isinstance(node_type, str) or not node_type:
        raise GraphFormatError(f"node {node_id!r} has no node_type")
    label = raw.get("label")
    if not isinstance(label, str) or not label:
        raise GraphFormatError(f"node {node_id!r} has no label")
    raw_engagement = raw.get("engagement_id", engagement_id)
    if raw_engagement != engagement_id:
        raise CrossEngagementError(
            f"node {node_id!r} belongs to engagement {raw_engagement!r}, "
            f"not {engagement_id!r}"
        )
    properties = raw.get("properties") or {}
    if not isinstance(properties, dict):
        raise GraphFormatError(f"node {node_id!r} properties must be an object")
    computed_size = _json_size(properties, f"node {node_id!r} properties")
    provenance = raw.get("provenance") or {}
    if not isinstance(provenance, dict):
        raise GraphFormatError(f"node {node_id!r} provenance must be an object")
    _json_size(provenance, f"node {node_id!r} provenance")
    status = raw.get("status") or "observed"
    if status not in NODE_STATUSES:
        raise InvalidStatusError(
            f"node {node_id!r} has unknown status {status!r}"
        )
    size = raw.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        size = computed_size  # stored size is authoritative when it is sane
    return {
        "id": node_id,
        "engagement_id": engagement_id,
        "node_type": node_type,
        "label": label,
        "canonical_key": raw.get("canonical_key") or f"{node_type}:{label}",
        "properties": properties,
        "provenance": provenance,
        "status": status,
        "size_bytes": size,
        "created_at": raw.get("created_at") or _utc_now_iso(),
    }


def _normalize_edge(raw: dict, engagement_id: str) -> dict:
    """Validate one serialized edge (shape only — references are checked
    once every node is loaded)."""
    if not isinstance(raw, dict):
        raise GraphFormatError("edge entries must be objects")
    edge_id = raw.get("id")
    if not isinstance(edge_id, str) or not edge_id:
        raise GraphFormatError("edge is missing a non-empty string 'id'")
    relationship = raw.get("relationship")
    if relationship not in RELATIONSHIP_TYPES:
        raise InvalidRelationshipError(
            f"edge {edge_id!r} has unregistered relationship {relationship!r}"
        )
    source = raw.get("source_node_id")
    target = raw.get("target_node_id")
    for role, value in (("source", source), ("target", target)):
        if not isinstance(value, str) or not value:
            raise GraphFormatError(f"edge {edge_id!r} has no {role}_node_id")
    raw_engagement = raw.get("engagement_id", engagement_id)
    if raw_engagement != engagement_id:
        raise CrossEngagementError(
            f"edge {edge_id!r} belongs to engagement {raw_engagement!r}, "
            f"not {engagement_id!r}"
        )
    properties = raw.get("properties") or {}
    if not isinstance(properties, dict):
        raise GraphFormatError(f"edge {edge_id!r} properties must be an object")
    computed_size = _json_size(properties, f"edge {edge_id!r} properties")
    provenance = raw.get("provenance") or {}
    if not isinstance(provenance, dict):
        raise GraphFormatError(f"edge {edge_id!r} provenance must be an object")
    _json_size(provenance, f"edge {edge_id!r} provenance")
    status = raw.get("status") or "observed"
    if status not in NODE_STATUSES:
        raise InvalidStatusError(f"edge {edge_id!r} has unknown status {status!r}")
    size = raw.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        size = computed_size
    return {
        "id": edge_id,
        "engagement_id": engagement_id,
        "source_node_id": source,
        "relationship": relationship,
        "target_node_id": target,
        "properties": properties,
        "provenance": provenance,
        "status": status,
        "size_bytes": size,
        "created_at": raw.get("created_at") or _utc_now_iso(),
    }


@dataclass
class EngagementGraph:
    """In-memory engagement security graph: nodes plus relationships.

    RAM-only. ``to_dict``/``from_dict`` are the serialization boundary;
    ``purple.graph_store`` is what moves a graph in and out of the
    ``stm_nodes``/``stm_edges`` tables.

    Node dicts are unchanged in shape from before Phase 1 except for the
    added ``id``, ``canonical_key``, ``provenance``, ``status`` and
    ``created_at`` keys — every existing reader of ``node["label"]`` and
    ``node["properties"]`` keeps working untouched.
    """

    engagement_id: str
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)

    # -- nodes ------------------------------------------------------------

    def add_node(
        self,
        node_type: str,
        label: str,
        properties: dict | None = None,
        *,
        provenance: dict | None = None,
        status: str = "observed",
        node_id: str | None = None,
        canonical_key: str | None = None,
    ) -> dict:
        """Create a node and return it.

        The first three arguments are unchanged from before the graph
        existed — existing callers pass them positionally and are
        unaffected. Everything after them is keyword-only and optional.
        """
        if not isinstance(node_type, str) or not node_type:
            raise ValueError("node_type must be a non-empty string")
        if not isinstance(label, str) or not label:
            raise ValueError("label must be a non-empty string")
        if properties is not None and not isinstance(properties, dict):
            raise ValueError("properties must be a dict or None")
        if provenance is not None and not isinstance(provenance, dict):
            raise ValueError("provenance must be a dict or None")
        if status not in NODE_STATUSES:
            raise InvalidStatusError(f"unknown status {status!r}")

        props = properties or {}
        size = _json_size(props, "node properties")
        prov = provenance or {}
        _json_size(prov, "node provenance")

        nid = node_id if node_id is not None else str(uuid.uuid4())
        if not isinstance(nid, str) or not nid:
            raise ValueError("node_id must be a non-empty string")
        if self.get_node(nid) is not None:
            raise DuplicateNodeError(
                f"node id {nid!r} already exists in engagement "
                f"{self.engagement_id!r}"
            )

        node = {
            "id": nid,
            "engagement_id": self.engagement_id,
            "node_type": node_type,
            "label": label,
            "canonical_key": canonical_key or f"{node_type}:{label}",
            "properties": props,
            "provenance": prov,
            "status": status,
            "size_bytes": size,  # app-layer computed (spec §4.5)
            "created_at": _utc_now_iso(),
        }
        self.nodes.append(node)
        return node

    def get_node(self, node_id: str) -> dict | None:
        """The node with this id, or None. Never raises."""
        for node in self.nodes:
            if node.get("id") == node_id:
                return node
        return None

    def by_type(self, node_type: str) -> list[dict]:
        return [n for n in self.nodes if n["node_type"] == node_type]

    def remove_node(self, node: dict | str) -> None:
        """Drop a node (used for deterministic dedup — never used to
        rewrite history: the audit chain keeps the full record).

        Every edge touching the node goes with it, so the graph can never
        hold a dangling edge. Unknown nodes are ignored, as before.
        """
        node_id = _node_id_of(node)
        victim = self.get_node(node_id) if node_id else None
        if victim is None and isinstance(node, dict):
            # A hand-built dict with no id: the old equality-based removal.
            victim = next((n for n in self.nodes if n is node), None)
            node_id = victim.get("id") if victim else None
        if victim is None:
            return
        self.nodes.remove(victim)
        if node_id is not None:
            self.edges = [
                e for e in self.edges
                if e.get("source_node_id") != node_id
                and e.get("target_node_id") != node_id
            ]

    def merge_node(self, node: dict | str, into: dict | str) -> int:
        """Fold ``node`` into ``into`` — dedup that keeps the graph whole.

        The deterministic dedup in ``report.dedup_hypotheses`` used to call
        ``remove_node``, which cascades: every relationship the duplicate
        had observed was deleted along with it. That is data loss, not
        dedup — the merge is a bookkeeping decision and must not decide
        that a hypothesis was never tested.

        So: every edge touching ``node`` is *rewired* to ``into``, never
        dropped. Edges the rewire makes identical (same source, the same
        relationship, same target) are collapsed into one — the
        ``stm_edges`` unique constraint requires that anyway — and the
        collapsed edge's provenance is folded into the survivor rather
        than thrown away. The absorbed node's provenance is recorded on the
        survivor too.

        Returns the number of edge endpoints rewired. Merging a node into
        itself is a no-op.
        """
        victim = self._resolve_node(node, "node")
        survivor = self._resolve_node(into, "into")
        if victim is survivor:
            return 0

        victim_id, survivor_id = victim["id"], survivor["id"]
        rewired = 0
        kept: list[dict] = []
        index: dict[tuple[str, str, str], dict] = {}
        for edge in self.edges:
            src = edge["source_node_id"]
            dst = edge["target_node_id"]
            if src == victim_id:
                src = survivor_id
                rewired += 1
            if dst == victim_id:
                dst = survivor_id
                rewired += 1
            key = (src, edge["relationship"], dst)
            already = index.get(key)
            if already is not None:
                _provenance_dict(already).setdefault("merged_edges", []).append({
                    "edge_id": edge.get("id"),
                    "provenance": edge.get("provenance") or {},
                })
                continue
            edge["source_node_id"] = src
            edge["target_node_id"] = dst
            index[key] = edge
            kept.append(edge)
        self.edges = kept

        self._record_merge(survivor, victim)
        # Nothing references the victim any more, so this cascades nothing.
        self.remove_node(victim)
        return rewired

    def _record_merge(self, survivor: dict, victim: dict) -> None:
        """Keep the absorbed node's origin on the survivor.

        A merge is the one place the graph deliberately forgets a node, so
        its provenance — where the claim came from — is the part that must
        survive it.
        """
        _provenance_dict(survivor).setdefault("merged_nodes", []).append({
            "node_id": victim.get("id"),
            "node_type": victim.get("node_type"),
            "label": victim.get("label"),
            "status": victim.get("status"),
            "provenance": victim.get("provenance") or {},
        })

    # -- edges ------------------------------------------------------------

    def add_edge(
        self,
        source: dict | str,
        relationship: str,
        target: dict | str,
        properties: dict | None = None,
        *,
        provenance: dict | None = None,
        status: str = "observed",
        edge_id: str | None = None,
    ) -> dict:
        """Create a relationship between two nodes of this engagement.

        ``source``/``target`` are node dicts (as returned by ``add_node``)
        or node ids. Both must already exist here.

        Duplicate edges are idempotent: adding the same
        (source, relationship, target) twice returns the edge that is
        already there and leaves it untouched — the first observation
        wins. That matches the unique constraint on ``stm_edges``, so the
        in-memory graph and the database can never disagree about which
        edges exist.
        """
        src = self._resolve_node(source, "source")
        dst = self._resolve_node(target, "target")
        self._validate_relationship(relationship)
        if status not in NODE_STATUSES:
            raise InvalidStatusError(f"unknown status {status!r}")

        duplicate = self._find_edge(src["id"], relationship, dst["id"])
        if duplicate is not None:
            return duplicate

        props = properties or {}
        size = _json_size(props, "edge properties")
        prov = provenance or {}
        _json_size(prov, "edge provenance")

        eid = edge_id if edge_id is not None else str(uuid.uuid4())
        if not isinstance(eid, str) or not eid:
            raise ValueError("edge_id must be a non-empty string")
        if self.get_edge(eid) is not None:
            raise GraphError(f"edge id {eid!r} already exists")

        edge = {
            "id": eid,
            "engagement_id": self.engagement_id,
            "source_node_id": src["id"],
            "relationship": relationship,
            "target_node_id": dst["id"],
            "properties": props,
            "provenance": prov,
            "status": status,
            "size_bytes": size,
            "created_at": _utc_now_iso(),
        }
        self.edges.append(edge)
        return edge

    def get_edge(self, edge_id: str) -> dict | None:
        """The edge with this id, or None. Never raises."""
        for edge in self.edges:
            if edge.get("id") == edge_id:
                return edge
        return None

    def find_edges(
        self,
        relationship: str | None = None,
        source: dict | str | None = None,
        target: dict | str | None = None,
    ) -> list[dict]:
        """Edges matching any combination of relationship/source/target.

        All three filters are optional and combine with AND. An
        unresolvable source or target simply matches nothing.
        """
        if relationship is not None:
            self._validate_relationship(relationship)
        source_id = _node_id_of(source) if source is not None else None
        target_id = _node_id_of(target) if target is not None else None
        return [
            e for e in self.edges
            if (relationship is None or e["relationship"] == relationship)
            and (source_id is None or e["source_node_id"] == source_id)
            and (target_id is None or e["target_node_id"] == target_id)
        ]

    def has_edge(
        self,
        source: dict | str,
        relationship: str,
        target: dict | str,
    ) -> bool:
        """True when this exact relationship exists. Never raises."""
        source_id = _node_id_of(source)
        target_id = _node_id_of(target)
        if source_id is None or target_id is None:
            return False
        return self._find_edge(source_id, relationship, target_id) is not None

    def neighbors(
        self,
        node: dict | str,
        relationship: str | None = None,
        direction: str = "both",
    ) -> list[dict]:
        """Adjacent nodes, optionally narrowed to one relationship.

        ``direction`` is "out" (edges leaving the node), "in" (edges
        arriving), or "both". Each neighbor appears once. Raises
        UnknownNodeError for a node this graph does not hold, so a typo
        cannot silently look like "no neighbors".
        """
        node_id = self._resolve_node(node, "node")["id"]
        if direction not in ("out", "in", "both"):
            raise ValueError("direction must be 'out', 'in' or 'both'")
        if relationship is not None:
            self._validate_relationship(relationship)

        found: list[dict] = []
        seen: set[str] = set()
        for edge in self.edges:
            if relationship is not None and edge["relationship"] != relationship:
                continue
            other: str | None = None
            if direction in ("out", "both") and edge["source_node_id"] == node_id:
                other = edge["target_node_id"]
            if other is None and direction in ("in", "both") \
                    and edge["target_node_id"] == node_id:
                other = edge["source_node_id"]
            if other is None or other in seen:
                continue
            seen.add(other)
            neighbor = self.get_node(other)
            if neighbor is not None:
                found.append(neighbor)
        return found

    # -- size accounting ---------------------------------------------------

    @property
    def size_bytes(self) -> int:
        """Sum of node payload sizes — unchanged meaning (spec §4.5).

        Edges are accounted separately so the existing budget guard that
        reads this number keeps behaving exactly as before.
        """
        return sum(n.get("size_bytes", 0) for n in self.nodes)

    @property
    def edges_size_bytes(self) -> int:
        return sum(e.get("size_bytes", 0) for e in self.edges)

    @property
    def total_size_bytes(self) -> int:
        """Nodes plus edges — the whole graph's footprint."""
        return self.size_bytes + self.edges_size_bytes

    # -- serialization -----------------------------------------------------

    def to_dict(self) -> dict:
        """A deep-copied, JSON-safe snapshot (the GUI's read shape)."""
        return {
            "version": GRAPH_FORMAT_VERSION,
            "engagement_id": self.engagement_id,
            "nodes": copy.deepcopy(self.nodes),
            "edges": copy.deepcopy(self.edges),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EngagementGraph":
        """Rebuild a graph from ``to_dict`` output.

        Validates everything the writer validated — a corrupt or
        hand-edited payload fails loudly instead of producing a graph
        that later blows up somewhere unrelated.
        """
        if not isinstance(data, dict):
            raise GraphFormatError("graph payload must be an object")
        version = data.get("version", GRAPH_FORMAT_VERSION)
        if not isinstance(version, int) or isinstance(version, bool):
            raise GraphFormatError(f"graph version must be an int, got {version!r}")
        if version > GRAPH_FORMAT_VERSION:
            raise GraphFormatError(
                f"graph format version {version} is newer than this build "
                f"understands ({GRAPH_FORMAT_VERSION})"
            )
        engagement_id = data.get("engagement_id")
        if not isinstance(engagement_id, str) or not engagement_id:
            raise GraphFormatError("graph payload has no engagement_id")
        raw_nodes = data.get("nodes") or []
        raw_edges = data.get("edges") or []
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            raise GraphFormatError("graph nodes/edges must be lists")

        graph = cls(engagement_id=engagement_id)
        graph.nodes = [_normalize_node(raw, engagement_id) for raw in raw_nodes]
        ids = [n["id"] for n in graph.nodes]
        if len(ids) != len(set(ids)):
            raise DuplicateNodeError(
                f"serialized graph repeats a node id in engagement "
                f"{engagement_id!r}"
            )
        graph.edges = [_normalize_edge(raw, engagement_id) for raw in raw_edges]
        edge_ids = [e["id"] for e in graph.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise GraphError(
                f"serialized graph repeats an edge id in engagement "
                f"{engagement_id!r}"
            )
        graph._validate_references()
        return graph

    # -- internals ---------------------------------------------------------

    def _validate_relationship(self, relationship: str) -> None:
        if not isinstance(relationship, str) or not relationship:
            raise InvalidRelationshipError("relationship must be a non-empty string")
        if not _RELATIONSHIP_RE.match(relationship):
            raise InvalidRelationshipError(
                f"relationship {relationship!r} must be lowercase "
                "snake_case (a-z, 0-9, _)"
            )
        if relationship not in RELATIONSHIP_TYPES:
            raise InvalidRelationshipError(
                f"relationship {relationship!r} is not registered; add it "
                "to RELATIONSHIP_TYPES to accept it"
            )

    def _resolve_node(self, ref: dict | str, role: str) -> dict:
        """Resolve a node dict or id to a node of this engagement."""
        if isinstance(ref, dict):
            ref_engagement = ref.get("engagement_id")
            if ref_engagement is not None and ref_engagement != self.engagement_id:
                raise CrossEngagementError(
                    f"edge {role} belongs to engagement {ref_engagement!r}, "
                    f"not {self.engagement_id!r}"
                )
            node_id = _node_id_of(ref)
        else:
            node_id = _node_id_of(ref)
        if node_id is None:
            raise UnknownNodeError(
                f"edge {role} must be a node dict or a non-empty node id"
            )
        node = self.get_node(node_id)
        if node is None:
            raise UnknownNodeError(
                f"edge {role} {node_id!r} is not a node in engagement "
                f"{self.engagement_id!r}"
            )
        return node

    def _find_edge(
        self, source_id: str, relationship: str, target_id: str
    ) -> dict | None:
        for edge in self.edges:
            if (
                edge["source_node_id"] == source_id
                and edge["relationship"] == relationship
                and edge["target_node_id"] == target_id
            ):
                return edge
        return None

    def _validate_references(self) -> None:
        """Every edge must point at two nodes that are actually here."""
        known = {n["id"] for n in self.nodes}
        for edge in self.edges:
            for role, key in (("source", "source_node_id"),
                              ("target", "target_node_id")):
                node_id = edge[key]
                if node_id not in known:
                    raise UnknownNodeError(
                        f"edge {edge['id']!r} {role} {node_id!r} is not a node "
                        f"in engagement {self.engagement_id!r}"
                    )



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

        target_node = self.graph.add_node(
            node_type="target",
            label=self.target,
            properties={"source": "engagement_config"},
            provenance={
                "source_type": "config",
                "source": "engagement_config",
                "agent": "RECON_PASSIVE",
            },
        )

        total_new = 0
        for fetcher in self.fetchers:
            source = getattr(fetcher, "__name__", str(fetcher))
            # Recorded before the fetch, not after: the ok/failed/skipped
            # events below say how it ended, but only this says it began,
            # so the console can show which source is running right now.
            # Observability only — no source's behaviour depends on it.
            self.audit.write({
                "event": "passive_source_start",
                "source": source,
            })
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
                subdomain_node = self.graph.add_node(
                    node_type="subdomain",
                    label=subdomain,
                    properties={"source": result.source},
                    provenance={
                        "source_type": "tool",
                        "source": result.source,
                        "agent": "RECON_PASSIVE",
                    },
                )
                # Phase 1: the one relationship passive recon actually
                # observes — the target has this subdomain, because a
                # source returned it under the target's own domain (the
                # scope check above). Nothing else is inferred here.
                self.graph.add_edge(
                    source=target_node,
                    relationship="has_subdomain",
                    target=subdomain_node,
                    properties={"source": result.source},
                    provenance={
                        "source_type": "tool",
                        "source": result.source,
                        "agent": "RECON_PASSIVE",
                    },
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

        # cloud asset discovery (Phase 8): a LOCAL pass over everything the
        # real sources collected — zero fetches, so it runs last, source-shaped
        # purely to flow through the same audit trail
        from .zonea import cloud_asset_notes
        collected = [n["label"] for n in self.graph.by_type("subdomain")]
        cloud = cloud_asset_notes(collected)
        if cloud.notes:
            self.graph.add_node(
                node_type="osint_note",
                label=cloud.source,
                properties={"notes": cloud.notes},
            )
        self.audit.write({
            "event": "passive_source_ok",
            "source": cloud.source,
            "found": 0,
            "new": 0,
            "paths": 0,
            "notes": len(cloud.notes),
        })

        return SubagentResult(status="ok")
