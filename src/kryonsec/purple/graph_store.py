"""Persistence for the Security Graph (stm_nodes + stm_edges).

The graph itself (``purple.recon_passive.EngagementGraph``) is RAM-only and
knows nothing about the database. This module is the whole boundary: it
turns a graph into rows and rows back into a graph, so a future localhost
GUI can read an engagement after Kryonsec has exited.

Where the tables come from
--------------------------
``stm_nodes``/``stm_edges`` are *purple* tables. ``init_db`` only creates
them when purple storage is enabled for the backend: PostgreSQL by default
(the system of record, spec §10.1), or SQLite when the caller explicitly
passes ``include_purple=True``. That gate is deliberate and this module does
not change it — ``save_graph`` on a database without those tables fails with
a clear error rather than quietly creating engagement storage inside the
Copilot fallback database.

How an engagement gets here
---------------------------
``purple.runner.persist_graph`` calls ``save_graph`` after the engagement's
loop reaches HALT, and ``purple.runner.checkpoint_graph`` calls it again
after every state, so an interrupted run still has a graph on disk
(Phase 4.3). Both report any failure through the audit chain. Engagement
storage itself is chosen by ``storage.db.get_purple_engine``: the system of
record when ``DATABASE_URL`` is set, otherwise ``~/.kryonsec/purple.db`` —
the Copilot fallback database never receives engagement tables.

Redaction is applied here rather than in either caller, because this is the
only door into storage. ``_redacted`` walks each node and edge and replaces
secret-shaped strings with placeholders (spec §6.4, the same detector the
compaction path uses), so the engagement record never holds a credential —
including on the boundary checkpoints, which is the copy most likely to
outlive an interrupted run. Node ids, edges, provenance keys, statuses and
relationships are untouched: redaction only ever rewrites a *value* that
matched a secret pattern.

To read a graph back (what the localhost GUI will do)::

    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        graph = load_graph(session, engagement_id)

Nothing here touches the audit chain, human approval, the sandbox or the
tool allowlists; it is a storage boundary and nothing else.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..secrets import redact
from ..storage.models import StmEdge, StmNode
from .recon_passive import (
    GRAPH_FORMAT_VERSION,
    EngagementGraph,
    _json_size,
    _parse_timestamp,
)

__all__ = ["save_graph", "load_graph"]


def _redacted(value):
    """``value`` with secret-shaped strings replaced by placeholders.

    Recursive over the payload rather than over its serialized text: a
    private-key block holds real newlines here, which JSON would write as
    ``\\n`` escapes, so a pattern matched against the serialized form would
    miss it — and rewriting inside serialized text risks producing something
    that is no longer valid JSON.

    The placeholder map ``redact`` returns is deliberately discarded. It is
    placeholder -> real value, so keeping it anywhere near the record would
    defeat the point.
    """
    if isinstance(value, str):
        return redact(value)[0]
    if isinstance(value, list):
        return [_redacted(item) for item in value]
    if isinstance(value, dict):
        return {key: _redacted(item) for key, item in value.items()}
    return value


def _iso(value: datetime | None) -> str:
    """A database timestamp back to the graph's ISO-8601 UTC form."""
    if value is None:
        return datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def _subagent_of(node: dict) -> str:
    """``stm_nodes.subagent`` is NOT NULL; the graph records the origin in
    provenance, so read it from there."""
    provenance = node.get("provenance") or {}
    agent = provenance.get("agent")
    return agent if isinstance(agent, str) and agent else "unknown"


def save_graph(session: Session, graph: EngagementGraph) -> tuple[int, int]:
    """Write ``graph`` as the current state of its engagement.

    The engagement's existing rows are replaced, not merged: the graph is
    the current state of what Kryonsec knows, and a node that was removed
    from the graph must not linger in the table. History is not lost — it
    lives in the append-only audit chain, which this never touches.

    Replacing is also what makes the rows *one run's*. An engagement id can
    be reused (``--id``), so the second run's save replaces the first run's
    graph rather than mixing with it — but it also means the rows on disk
    belong to whichever run saved last, which is not necessarily the run the
    browser is describing. Phase 4.5B resolves that from the chain, not from
    a column: each caller announces a successful save with
    ``checkpoint_written`` / ``graph_persisted``, so the run whose segment
    holds the last successful announcement is the run the rows belong to
    (``memory.data``). Nothing here is run-keyed, and no schema change was
    needed to say whose graph this is.

    Replacing rather than merging is also what makes the write atomic, and
    that is the property the boundary checkpoints depend on: the whole
    delete-and-insert is one transaction committed once at the end, so a
    crash part-way through it rolls back to the previous graph rather than
    leaving half of a new one (Phase 4.3).

    Secret-shaped strings in node and edge values are replaced with
    placeholders on the way in — see ``_redacted``. Ids, types, labels that
    match no pattern, statuses and relationships are unchanged, so a graph
    with nothing sensitive in it round-trips byte for byte.

    Returns ``(node_count, edge_count)``. Commits before returning.
    """
    engagement_id = graph.engagement_id

    # Edges first: they hold foreign keys into stm_nodes.
    session.query(StmEdge).filter(
        StmEdge.engagement_id == engagement_id
    ).delete(synchronize_session=False)
    session.query(StmNode).filter(
        StmNode.engagement_id == engagement_id
    ).delete(synchronize_session=False)

    for raw in graph.nodes:
        # Redacted before anything is read out of it, so the canonical_key
        # fallback is derived from the label that is actually stored rather
        # than from one that no longer exists.
        node = _redacted(raw)
        properties = node.get("properties") or {}
        size = node.get("size_bytes", 0)
        if properties != (raw.get("properties") or {}):
            # Redaction shrank the payload, so the recorded size no longer
            # describes what is stored. Compared rather than recomputed
            # unconditionally: size_bytes is the graph's own accounting, and
            # rewriting it for every node would change rows that have
            # nothing to do with redaction.
            size = _json_size(properties, f"node {node['id']!r} properties")
        session.add(StmNode(
            id=node["id"],
            engagement_id=engagement_id,
            subagent=_subagent_of(node),
            node_type=node["node_type"],
            label=node["label"],
            properties=properties,
            size_bytes=size,
            created_at=_parse_timestamp(node.get("created_at")),
            canonical_key=node.get("canonical_key")
            or f"{node['node_type']}:{node['label']}",
            provenance=node.get("provenance") or {},
            status=node.get("status") or "observed",
        ))

    # Nodes must reach the table before the edges that reference them:
    # stm_edges has foreign keys into stm_nodes, and an explicit flush makes
    # that ordering ours rather than the unit-of-work's.
    session.flush()

    for raw in graph.edges:
        edge = _redacted(raw)
        properties = edge.get("properties") or {}
        size = edge.get("size_bytes", 0)
        if properties != (raw.get("properties") or {}):
            size = _json_size(properties, f"edge {edge['id']!r} properties")
        session.add(StmEdge(
            id=edge["id"],
            engagement_id=engagement_id,
            source_node_id=edge["source_node_id"],
            relationship=edge["relationship"],
            target_node_id=edge["target_node_id"],
            properties=properties,
            provenance=edge.get("provenance") or {},
            status=edge.get("status") or "observed",
            size_bytes=size,
            created_at=_parse_timestamp(edge.get("created_at")),
        ))

    session.commit()
    return len(graph.nodes), len(graph.edges)


def load_graph(session: Session, engagement_id: str) -> EngagementGraph:
    """Rebuild the graph an earlier run saved.

    Rows written before the graph columns existed (canonical_key,
    provenance, status are NULL) load fine — ``EngagementGraph.from_dict``
    fills the defaults in. A row that has gone inconsistent (an edge whose
    node is missing) raises rather than producing a broken graph.
    """
    node_rows = session.query(StmNode).filter(
        StmNode.engagement_id == engagement_id
    ).all()
    edge_rows = session.query(StmEdge).filter(
        StmEdge.engagement_id == engagement_id
    ).all()

    payload = {
        "version": GRAPH_FORMAT_VERSION,
        "engagement_id": engagement_id,
        "nodes": [
            {
                "id": row.id,
                "engagement_id": row.engagement_id,
                "node_type": row.node_type,
                "label": row.label,
                "canonical_key": row.canonical_key,
                "properties": row.properties or {},
                "provenance": row.provenance or {},
                "status": row.status,
                "size_bytes": row.size_bytes,
                "created_at": _iso(row.created_at),
            }
            for row in node_rows
        ],
        "edges": [
            {
                "id": row.id,
                "engagement_id": row.engagement_id,
                "source_node_id": row.source_node_id,
                "relationship": row.relationship,
                "target_node_id": row.target_node_id,
                "properties": row.properties or {},
                "provenance": row.provenance or {},
                "status": row.status,
                "size_bytes": row.size_bytes,
                "created_at": _iso(row.created_at),
            }
            for row in edge_rows
        ],
    }
    return EngagementGraph.from_dict(payload)
