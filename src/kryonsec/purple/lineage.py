"""Evidence lineage: validated relationships between the engagement's
evidence records (Phase 1C).

Every lineage chain the report reasons over is explicit on the graph:

    hypothesis --tested_by--> exploit_attempt --produced--> finding
    finding --verified_by--> verify_attempt (its independent check)

Lineage edges use **node ids**, not labels: labels can be rewritten by
hypothesis dedup, ids are stable across save/load. Only registered
relationship names are ever stored. Both ends must be nodes of the same
graph — an edge with one dangling end is refused (and audited by the
caller), never stored as a guess. Re-linking the same pair is
idempotent: :meth:`EngagementGraph.add_edge` returns the edge that is
already there, first observation wins.
"""

from __future__ import annotations

from .recon_passive import EngagementGraph, GraphError, RELATIONSHIP_TYPES


def link(
    graph: EngagementGraph,
    relationship: str,
    source: "dict | str",
    target: "dict | str",
    properties: "dict | None" = None,
    provenance: "dict | None" = None,
    on_refuse: "callable | None" = None,
) -> "dict | None":
    """Create one lineage edge — or None when it must not exist.

    Failures are deliberate, never silent:
    - an unregistered relationship name is refused (the graph's own
      registry is the authority),
    - either end resolving to nothing here is refused — a dangling
      lineage edge would be a record that names nothing real,
    - any validation/serialization problem is refused (the chain is
      append-only; a refused link is reported by the caller instead of
      breaking a running subagent).
    ``on_refuse`` gets the refusal reason so the caller can audit it.
    """
    if relationship not in RELATIONSHIP_TYPES:
        if on_refuse:
            on_refuse(f"relationship {relationship!r} is not registered")
        return None
    try:
        return graph.add_edge(
            source, relationship, target, properties,
            provenance=provenance or {"agent": "PROGRAM"},
        )
    except (GraphError, ValueError) as e:
        if on_refuse:
            on_refuse(str(e)[:200])
        return None
