"""Tests for the Security Graph foundation (Phase 1 — SECURITY_GRAPH.md).

Two things matter most here:

* the phase is *additive* — graph.nodes, add_node, by_type, remove_node and
  the node dict keys all keep working exactly as they did, because eight
  subagents and the report read them directly; and
* a graph that is written down and read back is the same graph, because
  that is what a post-engagement GUI will depend on.
"""

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.graph_store import load_graph, save_graph
from kryonsec.purple.recon_passive import (
    RELATIONSHIP_TYPES,
    CrossEngagementError,
    DuplicateNodeError,
    EngagementGraph,
    GraphFormatError,
    InvalidRelationshipError,
    InvalidStatusError,
    UnknownNodeError,
    UnserializablePropertiesError,
)
from kryonsec.storage import get_session, init_db, reset_engine


@pytest.fixture()
def graph():
    return EngagementGraph(engagement_id="e-graph")


def _linked(graph):
    """A minimal graph with one edge — the shape most tests start from."""
    target = graph.add_node("target", "example.com")
    service = graph.add_node(
        "service", "example.com:443/tcp", {"port": 443, "proto": "tcp"}
    )
    edge = graph.add_edge(target, "has_service", service,
                          {"source": "nmap"})
    return target, service, edge


# --- 1. construction --------------------------------------------------------

def test_graph_construction():
    g = EngagementGraph(engagement_id="e1")
    assert g.engagement_id == "e1"
    assert g.nodes == []
    assert g.edges == []
    # positional, as the architecture note and existing callers use it
    assert EngagementGraph("e2").engagement_id == "e2"


def test_empty_graph_behavior(graph):
    assert graph.nodes == []
    assert graph.edges == []
    assert graph.size_bytes == 0
    assert graph.edges_size_bytes == 0
    assert graph.total_size_bytes == 0
    assert graph.by_type("target") == []
    assert graph.find_edges() == []
    assert graph.get_node("nope") is None
    assert graph.get_edge("nope") is None
    with pytest.raises(UnknownNodeError):
        graph.neighbors("nope")
    # an empty graph still round-trips
    assert EngagementGraph.from_dict(graph.to_dict()).to_dict() == graph.to_dict()


# --- 2-4. nodes -------------------------------------------------------------

def test_node_creation(graph):
    node = graph.add_node("target", "example.com", {"source": "engagement_config"})
    assert node["node_type"] == "target"
    assert node["label"] == "example.com"
    assert node["properties"] == {"source": "engagement_config"}
    assert node["engagement_id"] == "e-graph"
    assert node["status"] == "observed"
    assert node["canonical_key"] == "target:example.com"
    assert node["created_at"].endswith("Z")
    assert graph.nodes == [node]

    # two positional arguments still work (test_purple_ui.py relies on it)
    bare = graph.add_node("target", "other.example")
    assert bare["properties"] == {}


def test_node_ids_are_stable_and_unique(graph):
    first = graph.add_node("target", "example.com")
    second = graph.add_node("target", "example.com")  # same label, new node

    assert first["id"] and second["id"]
    assert first["id"] != second["id"], "labels are not identity"

    # the id never changes under later activity
    before = first["id"]
    graph.add_node("subdomain", "www.example.com")
    graph.add_edge(second, "related_to", first)
    assert first["id"] == before

    # an explicitly provided id is honoured, and cannot be reused
    explicit = graph.add_node("target", "third.example", node_id="fixed-id")
    assert explicit["id"] == "fixed-id"
    with pytest.raises(DuplicateNodeError):
        graph.add_node("target", "fourth.example", node_id="fixed-id")


def test_node_lookup(graph):
    node = graph.add_node("subdomain", "www.example.com")
    assert graph.get_node(node["id"]) is node
    assert graph.get_node("missing") is None


def test_node_properties_are_preserved(graph):
    props = {"port": 443, "tls": True, "ciphers": ["a", "b"], "nested": {"k": 1}}
    node = graph.add_node("service", "example.com:443/tcp", dict(props))
    assert node["properties"] == props
    # the caller's dict is the stored dict, exactly as before Phase 1 —
    # agents mutate properties in place after adding a node
    node["properties"]["port"] = 8443
    assert graph.by_type("service")[0]["properties"]["port"] == 8443


def test_node_provenance_is_preserved(graph):
    provenance = {
        "source_type": "tool",
        "source": "httpx",
        "agent": "RECON_ACTIVE",
        "observation_id": "obs-1",
    }
    node = graph.add_node("web_endpoint", "https://example.com",
                          provenance=provenance)
    assert node["provenance"] == provenance
    assert node["provenance"]["agent"] == "RECON_ACTIVE"


def test_proposed_nodes_are_distinguishable_from_observed(graph):
    """SECURITY_GRAPH.md §7: model output must not look like a fact."""
    graph.add_node("hypothesis", "H1", status="proposed",
                   provenance={"source_type": "model", "source": "HYPOTHESIZE"})
    observed = graph.add_node("target", "example.com")
    assert graph.by_type("hypothesis")[0]["status"] == "proposed"
    assert observed["status"] == "observed"


# --- 5-8. edges -------------------------------------------------------------

def test_edge_creation(graph):
    target, service, edge = _linked(graph)
    assert edge["source_node_id"] == target["id"]
    assert edge["target_node_id"] == service["id"]
    assert edge["relationship"] == "has_service"
    assert edge["engagement_id"] == "e-graph"
    assert edge["properties"] == {"source": "nmap"}
    assert edge["status"] == "observed"
    assert edge["created_at"].endswith("Z")
    assert graph.edges == [edge]


def test_edge_lookup(graph):
    target, service, edge = _linked(graph)
    assert graph.get_edge(edge["id"]) is edge
    assert graph.get_edge("missing") is None
    assert graph.has_edge(target, "has_service", service) is True
    assert graph.has_edge(service, "has_service", target) is False
    assert graph.has_edge(target, "has_service", "not-a-node") is False


def test_neighbors(graph):
    target, service, _ = _linked(graph)
    endpoint = graph.add_node("web_endpoint", "https://example.com")
    graph.add_edge(service, "exposes", endpoint)

    assert graph.neighbors(target) == [service]
    assert graph.neighbors(service) == [target, endpoint]
    assert graph.neighbors(service, direction="out") == [endpoint]
    assert graph.neighbors(service, direction="in") == [target]
    assert graph.neighbors(endpoint, direction="out") == []
    # a node with nothing attached
    lonely = graph.add_node("osint_note", "note")
    assert graph.neighbors(lonely) == []


def test_relationship_filtering(graph):
    target, service, _ = _linked(graph)
    endpoint = graph.add_node("web_endpoint", "https://example.com")
    graph.add_edge(target, "exposes", endpoint)
    graph.add_edge(target, "has_service", endpoint)   # same pair, other name

    assert len(graph.find_edges()) == 3
    assert [e["relationship"] for e in graph.find_edges(relationship="has_service")] \
        == ["has_service", "has_service"]
    assert graph.find_edges(relationship="exposes")[0]["target_node_id"] == endpoint["id"]
    assert len(graph.find_edges(source=target)) == 3
    assert len(graph.find_edges(target=service)) == 1
    assert graph.find_edges(target=target) == []      # nothing points at it
    assert graph.find_edges(source=service) == []
    assert graph.neighbors(target, relationship="exposes") == [endpoint]
    assert graph.neighbors(target, relationship="runs_service") == []


# --- 9-11. reference validation --------------------------------------------

def test_unknown_source_rejected(graph):
    service = graph.add_node("service", "example.com:443/tcp")
    with pytest.raises(UnknownNodeError):
        graph.add_edge("no-such-node", "has_service", service)
    with pytest.raises(UnknownNodeError):
        graph.add_edge(None, "has_service", service)
    assert graph.edges == []


def test_unknown_target_rejected(graph):
    target = graph.add_node("target", "example.com")
    with pytest.raises(UnknownNodeError):
        graph.add_edge(target, "has_service", "no-such-node")
    assert graph.edges == []


def test_cross_engagement_rejected():
    a = EngagementGraph(engagement_id="e-a")
    b = EngagementGraph(engagement_id="e-b")
    node_a = a.add_node("target", "a.example")
    node_b = b.add_node("target", "b.example")

    with pytest.raises(CrossEngagementError):
        a.add_edge(node_a, "related_to", node_b)
    with pytest.raises(CrossEngagementError):
        a.add_edge(node_b, "related_to", node_a)
    # ...and a b node id is simply not known here
    with pytest.raises(UnknownNodeError):
        a.add_edge(node_a, "related_to", node_b["id"])
    assert a.edges == [] and b.edges == []


def test_invalid_relationship_rejected(graph):
    target, service, _ = _linked(graph)
    for bad in ("", "Has Service", "has-service", "1starts_with_digit", None):
        with pytest.raises(InvalidRelationshipError):
            graph.add_edge(target, bad, service)
    with pytest.raises(InvalidRelationshipError):
        graph.add_edge(target, "not_a_registered_relationship", service)
    # filtering on an unregistered name is a mistake too, not an empty result
    with pytest.raises(InvalidRelationshipError):
        graph.find_edges(relationship="not_a_registered_relationship")


def test_registered_relationships_cover_the_design_contract():
    for name in ("has_subdomain", "has_port", "runs_service", "exposes",
                 "targets", "supported_by", "tested_by", "verified_by",
                 "caused_by", "produced", "leads_to", "fixed_by"):
        assert name in RELATIONSHIP_TYPES


def test_invalid_status_rejected(graph):
    with pytest.raises(InvalidStatusError):
        graph.add_node("target", "example.com", status="definitely")
    target = graph.add_node("target", "example.com")
    service = graph.add_node("service", "example.com:443/tcp")
    with pytest.raises(InvalidStatusError):
        graph.add_edge(target, "has_service", service, status="definitely")


def test_bad_node_arguments_rejected(graph):
    with pytest.raises(ValueError):
        graph.add_node("", "label")
    with pytest.raises(ValueError):
        graph.add_node("target", "")
    with pytest.raises(ValueError):
        graph.add_node("target", "example.com", properties=["not", "a", "dict"])
    assert graph.nodes == []


def test_unserializable_properties_rejected(graph):
    with pytest.raises(UnserializablePropertiesError):
        graph.add_node("target", "example.com", {"bad": {1, 2, 3}})
    # ...and it is still a TypeError, which is what the old code raised
    with pytest.raises(TypeError):
        graph.add_node("target", "example.com", {"bad": {1, 2, 3}})
    target = graph.add_node("target", "example.com")
    service = graph.add_node("service", "example.com:443/tcp")
    with pytest.raises(UnserializablePropertiesError):
        graph.add_edge(target, "has_service", service, {"bad": object()})
    assert graph.edges == []


# --- 12-15. backwards compatibility ----------------------------------------

def test_graph_nodes_still_a_list_of_plain_dicts(graph):
    """report.py:162 iterates graph.nodes and mutates node["label"]."""
    target, service, _ = _linked(graph)
    assert isinstance(graph.nodes, list)
    assert all(isinstance(n, dict) for n in graph.nodes)
    for node in graph.nodes:
        # every key that existed before Phase 1, with the same meaning
        for key in ("engagement_id", "node_type", "label", "properties",
                    "size_bytes"):
            assert key in node
    graph.nodes[0]["label"] = "renamed.example"      # mutate in place
    assert graph.by_type("target")[0]["label"] == "renamed.example"


def test_by_type_compatibility(graph):
    graph.add_node("subdomain", "a.example")
    graph.add_node("subdomain", "b.example")
    graph.add_node("target", "example.com")
    assert len(graph.by_type("subdomain")) == 2
    assert graph.by_type("nothing-uses-this") == []
    assert {n["label"] for n in graph.by_type("subdomain")} == {"a.example", "b.example"}


def test_remove_node_compatibility(graph):
    target, service, edge = _linked(graph)
    graph.remove_node(service)                 # by dict, as report.py calls it
    assert service not in graph.nodes
    assert graph.by_type("service") == []
    graph.remove_node(target)                  # by dict again
    assert graph.nodes == []
    # removing something that is not there stays a no-op, as before
    graph.remove_node(service)
    graph.remove_node("not-an-id")
    graph.remove_node({"node_type": "ghost", "label": "x"})


def test_removing_a_node_removes_its_edges(graph):
    """No dangling edges — in the graph or in the database."""
    target, service, edge = _linked(graph)
    endpoint = graph.add_node("web_endpoint", "https://example.com")
    graph.add_edge(service, "exposes", endpoint)
    assert len(graph.edges) == 2

    graph.remove_node(service)
    assert graph.edges == []
    assert graph.find_edges(source=target) == []

    # removing by id works too
    graph.add_edge(target, "exposes", endpoint)
    graph.remove_node(endpoint["id"])
    assert graph.edges == []


# --- 18. serialization ------------------------------------------------------

def test_serialization_round_trip(graph):
    target, service, edge = _linked(graph)
    graph.add_node("hypothesis", "H1", {"tools": ["sqlmap"]},
                   provenance={"source_type": "model", "agent": "HYPOTHESIZE"},
                   status="proposed")
    graph.remove_node(target)
    fresh = graph.add_node("target", "example.com")
    graph.add_edge(fresh, "has_service", service, {"source": "nmap"})

    payload = graph.to_dict()
    assert payload["version"] == 1
    assert payload["engagement_id"] == "e-graph"
    assert len(payload["nodes"]) == len(graph.nodes)
    assert len(payload["edges"]) == len(graph.edges)

    restored = EngagementGraph.from_dict(payload)
    assert restored.to_dict() == payload
    # a deep copy: editing the snapshot cannot reach back into the graph
    payload["nodes"][0]["label"] = "tampered"
    assert graph.nodes[0]["label"] != "tampered"


def test_deserialization_validates(graph):
    _linked(graph)
    payload = graph.to_dict()

    with pytest.raises(GraphFormatError):
        EngagementGraph.from_dict("not a dict")
    with pytest.raises(GraphFormatError):
        EngagementGraph.from_dict({**payload, "version": 999})
    with pytest.raises(GraphFormatError):
        EngagementGraph.from_dict({**payload, "engagement_id": ""})
    with pytest.raises(GraphFormatError):
        EngagementGraph.from_dict({**payload, "nodes": [{"node_type": "target"}]})

    # an edge whose node is gone must not load as a broken graph
    broken = graph.to_dict()
    broken["nodes"] = []
    with pytest.raises(UnknownNodeError):
        EngagementGraph.from_dict(broken)

    # duplicate ids are caught
    doubled = graph.to_dict()
    doubled["nodes"] = [dict(doubled["nodes"][0]), dict(doubled["nodes"][0])]
    doubled["edges"] = []
    with pytest.raises(DuplicateNodeError):
        EngagementGraph.from_dict(doubled)

    # cross-engagement payloads are caught
    foreign = graph.to_dict()
    foreign["nodes"][0]["engagement_id"] = "e-other"
    with pytest.raises(CrossEngagementError):
        EngagementGraph.from_dict(foreign)


def test_deserialization_tolerates_pre_phase_1_nodes():
    """A row written before canonical_key/provenance/status existed."""
    legacy = {
        "version": 1,
        "engagement_id": "e-old",
        "nodes": [{
            "id": "n1",
            "engagement_id": "e-old",
            "node_type": "target",
            "label": "example.com",
            "properties": {"source": "engagement_config"},
            "size_bytes": 29,
        }],
        "edges": [],
    }
    restored = EngagementGraph.from_dict(legacy)
    node = restored.nodes[0]
    assert node["canonical_key"] == "target:example.com"
    assert node["provenance"] == {}
    assert node["status"] == "observed"
    assert node["created_at"].endswith("Z")


# --- 19-21. accounting, duplicates -----------------------------------------

def test_size_accounting(graph):
    empty = graph.add_node("engagement_note", "note")
    assert graph.size_bytes == empty["size_bytes"]

    heavy = graph.add_node("service", "example.com:443/tcp",
                           {"port": 443, "banner": "x" * 100})
    assert heavy["size_bytes"] > empty["size_bytes"]
    assert graph.size_bytes == empty["size_bytes"] + heavy["size_bytes"]

    edge = graph.add_edge(empty, "related_to", heavy, {"source": "test"})
    assert graph.edges_size_bytes == edge["size_bytes"]
    assert graph.total_size_bytes == graph.size_bytes + edge["size_bytes"]
    # the property budget guard reads size_bytes and must not start seeing
    # edges in it
    assert graph.size_bytes == sum(n["size_bytes"] for n in graph.nodes)


def test_duplicate_edge_behavior(graph):
    target, service, edge = _linked(graph)

    again = graph.add_edge(target, "has_service", service,
                           {"source": "rustscan"})
    assert again is edge, "the existing edge is returned"
    assert len(graph.edges) == 1
    assert graph.edges[0]["properties"] == {"source": "nmap"}, "first wins"

    # the same nodes under a different relationship are a different edge
    graph.add_edge(target, "runs_service", service)
    assert len(graph.edges) == 2
    # so is the reverse direction
    graph.add_edge(service, "has_service", target)
    assert len(graph.edges) == 3


# --- 22. persistence --------------------------------------------------------

@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home")
    config.database_url = f"sqlite:///{tmp_path / 'graph.db'}"
    yield config
    reset_engine()


def _normalized(g: EngagementGraph) -> dict:
    """to_dict with nodes/edges sorted — row order is not part of the contract."""
    payload = g.to_dict()
    payload["nodes"] = sorted(payload["nodes"], key=lambda n: n["id"])
    payload["edges"] = sorted(payload["edges"], key=lambda e: e["id"])
    return payload


def test_persistence_round_trip(cfg):
    init_db(cfg, include_purple=True)

    graph = EngagementGraph(engagement_id="e-persist")
    target = graph.add_node("target", "example.com",
                            provenance={"source_type": "config",
                                        "agent": "RECON_PASSIVE"})
    service = graph.add_node("service", "example.com:443/tcp",
                             {"port": 443}, status="observed",
                             provenance={"source_type": "tool",
                                         "source": "nmap",
                                         "agent": "RECON_ACTIVE"})
    graph.add_edge(target, "has_service", service, {"source": "nmap"},
                   provenance={"source_type": "tool", "source": "nmap",
                               "agent": "RECON_ACTIVE"})

    with get_session(cfg) as session:
        assert save_graph(session, graph) == (2, 1)

    with get_session(cfg) as session:
        loaded = load_graph(session, "e-persist")

    assert _normalized(loaded) == _normalized(graph)
    # the specific things a GUI needs are intact
    assert loaded.by_type("target")[0]["label"] == "example.com"
    assert loaded.edges[0]["relationship"] == "has_service"
    assert loaded.find_edges(relationship="has_service")[0]["provenance"]["source"] == "nmap"
    assert loaded.size_bytes == graph.size_bytes


def test_persistence_replaces_previous_state(cfg):
    """A node dropped from the graph must not linger in the table."""
    init_db(cfg, include_purple=True)

    graph = EngagementGraph(engagement_id="e-replace")
    target = graph.add_node("target", "example.com")
    service = graph.add_node("service", "example.com:443/tcp")
    graph.add_edge(target, "has_service", service)
    with get_session(cfg) as session:
        save_graph(session, graph)

    graph.remove_node(service)
    with get_session(cfg) as session:
        assert save_graph(session, graph) == (1, 0)

    with get_session(cfg) as session:
        loaded = load_graph(session, "e-replace")
    assert [n["node_type"] for n in loaded.nodes] == ["target"]
    assert loaded.edges == []


def test_persistence_is_per_engagement(cfg):
    init_db(cfg, include_purple=True)
    first = EngagementGraph(engagement_id="e-1")
    first.add_node("target", "one.example")
    second = EngagementGraph(engagement_id="e-2")
    second.add_node("target", "two.example")

    with get_session(cfg) as session:
        save_graph(session, first)
        save_graph(session, second)

    with get_session(cfg) as session:
        assert load_graph(session, "e-1").by_type("target")[0]["label"] == "one.example"
        assert load_graph(session, "e-2").by_type("target")[0]["label"] == "two.example"
        assert load_graph(session, "e-none").nodes == []


def test_persistence_needs_purple_storage(cfg):
    """The SQLite fallback has no engagement tables unless asked for them —
    saving into the Copilot database must fail loudly, not create them."""
    init_db(cfg, include_purple=False)
    graph = EngagementGraph(engagement_id="e-nope")
    graph.add_node("target", "example.com")
    with get_session(cfg) as session:
        with pytest.raises(Exception):
            save_graph(session, graph)


# --- agent integration (TASK E) --------------------------------------------

def test_passive_recon_links_target_to_subdomains(tmp_path):
    """RECON_PASSIVE records the one relationship it actually observes."""
    from kryonsec.purple.audit import AuditLog
    from kryonsec.purple.recon_passive import ReconPassiveSubagent
    from kryonsec.purple.zonea import PassiveResult

    def fake_crt(domain):
        return PassiveResult(source="crt.sh", subdomains=[
            "target-corp.com", "www.target-corp.com", "api.target-corp.com",
        ])

    cfg = KryonsecConfig()
    graph = EngagementGraph(engagement_id="e-recon")
    sub = ReconPassiveSubagent(
        cfg=cfg, graph=graph, audit=AuditLog(tmp_path / "audit.jsonl"),
        target="target-corp.com", fetchers=[fake_crt],
    )
    assert sub.run().status == "ok"

    target = graph.by_type("target")[0]
    subdomains = graph.by_type("subdomain")
    assert len(subdomains) == 2

    edges = graph.find_edges(relationship="has_subdomain")
    assert len(edges) == 2
    assert {e["source_node_id"] for e in edges} == {target["id"]}
    assert {e["target_node_id"] for e in edges} == {n["id"] for n in subdomains}
    assert graph.neighbors(target, relationship="has_subdomain") == subdomains

    first = edges[0]
    assert first["provenance"] == {
        "source_type": "tool", "source": "crt.sh", "agent": "RECON_PASSIVE",
    }
    assert first["status"] == "observed"
    # passive recon still sends zero packets — this is the same local run
    assert graph.neighbors(target, direction="in") == []


def test_passive_recon_edge_is_idempotent_across_sources(tmp_path):
    """Two sources reporting the same subdomain must not double the edge."""
    from kryonsec.purple.audit import AuditLog
    from kryonsec.purple.recon_passive import ReconPassiveSubagent
    from kryonsec.purple.zonea import PassiveResult

    def source_a(domain):
        return PassiveResult(source="a", subdomains=["www.target-corp.com"])

    def source_b(domain):
        return PassiveResult(source="b", subdomains=["www.target-corp.com"])

    graph = EngagementGraph(engagement_id="e-recon-2")
    sub = ReconPassiveSubagent(
        cfg=KryonsecConfig(), graph=graph,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        target="target-corp.com", fetchers=[source_a, source_b],
    )
    sub.run()

    assert len(graph.by_type("subdomain")) == 1
    assert len(graph.find_edges(relationship="has_subdomain")) == 1
