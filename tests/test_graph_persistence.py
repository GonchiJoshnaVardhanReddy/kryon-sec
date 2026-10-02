"""Phase 2: engagement graphs survive a restart.

Phase 1 gave the Security Graph a shape worth saving and a store that can
save it, but nothing called it. This covers the wiring: where engagement
data lives on each supported storage configuration, that a saved graph
comes back intact, and that a storage problem is reported rather than
swallowed.

Nothing here drives the sandbox — the runner tests use the same two-tier
gating as ``test_runner.py``, so they exercise a real engagement on a
machine with no gVisor.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from kryonsec.config import KryonsecConfig
from kryonsec.migrations import REVISIONS, current_version
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.graph_store import load_graph, save_graph
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.report import dedup_hypotheses
from kryonsec.purple.runner import persist_graph, start_engagement
from kryonsec.purple.zonea import PassiveResult
from kryonsec.storage import (
    get_engine,
    get_purple_engine,
    get_purple_session,
    get_session,
    init_db,
    init_purple_db,
    reset_engine,
)
from kryonsec.storage.models import StmEdge, StmNode


@pytest.fixture()
def cfg(tmp_path):
    """The embedded install: no DATABASE_URL, so engagement storage is the
    dedicated file. Workspace is redirected so the fixture never writes to
    the real home directory."""
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = None
    yield config
    reset_engine()


def _events(audit: AuditLog) -> list[dict]:
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _graph(engagement_id: str = "e-1") -> EngagementGraph:
    graph = EngagementGraph(engagement_id=engagement_id)
    target = graph.add_node(
        "target", "example.com",
        provenance={"source_type": "config", "source": "engagement_config",
                    "agent": "RECON_PASSIVE"},
    )
    service = graph.add_node(
        "service", "example.com:443/tcp", {"port": 443, "service": "https"},
        provenance={"source_type": "tool", "source": "nmap",
                    "agent": "RECON_ACTIVE"},
    )
    graph.add_edge(
        target, "has_service", service, {"source": "nmap"},
        provenance={"source_type": "tool", "source": "nmap",
                    "agent": "RECON_ACTIVE"},
    )
    return graph


# --- STEP 2: where engagement data lives -----------------------------------

def test_embedded_install_gets_its_own_engagement_database(cfg):
    """No DATABASE_URL: engagement storage is a file of its own, created on
    first use, and the Copilot fallback database stays general-only."""
    init_purple_db(cfg)
    init_db(cfg)          # the Copilot side initialises too

    purple_tables = set(inspect(get_purple_engine(cfg)).get_table_names())
    fallback_tables = set(inspect(get_engine(cfg)).get_table_names())

    assert {"stm_nodes", "stm_edges"} <= purple_tables
    assert "stm_nodes" not in fallback_tables
    assert "stm_edges" not in fallback_tables
    assert cfg.purple_db_path != cfg.fallback_db_path
    assert cfg.purple_db_path.exists()


def test_engagement_storage_is_not_the_copilot_engine(cfg):
    assert get_purple_engine(cfg) is not get_engine(cfg)


def test_engagement_database_runs_the_same_migrations(cfg):
    """One migration runner, one schema history — a second database file,
    not a second memory system."""
    engine = init_purple_db(cfg)
    assert current_version(engine) == REVISIONS[-1].id
    # ...and its own version table does not collide with the general one
    assert "schema_version" in inspect(engine).get_table_names()


def test_database_url_reuses_the_system_of_record(tmp_path):
    """With DATABASE_URL set there is one store, not two."""
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = f"sqlite:///{tmp_path / 'sor.db'}"
    try:
        assert get_purple_engine(config) is get_engine(config)
        init_purple_db(config)
        assert current_version(get_engine(config)) == REVISIONS[-1].id
        names = inspect(get_engine(config)).get_table_names()
        assert {"general_sessions", "stm_nodes", "stm_edges"} <= set(names)
    finally:
        reset_engine()


def test_engine_is_cached_until_reset(cfg):
    first = get_purple_engine(cfg)
    assert get_purple_engine(cfg) is first
    reset_engine()
    assert get_purple_engine(cfg) is not first


# --- STEP 4: save, restart, load -------------------------------------------

def test_engagement_survives_a_restart(cfg):
    """The whole point: save, drop every cached connection (a restart, as
    close as an in-process test can get), reload by engagement id."""
    original = _graph("e-restart")
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        assert save_graph(session, original) == (2, 1)

    reset_engine()

    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-restart")

    assert loaded.engagement_id == "e-restart"
    assert {n["id"] for n in loaded.nodes} == {n["id"] for n in original.nodes}
    assert [e["relationship"] for e in loaded.edges] == ["has_service"]

    # the parts a GUI reads are intact, not just the ids
    service = loaded.by_type("service")[0]
    assert service["label"] == "example.com:443/tcp"
    assert service["properties"] == {"port": 443, "service": "https"}
    assert service["status"] == "observed"
    assert service["provenance"]["agent"] == "RECON_ACTIVE"
    assert service["canonical_key"] == "service:example.com:443/tcp"
    target = loaded.by_type("target")[0]
    assert loaded.has_edge(target, "has_service", service)
    assert loaded.find_edges(relationship="has_service")[0]["provenance"]["source"] == "nmap"


def test_an_empty_engagement_round_trips(cfg):
    init_purple_db(cfg)
    empty = EngagementGraph(engagement_id="e-empty")
    with get_purple_session(cfg) as session:
        assert save_graph(session, empty) == (0, 0)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-empty")
    assert loaded.nodes == [] and loaded.edges == []


def test_loading_an_unknown_engagement_is_empty_not_an_error(cfg):
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-never-existed")
    assert loaded.engagement_id == "e-never-existed"
    assert loaded.nodes == [] and loaded.edges == []


def test_engagements_are_isolated_from_each_other(cfg):
    init_purple_db(cfg)
    graphs = [_graph(f"e-{i}") for i in range(3)]
    for i, g in enumerate(graphs):
        g.add_node("finding", f"finding-{i}", {"verified": True})

    with get_purple_session(cfg) as session:
        for g in graphs:
            save_graph(session, g)

    with get_purple_session(cfg) as session:
        for i in range(3):
            loaded = load_graph(session, f"e-{i}")
            assert len(loaded.nodes) == 3
            assert [n["label"] for n in loaded.by_type("finding")] == [f"finding-{i}"]
            assert all(n["engagement_id"] == f"e-{i}" for n in loaded.nodes)


def test_resaving_replaces_the_engagement_not_the_others(cfg):
    init_purple_db(cfg)
    first, second = _graph("e-a"), _graph("e-b")
    with get_purple_session(cfg) as session:
        save_graph(session, first)
        save_graph(session, second)

    first.remove_node(first.by_type("service")[0])
    with get_purple_session(cfg) as session:
        assert save_graph(session, first) == (1, 0)

    with get_purple_session(cfg) as session:
        assert load_graph(session, "e-a").nodes == first.nodes
        assert len(load_graph(session, "e-b").edges) == 1


# --- the same schema on PostgreSQL -----------------------------------------

def test_the_engagement_schema_compiles_for_postgresql():
    """No PostgreSQL server here, but the DDL is what one would be sent:
    JSONB columns, cascading foreign keys, and the unique edge triple."""
    ddl = str(CreateTable(StmEdge.__table__).compile(dialect=postgresql.dialect()))
    assert "JSONB" in ddl
    assert "ON DELETE CASCADE" in ddl
    assert "uq_stm_edges_triple" in ddl
    assert "UNIQUE (engagement_id, source_node_id, relationship, target_node_id)" in ddl

    node_ddl = str(CreateTable(StmNode.__table__).compile(dialect=postgresql.dialect()))
    assert node_ddl.count("JSONB") == 2      # properties, provenance
    assert "canonical_key" in node_ddl and "status" in node_ddl


def test_the_engagement_schema_compiles_for_sqlite():
    """SQLite has no JSONB; the models must not emit it there."""
    ddl = str(CreateTable(StmNode.__table__).compile(dialect=sqlite.dialect()))
    assert "JSONB" not in ddl


# --- STEP 3: the runner saves when the engagement ends ---------------------

def _fake_recon(domain):
    return PassiveResult(source="crt.sh", subdomains=["www." + domain])


def _run_engagements(cfg, engagement_id, target="target-corp.com"):
    """One engagement, halting at RECON_ACTIVE as it does without a sandbox."""
    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers",
                   return_value=[_fake_recon]):
            orch, audit, graph = start_engagement(cfg, engagement_id, target=target)
            orch.run()
    return audit, graph


def test_a_finished_engagement_is_persisted_and_audited(cfg):
    audit, graph = _run_engagements(cfg, "e-run")

    assert persist_graph(cfg, "e-run", graph, audit) is True

    events = [e["event"] for e in _events(audit)]
    assert "graph_persisted" in events
    saved = [e for e in _events(audit) if e["event"] == "graph_persisted"][0]
    assert saved["nodes"] == len(graph.nodes) > 0
    assert saved["edges"] == len(graph.edges) > 0
    # the audit chain is still intact after the storage write
    ok, reason = audit.verify()
    assert ok, reason

    reset_engine()      # restart
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-run")
    assert [n["label"] for n in loaded.by_type("target")] == ["target-corp.com"]
    assert [n["label"] for n in loaded.by_type("subdomain")] == ["www.target-corp.com"]
    assert [e["relationship"] for e in loaded.edges] == ["has_subdomain"]


def test_persistence_failure_is_reported_not_raised(cfg, monkeypatch):
    """A storage problem must not turn a finished engagement into a crash —
    and must not disappear either."""
    audit, graph = _run_engagements(cfg, "e-broken")

    def _boom(_cfg):
        raise RuntimeError("disk is full")

    monkeypatch.setattr("kryonsec.storage.init_purple_db", _boom)
    assert persist_graph(cfg, "e-broken", graph, audit) is False

    failures = [e for e in _events(audit) if e["event"] == "graph_persist_failed"]
    assert len(failures) == 1
    assert "disk is full" in failures[0]["error"]
    assert failures[0]["engagement_id"] == "e-broken"
    ok, reason = audit.verify()
    assert ok, reason


def test_a_failed_save_leaves_the_previous_graph_intact(cfg, monkeypatch):
    """Nothing is destroyed by a save that fails: save_graph commits once."""
    graph = _graph("e-keep")
    init_purple_db(cfg)
    audit = AuditLog(cfg.home / "engagements" / "e-keep" / "audit.jsonl")
    assert persist_graph(cfg, "e-keep", graph, audit) is True

    def _boom(session, g):
        raise RuntimeError("write failed halfway")

    monkeypatch.setattr("kryonsec.purple.graph_store.save_graph", _boom)
    graph.add_node("finding", "F1", {"verified": True})
    assert persist_graph(cfg, "e-keep", graph, audit) is False

    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-keep")
    assert len(loaded.nodes) == 2          # the earlier save, not a half-write
    assert loaded.by_type("finding") == []


def test_persistence_does_not_touch_the_copilot_database(cfg):
    audit, graph = _run_engagements(cfg, "e-sep")
    assert persist_graph(cfg, "e-sep", graph, audit) is True
    assert "stm_nodes" not in inspect(get_engine(cfg)).get_table_names()


def test_the_cli_saves_the_engagement_when_it_finishes(cfg, monkeypatch):
    """End-to-end over the real CLI path, then read it back fresh."""
    from io import StringIO

    from rich.console import Console

    from kryonsec import cli

    monkeypatch.setattr("kryonsec.purple.runner.sandbox_available",
                        lambda image=None: (False, "not Linux"))
    monkeypatch.setattr("kryonsec.purple.recon_passive.zone_a_fetchers",
                        lambda _cfg: [_fake_recon])
    capture = Console(file=StringIO(), force_terminal=False, width=100,
                      no_color=True)
    monkeypatch.setattr(cli, "console", capture)
    monkeypatch.setattr(cli, "err_console", capture)

    assert cli._run_purple(cfg, "target-corp.com", "e-cli") == 0

    reset_engine()
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-cli")
    assert [n["label"] for n in loaded.by_type("subdomain")] == ["www.target-corp.com"]
    assert [e["relationship"] for e in loaded.edges] == ["has_subdomain"]

    out = capture.file.getvalue()
    assert "Graph memory" in out
    assert "not saved" not in out


# --- STEP 5: dedup must not destroy what it merges -------------------------

def _hypothesis_pair(graph):
    target = graph.add_node("target", "example.com")
    first = graph.add_node("hypothesis", "H1",
                           {"tools": ["sqlmap"], "target_asset": "example.com"})
    dup = graph.add_node(
        "hypothesis", "H2", {"tools": ["sqlmap"], "target_asset": "example.com"},
        provenance={"source_type": "llm", "source": "hypothesize",
                    "agent": "HYPOTHESIZE"},
    )
    attempt = graph.add_node("exploit_attempt", "H2:sqlmap")
    graph.add_edge(first, "targets", target)
    graph.add_edge(dup, "tested_by", attempt,
                   provenance={"source_type": "tool", "source": "sqlmap",
                               "agent": "EXPLOIT"})
    return target, first, dup, attempt


def test_merge_rewires_edges_instead_of_dropping_them():
    graph = EngagementGraph(engagement_id="e-merge")
    target, first, dup, attempt = _hypothesis_pair(graph)

    assert graph.merge_node(dup, first) == 1
    assert graph.get_node(dup["id"]) is None
    # the duplicate's relationship now belongs to the survivor
    assert graph.has_edge(first, "tested_by", attempt)
    assert graph.neighbors(first, direction="out", relationship="tested_by") == [attempt]
    # nothing dangles
    assert all(graph.get_node(e["source_node_id"]) for e in graph.edges)
    assert all(graph.get_node(e["target_node_id"]) for e in graph.edges)


def test_merge_keeps_the_absorbed_nodes_provenance():
    graph = EngagementGraph(engagement_id="e-merge")
    _, first, dup, _ = _hypothesis_pair(graph)
    graph.merge_node(dup, first)

    merged = first["provenance"]["merged_nodes"]
    assert len(merged) == 1
    assert merged[0]["node_id"] == dup["id"]
    assert merged[0]["label"] == "H2"
    assert merged[0]["provenance"]["agent"] == "HYPOTHESIZE"


def test_merge_collapses_the_duplicate_edges_it_creates():
    """Two hypotheses testing the same thing produce one edge afterwards —
    the stm_edges unique constraint allows nothing else — and the collapsed
    edge's provenance is kept on the survivor."""
    graph = EngagementGraph(engagement_id="e-merge")
    target, first, dup, attempt = _hypothesis_pair(graph)
    graph.add_edge(dup, "targets", target, provenance={"source": "second observation"})

    graph.merge_node(dup, first)

    targets_edges = graph.find_edges(source=first, target=target,
                                     relationship="targets")
    assert len(targets_edges) == 1
    collapsed = targets_edges[0]["provenance"].get("merged_edges", [])
    assert [c["provenance"]["source"] for c in collapsed] == ["second observation"]


def test_merge_into_itself_is_a_no_op():
    graph = EngagementGraph(engagement_id="e-merge")
    _, first, _, _ = _hypothesis_pair(graph)
    before = len(graph.edges)
    assert graph.merge_node(first, first) == 0
    assert len(graph.edges) == before


def test_merge_rejects_a_node_from_another_engagement():
    from kryonsec.purple.recon_passive import UnknownNodeError

    graph = EngagementGraph(engagement_id="e-a")
    graph.add_node("target", "a.example", node_id="n-a")
    with pytest.raises(UnknownNodeError):
        graph.merge_node("n-b", "n-a")


def test_dedup_hypotheses_keeps_the_merged_hypothesis_evidence(tmp_path):
    """The known dedup_hypotheses issue: it used to call remove_node, which
    cascaded the duplicate's edges away. The report joins still work, and
    now the graph does too."""
    graph = EngagementGraph(engagement_id="e-dedup")
    audit = AuditLog(tmp_path / "engagements" / "e-dedup" / "audit.jsonl")
    target, first, dup, attempt = _hypothesis_pair(graph)

    assert dedup_hypotheses(graph, audit) == 1

    assert graph.by_type("hypothesis") == [first]
    # the label join the report depends on
    assert attempt["label"] == "H1:sqlmap"
    assert first["properties"]["merged_from"] == ["H2"]
    # ...and the edge join it never had before
    assert graph.has_edge(first, "tested_by", attempt)
    assert graph.find_edges(source=first, relationship="tested_by")[0][
        "provenance"]["agent"] == "EXPLOIT"
    # no dangling edges survived the merge
    ids = {n["id"] for n in graph.nodes}
    assert all(e["source_node_id"] in ids and e["target_node_id"] in ids
               for e in graph.edges)


def test_dedup_hypotheses_result_still_saves_and_loads(cfg):
    graph = EngagementGraph(engagement_id="e-dedup-store")
    audit = AuditLog(cfg.home / "engagements" / "e-dedup-store" / "audit.jsonl")
    _hypothesis_pair(graph)
    dedup_hypotheses(graph, audit)

    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        save_graph(session, graph)
    with get_purple_session(cfg) as session:
        loaded = load_graph(session, "e-dedup-store")

    assert len(loaded.by_type("hypothesis")) == 1
    assert len(loaded.edges) == 2
    merged = loaded.by_type("hypothesis")[0]["provenance"]["merged_nodes"]
    assert merged[0]["provenance"]["agent"] == "HYPOTHESIZE"
