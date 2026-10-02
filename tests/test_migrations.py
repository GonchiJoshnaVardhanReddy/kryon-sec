"""Tests for the schema migration runner (spec §10.1, CLAUDE.md).

The behaviour that matters most is the one that must NOT happen: pointing
this at a database that already exists with data in it must not run DDL.
"""

import pytest
from sqlalchemy import inspect, text

from kryonsec.config import KryonsecConfig
from kryonsec.migrations import (
    REVISIONS,
    VERSION_TABLE,
    apply_pending,
    current_version,
)
from kryonsec.storage import init_db, reset_engine
from kryonsec.storage.models import GENERAL_TABLES, PURPLE_TABLES


@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    c = KryonsecConfig(home=tmp_path / "home")
    c.database_url = f"sqlite:///{tmp_path / 'm.db'}"
    yield c
    reset_engine()


def _tables(include_purple=False):
    models = GENERAL_TABLES + (PURPLE_TABLES if include_purple else [])
    return [t.__table__ for t in models]


# --- fresh database --------------------------------------------------------

def test_fresh_database_gets_every_revision(cfg):
    from kryonsec.storage import get_engine

    engine = get_engine(cfg)
    applied = apply_pending(engine, _tables())
    assert applied == [r.id for r in REVISIONS]
    assert current_version(engine) == REVISIONS[-1].id


def test_init_db_records_the_version(cfg):
    from kryonsec.storage import get_engine

    init_db(cfg, include_purple=False)
    assert current_version(get_engine(cfg)) == REVISIONS[-1].id


def test_second_run_applies_nothing(cfg):
    from kryonsec.storage import get_engine

    engine = get_engine(cfg)
    apply_pending(engine, _tables())
    assert apply_pending(engine, _tables()) == []   # idempotent


# --- the pre-existing database (the whole point) ---------------------------

def test_existing_database_is_stamped_not_rebuilt(cfg):
    """A database created by the old create_all path must be adopted as-is.

    Stamping has to leave the data alone: running the baseline DDL against
    tables that already exist would fail (or, worse, be silently ignored
    while the operator believed an upgrade had happened).
    """
    from kryonsec.storage import GeneralUserLtm, get_engine, get_session

    engine = get_engine(cfg)
    # build the pre-migrations world exactly as the old init_db did
    from kryonsec.storage.models import Base

    Base.metadata.create_all(engine, tables=_tables())
    with get_session(cfg) as s:
        s.add(GeneralUserLtm(category="fact", key="keep", value={"v": 1}))
        s.commit()

    applied = apply_pending(engine, _tables())
    # The baseline was stamped, not executed. Later revisions still run —
    # that is the whole point of having a runner — but this database has no
    # purple tables, so the graph revision no-ops.
    assert "0001_baseline" not in applied
    assert current_version(engine) == REVISIONS[-1].id   # but it is recorded

    # the row survived, and the version row explains itself
    with get_session(cfg) as s:
        assert s.query(GeneralUserLtm).count() == 1
    with engine.connect() as conn:
        note = conn.execute(
            text(f"SELECT note FROM {VERSION_TABLE}")   # noqa: S608 - fixed name
        ).scalar()
    assert "predates migrations" in note


def test_stamped_database_still_gets_later_revisions(cfg, monkeypatch):
    """Stamping the baseline must not stop a future revision from applying."""
    from kryonsec.storage import get_engine
    from kryonsec.storage.models import Base

    engine = get_engine(cfg)
    Base.metadata.create_all(engine, tables=_tables())

    ran: list[str] = []

    def _later(conn, tables):
        ran.append("0002")
        conn.execute(text("CREATE TABLE later_added (id INTEGER)"))

    later = type(REVISIONS[0])(
        id="0002_add_later", description="test-only", upgrade=_later,
    )
    monkeypatch.setattr("kryonsec.migrations.REVISIONS", [*REVISIONS, later])

    # REVISIONS itself keeps growing, so assert on the revision under test
    # rather than on the whole list.
    applied = apply_pending(engine, _tables())
    assert applied[-1] == "0002_add_later"
    assert ran == ["0002"]
    assert "later_added" in inspect(engine).get_table_names()
    assert current_version(engine) == "0002_add_later"


def test_stamp_can_be_disabled(cfg):
    """stamp_existing=False still runs the baseline — it just isn't recorded
    as a stamp. create_all is a no-op against tables that already exist."""
    from kryonsec.storage import get_engine
    from kryonsec.storage.models import Base

    engine = get_engine(cfg)
    Base.metadata.create_all(engine, tables=_tables())
    assert apply_pending(engine, _tables(), stamp_existing=False) == [
        r.id for r in REVISIONS
    ]
    assert current_version(engine) == REVISIONS[-1].id
    # ...but it is recorded as an application, not a stamp
    with engine.connect() as conn:
        note = conn.execute(text(f"SELECT note FROM {VERSION_TABLE}")).scalar()
    assert note is None


# --- failure handling ------------------------------------------------------

def test_failing_revision_is_not_recorded(cfg, monkeypatch):
    """A revision that raises must roll back its own version row.

    Recording a revision that did not finish would make the next run skip it,
    and the schema would be permanently half-migrated with nothing to say so.

    Note on the DDL itself: PostgreSQL rolls back DDL with the transaction, so
    the half-created table disappears there. SQLite's pysqlite driver issues
    an implicit COMMIT before DDL, so the table survives — which is precisely
    why the version row, not the DDL, is the thing that must be atomic.
    """
    from kryonsec.storage import get_engine

    engine = get_engine(cfg)

    def _boom(conn, tables):
        conn.execute(text("CREATE TABLE half_done (id INTEGER)"))
        raise RuntimeError("migration exploded")

    bad = type(REVISIONS[0])(id="0002_boom", description="fails", upgrade=_boom)
    monkeypatch.setattr("kryonsec.migrations.REVISIONS", [*REVISIONS, bad])

    with pytest.raises(RuntimeError, match="migration exploded"):
        apply_pending(engine, _tables())

    # the failed revision is not recorded; everything before it still is
    assert current_version(engine) == REVISIONS[-1].id
    with engine.connect() as conn:
        recorded = {r[0] for r in conn.execute(
            text(f"SELECT id FROM {VERSION_TABLE}")
        ).fetchall()}
    assert "0002_boom" not in recorded


def test_failed_revision_can_be_retried_after_a_fix(cfg, monkeypatch):
    """The point of not recording a failure: re-running picks it up again."""
    from kryonsec.storage import get_engine

    engine = get_engine(cfg)
    attempts: list[int] = []

    def _flaky(conn, tables):
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("first attempt fails")

    rev = type(REVISIONS[0])(id="0002_flaky", description="flaky", upgrade=_flaky)
    monkeypatch.setattr("kryonsec.migrations.REVISIONS", [*REVISIONS, rev])

    with pytest.raises(RuntimeError):
        apply_pending(engine, _tables())
    assert "0002_flaky" in apply_pending(engine, _tables())
    assert current_version(engine) == "0002_flaky"


# --- revision 0002: the Security Graph tables ------------------------------

def test_graph_revision_creates_the_edge_table(cfg):
    from kryonsec.storage import get_engine

    engine = get_engine(cfg)
    apply_pending(engine, _tables(include_purple=True))

    names = inspect(engine).get_table_names()
    assert "stm_nodes" in names and "stm_edges" in names
    edge_columns = {c["name"] for c in inspect(engine).get_columns("stm_edges")}
    assert {"id", "engagement_id", "source_node_id", "relationship",
            "target_node_id", "properties", "created_at"} <= edge_columns

    node_columns = {c["name"] for c in inspect(engine).get_columns("stm_nodes")}
    assert {"canonical_key", "provenance", "status"} <= node_columns


def test_graph_revision_is_skipped_without_purple_storage(cfg):
    """The Copilot fallback database must not grow engagement tables."""
    from kryonsec.storage import get_engine

    engine = get_engine(cfg)
    apply_pending(engine, _tables(include_purple=False))
    names = inspect(engine).get_table_names()
    assert "stm_nodes" not in names
    assert "stm_edges" not in names


def test_graph_revision_upgrades_an_old_database(cfg):
    """A database created before Phase 1 gains the edges table and the three
    node columns, and keeps the nodes it already had."""
    from kryonsec.storage import get_engine

    engine = get_engine(cfg)
    # the pre-Phase-1 stm_nodes, written out by hand: no canonical_key,
    # provenance or status, and no stm_edges at all
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE stm_nodes ("
            " id VARCHAR(36) NOT NULL PRIMARY KEY,"
            " engagement_id VARCHAR(36) NOT NULL,"
            " subagent VARCHAR(64) NOT NULL,"
            " node_type VARCHAR(32) NOT NULL,"
            " label TEXT NOT NULL,"
            " properties JSON,"
            " size_bytes INTEGER NOT NULL,"
            " created_at DATETIME)"
        ))
        conn.execute(text(
            "INSERT INTO stm_nodes"
            " (id, engagement_id, subagent, node_type, label, size_bytes)"
            " VALUES ('n-old', 'e-old', 'RECON_PASSIVE', 'target',"
            " 'example.com', 2)"
        ))

    # the pre-existing schema is stamped, so only 0002 actually runs
    assert apply_pending(engine, _tables(include_purple=True)) == [
        "0002_security_graph_edges"
    ]

    names = inspect(engine).get_table_names()
    assert "stm_edges" in names
    node_columns = {c["name"] for c in inspect(engine).get_columns("stm_nodes")}
    assert {"canonical_key", "provenance", "status"} <= node_columns

    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT label, canonical_key FROM stm_nodes WHERE id = 'n-old'"
        )).one()
    assert row[0] == "example.com"      # the old node survived
    assert row[1] is None               # and the new column is empty for it


def test_graph_revision_rows_load_with_phase_1_defaults(cfg):
    """The old row above must still load as a graph, with defaults filled in."""
    from kryonsec.purple.graph_store import load_graph
    from kryonsec.storage import get_engine, get_session

    engine = get_engine(cfg)
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE stm_nodes ("
            " id VARCHAR(36) NOT NULL PRIMARY KEY,"
            " engagement_id VARCHAR(36) NOT NULL,"
            " subagent VARCHAR(64) NOT NULL,"
            " node_type VARCHAR(32) NOT NULL,"
            " label TEXT NOT NULL,"
            " properties JSON,"
            " size_bytes INTEGER NOT NULL,"
            " created_at DATETIME)"
        ))
        conn.execute(text(
            "INSERT INTO stm_nodes"
            " (id, engagement_id, subagent, node_type, label, size_bytes)"
            " VALUES ('n-old', 'e-old', 'RECON_PASSIVE', 'target',"
            " 'example.com', 2)"
        ))
    apply_pending(engine, _tables(include_purple=True))

    with get_session(cfg) as session:
        graph = load_graph(session, "e-old")
    node = graph.nodes[0]
    assert node["label"] == "example.com"
    assert node["canonical_key"] == "target:example.com"
    assert node["status"] == "observed"
    assert node["provenance"] == {}


# --- shape -----------------------------------------------------------------

def test_revision_ids_are_unique_and_ordered():
    ids = [r.id for r in REVISIONS]
    assert len(ids) == len(set(ids)), "duplicate revision id"
    assert ids[0].startswith("0001"), "the baseline must stay first"


def test_empty_database_file_is_not_mistaken_for_an_old_one(tmp_path):
    """A zero-byte file has no tables — it is fresh, not pre-migrations."""
    reset_engine()
    cfg = KryonsecConfig(home=tmp_path / "h2")
    db = tmp_path / "empty.db"
    db.write_bytes(b"")
    cfg.database_url = f"sqlite:///{db}"
    try:
        from kryonsec.storage import get_engine

        engine = get_engine(cfg)
        assert apply_pending(engine, _tables()) == [r.id for r in REVISIONS]
    finally:
        reset_engine()
