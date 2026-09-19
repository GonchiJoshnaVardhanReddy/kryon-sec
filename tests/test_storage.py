"""Tests for storage layer (spec §10.1): schema creation, persistence."""

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.storage import (
    GeneralSession,
    GeneralUserLtm,
    SystemKnowledge,
    get_session,
    init_db,
    reset_engine,
)


@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    c = KryonsecConfig(home=tmp_path / "home")
    c.database_url = f"sqlite:///{tmp_path / 'test.db'}"
    yield c
    reset_engine()


def test_init_creates_general_tables(cfg):
    init_db(cfg, include_purple=False)
    with get_session(cfg) as s:
        row = GeneralSession(messages=[{"role": "user", "content": "hi"}], token_count=1)
        s.add(row)
        s.commit()
        assert s.query(GeneralSession).count() == 1


def test_user_ltm_unique_constraint(cfg):
    init_db(cfg)
    with get_session(cfg) as s:
        s.add(GeneralUserLtm(category="preference", key="explain_mode", value={"v": "simple"}))
        s.commit()
    with get_session(cfg) as s:
        s.add(GeneralUserLtm(category="preference", key="explain_mode", value={"v": "other"}))
        with pytest.raises(Exception):
            s.commit()


def test_system_knowledge_upsert(cfg):
    init_db(cfg)
    with get_session(cfg) as s:
        s.add(SystemKnowledge(category="cve", key="CVE-2021-44228", value={"score": 10.0}))
        s.commit()
    with get_session(cfg) as s:
        row = s.query(SystemKnowledge).filter_by(key="CVE-2021-44228").one()
        assert row.value["score"] == 10.0


# --- PostgreSQL URL driver selection (spec §10.1 system of record) -----------

def test_bare_postgres_url_is_pointed_at_installed_driver(monkeypatch):
    """`postgresql://…` must not demand psycopg2 when we ship psycopg v3.

    SQLAlchemy reads a bare scheme as `postgresql+psycopg2`, but the project's
    `postgres` extra installs psycopg **v3** (`psycopg[binary]`). The
    documented DATABASE_URL therefore died in create_engine with
    ModuleNotFoundError, Copilot logged "storage init failed" and silently
    stopped persisting, and Purple Team lost its system of record.
    """
    from kryonsec.storage import db as db_mod

    monkeypatch.setattr(db_mod, "_pg_driver", lambda: "psycopg")
    url = db_mod._normalize_database_url("postgresql://u:p@localhost:5432/kryonsec")
    assert url.startswith("postgresql+psycopg://")
    assert "u:p@localhost:5432/kryonsec" in url  # credentials survive intact


def test_postgres_alias_scheme_is_normalized_too(monkeypatch):
    from kryonsec.storage import db as db_mod

    monkeypatch.setattr(db_mod, "_pg_driver", lambda: "psycopg")
    assert db_mod._normalize_database_url(
        "postgres://u@h/db"
    ).startswith("postgresql+psycopg://")


def test_explicit_driver_is_left_alone(monkeypatch):
    """An explicit +driver means the user chose it — don't override."""
    from kryonsec.storage import db as db_mod

    monkeypatch.setattr(db_mod, "_pg_driver", lambda: "psycopg")
    url = "postgresql+psycopg2://u:p@h/db"
    assert db_mod._normalize_database_url(url) == url


def test_falls_back_to_psycopg2_when_that_is_what_is_installed(monkeypatch):
    from kryonsec.storage import db as db_mod

    monkeypatch.setattr(db_mod, "_pg_driver", lambda: "psycopg2")
    assert db_mod._normalize_database_url(
        "postgresql://u:h@h/db"
    ).startswith("postgresql+psycopg2://")


def test_missing_driver_names_the_fix(monkeypatch):
    """No driver at all must say what to install, not raise ModuleNotFoundError."""
    from kryonsec.storage import db as db_mod

    monkeypatch.setattr(db_mod, "_pg_driver", lambda: None)
    with pytest.raises(RuntimeError, match=r"kryonsec\[postgres\]"):
        db_mod._normalize_database_url("postgresql://u:h@h/db")


def test_sqlite_urls_are_untouched():
    from kryonsec.storage import db as db_mod

    for url in ("sqlite:///x.db", "sqlite+pysqlite:///x.db"):
        assert db_mod._normalize_database_url(url) == url


def test_engine_uses_the_normalized_url(monkeypatch, tmp_path):
    """get_engine must actually consume the normalized URL."""
    import sqlalchemy

    from kryonsec.storage import db as db_mod

    seen = {}
    monkeypatch.setattr(db_mod, "_pg_driver", lambda: "psycopg")

    def fake_create(url, **kw):
        seen["url"] = url
        raise RuntimeError("stop here")  # don't touch a real server

    reset_engine()
    monkeypatch.setattr(db_mod, "create_engine", fake_create)
    c = KryonsecConfig(home=tmp_path / "h")
    c.database_url = "postgresql://u:p@localhost/kryonsec"
    try:
        with pytest.raises(RuntimeError, match="stop here"):
            db_mod.get_engine(c)
    finally:
        reset_engine()
    assert seen["url"].startswith("postgresql+psycopg://")
    assert sqlalchemy is not None  # keep the import honest


def test_reset_engine_disposes_the_pool(tmp_path, monkeypatch):
    """Dropping the reference leaked pooled connections on every reset.

    reset_engine() used to just set `_engine = None`, so the connection pool
    (and every checked-out connection in it) was never returned to the
    server. Enough test/CLI cycles exhausted PostgreSQL max_connections.
    """
    from kryonsec.storage import db as db_mod

    c = KryonsecConfig(home=tmp_path / "h")
    c.database_url = f"sqlite:///{tmp_path / 'd.db'}"
    engine = init_db(c, include_purple=False)

    disposed = []
    real_dispose = engine.dispose
    monkeypatch.setattr(
        engine, "dispose", lambda *a, **kw: (disposed.append(True), real_dispose())[1]
    )

    reset_engine()

    assert disposed == [True], "reset_engine must dispose the pooled connections"
    assert db_mod._engine is None
    assert db_mod._session_factory is None


def test_reset_engine_survives_a_failing_dispose(tmp_path, monkeypatch):
    """dispose() is best-effort — a dead server must not break the reset."""
    from kryonsec.storage import db as db_mod

    c = KryonsecConfig(home=tmp_path / "h")
    c.database_url = f"sqlite:///{tmp_path / 'e.db'}"
    engine = init_db(c, include_purple=False)

    def boom(*a, **kw):
        raise RuntimeError("server went away")

    monkeypatch.setattr(engine, "dispose", boom)
    reset_engine()  # must not raise
    assert db_mod._engine is None
