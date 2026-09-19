"""Database engine and schema bootstrap (spec v2.1.1 §10, §11.1)."""

from __future__ import annotations

import logging

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import KryonsecConfig
from .models import GENERAL_TABLES, PURPLE_TABLES

log = logging.getLogger(__name__)

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine(cfg: KryonsecConfig) -> Engine:
    """Return the process-wide engine.

    PostgreSQL when DATABASE_URL is set (system of record); otherwise the
    Profile-1 embedded fallback (SQLite) for general-mode memory only.
    """
    global _engine
    if _engine is not None:
        return _engine

    cfg.ensure_dirs()
    if cfg.database_url:
        url = _normalize_database_url(cfg.database_url)
    else:
        url = f"sqlite:///{cfg.fallback_db_path}"

    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)

    if _engine.name == "sqlite":
        @event.listens_for(_engine, "connect")
        def _fk_on(dbapi_conn, _record):  # pragma: no cover - driver glue
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    log.info("storage backend: %s (%s)", cfg.storage_kind, _safe_url(url))
    return _engine


def _pg_driver() -> str | None:
    """The installed psycopg driver, or None. Prefers v3 (`psycopg`)."""
    import importlib.util

    for mod in ("psycopg", "psycopg2"):
        try:
            if importlib.util.find_spec(mod) is not None:
                return mod
        except (ImportError, ValueError):  # pragma: no cover - broken install
            continue
    return None


def _normalize_database_url(url: str) -> str:
    """Point a bare PostgreSQL URL at a driver that is actually installed.

    SQLAlchemy reads `postgresql://…` as `postgresql+psycopg2://…`, but this
    project declares psycopg **v3** (`psycopg[binary]`), which is the
    `postgresql+psycopg` dialect. So the DATABASE_URL the README documents
    raised `ModuleNotFoundError: No module named 'psycopg2'` at create_engine
    time — Copilot logged "storage init failed" and stopped persisting, and
    Purple Team lost its system of record entirely.

    An explicit `postgresql+psycopg2://` (or any `+driver`) is left alone:
    the user asked for that driver, so a missing one should be their error.
    """
    from sqlalchemy.engine import make_url

    try:
        parsed = make_url(url)
    except Exception:
        return url  # not SQLAlchemy-shaped — let create_engine report it

    if parsed.drivername not in ("postgresql", "postgres"):
        return url

    driver = _pg_driver()
    if driver is None:
        raise RuntimeError(
            "DATABASE_URL points at PostgreSQL but no driver is installed — "
            "run: pip install 'kryonsec[postgres]'"
        )
    # hide_password=False: this string is what create_engine consumes, not a log
    return parsed.set(drivername=f"postgresql+{driver}").render_as_string(
        hide_password=False
    )


def _safe_url(url: str) -> str:
    """The URL for logs — password masked (never log credentials)."""
    try:
        from sqlalchemy.engine import make_url

        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        # non-SQLAlchemy-shaped string: mask after scheme://user:pass@
        import re

        return re.sub(r"(://[^:/@]+:)[^@]+(@)", r"\1***\2", url)


def init_db(cfg: KryonsecConfig, include_purple: bool | None = None) -> Engine:
    """Bring the schema up to date. Purple-team tables only on PostgreSQL.

    Goes through the migration runner (CLAUDE.md) rather than create_all():
    create_all never ALTERs, so a bare call could not deliver a schema change
    to a database that already existed.
    """
    from ..migrations import apply_pending

    engine = get_engine(cfg)
    if include_purple is None:
        include_purple = cfg.storage_is_postgres
    tables = GENERAL_TABLES + (PURPLE_TABLES if include_purple else [])
    apply_pending(engine, [t.__table__ for t in tables])
    return engine


def get_session(cfg: KryonsecConfig) -> Session:
    """Return a new session bound to the process-wide engine."""
    global _session_factory
    engine = get_engine(cfg)
    if _session_factory is None:
        _session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    return _session_factory()


def reset_engine() -> None:
    """For tests: close the pool and drop the cached engine/factory."""
    global _engine, _session_factory
    # dispose(), not just dropping the reference: it returns pooled
    # connections to the server. Without it every reset leaked its pool —
    # PostgreSQL hit max_connections after enough test/CLI cycles.
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:  # pragma: no cover - dispose is best-effort
            log.debug("engine dispose failed", exc_info=True)
    _engine = None
    _session_factory = None
