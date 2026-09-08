"""Database engine and schema bootstrap (spec v2.1.1 §10, §11.1)."""

from __future__ import annotations

import logging

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import KryonsecConfig
from .models import GENERAL_TABLES, PURPLE_TABLES, Base

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
        url = cfg.database_url
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
    """Create tables. Purple-team tables are created only on PostgreSQL."""
    engine = get_engine(cfg)
    if include_purple is None:
        include_purple = cfg.storage_is_postgres
    tables = GENERAL_TABLES + (PURPLE_TABLES if include_purple else [])
    Base.metadata.create_all(engine, tables=[t.__table__ for t in tables])
    return engine


def get_session(cfg: KryonsecConfig) -> Session:
    """Return a new session bound to the process-wide engine."""
    global _session_factory
    engine = get_engine(cfg)
    if _session_factory is None:
        _session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    return _session_factory()


def reset_engine() -> None:
    """For tests: drop the cached engine/factory."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None
