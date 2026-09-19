"""Schema migrations (spec §10.1).

CLAUDE.md: "schema changes go through migrations in `migrations/`, never
ad-hoc DDL." Why this exists: ``init_db()`` was a bare
``Base.metadata.create_all()``. ``create_all`` issues
``CREATE TABLE IF NOT EXISTS`` — it never ``ALTER``\\s — so once a database
existed, no future column or table change could ever reach it. Every release
that touched the schema would have needed a manual ``DROP``.

How it behaves
--------------
* A **fresh** database gets every revision applied in order.
* A database that **predates this runner** (it has our tables but no
  ``schema_version`` table) is *stamped* with the baseline and otherwise left
  untouched — creating the tables it already has would fail. Its schema is
  already the baseline, because the baseline is defined as the schema that
  was current when migrations were introduced.
* Only then are later revisions applied.

Revisions are plain Python callables run inside a transaction together with
their own version row, so a failure rolls back both.
"""

from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass
from typing import Callable

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

from ..storage.models import Base

log = logging.getLogger(__name__)

VERSION_TABLE = "schema_version"

# Portable across SQLite and PostgreSQL: explicit lengths, and
# IF NOT EXISTS is supported by both (PostgreSQL 9.1+).
_VERSION_DDL = (
    f"CREATE TABLE IF NOT EXISTS {VERSION_TABLE} ("
    " id VARCHAR(64) NOT NULL PRIMARY KEY,"
    " applied_at VARCHAR(40) NOT NULL,"
    " note VARCHAR(200)"
    ")"
)


@dataclass(frozen=True)
class Revision:
    """One schema change.

    ``upgrade`` receives the open connection and the table list ``init_db``
    resolved (general, plus purple on PostgreSQL) — the baseline needs the
    list, later revisions generally ignore it.
    """

    id: str
    description: str
    upgrade: Callable[[Connection, list], None]


def _baseline(conn: Connection, tables: list) -> None:
    """Revision 0001: the schema as it stood when migrations were introduced.

    Equivalent to the old ``init_db()`` body, kept as the first revision so a
    fresh database reaches the same state one stamp would imply.
    """
    Base.metadata.create_all(bind=conn, tables=tables)


# Append new revisions here; never edit or renumber an existing one.
REVISIONS: list[Revision] = [
    Revision(
        id="0001_baseline",
        description="initial schema (general tables; purple tables on PostgreSQL)",
        upgrade=_baseline,
    ),
]


def _ensure_version_table(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text(_VERSION_DDL))


def _applied(engine: Engine) -> dict[str, str]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(f"SELECT id, note FROM {VERSION_TABLE}")
        ).fetchall()
    return {r[0]: (r[1] or "") for r in rows}


def _user_tables_present(engine: Engine, tables: list) -> bool:
    """True when any of our tables already exists (ignoring the version table)."""
    existing = set(inspect(engine).get_table_names())
    wanted = {t.name for t in tables} - {VERSION_TABLE}
    return bool(existing & wanted)


def _record(conn: Connection, revision_id: str, note: str | None = None) -> None:
    conn.execute(
        text(
            f"INSERT INTO {VERSION_TABLE} (id, applied_at, note) "
            "VALUES (:id, :ts, :note)"
        ),
        {
            "id": revision_id,
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "note": note,
        },
    )


def apply_pending(
    engine: Engine, tables: list, *, stamp_existing: bool = True
) -> list[str]:
    """Bring ``engine`` up to date. Returns the revision ids actually applied.

    Stamped revisions are *not* in the return value — nothing was executed for
    them, and callers use this to decide whether to log "upgraded".
    """
    _ensure_version_table(engine)
    applied = _applied(engine)
    pending = [r for r in REVISIONS if r.id not in applied]

    if not applied and stamp_existing and _user_tables_present(engine, tables):
        # Pre-existing schema (created by the old create_all path). Recording
        # the baseline is the only safe move: the tables are already there, so
        # running the baseline DDL would either fail or be a no-op, and we
        # must not touch data we did not create.
        baseline = REVISIONS[0]
        with engine.begin() as conn:
            _record(conn, baseline.id, note="stamped (schema predates migrations)")
        log.info(
            "schema predates the migration runner — stamped %s, no DDL executed",
            baseline.id,
        )
        pending = [r for r in pending if r.id != baseline.id]

    done: list[str] = []
    for rev in pending:
        # DDL and its version row commit together: a revision that fails
        # halfway must not be recorded as applied.
        with engine.begin() as conn:
            rev.upgrade(conn, tables)
            _record(conn, rev.id)
        done.append(rev.id)
        log.info("migration applied: %s (%s)", rev.id, rev.description)
    return done


def current_version(engine: Engine) -> str | None:
    """The newest applied revision id, or None for an empty/absent table."""
    if VERSION_TABLE not in inspect(engine).get_table_names():
        return None
    applied = _applied(engine)
    ordered = [r.id for r in REVISIONS if r.id in applied]
    return ordered[-1] if ordered else None
