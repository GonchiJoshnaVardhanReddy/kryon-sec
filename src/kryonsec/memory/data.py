"""Read-only access to persisted engagement memory (the memory browser's data layer).

Everything the browser can see passes through this module. It is written
around three rules:

1. **Read-only means no DDL either.** ``init_purple_db`` migrates a schema;
   the viewer must never be the thing that creates a database or upgrades
   one. So storage is *inspected* (does the file exist? do the tables?), and
   a missing store is a reported state, not something to build on demand.

2. **Nothing is read out of the audit chain except a whitelist of fields.**
   The chain holds tool output and free-text error messages. The browser
   needs to answer "did this engagement finish, and if not why" — so this
   module pulls event names, the state name, the target and the halt reason,
   and never passes an audit entry through.

3. **Secrets are scrubbed on the way out.** Node properties are
   observations — the one place a credential could plausibly have been
   recorded. Every string in a response is run through the same detector the
   LLM gates and the report use (``secrets.find_secrets``), so the pattern
   list cannot drift, and matches are replaced with ``«SECRET_n»``
   placeholders numbered across the whole response. The mapping is not kept:
   the browser is a viewer, not a place to reveal secrets.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import inspect

from ..config import KryonsecConfig
from ..engagement_id import is_valid_engagement_id
from ..secrets import find_secrets

log = logging.getLogger(__name__)

__all__ = [
    "InvalidEngagementId",
    "MemoryUnavailable",
    "list_engagements",
    "load_engagement",
    "scrub",
    "storage_status",
]

# Audit events whose *fields* this module is willing to read. Anything else
# in the chain stays there.
_STATE_EVENT = "state_enter"
_CREATED_EVENT = "engagement_created"
_BLOCKED_EVENT = "zone_b_blocked"
_REPORT_EVENT = "report_written"
_PERSIST_FAILED_EVENT = "graph_persist_failed"


class InvalidEngagementId(ValueError):
    """The requested id is not a safe engagement id."""


class MemoryUnavailable(RuntimeError):
    """Engagement storage cannot be read right now."""


# ---- storage state --------------------------------------------------------

def storage_status(cfg: KryonsecConfig) -> dict:
    """Whether engagement storage exists and is readable.

    Never creates anything. For the embedded SQLite store the file's
    existence is checked before a connection is opened, because opening one
    is what creates the file.
    """
    kind = cfg.purple_storage_kind

    if not cfg.database_url and not cfg.purple_db_path.exists():
        return {
            "available": False,
            "kind": kind,
            "detail": ("no engagement database yet — the memory browser "
                       "shows engagements once one has been run"),
        }

    try:
        from ..storage import get_purple_engine

        engine = get_purple_engine(cfg)
        if "stm_nodes" not in inspect(engine).get_table_names():
            return {
                "available": False,
                "kind": kind,
                "detail": ("the engagement tables are not in this database "
                           "yet — run a Purple Team engagement first"),
            }
    except Exception as exc:
        # A database that cannot be opened is a state to report, not a
        # traceback to render. The detail deliberately carries the exception
        # type only: driver messages can quote the connection URL.
        log.warning("memory: engagement storage unavailable", exc_info=True)
        return {
            "available": False,
            "kind": kind,
            "detail": f"storage unavailable ({type(exc).__name__})",
        }

    return {"available": True, "kind": kind, "detail": "ready"}


# ---- engagements ----------------------------------------------------------

def list_engagements(cfg: KryonsecConfig) -> list[dict]:
    """Every engagement Kryonsec knows about, newest first.

    The persisted graph is the source of truth. Engagements that exist on
    disk but have no rows — the ones interrupted before they could be
    saved — are listed too, flagged ``persisted: false``, because "this
    engagement exists and has no memory" is exactly what an operator needs
    to see rather than an entry that silently is not there.
    """
    rows: dict[str, dict] = {}

    status = storage_status(cfg)
    if status["available"]:
        for eid, counts in _graph_counts(cfg).items():
            rows[eid] = {"engagement_id": eid, "persisted": True, **counts}

    for eid in _disk_engagements(cfg):
        rows.setdefault(
            eid, {"engagement_id": eid, "persisted": False, "nodes": 0, "edges": 0}
        )

    for row in rows.values():
        row.update(_audit_summary(cfg, row["engagement_id"]))

    return sorted(
        rows.values(),
        key=lambda r: (r.get("updated_at") or "", r["engagement_id"]),
        reverse=True,
    )


def load_engagement(cfg: KryonsecConfig, engagement_id: str) -> dict:
    """One engagement: its graph plus the status derived from its audit chain."""
    if not is_valid_engagement_id(engagement_id):
        raise InvalidEngagementId(f"invalid engagement id: {engagement_id!r}")

    status = storage_status(cfg)
    if not status["available"]:
        raise MemoryUnavailable(status["detail"])

    from ..storage import get_purple_session
    from ..purple.graph_store import load_graph

    with get_purple_session(cfg) as session:
        # Scoped by engagement id at the query level: one engagement's rows
        # can never appear in another's response.
        graph = load_graph(session, engagement_id)

    meta = _audit_summary(cfg, engagement_id)
    meta.update({
        "engagement_id": engagement_id,
        "persisted": True,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
    })
    return {"meta": meta, "graph": graph.to_dict()}


# ---- internals ------------------------------------------------------------

def _graph_counts(cfg: KryonsecConfig) -> dict[str, dict]:
    """Node and edge counts per engagement, straight from the tables."""
    from sqlalchemy import func

    from ..storage import get_purple_session
    from ..storage.models import StmEdge, StmNode

    with get_purple_session(cfg) as session:
        nodes = dict(
            session.query(StmNode.engagement_id, func.count(StmNode.id))
            .group_by(StmNode.engagement_id)
            .all()
        )
        edges = dict(
            session.query(StmEdge.engagement_id, func.count(StmEdge.id))
            .group_by(StmEdge.engagement_id)
            .all()
        )

    return {
        eid: {"nodes": int(nodes.get(eid, 0)), "edges": int(edges.get(eid, 0))}
        for eid in set(nodes) | set(edges)
    }


def _disk_engagements(cfg: KryonsecConfig) -> list[str]:
    """Engagement ids that have a directory, validated before use.

    Directory names are attacker-controlled only in the sense that anything
    could have been put in the home directory; the id rule is what keeps a
    name from becoming a path traversal, and it is applied here too.
    """
    root = cfg.home / "engagements"
    try:
        entries = list(root.iterdir())
    except (OSError, ValueError):
        return []
    return sorted(
        entry.name for entry in entries
        if entry.is_dir() and is_valid_engagement_id(entry.name)
    )


def _audit_summary(cfg: KryonsecConfig, engagement_id: str) -> dict:
    """Engagement status, derived from a whitelist of audit events.

    Returns only facts the browser needs. The chain itself is not exposed:
    it contains tool output and free-text errors.
    """
    summary: dict[str, Any] = {
        "status": "unknown",
        "target": None,
        "states": [],
        "halt_reason": None,
        "report_written": False,
        "persist_failed": False,
        "audit_entries": 0,
        "started_at": None,
        "updated_at": None,
    }
    if not is_valid_engagement_id(engagement_id):
        return summary

    path = cfg.home / "engagements" / engagement_id / "audit.jsonl"
    if not path.is_file():
        return summary

    states: list[str] = []
    entries = 0
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                entries += 1
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue  # verify() reports corruption; summarise anyway
                if not isinstance(entry, dict):
                    continue
                ts = entry.get("ts")
                if isinstance(ts, str) and ts:
                    summary["updated_at"] = ts
                    if summary["started_at"] is None:
                        summary["started_at"] = ts
                event = entry.get("event")
                if event == _STATE_EVENT:
                    state = entry.get("state")
                    if isinstance(state, str) and state not in states:
                        states.append(state)
                elif event == _CREATED_EVENT:
                    target = entry.get("target")
                    if isinstance(target, str):
                        summary["target"] = target
                elif event == _BLOCKED_EVENT:
                    reason = entry.get("reason")
                    if isinstance(reason, str):
                        summary["halt_reason"] = reason
                elif event == _REPORT_EVENT:
                    summary["report_written"] = True
                elif event == _PERSIST_FAILED_EVENT:
                    summary["persist_failed"] = True
    except OSError:
        return summary

    summary["audit_entries"] = entries
    summary["states"] = states
    if summary["report_written"]:
        summary["status"] = "complete"
    elif summary["halt_reason"]:
        summary["status"] = "halted"
    elif entries:
        summary["status"] = "incomplete"
    return summary


# ---- secret scrubbing -----------------------------------------------------

def scrub(payload: Any) -> tuple[Any, int]:
    """Replace secret-shaped spans with placeholders. Returns (payload, count).

    Walks values rather than the serialized body: a pattern like the
    connection-string one ends in ``[^\\s]+``, which inside compact JSON would
    happily swallow the following ``","next_key":"`` and produce invalid
    output. Scrubbing each string keeps the structure intact.

    Detect-only against ``secrets.SECRET_PATTERNS`` — the same list that
    gates LLM calls and sanitizes the report — so this cannot fall behind it.
    """
    counter = [0]
    return _scrub(payload, counter), counter[0]


def _scrub(value: Any, counter: list[int]) -> Any:
    if isinstance(value, str):
        spans = find_secrets(value)
        if not spans:
            return value
        out: list[str] = []
        cursor = 0
        for _name, _secret, start, end in spans:
            counter[0] += 1
            out.append(value[cursor:start])
            out.append(f"«SECRET_{counter[0]}»")
            cursor = end
        out.append(value[cursor:])
        return "".join(out)
    if isinstance(value, dict):
        return {key: _scrub(item, counter) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub(item, counter) for item in value]
    return value
