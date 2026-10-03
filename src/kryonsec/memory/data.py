"""Read-only access to persisted engagement memory (the memory browser's data layer).

Everything the browser can see passes through this module. It is written
around four rules:

1. **Read-only means no DDL either.** ``init_purple_db`` migrates a schema;
   the viewer must never be the thing that creates a database or upgrades
   one. So storage is *inspected* (does the file exist? do the tables?), and
   a missing store is a reported state, not something to build on demand.

2. **Nothing is read out of the audit chain except a whitelist of fields.**
   The chain holds tool output and free-text error messages. The browser
   needs to answer "what happened to this engagement" — so this module pulls
   event names, the outcome, state names, the target, checkpoint counts and a
   scrubbed reason, and never passes an audit entry through.

   **One run at a time.** An engagement id names a directory that can host
   several executions, and the chain is append-only, so the file is not one
   run's story. The summary describes the run that is *current* — the last
   one to open its chain (Phase 4.5B) — so a newer run can never be read
   with an older run's status, state count or ending: an ending counts for a
   run only when it carries that run's id, or when neither carries one. A
   chain with no creation event at all is the single anonymous run every
   pre-4.5B chain is, and reads exactly as it did before.

3. **Secrets are scrubbed on the way out.** Node properties are
   observations — the one place a credential could plausibly have been
   recorded. Every string in a response is run through the same detector the
   LLM gates and the report use (``secrets.find_secrets``), so the pattern
   list cannot drift, and matches are replaced with ``«SECRET_n»``
   placeholders numbered across the whole response. The mapping is not kept:
   the browser is a viewer, not a place to reveal secrets.

4. **A chain field is untrusted input.** The chain is a local file, and the
   browser renders what is in it. Free text reaches the page only through
   :func:`_text`, which strips the local home directory and removes
   path-shaped runs, so a status line cannot carry a filesystem path from a
   machine onto a screen. Identifiers reach it only through :func:`_ident`,
   which validates the shape and caps the length.

   Secrets are deliberately *not* handled here. They are caught by
   :func:`scrub` at the response boundary, which is the single place that
   knows how many it found — and that count is the operator's only signal
   that a credential-shaped value was recorded at all. Redacting earlier
   would hide the secret and the warning with it.
"""

from __future__ import annotations

import json
import logging
import re
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
# Phase 4.2 added the single terminal event; Phase 4.3 added the two
# checkpoint events. Before 4.2 an engagement's ending had to be inferred
# from report_written / zone_b_blocked, which is why those are still read.
_FINISHED_EVENT = "engagement_finished"
_CHECKPOINT_EVENT = "checkpoint_written"
_CHECKPOINT_FAILED_EVENT = "checkpoint_failed"
# Phase 4.5B: how a run is told apart from the runs before it under the same
# id. ``run_id`` is on every creation event the engine writes now; a chain
# older than that has none, which is a state this module has to keep reading.
_GRAPH_PERSISTED_EVENT = "graph_persisted"

# How a recorded outcome reads as a status. The same four words the engine
# writes (``purple.runner.OUTCOMES``), duplicated rather than imported
# because this package must not import the runner at all — that is what the
# import allowlist in tests/test_memory.py enforces. A test pins the two
# vocabularies together so the copy cannot drift unnoticed.
#
# An outcome outside this table is not an error: it falls back to the
# inferred status below, so a chain written by a later version still renders.
_OUTCOME_STATUS = {
    "completed": "complete",
    "halted": "halted",
    "failed": "failed",
    "interrupted": "interrupted",
}

# Absolute-path-shaped runs in free text. Deliberately narrow: this is a
# display filter, not a validator, and over-matching would eat ordinary
# status text. A drive letter or an explicit POSIX root is what a real path
# in a sandbox or storage message looks like.
_ABS_PATH = re.compile(
    r"[A-Za-z]:[\\/][^\s'\"]*"                      # C:\… and C:/…
    r"|\\\\[^\s'\"]*"                               # \\host\share
    r"|/(?:home|Users|root|tmp|var|opt|etc|mnt|media|srv|usr|proc)/[^\s'\"]*"
)


class InvalidEngagementId(ValueError):
    """The requested id is not a safe engagement id."""


class MemoryUnavailable(RuntimeError):
    """Engagement storage cannot be read right now."""


# ---- reading a chain field safely -----------------------------------------

def _ident(value: Any, limit: int = 64) -> str | None:
    """A short identifier from the chain, or None.

    Used for the engine's closed vocabularies — an outcome, a state name, a
    halt code, an exception class. ``isidentifier`` is the cheapest way to
    say "a bare word and nothing else", which is what all of those are; a
    value that fails it is dropped rather than rendered.
    """
    if isinstance(value, str) and value.isidentifier() and len(value) <= limit:
        return value
    return None


def _count(value: Any) -> int:
    """A non-negative integer from the chain, or 0. ``bool`` is excluded
    because ``True`` is an ``int`` and would render as a count of 1."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def _text(value: Any, home: Path | None = None, limit: int = 200) -> str | None:
    """Free text from the chain, reduced to something safe to render.

    Two passes, in this order:

    * **the local home directory** — replaced with ``<home>`` before anything
      else, because it names the machine's user and it is the one path we
      know exactly rather than by pattern;
    * **path-shaped runs** — :data:`_ABS_PATH`, for a path that is not under
      the home directory.

    Then whitespace is collapsed and the result capped: the chain is written
    by a machine and read by a person looking at a status line.

    Secrets are left in place for :func:`scrub` to find, so that the
    response reports them rather than silently losing them.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    if home is not None:
        prefix = str(home)
        for form in (prefix, prefix.replace("\\", "\\\\"),
                     prefix.replace("\\", "/")):
            value = value.replace(form, "<home>")
    value = _ABS_PATH.sub("<path>", value)
    value = " ".join(value.split())
    return value[:limit] or None



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


def _infer_status(summary: dict, readable_lines: int) -> str:
    """The reading of a chain that has no ``engagement_finished`` event.

    Every engagement recorded before Phase 4.2 has only these signals, and a
    chain whose last line was lost still does. A report is the strongest of
    them — it is only written at the end — then a sandbox block, then simply
    "there are lines we could read, so something ran".

    ``readable_lines`` rather than ``audit_entries``: a chain of nothing but
    unreadable lines is evidence of a file, not of an engagement, and calling
    that "incomplete" would claim more than is known.
    """
    if summary["report_written"]:
        return "complete"
    if summary["halt_reason"]:
        return "halted"
    if readable_lines:
        return "incomplete"
    return "unknown"


def _new_run() -> dict[str, Any]:
    """The facts gathered for one execution, reset at every creation event.

    An engagement id names a directory that can host several runs, and the
    chain is append-only, so the whole file is not one run's story. The
    browser shows the run that is current — the last to open its chain with
    an ``engagement_created`` — and this is what its segment is read into.
    """
    return {
        "run_id": None,
        "target": None,
        "halt_reason": None,
        "report_written": False,
        "persist_failed": False,
        "lifecycle_recorded": False,
        "outcome": None,
        "last_state": None,
        "states_entered": 0,
        "exception_type": None,
        "reason": None,
        "states": [],
        "checkpoints": 0,
        "last_checkpoint_state": None,
        "checkpoint_failures": 0,
        "checkpoint_error": None,
        "saved_graph": False,
        "started_at": None,
        "updated_at": None,
        "readable": 0,
    }


def _audit_summary(cfg: KryonsecConfig, engagement_id: str) -> dict:
    """Engagement lifecycle and artifact availability, from whitelisted events.

    Three sources, in order of authority:

    * ``engagement_finished`` — the terminal event Phase 4.2 added. When it is
      present its recorded outcome *is* the status. A chain written by an
      older version, or one cut off before the last line, has no such event
      and falls back to :func:`_infer_status`.
    * the checkpoint events Phase 4.3 added — how far the graph got saved, and
      whether saving ever failed.
    * the pre-4.2 events (``state_enter``, ``zone_b_blocked``,
      ``report_written``, ``graph_persist_failed``), which are still the only
      record some engagements have.

    All of them are read **per run**. A creation event opens a run and the
    next creation event closes it, so the summary describes the last run in
    the chain and never a mixture of two (Phase 4.5B). Within a run, the
    ending is read only when its ``run_id`` is that run's — or when neither
    carries one, which is every chain written before run ids existed. A chain
    with no creation event is the single anonymous run that every pre-4.5B
    chain is, and reads exactly as it did before this phase.

    The chain itself is never exposed — it holds tool output and free-text
    errors. Everything that leaves here has been through :func:`_text` or
    :func:`_ident`, so no field can carry a path or a credential to a screen.

    The status is deliberately *event-driven*: a report file on disk is
    reported separately as ``report_available`` rather than upgrading the
    status, because "a report exists" and "the engagement recorded itself as
    finished" are two different facts and the browser shows both. Which run
    each artifact belongs to is reported too — ``graph_current`` and
    ``report_current`` — because both are replaced in place under a reused id.
    """
    home = cfg.home
    summary: dict[str, Any] = {
        # -- read by the browser before Phase 4.4; names and meanings kept --
        "status": "unknown",
        "target": None,
        "states": [],
        "halt_reason": None,
        "report_written": False,
        "persist_failed": False,
        "audit_entries": 0,
        "started_at": None,
        "updated_at": None,
        # -- lifecycle ------------------------------------------------------
        "lifecycle_recorded": False,
        "outcome": None,
        "last_state": None,
        "states_entered": 0,
        "exception_type": None,
        "reason": None,
        "report_available": False,
        "checkpoints": 0,
        "last_checkpoint_state": None,
        "checkpoint_failures": 0,
        "checkpoint_error": None,
        # ``None`` means there is no chain at all — a distinct state from a
        # chain that exists and could not be opened.
        "audit_readable": None,
        "audit_damaged_lines": 0,
        # -- run identity (Phase 4.5B) --------------------------------------
        "run_id": None,
        "run_count": 0,
        # Whether the graph rows and the report file on disk were written by
        # the current run. Only ever False when the id hosts several runs.
        "graph_current": True,
        "report_current": True,
    }
    if not is_valid_engagement_id(engagement_id):
        return summary

    directory = home / "engagements" / engagement_id
    path = directory / "audit.jsonl"

    # The report path is built from the validated id, never from the
    # ``report_written`` event, whose ``path`` field is a real filesystem
    # path and is deliberately not read.
    summary["report_available"] = (directory / "report.md").is_file()

    if not path.is_file():
        return summary

    entries = 0
    damaged = 0
    runs_opened = 0        # creation events seen in the chain
    pre_run_entries = 0    # readable entries before the first creation
    cur = _new_run()       # the facts of the run currently being read
    try:
        # ``errors="replace"`` because a crash can leave the last line ending
        # mid-character, and a decode error would otherwise throw away an
        # engagement's entire history over one bad byte. The line that
        # results is almost always unparseable JSON and is counted as
        # damaged below, which is the honest reading of it.
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                entries += 1
                try:
                    entry = json.loads(line)
                except ValueError:
                    damaged += 1  # verify() reports corruption; summarise anyway
                    continue
                if not isinstance(entry, dict):
                    damaged += 1
                    continue
                event = entry.get("event")
                if event == _CREATED_EVENT:
                    # A new run opens here. Everything gathered so far
                    # belonged to the run before it — and any ending among it
                    # is that run's, not this one's.
                    runs_opened += 1
                    cur = _new_run()
                    cur["run_id"] = _ident(entry.get("run_id"))
                if runs_opened == 0:
                    pre_run_entries += 1
                cur["readable"] += 1
                ts = entry.get("ts")
                if isinstance(ts, str) and ts:
                    cur["updated_at"] = ts
                    if cur["started_at"] is None:
                        cur["started_at"] = ts
                if event == _STATE_EVENT:
                    state = _ident(entry.get("state"))
                    if state is not None:
                        if state not in cur["states"]:
                            cur["states"].append(state)
                        cur["last_state"] = state
                elif event == _CREATED_EVENT:
                    cur["target"] = _text(entry.get("target"), home)
                elif event == _BLOCKED_EVENT:
                    cur["halt_reason"] = _text(entry.get("reason"), home)
                elif event == _REPORT_EVENT:
                    cur["report_written"] = True
                elif event == _PERSIST_FAILED_EVENT:
                    cur["persist_failed"] = True
                elif event == _GRAPH_PERSISTED_EVENT:
                    # Both callers announce only after their storage commit,
                    # so this is evidence the rows on disk are this run's.
                    cur["saved_graph"] = True
                elif event == _FINISHED_EVENT:
                    # An ending is read only for the run it belongs to: the
                    # same run id, or none on either side. A chain written
                    # before run ids existed has none on both, so every
                    # ending recorded before Phase 4.5B still reads; an
                    # ending carrying another run's id is that run's and is
                    # not read here. This is the reader's half of the guard
                    # the engine applies in ``runner._current_run``, so the
                    # two cannot disagree about whether the current run has
                    # ended — and a damaged or hand-edited chain can never
                    # lend a run an outcome it did not record.
                    if _ident(entry.get("run_id")) != cur["run_id"]:
                        continue
                    # The event's presence is the record, even if its outcome
                    # is not one this version knows — an unknown outcome still
                    # means the ending was recorded, and the status then falls
                    # back to inference rather than claiming to be unknown.
                    cur["lifecycle_recorded"] = True
                    cur["outcome"] = _ident(entry.get("outcome"))
                    cur["last_state"] = (
                        _ident(entry.get("last_state")) or cur["last_state"]
                    )
                    cur["states_entered"] = _count(entry.get("states_entered"))
                    cur["exception_type"] = _ident(entry.get("exception_type"))
                    cur["reason"] = _ident(entry.get("reason"))
                elif event == _CHECKPOINT_EVENT:
                    cur["checkpoints"] += 1
                    cur["saved_graph"] = True
                    state = _ident(entry.get("state"))
                    if state is not None:
                        cur["last_checkpoint_state"] = state
                elif event == _CHECKPOINT_FAILED_EVENT:
                    cur["checkpoint_failures"] += 1
                    error = _text(entry.get("error"), home)
                    if error is not None:
                        cur["checkpoint_error"] = error
    except OSError:
        # The chain exists and could not be opened. Reported as such rather
        # than as an engagement with no events.
        summary["audit_readable"] = False
        return summary

    summary["audit_entries"] = entries
    summary["audit_damaged_lines"] = damaged
    summary["audit_readable"] = True

    # The current run is the last to open its chain. A chain with no creation
    # event holds one anonymous run — every chain written before Phase 4.5B,
    # plus the fixtures — and is read exactly as it was before this phase.
    run_count = runs_opened + (1 if pre_run_entries else 0)

    summary["target"] = cur["target"]
    summary["states"] = cur["states"]
    summary["halt_reason"] = cur["halt_reason"]
    summary["report_written"] = cur["report_written"]
    summary["persist_failed"] = cur["persist_failed"]
    summary["lifecycle_recorded"] = cur["lifecycle_recorded"]
    summary["outcome"] = cur["outcome"]
    summary["last_state"] = cur["last_state"]
    summary["states_entered"] = cur["states_entered"]
    summary["exception_type"] = cur["exception_type"]
    summary["reason"] = cur["reason"]
    summary["started_at"] = cur["started_at"]
    summary["updated_at"] = cur["updated_at"]
    summary["checkpoints"] = cur["checkpoints"]
    summary["last_checkpoint_state"] = cur["last_checkpoint_state"]
    summary["checkpoint_failures"] = cur["checkpoint_failures"]
    summary["checkpoint_error"] = cur["checkpoint_error"]
    summary["run_id"] = cur["run_id"]
    summary["run_count"] = run_count

    # Which run the two artifacts on disk belong to. With one run there is
    # nothing to confuse them with. With several, an artifact counts as the
    # current run's only when that run's own segment says it wrote it: the
    # graph rows are replaced wholesale by whoever saves last, and report.md
    # is overwritten only by a run that reaches REPORT, so either can
    # otherwise linger from an earlier run and be read as this run's.
    reused = run_count > 1
    summary["graph_current"] = cur["saved_graph"] if reused else True
    summary["report_current"] = cur["report_written"] if reused else True

    summary["status"] = _OUTCOME_STATUS.get(summary["outcome"] or "") \
        or _infer_status(summary, cur["readable"])
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
