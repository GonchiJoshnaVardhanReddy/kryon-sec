"""Audit chain (spec v2.1.1 §10.2).

Append-only JSONL with SHA256 chaining. Hashes are computed over the exact
canonical serialization written to disk (sorted keys, tight separators) so
verification replays byte-identically. Head hash can be anchored externally.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

_GENESIS_PREV = "0" * 64

_CANON: dict[str, Any] = {"sort_keys": True, "separators": (",", ":")}


class AuditChainError(RuntimeError):
    """The on-disk chain is damaged. Raised instead of appending to it.

    Continuing past a bad line is worse than refusing: the new entry chains
    onto a hash that verify() will reject, so the file becomes permanently
    unverifiable while the run happily keeps going.
    """


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, **_CANON)


class AuditLog:
    """Append-only, SHA256-chained audit log."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.last_hash = self._load_last_hash()
        self._observers: list[Callable[[dict], None]] = []

    # ---- observers -------------------------------------------------------

    def add_observer(self, callback: Callable[[dict], None]) -> None:
        """Watch the stream as it is written. Returns nothing; removal is
        not offered — a run is short and the observer list is rebuilt per
        engagement.

        This is how the Purple Team console learns what tools are running
        without every subagent having to know a UI exists: the audit log
        already records each tool_spawn/tool_result, so it *is* the event
        stream. Observers are presentation only and can never affect the
        chain — see write().
        """
        self._observers.append(callback)

    # ---- writing ---------------------------------------------------------

    def write(self, entry: dict) -> str:
        """Append an entry; returns its hash. Entry is mutated: gains
        ts, prev_hash and hash fields.

        ts (Phase 8): ISO-8601 UTC wall-clock for the report timeline —
        informational, NOT part of the ordering guarantee (the hash chain
        is). Included in the hashed body like every other field."""
        import datetime as _dt

        with self._lock:
            entry = dict(entry)
            entry.setdefault(
                "ts", _dt.datetime.now(_dt.timezone.utc).isoformat(
                    timespec="seconds"))
            entry["prev_hash"] = self.last_hash
            body = canonical_json(entry)
            entry["hash"] = hashlib.sha256(body.encode()).hexdigest()
            line = canonical_json(entry)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self.last_hash = entry["hash"]

            # Notified while still holding the lock, and after the line is
            # durable. Chains and console must agree on order: releasing the
            # lock first would let a concurrent writer append and notify
            # ahead of us, so the UI would show tool results before the
            # spawns that produced them.
            #
            # On a copy, so an observer that mutates its argument cannot
            # reach back into anything that was hashed. In try/except, so a
            # broken observer costs a UI row and never an audit entry —
            # silence is deliberate, since raising would turn a cosmetic
            # bug into a failed engagement.
            for callback in self._observers:
                try:
                    callback(dict(entry))
                except Exception:
                    log.debug("audit observer failed (ignored)", exc_info=True)

            return entry["hash"]

    def head_hash(self) -> str:
        return self.last_hash

    # ---- verification ----------------------------------------------------

    def verify(self) -> tuple[bool, str | None]:
        """Replay the chain; return (ok, failure reason)."""
        prev = _GENESIS_PREV
        with open(self.path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    return False, f"line {i}: unparseable JSON ({e})"
                if entry.get("prev_hash") != prev:
                    return False, (
                        f"line {i}: prev_hash mismatch — chain broken "
                        f"(expected {prev[:12]}…, got {str(entry.get('prev_hash'))[:12]}…)"
                    )
                body = {k: v for k, v in entry.items() if k != "hash"}
                expected = hashlib.sha256(canonical_json(body).encode()).hexdigest()
                if entry.get("hash") != expected:
                    return False, f"line {i}: hash mismatch — entry tampered"
                prev = entry["hash"]
        return True, None

    # ---- internals -------------------------------------------------------

    def _load_last_hash(self) -> str:
        """The chain head, or refuse to continue on a damaged file.

        This used to `continue` past an unparseable line. A torn final line
        (a crash mid-write) was therefore skipped silently: appends resumed
        from the previous hash and the incomplete line stayed in the file, so
        verify() reported "unparseable JSON" on every subsequent run while
        nothing warned at write time. Damage to an audit chain has to be
        loud, and refusing is the only non-destructive option — re-writing
        the file would itself destroy evidence.
        """
        if not self.path.exists():
            return _GENESIS_PREV
        lines = self.path.read_text(encoding="utf-8").splitlines()
        # index of the last line with any content — only that one can be a
        # half-written record; an earlier bad line is corruption or tampering
        try:
            tail = max(i for i, l in enumerate(lines) if l.strip())
        except ValueError:
            return _GENESIS_PREV  # empty file: nothing written yet
        last = _GENESIS_PREV
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                last = json.loads(line)["hash"]
            except (json.JSONDecodeError, KeyError) as e:
                where = ("the last line — the process was probably interrupted "
                         "mid-write" if i == tail else "an entry that is not "
                         "the last — the file was edited or corrupted")
                raise AuditChainError(
                    f"{self.path}: line {i + 1} is not a valid audit entry "
                    f"({e}). It is {where}. Refusing to append — appending "
                    f"would chain onto a hash verify() rejects, leaving the "
                    f"whole log unverifiable. Inspect the file and remove the "
                    f"damaged line yourself if you accept the loss."
                ) from e
        return last
