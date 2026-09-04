"""Audit chain (spec v2.1.1 §10.2).

Append-only JSONL with SHA256 chaining. Hashes are computed over the exact
canonical serialization written to disk (sorted keys, tight separators) so
verification replays byte-identically. Head hash can be anchored externally.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

_GENESIS_PREV = "0" * 64

_CANON: dict[str, Any] = {"sort_keys": True, "separators": (",", ":")}


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, **_CANON)


class AuditLog:
    """Append-only, SHA256-chained audit log."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.last_hash = self._load_last_hash()

    # ---- writing ---------------------------------------------------------

    def write(self, entry: dict) -> str:
        """Append an entry; returns its hash. Entry is mutated: gains
        prev_hash and hash fields."""
        with self._lock:
            entry = dict(entry)
            entry["prev_hash"] = self.last_hash
            body = canonical_json(entry)
            entry["hash"] = hashlib.sha256(body.encode()).hexdigest()
            line = canonical_json(entry)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self.last_hash = entry["hash"]
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
        if not self.path.exists():
            return _GENESIS_PREV
        last = _GENESIS_PREV
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line)["hash"]
                except (json.JSONDecodeError, KeyError):
                    continue
        return last
