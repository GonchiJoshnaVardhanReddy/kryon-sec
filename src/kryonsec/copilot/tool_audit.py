"""Mode A's tool-audit chain (Phase 2A).

Append-only JSONL with SHA256 chaining — deliberately the SAME wire
format as ``purple/audit.py`` (canonical JSON, sorted keys, chained
hashes), so the existing verification tooling can replay Mode A logs
byte-identically.

Why a copy instead of an import: the copilot AGENT layer must never
import anything from ``purple/`` (Mode A / Mode B module boundary —
tests/test_mode_b_isolation.py scans for exactly that). The registry
audits host-side MCP activity (connection/discovery/invocation/refusal/
errors) here; an engagement's audit chain stays in purple's module.
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


class AuditChainError(RuntimeError):
    """The on-disk chain is damaged — appending is refused."""


class ToolAuditLog:
    """Append-only, SHA256-chained audit log for Mode A tool activity.

    Semantics mirror purple's AuditLog: construction RESUMES the chain
    from the stored head, a damaged file refuses to append (loudly),
    and verify() replays the chain and never raises.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.last_hash = self._load_last_hash()

    def write(self, entry: dict) -> str:
        """Append one entry; returns its hash. Entry gains ts, prev_hash
        and hash fields (informational ts; ordering is the chain's)."""
        import datetime as _dt

        with self._lock:
            entry = dict(entry)
            entry.setdefault(
                "ts", _dt.datetime.now(_dt.timezone.utc).isoformat(
                    timespec="seconds"))
            if "prev_hash" in entry or "hash" in entry:
                raise ValueError(
                    "audit entries cannot pre-set prev_hash/hash")
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

    def verify(self) -> "tuple[bool, str | None]":
        """Replay the chain; return (ok, failure reason). Never raises:
        a chain that was never written is simply not verified."""
        prev = _GENESIS_PREV
        if not self.path.exists():
            return (False, "no audit file — nothing written yet")
        with open(self.path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    return (False,
                            f"line {i}: unparseable JSON ({e})")
                if entry.get("prev_hash") != prev:
                    return False, (
                        f"line {i}: prev_hash mismatch — chain broken")
                body = {k: v for k, v in entry.items() if k != "hash"}
                expected = hashlib.sha256(
                    canonical_json(body).encode()).hexdigest()
                if entry.get("hash") != expected:
                    return (False, f"line {i}: hash mismatch — tampered")
                prev = entry["hash"]
        return True, None

    # ---- internals -------------------------------------------------------

    def _load_last_hash(self) -> str:
        """The chain head, or refuse to continue on a damaged file."""
        if not self.path.exists():
            return _GENESIS_PREV
        lines = self.path.read_text(encoding="utf-8").splitlines()
        try:
            max(i for i, line in enumerate(lines) if line.strip())
        except ValueError:
            return _GENESIS_PREV  # empty file
        last = _GENESIS_PREV
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                last = json.loads(line)["hash"]
            except (json.JSONDecodeError, KeyError) as e:
                raise AuditChainError(
                    f"{self.path}: line {i + 1} is not a valid audit "
                    f"entry ({e}). Refusing to append — the chain would "
                    "become permanently unverifiable."
                ) from e
        return last
