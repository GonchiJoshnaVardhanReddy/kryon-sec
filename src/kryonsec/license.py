"""License verification (membership model, 2026-09 plan).

Copilot mode is free. Purple Team (the paid feature) is gated: a valid
membership key must verify against kryonsec.in before an engagement
starts. The check is honest, not aggressive:

- phones home at most once per day (result cached in the state file)
- a dead network never locks a member out: offline operation runs on a
  7-day grace period from the last successful verification
- a clock rollback (state timestamp in the future) counts as tampering
- nothing is ever deleted; the only enforcement is refusing to START a
  new Purple Team engagement

The verify endpoint starts life as an n8n webhook on kryonsec.in — no
backend code of ours runs there. Contract:

    GET {VERIFY_URL}?key=KRYO-XXXX-XXXX-XXXX
    200 {"valid": true,  "expires": "2027-01-01"}
    200 {"valid": false, "reason": "expired"}

Keys are crockford-base32 groups (no 0/O/1/I) after a "KRYO-" prefix.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# crockford base32, ambiguous characters removed (0/O look alike, 1/I)
KEY_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
KEY_PATTERN = re.compile(
    rf"^KRYO-[{KEY_ALPHABET}]{{4}}-[{KEY_ALPHABET}]{{4}}-[{KEY_ALPHABET}]{{4}}$")

VERIFY_URL = os.environ.get(
    "KRYONSEC_LICENSE_URL", "https://kryonsec.in/api/license/verify")
VERIFY_TIMEOUT_S = 8         # matches doctor's ollama probe
GRACE_DAYS = 7               # offline tolerance after a successful check
CHECK_INTERVAL_H = 24        # phone home at most once a day
EXPIRING_SOON_DAYS = 14      # doctor shows "renews soon" inside this window

STATE_FILENAME = "license.state.json"

# statuses a VerifyResult can carry
VALID = "valid"
GRACE = "grace"
EXPIRED = "expired"
INVALID = "invalid"
NOT_CONFIGURED = "not_configured"


class LicenseError(Exception):
    """Purple Team blocked by license status. `result` carries the details."""


@dataclass
class VerifyResult:
    status: str
    expires: str = ""          # ISO date from the API, informational
    days_left: int | None = None
    message: str = ""

    @property
    def purple_allowed(self) -> bool:
        return self.status in (VALID, GRACE)


# ---- state file ------------------------------------------------------------

def license_state_path(cfg: Any) -> Path:
    return Path(cfg.home) / STATE_FILENAME


def load_state(cfg: Any) -> dict:
    """Missing or corrupt state -> {} (never crashes the caller)."""
    path = license_state_path(cfg)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError):
        return {}


def save_state(cfg: Any, state: dict) -> None:
    path = license_state_path(cfg)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except OSError:
        pass  # state is an optimization; a read-only home must not crash


# ---- helpers ----------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _http_get_json(url: str) -> dict | None:
    """GET url, parse a JSON object response. None on any failure —
    the caller decides whether that means grace or first-run-invalid.
    (Seam for tests: monkeypatch this.)"""
    import urllib.parse
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=VERIFY_TIMEOUT_S) as r:
            if r.status != 200:
                return None
            data = json.loads(r.read().decode("utf-8"))
            return data if isinstance(data, dict) else None
    except Exception:
        return None


def _days_between(later: datetime, earlier: datetime) -> int:
    return (later - earlier).days


def _from_state_grace(state: dict, now: datetime) -> VerifyResult:
    """Network is down (or the API misbehaved): decide from saved state."""
    last_success = _parse_ts(state.get("last_success"))
    if last_success is None:
        return VerifyResult(
            INVALID,
            message="license could not be verified online and was never "
                    "verified on this machine — go online once to activate")
    days = _days_between(now, last_success)
    if days < 0:
        # last_success in the future = clock rollback = tampering
        return VerifyResult(
            EXPIRED,
            message="license state inconsistent (system clock rolled back?) "
                    "— re-verify online to continue")
    if days <= GRACE_DAYS:
        return VerifyResult(
            GRACE,
            expires=state.get("expires", ""),
            days_left=GRACE_DAYS - days,
            message=f"offline — {GRACE_DAYS - days} day(s) of grace left")
    return VerifyResult(
        EXPIRED,
        message=f"license not verified for {days} days (limit {GRACE_DAYS}) "
                "— go online to re-verify")


# ---- the entry point ---------------------------------------------------------

def verify(cfg: Any) -> VerifyResult:
    """Check the license. One call for every consumer (doctor, wizard,
    purple gate). Never raises; the result object tells the story."""
    key = (getattr(cfg, "license_key", None) or "").strip()
    if not key:
        return VerifyResult(
            NOT_CONFIGURED,
            message="no membership key configured — Copilot mode only "
                    "(Purple Team needs a key from kryonsec.in)")
    if not KEY_PATTERN.match(key):
        return VerifyResult(
            INVALID,
            message="malformed key (expected KRYO-XXXX-XXXX-XXXX) — "
                    "check for typos or copy it again from your membership "
                    "email")

    now = _now()
    state = load_state(cfg)

    # daily cache: a successful check inside the interval is replayed
    # without touching the network (phone home at most once a day)
    last_check = _parse_ts(state.get("last_check"))
    if (
        last_check is not None
        and state.get("cached_status") == VALID
        and _days_between(now, last_check) * 24 < CHECK_INTERVAL_H
        and _parse_ts(state.get("last_success")) is not None
        and _days_between(now, _parse_ts(state.get("last_success"))) >= 0
    ):
        expires = state.get("expires", "")
        days_left = None
        if expires:
            try:
                days_left = (datetime.fromisoformat(expires) - now).days
            except ValueError:
                pass
        return VerifyResult(VALID, expires=expires, days_left=days_left)

    import urllib.parse

    data = _http_get_json(f"{VERIFY_URL}?{urllib.parse.urlencode({'key': key})}")
    if data is None:
        # unreachable/broken endpoint: grace decides; last_success is
        # never overwritten by a failure, so a dead webhook cannot lock
        # out a member who verified recently
        return _from_state_grace(state, now)

    if data.get("valid") is True:
        expires = str(data.get("expires", ""))
        save_state(cfg, {
            "last_check": now.isoformat(),
            "last_success": now.isoformat(),
            "cached_status": VALID,
            "expires": expires,
        })
        days_left = None
        if expires:
            try:
                days_left = (datetime.fromisoformat(expires) - now).days
            except ValueError:
                pass
        return VerifyResult(VALID, expires=expires, days_left=days_left)

    # the API answered "not valid": record the check (so the daily cache
    # doesn't hammer a revoked key) but keep last_success untouched —
    # a later genuine renewal overwrites cached_status again
    reason = str(data.get("reason", "key not valid"))
    save_state(cfg, {
        "last_check": now.isoformat(),
        "last_success": state.get("last_success"),
        "cached_status": EXPIRED if reason == "expired" else INVALID,
        "expires": state.get("expires", ""),
    })
    status = EXPIRED if reason == "expired" else INVALID
    return VerifyResult(
        status,
        message=f"license {reason} — renew at kryonsec.in "
                "(membership: your key stops working when it lapses)")


def ensure_purple_allowed(cfg: Any) -> VerifyResult:
    """Blocking gate for Purple Team engagements. Raises LicenseError
    unless the license is valid or in offline grace — callers print the
    message, never a stack trace."""
    result = verify(cfg)
    if not result.purple_allowed:
        raise LicenseError(result.message or f"license {result.status}")
    return result
