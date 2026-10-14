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

The verify endpoint is a Cloudflare Pages Function on kryonsec.in
(`functions/api/license/verify.js`). Contract:

    GET {VERIFY_URL}?device=..&os=..&arch=..&version=..
    X-Kryonsec-Key: KRYO-XXXX-XXXX-XXXX
    200 {"valid": true,  "expires": "2027-01-01"}
    200 {"valid": false, "reason": "expired"}

A refusal is a 200 carrying `valid: false`, never a 4xx — this file reads
a non-200 as "the network is down" and falls back to grace, so serving a
revocation as an error status is what would keep a revoked key alive.

Machine registration (the one-time browser step) lives in `connect.py` and
talks to the same site; this file owns the device id and the state file both
of them use.

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

from . import __version__

# crockford base32, ambiguous characters removed (0/O look alike, 1/I)
KEY_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
KEY_PATTERN = re.compile(
    rf"^KRYO-[{KEY_ALPHABET}]{{4}}-[{KEY_ALPHABET}]{{4}}-[{KEY_ALPHABET}]{{4}}$")

VERIFY_URL = os.environ.get(
    "KRYONSEC_LICENSE_URL", "https://kryonsec.in/api/license/verify")
# The connect flow (kryonsec/connect.py) talks to the same site.
CONNECT_START_URL = os.environ.get(
    "KRYONSEC_CONNECT_START_URL", "https://kryonsec.in/api/device/start")
CONNECT_POLL_URL = os.environ.get(
    "KRYONSEC_CONNECT_POLL_URL", "https://kryonsec.in/api/device/poll")
VERIFY_TIMEOUT_S = 8         # matches doctor's ollama probe
GRACE_DAYS = 7               # offline tolerance after a successful check
CHECK_INTERVAL_H = 24        # phone home at most once a day
EXPIRING_SOON_DAYS = 14      # doctor shows "renews soon" inside this window

STATE_FILENAME = "license.state.json"

# Cloudflare answers urllib's default "Python-urllib/3.x" User-Agent with
# 403 (error 1010, "banned browser signature") — the zone's Browser Integrity
# Check reads it as a bot. That 403 is indistinguishable from an outage here,
# so every member would have fallen through to grace and never activated.
# Identify the client instead; any well-formed agent is allowed through.
USER_AGENT = f"kryonsec/{__version__} (+https://kryonsec.in)"

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


def device_id(cfg: Any) -> str:
    """A random id for this installation, made once and kept in the state file.

    It is how the admin view tells one machine from another. Deliberately NOT
    a credential — it authorises nothing, so leaking it costs nothing — and
    deliberately NOT derived from the host: no hostname, no MAC, no machine
    id. Just 128 random bits that identify this install and nothing else.
    """
    state = load_state(cfg)
    existing = str(state.get("device_id") or "")
    if existing:
        return existing

    import secrets

    fresh = secrets.token_hex(16)
    state["device_id"] = fresh
    save_state(cfg, state)
    return fresh


def member_email(cfg: Any) -> str:
    """The email this machine was connected to, or "" if it never was."""
    return str(load_state(cfg).get("member_email") or "")


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


def _http_json(url: str, payload: dict | None = None, *, key: str = "") -> dict | None:
    """GET url, or POST `payload` to it as JSON. Returns the parsed JSON
    object, or None on any failure — the caller decides whether that means
    grace, a refusal, or "the network is down".
    (Seam for tests: monkeypatch this.)"""
    import urllib.request

    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if key:
        # A membership key is a credential, and a URL is a leaky place to put
        # one: query strings land in access logs, in proxy logs, and in
        # Referer headers. A request header goes nowhere but the request. The
        # endpoint still accepts ?key= so older installs keep working.
        headers["X-Kryonsec-Key"] = key
    if data is not None:
        headers["Content-Type"] = "application/json"

    # An explicit Request, not urlopen(url): the default agent is refused by
    # the verify endpoint's zone. See USER_AGENT. One builder for both verbs,
    # so the agent can't be fixed in one path and drift in the other.
    req = urllib.request.Request(url, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=VERIFY_TIMEOUT_S) as r:
            if r.status != 200:
                return None
            body = json.loads(r.read().decode("utf-8"))
            return body if isinstance(body, dict) else None
    except Exception:
        return None


def _http_get_json(url: str, *, key: str = "") -> dict | None:
    """GET url, parse a JSON object response. None on any failure."""
    return _http_json(url, None, key=key)


def http_post_json(url: str, payload: dict) -> dict | None:
    """POST a JSON body, parse a JSON object response. None on any failure.
    The connect flow (kryonsec/connect.py) is the caller."""
    return _http_json(url, payload)


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

    import platform
    import urllib.parse

    # The device parameters are what let the admin view show a machine as
    # alive: an id this install made up, the OS, the architecture, the app
    # version. Nothing about the work being done — no hostname, no path, no
    # target — and nothing that could be replayed as a credential.
    params = {
        "device": device_id(cfg),
        "os": platform.system(),
        "arch": platform.machine(),
        "version": __version__,
    }
    data = _http_get_json(
        f"{VERIFY_URL}?{urllib.parse.urlencode(params)}", key=key)
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
    unless the license is valid or in offline grace AND this machine has
    been connected to a membership once — callers print the message, never
    a stack trace.

    Every Purple entry point routes through here rather than checking the
    license itself, so a new caller cannot forget one of the two conditions.
    Copilot mode never calls it: the free mode has no gate.
    """
    result = verify(cfg)
    if not result.purple_allowed:
        raise LicenseError(result.message or f"license {result.status}")
    if not member_email(cfg):
        raise LicenseError(
            "this machine has not been connected to a membership yet — run "
            "`kryonsec connect` (it opens a browser once; after that the "
            "machine is registered and never asks again)")
    return result
