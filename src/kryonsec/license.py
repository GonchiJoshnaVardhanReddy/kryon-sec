"""License verification (membership model, 2026-09 plan).

Copilot mode is free. Purple Team (the paid feature) is gated: the machine
must be authorised before an engagement starts, by one of two credentials:

- a **membership key** (`KRYO-XXXX-XXXX-XXXX`), typed in once, posted by
  email, and not revocable in any meaningful sense
- a **beta session token** (`s_…`), obtained by `kryonsec login`, revocable
  from the dashboard, and what an early-access account gets

Both end at the same endpoint and the same `accessFor()` answer there; the
key is checked first. See kryonsec/auth.py for the token's half.

The check is honest, not aggressive:

- phones home at most once per day (result cached in the state file, keyed on
  which credential was checked, so switching accounts cannot replay a stale
  "valid")
- a dead network never locks a member out: offline operation runs on a
  7-day grace period from the last successful verification
- a clock rollback (state timestamp in the future) counts as tampering
- nothing is ever deleted; the only enforcement is refusing to START a
  new Purple Team engagement

The verify endpoint is a Cloudflare Pages Function on kryonsec.in
(`functions/api/license/verify.js`). Contract:

    GET {VERIFY_URL}?device=..&os=..&arch=..&version=..
    X-Kryonsec-Key: KRYO-XXXX-XXXX-XXXX     — or —
    Authorization: Bearer s_<64 hex>
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
from contextvars import ContextVar
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
# ...but a key and a token are not the same promise. A key is a flat allowlist
# entry with no expiry: this daily check IS the enforcement, so it cannot be
# more or less often than "once a day". A token is revocable, and the dashboard
# offers a button that says so — a day of stale "valid" after someone clicks it
# is the difference between cutting an account off and cutting it off tomorrow.
#
# An hour costs one request per hour of use. It does not cost offline operation:
# a failed check falls through to grace, which is the offline mechanism, and is
# unchanged. See LIMITATIONS in SECURITY-NOTES.md for what this window is.
TOKEN_CHECK_INTERVAL_H = 1
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


@dataclass(frozen=True)
class HttpFailure:
    """A safe, user-facing classification of a failed site request.

    The raw exception is deliberately not retained: it can contain a full URL,
    proxy details, or a credential supplied by a caller.  The CLI needs to tell
    DNS, TLS, timeout, HTTP, and malformed-response failures apart, but it does
    not need to print transport internals.
    """

    kind: str
    message: str


HTTP_FAILURE = "http"
DNS_FAILURE = "dns"
TLS_FAILURE = "tls"
TIMEOUT_FAILURE = "timeout"
MALFORMED_FAILURE = "malformed_response"
NETWORK_FAILURE = "network"

_LAST_HTTP_FAILURE: ContextVar[HttpFailure | None] = ContextVar(
    "kryonsec_last_http_failure", default=None)


def clear_http_error() -> None:
    """Forget the previous request's failure before a new request starts."""
    _LAST_HTTP_FAILURE.set(None)


def last_http_error() -> HttpFailure | None:
    """Return the current request's safe failure, if it had one."""
    return _LAST_HTTP_FAILURE.get()


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


def _endpoint_host(url: str) -> str:
    import urllib.parse

    try:
        return urllib.parse.urlsplit(url).hostname or "the license server"
    except ValueError:
        return "the license server"


def _record_http_failure(kind: str, message: str) -> None:
    _LAST_HTTP_FAILURE.set(HttpFailure(kind, message))


def _classify_http_exception(exc: Exception, url: str) -> HttpFailure:
    """Turn urllib/socket exceptions into stable, non-sensitive diagnostics."""
    import socket
    import ssl

    host = _endpoint_host(url)
    candidates: list[object] = [exc]
    reason = getattr(exc, "reason", None)
    if reason is not None:
        candidates.append(reason)
    if exc.__cause__ is not None:
        candidates.append(exc.__cause__)
    if exc.__context__ is not None:
        candidates.append(exc.__context__)

    text = " ".join(str(item).lower() for item in candidates if item)
    if any(isinstance(item, (TimeoutError, socket.timeout)) for item in candidates):
        return HttpFailure(TIMEOUT_FAILURE, f"request to {host} timed out")
    if "timed out" in text or "timeout" in text:
        return HttpFailure(TIMEOUT_FAILURE, f"request to {host} timed out")
    if any(isinstance(item, ssl.SSLError) for item in candidates):
        return HttpFailure(TLS_FAILURE, f"TLS connection to {host} failed")
    if any(isinstance(item, socket.gaierror) for item in candidates):
        return HttpFailure(DNS_FAILURE, f"DNS lookup failed for {host}")
    if any(term in text for term in (
        "getaddrinfo",
        "name or service not known",
        "nodename nor servname",
        "no such host",
    )):
        return HttpFailure(DNS_FAILURE, f"DNS lookup failed for {host}")
    if any(term in text for term in ("ssl", "tls", "certificate verify failed")):
        return HttpFailure(TLS_FAILURE, f"TLS connection to {host} failed")
    return HttpFailure(NETWORK_FAILURE, f"could not connect to {host}")


def _http_json(
    url: str, payload: dict | None = None, *, key: str = "", token: str = ""
) -> dict | None:
    """GET url, or POST `payload` to it as JSON. Returns the parsed JSON
    object, or None on any failure — the caller decides whether that means
    grace, a refusal, or "the network is down".  `last_http_error()` carries a
    safe classification for the caller that needs to explain the failure.
    (Seam for tests: monkeypatch this.)

    Sends whichever credentials it is given. The verify endpoint checks the
    key first and the token only when there is no key, so passing both from a
    machine that somehow has both is not ambiguous — the server's precedence
    decides, and it is the same precedence this file uses when it decides
    whether anything is configured at all.
    """
    import urllib.error
    import urllib.request

    clear_http_error()
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if key:
        # A membership key is a credential, and a URL is a leaky place to put
        # one: query strings land in access logs, in proxy logs, and in
        # Referer headers. A request header goes nowhere but the request. The
        # endpoint still accepts ?key= so older installs keep working.
        headers["X-Kryonsec-Key"] = key
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        headers["Content-Type"] = "application/json"

    # An explicit Request, not urlopen(url): the default agent is refused by
    # the verify endpoint's zone. See USER_AGENT. One builder for both verbs,
    # so the agent can't be fixed in one path and drift in the other.
    req = urllib.request.Request(url, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=VERIFY_TIMEOUT_S) as r:
            if r.status != 200:
                _record_http_failure(
                    HTTP_FAILURE,
                    f"{_endpoint_host(url)} returned HTTP {r.status}",
                )
                return None
            try:
                body = json.loads(r.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                _record_http_failure(
                    MALFORMED_FAILURE,
                    f"{_endpoint_host(url)} returned malformed JSON",
                )
                return None
            if not isinstance(body, dict):
                _record_http_failure(
                    MALFORMED_FAILURE,
                    f"{_endpoint_host(url)} returned an unexpected JSON value",
                )
                return None
            return body
    except Exception as exc:
        # HTTPError is raised by urllib for a non-2xx response instead of
        # reaching the status check above.
        if isinstance(exc, urllib.error.HTTPError):
            _record_http_failure(
                HTTP_FAILURE,
                f"{_endpoint_host(url)} returned HTTP {exc.code}",
            )
            return None
        failure = _classify_http_exception(exc, url)
        _LAST_HTTP_FAILURE.set(failure)
        return None


def _http_get_json(url: str, *, key: str = "", token: str = "") -> dict | None:
    """GET url, parse a JSON object response. None on any failure."""
    return _http_json(url, None, key=key, token=token)


def http_post_json(url: str, payload: dict, *, token: str = "") -> dict | None:
    """POST a JSON body, parse a JSON object response. None on any failure.
    The connect and login flows (kryonsec/connect.py, kryonsec/auth.py) are
    the callers; `token` is how logout revokes the credential it presents."""
    return _http_json(url, payload, token=token)


def _days_between(later: datetime, earlier: datetime) -> int:
    return (later - earlier).days


def _hours_between(later: datetime, earlier: datetime) -> float:
    """Exact hours, not `_days_between * 24`: timedelta.days truncates, so a
    day-based comparison of a sub-day interval can only ever be 0 or 24."""
    return (later - earlier).total_seconds() / 3600


def _remember(cfg: Any, updates: dict) -> None:
    """Merge `updates` into the state file instead of replacing it.

    `member_email`, `device_id`, and `connect_offered` live in the same file
    and belong to other flows; a plain save_state here would silently drop
    every field this function did not think to name.
    """
    state = load_state(cfg)
    state.update(updates)
    save_state(cfg, state)


def _credential_id(key: str, token: str) -> str:
    """A short, non-reversible label for whichever credential was checked, so
    the daily cache can tell one account from another. Not a credential: it is
    a hash of one, and it only ever goes into this machine's own state file."""
    import hashlib

    return hashlib.sha256((key or token).encode("utf-8")).hexdigest()[:16]


def _from_state_grace(
    state: dict, now: datetime, failure: HttpFailure | None = None
) -> VerifyResult:
    """Network is down (or the API misbehaved): decide from saved state."""
    detail = f" (last attempt: {failure.message})" if failure else ""
    last_success = _parse_ts(state.get("last_success"))
    if last_success is None:
        return VerifyResult(
            INVALID,
            message="license could not be verified online and was never "
                    "verified on this machine — go online once to activate"
                    f"{detail}")
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
            message=f"offline — {GRACE_DAYS - days} day(s) of grace left"
                    f"{detail}")
    return VerifyResult(
        EXPIRED,
        message=f"license not verified for {days} days (limit {GRACE_DAYS}) "
                f"— go online to re-verify{detail}")


# ---- the entry point ---------------------------------------------------------

def verify(cfg: Any) -> VerifyResult:
    """Check the license. One call for every consumer (doctor, wizard,
    purple gate). Never raises; the result object tells the story.

    Two credentials can authorise this machine, and they are not
    interchangeable: a membership key (typed in once, posted by email, cannot
    be taken back) and a beta session token (`kryonsec login`, revocable). The
    key is checked first, matching the server, so a machine that holds both
    behaves the same here as it does there.
    """
    key = (getattr(cfg, "license_key", None) or "").strip()
    # Imported here rather than at the top: auth.py imports this module for
    # `http_post_json`, so a module-level import back would be a cycle.
    from . import auth

    token = auth.token(cfg)

    if not key and not token:
        return VerifyResult(
            NOT_CONFIGURED,
            message="no account on this machine — Copilot mode only. Purple "
                    "Team needs either `kryonsec login` (beta) or a "
                    "membership key from kryonsec.in")
    # Only a key is shape-checked here. A token's shape is checked where it is
    # read (auth.load), which cannot return one that is malformed — so a bad
    # token is indistinguishable from no token, and lands above.
    if key and not KEY_PATTERN.match(key):
        return VerifyResult(
            INVALID,
            message="malformed key (expected KRYO-XXXX-XXXX-XXXX) — "
                    "check for typos or copy it again from your membership "
                    "email")

    now = _now()
    state = load_state(cfg)

    # daily cache: a successful check inside the interval is replayed
    # without touching the network (phone home at most once a day).
    #
    # Keyed on *which* credential was checked. Without that, signing out and
    # back in as an account that has since been revoked — or swapping a key in
    # config.toml — would replay the previous account's "valid" for up to a
    # day, which is exactly the window revocation exists to close.
    credential_id = _credential_id(key, token)
    # A key is checked daily because there is nothing to check it against more
    # often; a token is checked hourly because the server can revoke it at any
    # moment and the dashboard says so. See TOKEN_CHECK_INTERVAL_H.
    interval_h = CHECK_INTERVAL_H if key else TOKEN_CHECK_INTERVAL_H
    last_check = _parse_ts(state.get("last_check"))
    last_success = _parse_ts(state.get("last_success"))
    if (
        last_check is not None
        and state.get("cached_status") == VALID
        and state.get("cached_for") == credential_id
        and _hours_between(now, last_check) < interval_h
        and last_success is not None
        and _days_between(now, last_success) >= 0
    ):
        expires = state.get("expires", "")
        days_left = None
        if expires:
            # _parse_ts, not fromisoformat: the documented shape is a DATE
            # ("2027-01-01"), which fromisoformat returns naive — and
            # naive - aware is a TypeError, which the ValueError guard around
            # this did not catch, so verify() raised out of the function whose
            # whole contract is that it never does.
            parsed = _parse_ts(expires)
            if parsed is not None:
                days_left = (parsed - now).days
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
    clear_http_error()
    data = _http_get_json(
        f"{VERIFY_URL}?{urllib.parse.urlencode(params)}", key=key, token=token)
    if data is None:
        # unreachable/broken endpoint: grace decides; last_success is
        # never overwritten by a failure, so a dead webhook cannot lock
        # out a member who verified recently
        return _from_state_grace(state, now, last_http_error())

    if data.get("valid") is True:
        expires = str(data.get("expires", ""))
        updates = {
            "last_check": now.isoformat(),
            "last_success": now.isoformat(),
            "cached_status": VALID,
            "cached_for": credential_id,
            "expires": expires,
        }
        # A beta key carries no browser claim, so the endpoint names the
        # identity instead. Only adopted when this machine holds no address
        # yet: a member who claimed it in a browser is the attribution the
        # admin view exists to see, and a shared beta identity must not
        # quietly replace it on the next check-in.
        member = str(data.get("member") or "").strip()
        if member and not str(state.get("member_email") or "").strip():
            updates["member_email"] = member
        # Re-read before writing: `device_id()` may have minted an id into the
        # file after the `state` above was loaded, and save_state replaces the
        # whole document — writing the stale copy dropped it, so the admin view
        # saw a brand-new machine id every single day.
        _remember(cfg, updates)
        days_left = None
        if expires:
            try:
                days_left = (datetime.fromisoformat(expires) - now).days
            except ValueError:
                pass
        return VerifyResult(VALID, expires=expires, days_left=days_left)

    if not isinstance(data.get("valid"), bool):
        failure = HttpFailure(
            MALFORMED_FAILURE,
            f"{_endpoint_host(VERIFY_URL)} returned an unexpected license response",
        )
        _LAST_HTTP_FAILURE.set(failure)
        return _from_state_grace(state, now, failure)

    # the API answered "not valid": record the check (so the daily cache
    # doesn't hammer a revoked key) but keep last_success untouched —
    # a later genuine renewal overwrites cached_status again
    reason = str(data.get("reason", "key not valid"))
    _remember(cfg, {
        "last_check": now.isoformat(),
        "cached_status": EXPIRED if reason == "expired" else INVALID,
        "cached_for": credential_id,
    })
    status = EXPIRED if reason == "expired" else INVALID
    # The advice has to match the credential. A beta account told to renew a
    # membership key has been sent to look for something it never had.
    hint = (
        "renew at kryonsec.in (membership: your key stops working when it lapses)"
        if key
        else "run `kryonsec login` again — the sign-in on this machine has ended"
    )
    return VerifyResult(status, message=f"license {reason} — {hint}")


def ensure_purple_allowed(cfg: Any) -> VerifyResult:
    """Blocking gate for Purple Team engagements. Raises LicenseError
    unless the license is valid or in offline grace AND this machine has
    been registered once — callers print the message, never a stack trace.

    Every Purple entry point routes through here rather than checking the
    license itself, so a new caller cannot forget one of the two conditions.
    Copilot mode never calls it: the free mode has no gate.
    """
    result = verify(cfg)
    if not result.purple_allowed:
        raise LicenseError(result.message or f"license {result.status}")
    if not member_email(cfg):
        raise LicenseError(
            "this machine has not been registered yet — run `kryonsec login` "
            "(beta) or `kryonsec connect` (membership key). Either opens a "
            "browser once; after that the machine never asks again")
    return result
