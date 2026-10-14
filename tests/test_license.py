"""The license gate's own safety tests.

The gate decides whether a paying member can start a Purple Team
engagement, so the parts that fail *silently* matter most: a request the
verify endpoint refuses must never look like a valid answer, and must
never look like an outage either.
"""

import json
import urllib.request

import pytest

from kryonsec import license

# a well-formed key: the alphabet has no 0/O/1/I, so this one is real-shaped
GOOD_KEY = "KRYO-4F2K-9QRT-7XMN"


class _Cfg:
    """Minimal stand-in: verify() reads `license_key` before it either
    rejects the key outright or goes to the network, and `home` for the
    state file the device id and the connect result live in."""

    def __init__(self, key, home=None):
        self.license_key = key
        self.home = home


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_http_get_json_identifies_itself(monkeypatch):
    """Cloudflare answers urllib's default User-Agent with 403 (error 1010,
    banned browser signature). _http_get_json maps any failure to None, which
    the caller reads as "offline" — so the default agent silently turned every
    activation into a grace-period fallback. The request must say who it is."""
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["agent"] = req.get_header("User-agent")
        seen["accept"] = req.get_header("Accept")
        return _FakeResponse(json.dumps({"valid": True}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert license._http_get_json("https://example.invalid/verify") == {"valid": True}
    assert seen["agent"].startswith("kryonsec/"), seen["agent"]
    assert "Python-urllib" not in seen["agent"]
    assert seen["accept"] == "application/json"


def test_a_refusal_is_read_as_a_refusal(monkeypatch):
    """The endpoint answers 200 with valid:false. That must surface as a
    refusal, not as None — None would send the caller to grace instead."""
    def fake_urlopen(req, timeout=None):
        return _FakeResponse(json.dumps({"valid": False, "reason": "expired"}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    data = license._http_get_json("https://example.invalid/verify")
    assert data == {"valid": False, "reason": "expired"}


def test_verify_never_touches_the_network_for_a_bad_key(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("a malformed key must be rejected locally")

    monkeypatch.setattr(urllib.request, "urlopen", explode)

    assert license.verify(_Cfg("nope")).status == license.INVALID
    assert license.verify(_Cfg("")).status == license.NOT_CONFIGURED
    # right shape, wrong alphabet (0 and O are not in crockford base32)
    assert license.verify(_Cfg("KRYO-0000-OOOO-0000")).status == license.INVALID


def test_a_non_200_from_the_endpoint_is_none(monkeypatch):
    """A 5xx is an outage, not a verdict — None is what triggers grace."""
    import urllib.error

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert license._http_get_json("https://example.invalid/verify") is None


# ---- the key must not travel in the URL ------------------------------------

def test_the_key_travels_in_a_header_not_the_url(monkeypatch):
    """A query string lands in access logs, proxy logs and Referer headers.
    A membership key is a credential, so it goes in a header."""
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["key"] = req.get_header("X-kryonsec-key")
        return _FakeResponse(json.dumps({"valid": True}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    license._http_get_json("https://example.invalid/verify", key=GOOD_KEY)
    assert seen["key"] == GOOD_KEY
    assert "KRYO-" not in seen["url"]


def test_verify_reports_the_machine_without_leaking_the_key(tmp_path, monkeypatch):
    """The device parameters are what let the admin view show a machine as
    alive. They ride along on the daily check-in — and the key still does not
    appear anywhere in the URL."""
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["key"] = req.get_header("X-kryonsec-key")
        return _FakeResponse(json.dumps({"valid": True}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    cfg = _Cfg(GOOD_KEY, home=tmp_path)
    assert license.verify(cfg).status == license.VALID

    assert seen["key"] == GOOD_KEY
    assert "KRYO-" not in seen["url"]
    assert "device=" in seen["url"]
    assert "os=" in seen["url"]


# ---- the machine identity --------------------------------------------------

def test_device_id_is_random_stable_and_not_the_host(tmp_path):
    """It identifies an installation and authorises nothing, so it must not
    be a fact about the machine that could be recognised elsewhere."""
    import platform

    cfg = _Cfg("", home=tmp_path)
    first = license.device_id(cfg)

    assert first == license.device_id(cfg), "must be stable across calls"
    assert len(first) == 32 and all(c in "0123456789abcdef" for c in first)
    assert platform.node() not in first, "must not be derived from the host"

    # a different installation gets a different id
    assert license.device_id(_Cfg("", home=tmp_path / "other")) != first


# ---- the gate --------------------------------------------------------------

def test_purple_gate_needs_a_connected_machine(tmp_path, monkeypatch):
    """A valid key is not enough any more: the machine has to have been
    connected once. Both conditions are checked here rather than by each
    caller, so no caller can forget one."""
    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: {"valid": True})
    cfg = _Cfg(GOOD_KEY, home=tmp_path)

    with pytest.raises(license.LicenseError) as raised:
        license.ensure_purple_allowed(cfg)
    assert "kryonsec connect" in str(raised.value)

    state = license.load_state(cfg)
    state["member_email"] = "member@example.com"
    license.save_state(cfg, state)

    assert license.ensure_purple_allowed(cfg).status == license.VALID


def test_purple_gate_still_refuses_a_bad_key_on_a_connected_machine(tmp_path):
    """Connecting is not a way in. Without a key the gate refuses before it
    ever looks at the machine."""
    cfg = _Cfg("", home=tmp_path)
    state = license.load_state(cfg)
    state["member_email"] = "member@example.com"
    license.save_state(cfg, state)

    with pytest.raises(license.LicenseError):
        license.ensure_purple_allowed(cfg)


def test_the_purple_command_stops_at_the_gate(tmp_path):
    """The wiring, not the gate: this file is the one place the suite's
    `_member` fixture leaves the gate standing, so `_run_purple` itself is
    checked here. Without this, the gate could be unwired entirely and every
    other Purple test would still pass against the stub.
    """
    from kryonsec.cli import _run_purple
    from kryonsec.config import KryonsecConfig

    cfg = KryonsecConfig(home=tmp_path)
    # valid target and valid id, so the refusal can only be the membership
    assert _run_purple(cfg, "target-corp.com", "e-stopped") == 3


def test_a_date_only_expiry_does_not_crash_the_cached_path(tmp_path, monkeypatch):
    """The endpoint's documented shape is a date, not a datetime. Subtracting
    a naive date from an aware `now` is a TypeError, and the ValueError guard
    that was there did not catch it — so verify() would raise out of a
    function whose whole contract is that it never does, on the one path a
    member hits every launch for a day after a successful check.
    """
    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: {"valid": True})
    cfg = _Cfg(GOOD_KEY, home=tmp_path)
    license.verify(cfg)  # populates the state file

    state = license.load_state(cfg)
    state["expires"] = "2027-01-01"          # a date, as documented
    state["cached_status"] = license.VALID
    state["last_check"] = license._now().isoformat()
    state["last_success"] = license._now().isoformat()
    license.save_state(cfg, state)

    # no network: this must be answered from the cache, and must not raise
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("the cache should have answered this")))
    result = license.verify(cfg)
    assert result.status == license.VALID
    assert result.days_left is not None and result.days_left > 0


def test_post_identifies_itself_and_sends_json(monkeypatch):
    """The connect flow posts to the same zone as the verify call, so it
    inherits the same banned-default-User-Agent trap."""
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["agent"] = req.get_header("User-agent")
        seen["type"] = req.get_header("Content-type")
        seen["method"] = req.get_method()
        seen["body"] = req.data
        return _FakeResponse(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert license.http_post_json("https://example.invalid/x", {"a": 1}) == {"ok": True}
    assert seen["agent"].startswith("kryonsec/")
    assert seen["method"] == "POST"
    assert seen["type"] == "application/json"
    assert json.loads(seen["body"]) == {"a": 1}


def test_a_post_that_cannot_connect_is_none(monkeypatch):
    """None is the connect flow's "the site is unreachable" — it must not be
    confused with the endpoint answering."""
    def explode(req, timeout=None):
        raise OSError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", explode)

    assert license.http_post_json("https://example.invalid/x", {"a": 1}) is None
