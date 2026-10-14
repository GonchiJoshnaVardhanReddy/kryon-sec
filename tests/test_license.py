"""The license gate's own safety tests.

The gate decides whether a paying member can start a Purple Team
engagement, so the parts that fail *silently* matter most: a request the
verify endpoint refuses must never look like a valid answer, and must
never look like an outage either.
"""

import json
import urllib.request

from kryonsec import license


class _Cfg:
    """Minimal stand-in: verify() only reads `license_key` before it either
    rejects the key outright or goes to the network."""

    def __init__(self, key):
        self.license_key = key


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
