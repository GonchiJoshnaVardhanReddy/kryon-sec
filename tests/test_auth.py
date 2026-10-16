"""`kryonsec login` / `logout` / `auth status`, and the token's half of verify.

The rules these pin down are the brief's §13 and §14: no password, no provider
client secret, no permanent key — and a token that is never printed, never
passed on a command line, and can genuinely be taken away. The last one is the
reason `logout` revokes on the server before it deletes anything locally: a
local-only delete is a sign-out in name only, and a stolen copy of the file
would keep working.
"""

import json
import os
import stat
import urllib.request

import pytest

from kryonsec import auth, license

GOOD_KEY = "KRYO-4F2K-9QRT-7XMN"
TOKEN = "s_" + "a1" * 32          # `s_` + 64 hex, the shape createCliSession mints


class _Cfg:
    def __init__(self, key="", home=None, **rest):
        self.license_key = key
        self.home = home
        for name, value in rest.items():
            setattr(self, name, value)


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


@pytest.fixture
def cfg(tmp_path):
    return _Cfg(home=tmp_path)


@pytest.fixture(autouse=True)
def fast_polls(monkeypatch):
    """The flow sleeps before its first poll. Nothing here is testing the
    sleep, and two seconds per test adds up."""
    monkeypatch.setattr(auth, "POLL_INTERVAL_S", 0)


def _signed_in(cfg) -> str:
    """A machine that has already logged in, written the way login writes it."""
    assert auth.save(cfg, {"token": TOKEN, "email": "beta@example.com"})
    return TOKEN


# ---- what is on disk -------------------------------------------------------

def test_the_credential_file_holds_a_token_and_nothing_secret(cfg):
    """Never a password, never a provider client secret, never a key. If a
    field is not in this assertion, it should not be in the file."""
    _signed_in(cfg)
    raw = auth.auth_path(cfg)

    assert json.loads(raw.read_text(encoding="utf-8")) == {
        "token": TOKEN,
        "email": "beta@example.com",
    }
    # 0600 where the bits mean something. On Windows they do not: chmod only
    # toggles the read-only attribute, and what protects the file is the
    # profile directory's ACLs. Auth._tighten says the same thing.
    if os.name == "posix":
        assert stat.S_IMODE(raw.stat().st_mode) == 0o600


def test_a_malformed_or_corrupt_file_reads_as_not_signed_in(cfg):
    """A half-written file must send the person to `login` again, not send a
    truncated token to the server and report a message about nothing."""
    for junk in ["", "not json", "[]", "null", json.dumps({"token": "nope"}),
                 json.dumps({"token": TOKEN[:20]})]:
        auth.auth_path(cfg).write_text(junk, encoding="utf-8")
        assert auth.load(cfg) == {}, junk
        assert auth.token(cfg) == ""


def test_a_missing_home_is_not_signed_in_rather_than_a_crash():
    """`license.verify` asks this on every launch and promises never to raise."""
    assert auth.token(_Cfg(home=None)) == ""


# ---- login -----------------------------------------------------------------

def test_login_stores_the_token_and_registers_the_machine(cfg, monkeypatch):
    monkeypatch.setattr(license, "http_post_json", lambda url, payload, **kw: (
        {"code": "AB12-CD34", "device_code": "d" * 64, "url": "https://kryonsec.in/beta/device?code=AB12-CD34"}
        if url == auth.LOGIN_START_URL
        else {"status": "approved", "token": TOKEN, "email": "beta@example.com", "prefix": "s_a1a1a1a1…"}
    ))

    assert auth.login(cfg, open_browser=False) == 0
    assert auth.token(cfg) == TOKEN

    # The email is what `doctor` shows and what the Purple gate reads, and it
    # goes into the license state file that connect already owns — one notion
    # of "this machine is registered", not two that can disagree.
    assert license.member_email(cfg) == "beta@example.com"


def test_login_leaves_the_other_licence_state_alone(cfg, monkeypatch):
    """The device id and the daily cache live in the same file. A login that
    reset them would make every machine look brand new to the admin view."""
    device = license.device_id(cfg)
    state = license.load_state(cfg)
    state["last_success"] = "2020-01-01T00:00:00+00:00"
    license.save_state(cfg, state)

    monkeypatch.setattr(license, "http_post_json", lambda url, payload, **kw: (
        {"code": "AB12-CD34", "device_code": "d" * 64, "url": "https://kryonsec.in/x"}
        if url == auth.LOGIN_START_URL else {"status": "approved", "token": TOKEN, "email": "b@e.com"}
    ))
    assert auth.login(cfg, open_browser=False) == 0

    assert license.device_id(cfg) == device
    assert license.load_state(cfg)["last_success"] == "2020-01-01T00:00:00+00:00"


def test_login_never_prints_the_token(cfg, monkeypatch, capsys):
    """§14: do not print tokens. The prefix is what a person needs in order to
    match a row on the dashboard, and it is not usable."""
    monkeypatch.setattr(license, "http_post_json", lambda url, payload, **kw: (
        {"code": "AB12-CD34", "device_code": "d" * 64, "url": "https://kryonsec.in/x"}
        if url == auth.LOGIN_START_URL
        else {"status": "approved", "token": TOKEN, "email": "b@e.com", "prefix": "s_a1a1a1a1…"}
    ))
    auth.login(cfg, open_browser=False)

    out = capsys.readouterr().out
    assert TOKEN not in out
    assert "s_a1a1a1a1…" in out


def test_login_does_not_accept_a_token_that_is_not_a_token(cfg, monkeypatch):
    """Trusting the server's field blindly would write a non-credential that
    fails later with a confusing message. Fail here, where it can be said."""
    monkeypatch.setattr(license, "http_post_json", lambda url, payload, **kw: (
        {"code": "AB12-CD34", "device_code": "d" * 64, "url": "https://kryonsec.in/x"}
        if url == auth.LOGIN_START_URL else {"status": "approved", "token": "hunter2"}
    ))
    assert auth.login(cfg, open_browser=False) == 1
    assert auth.token(cfg) == ""


def test_login_stores_nothing_when_it_is_denied_or_expires(cfg, monkeypatch):
    for answer in ({"status": "denied"}, {"status": "expired"}, {"status": "unknown"}):
        monkeypatch.setattr(license, "http_post_json", lambda url, payload, **kw: (
            {"code": "AB12-CD34", "device_code": "d" * 64, "url": "https://kryonsec.in/x"}
            if url == auth.LOGIN_START_URL else answer
        ))
        assert auth.login(cfg, open_browser=False) == 1
        assert auth.token(cfg) == ""
        assert license.member_email(cfg) == ""


def test_login_says_so_when_the_site_cannot_be_reached(cfg, monkeypatch):
    monkeypatch.setattr(license, "http_post_json", lambda *a, **kw: None)
    assert auth.login(cfg, open_browser=False) == 1
    assert auth.token(cfg) == ""


def test_login_refuses_a_machine_that_already_has_a_key(cfg, monkeypatch):
    """A key is checked first by the verify endpoint, so a token obtained
    alongside one would be stored and then never consulted. Accepting it would
    look like it worked and change nothing."""
    cfg.license_key = GOOD_KEY
    monkeypatch.setattr(license, "http_post_json", lambda *a, **kw: (
        pytest.fail("no request should be made")))
    assert auth.login(cfg, open_browser=False) == 1
    assert auth.token(cfg) == ""


def test_a_token_that_cannot_be_written_is_not_reported_as_success(cfg, monkeypatch):
    """The token exists on the server and not on this machine. Saying nothing
    would leave the person believing they are signed in."""
    monkeypatch.setattr(auth, "save", lambda *a, **kw: False)
    monkeypatch.setattr(license, "http_post_json", lambda url, payload, **kw: (
        {"code": "AB12-CD34", "device_code": "d" * 64, "url": "https://kryonsec.in/x"}
        if url == auth.LOGIN_START_URL else {"status": "approved", "token": TOKEN, "email": "b@e.com"}
    ))
    assert auth.login(cfg, open_browser=False) == 1


# ---- logout ----------------------------------------------------------------

def test_logout_revokes_on_the_server_before_forgetting_locally(cfg, monkeypatch):
    _signed_in(cfg)
    license.save_state(cfg, {**license.load_state(cfg), "member_email": "beta@example.com"})
    device = license.device_id(cfg)
    seen = {}

    def fake(url, payload, **kw):
        seen["url"], seen["token"] = url, kw.get("token")
        return {"ok": True, "revoked": True}

    monkeypatch.setattr(license, "http_post_json", fake)

    assert auth.logout(cfg) == 0
    assert seen["url"] == auth.LOGOUT_URL
    assert seen["token"] == TOKEN, "the revocation has to carry the token itself"
    assert not auth.auth_path(cfg).exists()
    # ...and the registered email goes, while the device id stays: this is a
    # sign-out, not a factory reset.
    assert license.member_email(cfg) == ""
    assert license.device_id(cfg) == device


def test_logout_still_signs_out_when_the_site_is_unreachable(cfg, monkeypatch, capsys):
    """Leaving the file behind would mean `logout` silently did nothing. It
    says which half happened instead."""
    _signed_in(cfg)
    monkeypatch.setattr(license, "http_post_json", lambda *a, **kw: None)

    assert auth.logout(cfg) == 0
    assert auth.token(cfg) == ""
    assert "could not be reached" in capsys.readouterr().out


def test_logout_without_a_token_does_nothing(cfg, monkeypatch):
    monkeypatch.setattr(license, "http_post_json", lambda *a, **kw: (
        pytest.fail("nothing to revoke, nothing to call")))
    assert auth.logout(cfg) == 0


# ---- status ----------------------------------------------------------------

def test_status_says_not_signed_in_on_a_bare_machine(cfg, capsys):
    assert auth.status(cfg) == 1
    assert "Not signed in" in capsys.readouterr().out


def test_status_reports_a_live_token_without_printing_it(cfg, monkeypatch, capsys):
    _signed_in(cfg)
    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: {"valid": True})

    assert auth.status(cfg) == 0
    out = capsys.readouterr().out
    assert "beta@example.com" in out
    assert TOKEN not in out
    assert TOKEN[:10] in out


def test_status_agrees_with_the_purple_gate(cfg, monkeypatch, capsys):
    """A status command that says "signed in" about a token the gate refuses
    is worse than no status command."""
    _signed_in(cfg)
    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: {
        "valid": False, "reason": "access revoked"})

    assert auth.status(cfg) == 1
    assert auth.status(cfg) != 0


# ---- the token at the verify endpoint --------------------------------------

def test_verify_sends_the_token_as_a_bearer_and_not_in_the_url(cfg, monkeypatch):
    _signed_in(cfg)
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["auth"] = req.get_header("Authorization")
        seen["key"] = req.get_header("X-kryonsec-key")
        return _FakeResponse(json.dumps({"valid": True}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert license.verify(cfg).status == license.VALID
    assert seen["auth"] == f"Bearer {TOKEN}"
    assert seen["key"] is None, "no key on a machine that has none"
    assert TOKEN not in seen["url"]


def test_a_machine_with_neither_credential_is_told_about_both_ways_in(cfg):
    result = license.verify(cfg)
    assert result.status == license.NOT_CONFIGURED
    assert "kryonsec login" in result.message


def test_a_key_still_wins_and_is_still_validated_first(tmp_path, monkeypatch):
    """The server checks the key before the token, so this file has to agree.
    A machine holding a malformed key is refused, token or no token — telling
    it "valid" while the server refuses it is the disagreement to avoid."""
    cfg = _Cfg(key="nope", home=tmp_path)
    _signed_in(cfg)
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (
        pytest.fail("a malformed key is rejected locally")))

    assert license.verify(cfg).status == license.INVALID


# ---- the daily cache -------------------------------------------------------

def test_the_cache_does_not_answer_for_a_different_credential(tmp_path, monkeypatch):
    """The cache exists so a launch does not phone home. Keyed only on the
    clock it would replay one account's "valid" for up to a day — which is
    exactly the window a revocation is supposed to close."""
    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: {"valid": True})
    first = _Cfg(key=GOOD_KEY, home=tmp_path)
    assert license.verify(first).status == license.VALID

    # Same machine, same state file, a different credential — the account that
    # logged in after the key was taken away.
    other = _Cfg(home=tmp_path)
    _signed_in(other)
    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: {
        "valid": False, "reason": "access revoked"})

    # The server is asked again rather than the previous answer being replayed.
    assert not license.verify(other).purple_allowed
    assert license.load_state(other)["cached_for"] == license._credential_id("", TOKEN)


def test_a_second_check_of_the_same_credential_is_answered_from_the_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: {"valid": True})
    cfg = _Cfg(home=tmp_path)
    _signed_in(cfg)
    assert license.verify(cfg).status == license.VALID

    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: (
        pytest.fail("the second check should have been cached")))
    assert license.verify(cfg).status == license.VALID


def test_verify_keeps_the_device_id_it_minted(tmp_path, monkeypatch):
    """save_state replaces the whole document, so writing a fresh dict dropped
    the device id that device_id() had just minted — the admin view saw a new
    machine every single day."""
    monkeypatch.setattr(license, "_http_get_json", lambda *a, **k: {"valid": True})
    cfg = _Cfg(key=GOOD_KEY, home=tmp_path)

    assert license.verify(cfg).status == license.VALID
    device = license.device_id(cfg)
    assert license.verify(cfg).status == license.VALID

    assert license.device_id(cfg) == device
    assert license.load_state(cfg)["device_id"] == device
