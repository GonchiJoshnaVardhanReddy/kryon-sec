"""The development build runs with no account.

Product login, beta approval, membership keys and license verification were
removed from this development build on purpose. These tests lock the result
in: every Mode A and Mode B entry point works with no account, no key and no
auth/license network traffic — while every TECHNICAL Mode B gate keeps its
authority.

The old license/auth suites (test_license.py, test_auth.py) were deleted
with the feature; this file replaces them. It does not weaken the technical
isolation coverage — that lives in test_mode_b_isolation.py, test_egress*.py,
test_human_review.py and the runtime-check tests, and must keep passing.
"""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import sys
from pathlib import Path

import pytest

from kryonsec import cli, doctor, tui
from kryonsec.config import KryonsecConfig, config_path, read_config

# The account/license machinery that must stay gone: modules, endpoints,
# headers, and the state files it cached credentials in. A reappearance of
# any of these in src/ is a regression to a gated product, caught here.
_BANNED_STRINGS = (
    "kryonsec.in/api",
    "/api/license",
    "/api/device/",
    "/api/beta",
    "/api/cli/logout",
    "X-Kryonsec-Key",
    "KRYONSEC_LICENSE_URL",
    "KRYONSEC_CONNECT_",
    "KRYONSEC_LOGIN_",
    "KRYONSEC_LOGOUT_URL",
    "license.state.json",
    "auth.json",
    "ensure_purple_allowed",
)
_GONE_MODULES = ("kryonsec.license", "kryonsec.auth", "kryonsec.connect")


# ---- the machinery is really gone -------------------------------------------

@pytest.mark.parametrize("module", _GONE_MODULES)
def test_removed_auth_modules_are_gone(module: str) -> None:
    assert importlib.util.find_spec(module) is None
    assert module not in sys.modules


def test_no_auth_endpoints_in_source() -> None:
    """No src file may reference the license/beta/auth endpoints or the
    credential caches the old gate used. (KRYONSEC_LICENSE_KEY is allowed
    to remain parsed in config.py — an old config/env value is read into an
    inert field so nothing crashes; it gates nothing.)"""
    src = Path(__file__).resolve().parent.parent / "src" / "kryonsec"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in _BANNED_STRINGS:
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert not offenders, f"account/license machinery is back: {offenders}"


def test_cli_help_names_no_account_commands(capsys) -> None:
    """login/logout/connect/auth are gone from the CLI, not just broken."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out.lower()
    for word in ("login", "logout", "connect", "auth"):
        assert word not in out, f"`kryonsec --help` still mentions {word}"


# ---- Mode A starts with no account and no network ----------------------------

def test_cli_starts_without_account(monkeypatch) -> None:
    """`kryonsec --version` works in a fresh home with no config, no key,
    and no auth state."""
    monkeypatch.delenv("KRYONSEC_LICENSE_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0


def test_entry_points_attempt_no_license_network(monkeypatch, tmp_path) -> None:
    """A socket tripwire over the startup paths that used to phone home:
    version/help, the mode toggle, and doctor. None may open a socket —
    the license/beta endpoints no longer exist on any code path."""
    monkeypatch.delenv("KRYONSEC_LICENSE_KEY", raising=False)

    def _no_sockets(*a, **k):  # noqa: unused args — any construction is a failure
        raise AssertionError("network attempted from an account-free entry point")

    monkeypatch.setattr(socket, "socket", _no_sockets)
    monkeypatch.setattr(socket, "create_connection", _no_sockets)

    with pytest.raises(SystemExit):
        cli.main(["--help"])

    cfg = KryonsecConfig(home=tmp_path)
    mode, notice = ["copilot"], [""]

    def _sandbox_ready(image):
        return True, "ready"

    monkeypatch.setattr("kryonsec.purple.runner.sandbox_available", _sandbox_ready)
    assert tui.set_mode(mode, notice, cfg, "purple")
    assert mode[0] == "purple"

    monkeypatch.setattr(doctor, "_check_storage", lambda c: (True, "OK"))
    monkeypatch.setattr(doctor, "_check_ollama", lambda c: (True, "OK"))
    monkeypatch.setattr(doctor, "_check_openai", lambda c: (False, "no key"))
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    cfg = KryonsecConfig(home=tmp_path)
    cfg.provider = "ollama"
    assert doctor.run_doctor(cfg) == 0


# ---- Mode B needs no account (and still its technical gates) ------------------

class _ReachedStartEngagement(BaseException):
    """Sentinel: proves the run reached the real engagement boundary."""


def test_purple_starts_without_membership_key(monkeypatch, tmp_path, capsys):
    """`kryonsec purple` with no key, no token and no auth files reaches
    start_engagement. The old gate sat exactly here and returned exit 3 on
    a LicenseError; reaching the sandbox/engagement boundary proves it is
    gone — while the technical gates further in (runtime checks, egress,
    Gates 2/3) are untouched and keep their own tests."""
    cfg = KryonsecConfig(home=tmp_path)
    assert not cfg.license_key  # no key anywhere

    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available",
        lambda image: (True, "ready"),
    )

    def _fake_start(*a, **k):
        raise _ReachedStartEngagement

    monkeypatch.setattr("kryonsec.purple.runner.start_engagement", _fake_start)

    with pytest.raises(_ReachedStartEngagement):
        cli._run_purple(cfg, "lab.example.com", memory_browser=False)

    # No credential state was created or consumed along the way.
    assert not (tmp_path / "license.state.json").exists()
    assert not (tmp_path / "auth.json").exists()


def test_mode_toggle_refuses_on_technical_grounds_only(monkeypatch, tmp_path):
    """Shift+Tab and /mode share tui.set_mode. With no account of any kind:
    a purple request is judged by the SANDBOX check alone — a technical
    refusal names the technical reason and never a membership problem."""
    cfg = KryonsecConfig(home=tmp_path)
    mode, notice = ["copilot"], [""]

    def _sandbox_down(image):
        return False, "Docker daemon unreachable"

    monkeypatch.setattr("kryonsec.purple.runner.sandbox_available", _sandbox_down)
    assert not tui.set_mode(mode, notice, cfg, "purple")
    assert mode[0] == "copilot"
    assert "Docker daemon unreachable" in notice[0]
    low = notice[0].lower()
    for word in ("membership", "license", "key", "sign in", "account"):
        assert word not in low, f"mode toggle mentioned '{word}' — a product gate is back"

    def _sandbox_up(image):
        return True, "ready"

    monkeypatch.setattr("kryonsec.purple.runner.sandbox_available", _sandbox_up)
    assert tui.set_mode(mode, notice, cfg, "purple")
    assert mode[0] == "purple"
    assert "membership" not in notice[0].lower()


class _StubQuery:
    def filter(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def limit(self, *a, **k):
        return self

    def all(self):
        return []


class _StubDb:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def query(self, *a, **k):
        return _StubQuery()


class _StubToolbox:
    def connect_all(self, *a, **k):
        return {}

    def snapshot(self):
        return {}

    def close(self):
        pass


def test_chat_loop_mode_request_works_without_membership(monkeypatch, tmp_path, capsys):
    """End to end through the chat loop: `/mode` reaches the sandbox check
    (the only check it ever needed besides membership) and switches to
    purple with no account anywhere."""
    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [{"name": "stub", "command": "x", "args": []}]
    toolbox = _StubToolbox()
    replies = ["/mode", "quit"]

    monkeypatch.setattr(cli, "_persist_session", lambda cfg, session: None)
    monkeypatch.setattr("kryonsec.storage.init_db", lambda *a, **k: None)
    import kryonsec.storage as storage
    monkeypatch.setattr(storage, "get_session", lambda cfg: _StubDb())
    monkeypatch.setattr(
        "kryonsec.copilot.mcp_tools.McpToolbox", lambda cfg, on_notice=None: toolbox)

    class _Ps:
        async def prompt_async(self):
            if not replies:
                raise EOFError
            return replies.pop(0)

    import kryonsec.tui as tui_mod
    monkeypatch.setattr(tui_mod, "make_prompt_session", lambda *a, **k: _Ps())
    monkeypatch.setattr(tui_mod, "build_key_bindings", lambda *a, **k: None)
    import kryonsec.llm as llm
    monkeypatch.setattr(llm, "preload_litellm", lambda: None)
    import kryonsec.copilot.agent as agent_mod
    monkeypatch.setattr(agent_mod, "build_toolbox", lambda cfg, ft, extra=None: {})
    import kryonsec.status as status_mod
    monkeypatch.setattr(status_mod, "StatusLine", lambda console: type(
        "S", (), {"show": lambda s, m: None, "hide": lambda s: None,
                  "running": lambda s, m: None})())

    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available", lambda image: (True, "ready"))

    asyncio.run(cli._chat_loop(cfg))

    out = capsys.readouterr().out
    # the loop announced the switch (rich strips markup under capsys, so
    # the assertion is on the plain notice, not on style wrappers)
    assert "mode: PURPLE" in out
    low = out.lower()
    for word in ("membership", "license key", "sign in", "device"):
        assert word not in low, f"chat loop printed '{word}' — a product gate is back"
    assert not (tmp_path / "license.state.json").exists()
    assert not (tmp_path / "auth.json").exists()


# ---- old credential files are ignored, never fatal, never deleted -------------

def test_old_license_config_loads_and_is_ignored(tmp_path):
    """A config.toml written by an older, gated build (plus whatever stale
    credential files it left behind) must load cleanly in this build: the
    values are read into an inert field, nothing crashes, nothing calls
    home, and the user's files are not deleted."""
    (tmp_path / "config.toml").write_text(
        '[license]\nkey = "KRYO-AAAA-BBBB-CCCC"\n', encoding="utf-8")
    stale_state = tmp_path / "license.state.json"
    stale_state.write_text('{"verifications": []}', encoding="utf-8")
    stale_auth = tmp_path / "auth.json"
    stale_auth.write_text(
        '{"token": "s_' + "0" * 64 + '"}', encoding="utf-8")

    data = read_config(config_path(tmp_path))
    cfg = KryonsecConfig.from_toml(data, home=tmp_path)
    assert cfg.license_key == "KRYO-AAAA-BBBB-CCCC"  # parsed, then ignored

    # ignored means ignored: no doctor/purple/auth path may touch them
    assert (tmp_path / "license.state.json").exists()
    assert (tmp_path / "auth.json").exists()


def test_setup_wizard_has_no_account_steps() -> None:
    """The wizard covers LLM, models, tools, MCP and workspace only — no
    beta signup, membership key, device approval or license step."""
    wizard_src = (
        Path(__file__).resolve().parent.parent / "src" / "kryonsec" / "wizard.py"
    ).read_text(encoding="utf-8")
    low = wizard_src.lower()
    for word in ("membership", "beta", "device approval", "license",
                 "kryo-", "sign in", "login"):
        assert word not in low, f"wizard still asks about {word!r}"


# ---- doctor reports the new reality -------------------------------------------

def test_doctor_reports_authentication_not_required(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(doctor, "_check_storage", lambda c: (True, "OK"))
    monkeypatch.setattr(doctor, "_check_ollama", lambda c: (True, "OK"))
    monkeypatch.setattr(doctor, "_check_openai", lambda c: (False, "no key"))
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    cfg = KryonsecConfig(home=tmp_path)
    cfg.provider = "ollama"
    assert doctor.run_doctor(cfg) == 0
    out = capsys.readouterr().out
    assert "NOT REQUIRED" in out
    assert "Membership" not in out
