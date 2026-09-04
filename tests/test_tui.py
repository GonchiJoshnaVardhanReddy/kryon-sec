"""Tests for the TUI layer (spec §5.1): Shift+Tab mode toggle and the
prompt indicator, without a live terminal."""

from unittest.mock import patch

from kryonsec.config import KryonsecConfig
from kryonsec.tui import (
    build_key_bindings,
    prompt_message,
    set_mode,
)


def _holders():
    return (["copilot"], [""])


def test_set_mode_switches_to_purple(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    mode, notice = _holders()
    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(True, "")):
        assert set_mode(mode, notice, cfg, "purple") is True
    assert mode[0] == "purple"
    assert "PURPLE" in notice[0]


def test_set_mode_refuses_purple_without_sandbox(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    mode, notice = _holders()
    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(False, "no runsc runtime")):
        assert set_mode(mode, notice, cfg, "purple") is False
    assert mode[0] == "copilot"  # unchanged
    assert "no runsc runtime" in notice[0]


def test_set_mode_back_to_copilot_no_check_needed(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    mode, notice = (["purple"], [""])
    # switching back to copilot must not require any sandbox check
    with patch("kryonsec.purple.runner.sandbox_available",
               side_effect=AssertionError("must not be called")):
        assert set_mode(mode, notice, cfg, "copilot") is True
    assert mode[0] == "copilot"


def test_set_mode_noop_when_same(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    mode, notice = _holders()
    assert set_mode(mode, notice, cfg, "copilot") is False
    assert mode[0] == "copilot"


def test_prompt_message_shows_mode_indicator():
    mode, notice = (["copilot"], [""])
    fragments = prompt_message(mode, notice)
    assert fragments[-1][1] == "[COPILOT]> "

    mode[0] = "purple"
    fragments = prompt_message(mode, notice)
    assert fragments[-1][1] == "[PURPLE]> "


def test_prompt_message_notice_line():
    mode, notice = (["copilot"], ["cannot switch to purple: no runsc"])
    fragments = prompt_message(mode, notice)
    assert fragments[0][1].startswith("cannot switch to purple")
    assert fragments[-1][1] == "[COPILOT]> "  # still copilot


def test_shift_tab_binding_toggles_mode(tmp_path):
    """The s-tab key binding flips the mode holder — the actual key
    wiring, tested without a terminal."""
    cfg = KryonsecConfig(home=tmp_path)
    mode, notice = _holders()
    kb = build_key_bindings(mode, notice, cfg)

    class FakeEvent:
        app = type("App", (), {"invalidate": lambda self: None})()

    handler = kb.get_bindings_for_keys(("s-tab",))[0].handler
    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(True, "")):
        handler(FakeEvent())
    assert mode[0] == "purple"

    # Shift+Tab again — back to copilot, no sandbox check needed
    with patch("kryonsec.purple.runner.sandbox_available",
               side_effect=AssertionError("must not be called")):
        handler(FakeEvent())
    assert mode[0] == "copilot"
