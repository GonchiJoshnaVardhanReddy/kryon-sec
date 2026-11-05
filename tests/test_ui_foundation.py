"""Tests for the shared terminal UI foundation.

These tests use Rich's non-terminal console and synthetic data.  They do not
start an LLM, Docker, MCP server, or Purple Team tool.
"""

from io import StringIO

from rich.console import Console

from kryonsec.config import KryonsecConfig
from kryonsec.ui.components import (
    approval_panel,
    conversation_panel,
    workflow_timeline,
)
from kryonsec.ui.events import UIEventBus
from kryonsec.ui.prefs import UiPreferences, load_ui_preferences, save_ui_preferences
from kryonsec.ui.shell import KryonsecShell
from kryonsec.ui.theme import resolve_theme, terminal_capabilities


def test_theme_falls_back_and_supports_limited_terminal():
    theme = resolve_theme("does-not-exist", truecolor=False)
    assert theme.name == "kryonsec"
    assert theme.accent == "magenta"
    assert terminal_capabilities(StringIO())["tty"] is False


def test_ui_preferences_are_separate_from_runtime_config(tmp_path):
    save_ui_preferences(tmp_path, UiPreferences(theme="dracula", mode="light"))
    loaded = load_ui_preferences(tmp_path)
    assert loaded.theme == "dracula"
    assert loaded.mode == "light"
    assert not (tmp_path / "config.toml").exists()


def test_event_bus_redacts_sensitive_display_values():
    bus = UIEventBus()
    bus.publish("notice", "token=sk-abcdefghijklmnopqrstuvwxyz123456")
    event = bus.drain()[0]
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in event.text
    assert "SECRET_" in event.text


def test_approval_component_shows_both_paths_without_leaking_secret():
    console = Console(file=StringIO(), force_terminal=False, no_color=True)
    theme = resolve_theme(truecolor=False)
    console.print(approval_panel(
        action="Read",
        requested_path="workspace/link.txt",
        resolved_path="/outside/secret.txt",
        reason="agent requested a file with api_key=sk-abcdefghijklmnopqrstuvwxyz123456",
        theme=theme,
    ))
    output = console.file.getvalue()
    assert "workspace/link.txt" in output
    assert "/outside/secret.txt" in output
    assert "api_key=sk-abcdefghijklmnopqrstuvwxyz123456" not in output
    assert "SECRET_" in output


def test_shell_redacts_assistant_display_but_keeps_runtime_config_untouched(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    console = Console(file=StringIO(), force_terminal=False, no_color=True)
    shell = KryonsecShell(cfg, console, ["copilot"], [""])
    shell.record_assistant("use sk-abcdefghijklmnopqrstuvwxyz123456 only locally")
    output = console.file.getvalue()
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in output
    assert "SECRET_" in output
    assert cfg.provider == "openai"


def test_workflow_timeline_is_honest_and_responsive():
    console = Console(file=StringIO(), force_terminal=False, width=60, no_color=True)
    theme = resolve_theme(truecolor=False)
    console.print(workflow_timeline(
        ["INIT", "RECON_PASSIVE", "HUMAN_REVIEW"],
        current="HUMAN_REVIEW",
        completed={"INIT", "RECON_PASSIVE"},
        theme=theme,
    ))
    output = console.file.getvalue()
    assert "HUMAN REVIEW" in output
    assert "completed" in output
    for line in output.splitlines():
        assert len(line) <= 60
