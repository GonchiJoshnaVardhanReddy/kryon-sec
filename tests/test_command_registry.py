"""The one slash-command table every surface reads.

These tests pin the contract: names are unique, aliases resolve, mode
availability is explicit, and the generated help/command lists contain only
real entries.  No handler runs here.
"""

from __future__ import annotations

from kryonsec.command_registry import (
    COMMANDS,
    PURPLE_BUSY_SAFE,
    command_groups,
    command_name,
    commands_for,
    commands_text,
    help_text,
    lookup,
)


def test_registry_names_and_aliases_are_unique():
    names = [spec.name for spec in COMMANDS]
    assert len(names) == len(set(names))
    aliases = [alias for spec in COMMANDS for alias in spec.aliases]
    assert len(aliases) == len(set(aliases))
    assert not set(aliases) & set(names)


def test_lookup_is_case_insensitive_and_follows_aliases():
    assert lookup("/HELP").name == "/help"
    assert lookup("  /models use ollama llama3 ").name == "/models"
    assert lookup("/exit").name == "/quit"
    assert lookup("plain text") is None
    assert lookup("") is None


def test_command_name_only_returns_a_leading_slash_token():
    assert command_name("/mcp tools fetch") == "/mcp"
    assert command_name(" /Skills ") == "/skills"
    assert command_name("read /etc/passwd") == ""
    assert command_name("") == ""


def test_mode_specific_commands_are_separated():
    copilot = {spec.name for spec in commands_for("copilot")}
    purple = {spec.name for spec in commands_for("purple")}

    assert {"/cve", "/search", "/read", "/ls", "/write"} <= copilot
    assert not {"/engage", "/report"} & copilot
    assert {"/engage", "/report"} <= purple
    assert not {"/cve", "/search", "/read", "/ls", "/write"} & purple
    assert {"/help", "/commands", "/models", "/mcp", "/skills"} <= copilot & purple


def test_every_command_has_a_summary_and_group():
    for spec in COMMANDS:
        assert spec.name.startswith("/")
        assert spec.summary.strip()
        assert spec.group.strip()


def test_registry_has_no_duplicate_generated_lines():
    for mode in ("copilot", "purple"):
        text = commands_text(mode)
        lines = [line.strip() for line in text.splitlines() if line.strip().startswith("/")]
        assert len(lines) == len(set(lines)), mode


def test_help_lists_real_commands_and_shortcuts():
    text = help_text("copilot")
    assert "COMMANDS · Mode A" in text
    assert "/models" in text
    assert "/engage" not in text
    assert "Ctrl+P" in text

    purple = help_text("purple")
    assert "/engage <authorized target>" in purple
    assert "/cve" not in purple


def test_groups_are_stable_and_omit_empty_groups():
    groups = command_groups("purple")
    assert [name for name, _ in groups] == ["Workspace", "Purple Team"]
    assert all(specs for _, specs in groups)


def test_busy_safe_commands_never_start_or_change_an_engagement():
    specs = {spec.name: spec for spec in COMMANDS}
    assert "/engage" not in PURPLE_BUSY_SAFE
    assert "/mode" not in PURPLE_BUSY_SAFE
    assert "/rename" not in PURPLE_BUSY_SAFE
    for name in PURPLE_BUSY_SAFE:
        # /exit is an alias, not a registered name; every other entry is real.
        assert name == "/exit" or name in specs
