"""The one command registry every Kryonsec surface reads.

Slash dispatch, the Ctrl+P palette, `/help`, `/commands`, and the legacy
shell all render from the same table.  A command that is not described here
does not exist in the UI, and a command that is hidden from one surface is
hidden from all of them.

This module is presentation only.  It names handlers that the workspace
already owns; it never executes anything, never starts an engagement, and
never touches security policy.
"""

from __future__ import annotations

from dataclasses import dataclass

MODE_A = "copilot"
MODE_B = "purple"
BOTH = (MODE_A, MODE_B)


@dataclass(frozen=True)
class CommandSpec:
    """One user-visible slash command and the modes that may run it."""

    name: str
    summary: str
    usage: str = ""
    modes: tuple[str, ...] = BOTH
    aliases: tuple[str, ...] = ()
    group: str = "Workspace"

    def label(self) -> str:
        return self.usage or self.name

    def available_in(self, mode: str) -> bool:
        return mode in self.modes


COMMANDS: tuple[CommandSpec, ...] = (
    # ---- shared workspace ------------------------------------------------
    CommandSpec(
        "/help",
        "Show commands and keyboard shortcuts",
        group="Workspace",
    ),
    CommandSpec(
        "/commands",
        "List commands available in this mode",
        group="Workspace",
    ),
    CommandSpec(
        "/mode",
        "Switch between Copilot and Purple Team",
        group="Workspace",
    ),
    CommandSpec(
        "/models",
        "Show or switch the chat model",
        "/models [list|current|use <provider> <model>|save]",
        group="Workspace",
    ),
    CommandSpec(
        "/mcp",
        "Show MCP servers, status, policy, and tool counts",
        "/mcp [list|status|tools <server>]",
        group="Workspace",
    ),
    CommandSpec(
        "/skills",
        "List packaged knowledge skills",
        "/skills [list|info <name>]",
        group="Workspace",
    ),
    CommandSpec(
        "/sessions",
        "List sessions (or engagements) and optionally switch",
        "/sessions [number]",
        group="Workspace",
    ),
    CommandSpec(
        "/rename",
        "Rename the current session or engagement tab",
        "/rename <name>",
        group="Workspace",
    ),
    CommandSpec(
        "/workspace",
        "Show the active workspace path",
        group="Workspace",
    ),
    CommandSpec(
        "/theme",
        "Choose a theme for the legacy terminal surfaces",
        "/theme [name]",
        group="Workspace",
    ),
    CommandSpec(
        "/quit",
        "Save the session and exit",
        aliases=("/exit",),
        group="Workspace",
    ),
    # ---- Mode A ----------------------------------------------------------
    CommandSpec(
        "/cve",
        "Look up a CVE by id",
        "/cve <CVE-ID>",
        modes=(MODE_A,),
        group="Copilot",
    ),
    CommandSpec(
        "/search",
        "Search the web and add the results to this session",
        "/search <query>",
        modes=(MODE_A,),
        group="Copilot",
    ),
    CommandSpec(
        "/read",
        "Read a file into the session context",
        "/read <path>",
        modes=(MODE_A,),
        group="Copilot",
    ),
    CommandSpec(
        "/ls",
        "List a directory in the workspace",
        "/ls [path]",
        modes=(MODE_A,),
        group="Copilot",
    ),
    CommandSpec(
        "/write",
        "Write a file after the normal approval gate",
        "/write <path>\\n<content>",
        modes=(MODE_A,),
        group="Copilot",
    ),
    # ---- Mode B ----------------------------------------------------------
    CommandSpec(
        "/engage",
        "Start a human-approved Purple Team engagement",
        "/engage <authorized target>",
        modes=(MODE_B,),
        group="Purple Team",
    ),
    CommandSpec(
        "/report",
        "Show or open the current engagement report",
        "/report [open]",
        modes=(MODE_B,),
        group="Purple Team",
    ),
)

_BY_NAME: dict[str, CommandSpec] = {spec.name: spec for spec in COMMANDS}
_ALIASES: dict[str, CommandSpec] = {
    alias: spec for spec in COMMANDS for alias in spec.aliases
}

# Commands that stay usable while a Purple engagement is running.  They are
# read-only or presentation-only: none can start, stop, widen, or approve an
# engagement.  `/models use` checks the engagement lock again in its handler.
PURPLE_BUSY_SAFE: frozenset[str] = frozenset({
    "/help", "/commands", "/models", "/mcp", "/skills", "/sessions",
    "/report", "/quit", "/exit",
})


def command_name(text: str) -> str:
    """The leading slash token, lower-cased; empty for plain text."""
    value = (text or "").strip()
    if not value.startswith("/"):
        return ""
    return value.split(None, 1)[0].lower()


def lookup(text: str) -> CommandSpec | None:
    """The registered command for this input, following aliases."""
    name = command_name(text)
    return _BY_NAME.get(name) or _ALIASES.get(name)


def commands_for(mode: str) -> list[CommandSpec]:
    return [spec for spec in COMMANDS if spec.available_in(mode)]


def command_groups(mode: str) -> list[tuple[str, list[CommandSpec]]]:
    """Commands grouped in stable display order, empty groups omitted."""
    groups: list[tuple[str, list[CommandSpec]]] = []
    seen: list[str] = []
    for spec in commands_for(mode):
        if spec.group not in seen:
            seen.append(spec.group)
            groups.append((spec.group, []))
        groups[seen.index(spec.group)][1].append(spec)
    return groups


def usage_line(spec: CommandSpec) -> str:
    return f"{spec.label():<44} {spec.summary}"


def commands_text(mode: str) -> str:
    """Plain command list for the workspace, generated from the registry."""
    label = "Mode A · Copilot" if mode == MODE_A else "Mode B · Purple Team"
    lines = [f"COMMANDS · {label}"]
    for group, specs in command_groups(mode):
        lines.append("")
        lines.append(group.upper())
        lines.extend(f"  {usage_line(spec)}".rstrip() for spec in specs)
    return "\n".join(lines)


def help_text(mode: str) -> str:
    """`/help` output: the registry list plus mode-appropriate shortcuts."""
    if mode == MODE_A:
        shortcuts = (
            "Enter send · Shift+Enter newline · Ctrl+P commands · "
            "Shift+Tab mode · Ctrl+←/→ sessions · Ctrl+N new session · Ctrl+Q quit"
        )
    else:
        shortcuts = (
            "Enter send · Shift+Enter newline · Ctrl+P commands · "
            "Shift+Tab mode · Ctrl+←/→ engagements · Ctrl+N new engagement · Ctrl+Q quit"
        )
    return f"{commands_text(mode)}\n\nSHORTCUTS\n  {shortcuts}"


__all__ = [
    "BOTH",
    "COMMANDS",
    "CommandSpec",
    "MODE_A",
    "MODE_B",
    "PURPLE_BUSY_SAFE",
    "command_groups",
    "command_name",
    "commands_for",
    "commands_text",
    "help_text",
    "lookup",
    "usage_line",
]
