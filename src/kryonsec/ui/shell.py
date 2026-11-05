"""Unified Copilot workspace shell.

The shell is intentionally a thin presentation adapter around the existing
prompt loop.  It gives Mode A a stable OpenCode-like visual language while
leaving the agent, tools, persistence, and approval decisions untouched.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from ..config import KryonsecConfig
from ..secrets import redact
from .components import (
    command_palette_panel,
    conversation_panel,
    footer_text,
    header_panel,
    tool_activity_panel,
    ToolActivityRow,
)
from .events import UIEventBus
from .prefs import UiPreferences, load_ui_preferences, save_ui_preferences
from .theme import resolve_theme, terminal_capabilities


@dataclass
class ConversationItem:
    role: str
    content: str
    label: str | None = None


@dataclass
class ShellState:
    mode: str = "copilot"
    active: str = "ready"
    session_id: str | None = None
    engagement_id: str | None = None
    messages: list[ConversationItem] = field(default_factory=list)
    tools: list[ToolActivityRow] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)


class KryonsecShell:
    """Presentation shell shared by the interactive Copilot loop."""

    COMMANDS = {
        "/help": "show commands and shortcuts",
        "/mode": "switch between Copilot and Purple Team",
        "/theme": "choose a terminal theme",
        "/workspace": "show the current workspace",
        "/quit": "save the session and exit",
    }

    def __init__(
        self,
        cfg: KryonsecConfig,
        console: Console,
        mode: list[str],
        notice: list[str],
        *,
        session_id: str | None = None,
    ) -> None:
        self.cfg = cfg
        self.console = console
        self.mode = mode
        self.notice = notice
        self.state = ShellState(mode=mode[0], session_id=session_id)
        self.events = UIEventBus()
        self.preferences: UiPreferences = load_ui_preferences(cfg.home)
        capabilities = terminal_capabilities(getattr(console, "file", None))
        self.theme = resolve_theme(
            self.preferences.theme,
            self.preferences.mode,
            truecolor=capabilities.get("truecolor", False),
        )
        self._started = False

    @property
    def interactive(self) -> bool:
        try:
            return bool(self.console.is_terminal and sys.stdin.isatty() and sys.stdout.isatty())
        except Exception:
            return False

    def _renderable(self) -> Group:
        recent = self.state.messages[-8:]
        message_parts: list[Any] = []
        for item in recent:
            message_parts.append(conversation_panel(item.role, item.content, theme=self.theme, label=item.label))
        if not message_parts:
            message_parts.append(
                Panel(
                    Text(
                        "Ask a security question, run /help, or press Ctrl+P for commands.",
                        style=self.theme.muted,
                    ),
                    title="[bold]WORKSPACE[/bold]",
                    border_style=self.theme.border,
                )
            )
        return Group(
            header_panel(
                self.cfg,
                mode=self.mode[0],
                theme=self.theme,
                session_id=self.state.session_id,
                engagement_id=self.state.engagement_id,
                status=self.state.active,
            ),
            *message_parts,
            tool_activity_panel(self.state.tools, theme=self.theme),
            footer_text(self.mode[0], active=self.state.active, compact=not self.interactive),
        )

    def show_startup(self) -> None:
        """Print the workspace once; never emits terminal escapes in pipes."""
        self.console.print(self._renderable())
        self._started = True

    def refresh(self) -> None:
        """Redraw only when a terminal is available (used for mode/theme)."""
        if self.interactive:
            try:
                self.console.clear()
            except Exception:
                pass
        self.console.print(self._renderable())
        self._started = True

    def record_user(self, text: str, *, active: bool = True) -> None:
        safe = redact(text or "")[0]
        self.state.messages.append(ConversationItem("user", safe, "you"))
        if active:
            self.state.active = "thinking"
        self.events.publish("user_message", text=safe)
        self.console.print(conversation_panel("user", safe, theme=self.theme, label="you"))

    def record_assistant(self, text: str) -> None:
        safe = redact(text or "")[0]
        # The existing agent callback exposes tool start and agent rounds, but
        # not a success/failure result callback.  Marking a call as
        # "returned" is honest: the call completed and control returned to
        # the agent, while its result standing remains in the response.
        for row in self.state.tools:
            if row.status == "running":
                row.status = "returned"
                row.detail = "result returned to agent"
        self.state.messages.append(ConversationItem("assistant", safe, "assistant"))
        self.state.active = "ready"
        self.events.publish("assistant_message", text=safe)
        self.console.print(conversation_panel("assistant", safe, theme=self.theme, label="assistant"))

    def record_tool(self, name: str, args: dict[str, Any] | None = None) -> None:
        preview = ", ".join(
            f"{key}={redact(str(value))[0][:36]}"
            for key, value in (args or {}).items()
        )
        self.state.tools.append(ToolActivityRow(name=name, status="running", detail=preview))
        self.state.active = f"running {name}"
        self.events.publish("tool_started", data={"tool": name, "args": args or {}})
        self.console.print(
            f"  [bold {self.theme.running}]›[/bold {self.theme.running}] "
            f"[{self.theme.running}]{name}[/{self.theme.running}] "
            f"[dim]{preview}[/dim]"
        )

    def record_round(self) -> None:
        self.state.active = "thinking"
        self.events.publish("agent_round")

    def record_notice(self, message: str) -> None:
        safe = redact(str(message or ""))[0]
        if not safe:
            return
        self.state.notices.append(safe)
        self.notice[0] = safe
        self.events.publish("notice", text=safe)

    def finish_tool(self, name: str, *, ok: bool, detail: str = "") -> None:
        for row in reversed(self.state.tools):
            if row.name == name and row.status == "running":
                row.status = "completed" if ok else "failed"
                row.detail = redact(detail)[0]
                break
        self.state.active = "thinking"
        self.events.publish("tool_finished", data={"tool": name, "ok": ok, "detail": detail})

    def open_palette(self, event: Any) -> None:
        """Open a small command palette without taking over backend logic."""
        def choose() -> None:
            self.console.print(command_palette_panel(self.theme, self.COMMANDS))
            try:
                selected = self.console.input("[bold]palette › [/bold]").strip()
            except (EOFError, KeyboardInterrupt):
                return
            if selected.isdigit():
                selected = list(self.COMMANDS)[int(selected) - 1] if 0 < int(selected) <= len(self.COMMANDS) else ""
            if selected in self.COMMANDS:
                event.app.current_buffer.text = selected
            elif selected.startswith("/"):
                event.app.current_buffer.text = selected
            event.app.invalidate()

        try:
            event.app.run_in_terminal(choose)
        except Exception:
            self.record_notice("command palette unavailable in this terminal")

    def choose_theme(self, name: str | None = None) -> str:
        """Set a built-in theme and persist only UI preferences."""
        if not name:
            names = ("kryonsec", "tokyonight", "dracula")
            self.console.print("Themes: " + ", ".join(names))
            try:
                name = self.console.input("theme › ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return self.theme.name
        if name not in {"kryonsec", "tokyonight", "dracula"}:
            self.record_notice(f"unknown theme: {name}")
            return self.theme.name
        self.preferences.theme = name
        save_ui_preferences(self.cfg.home, self.preferences)
        capabilities = terminal_capabilities(getattr(self.console, "file", None))
        self.theme = resolve_theme(name, self.preferences.mode, truecolor=capabilities.get("truecolor", False))
        self.refresh()
        return name
