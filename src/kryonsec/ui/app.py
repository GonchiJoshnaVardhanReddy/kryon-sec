"""Persistent full-screen Kryonsec workspace.

This is the interactive terminal experience: session tabs across the top, a
large conversation or engagement workspace in the centre, a live context
sidebar on the right, and a composer anchored at the bottom.  It is a single
Textual application; updates are painted inside the screen instead of being
appended to the shell.

The app is presentation only.  ``WorkspaceController`` owns Copilot calls,
Purple Team execution, persistence, and approval hand-offs.  Nothing here can
transition a workflow state, run a tool, or approve an action by itself.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from textwrap import dedent
from typing import Any

from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, HorizontalScroll, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.theme import Theme
from textual.widgets import (
    Button,
    Input,
    Markdown,
    OptionList,
    Static,
    TextArea,
)
from textual.widgets.option_list import Option

from .. import __version__
from ..config import KryonsecConfig
from .state import (
    AGENT_LABELS,
    PURPLE_STATES,
    SECURITY_AGENT_STATES,
    ApprovalGate,
    display_command,
    elapsed,
    safe,
    status_mark,
)
from .theme import ThemeTokens, terminal_capabilities, workspace_tokens
from .workspace import WorkspaceController

STATE_ACTION: dict[str, str] = {
    "INIT": "Validating scope",
    "RECON_PASSIVE": "Collecting intelligence",
    "RECON_ACTIVE": "Mapping services",
    "HYPOTHESIZE": "Generating hypotheses",
    "HUMAN_REVIEW": "Awaiting approval",
    "EXPLOIT": "Testing hypotheses",
    "POST_EXPLOIT": "Enumerating access",
    "VERIFY": "Confirming findings",
    "BLUE_TEAM": "Writing remediation",
    "REPORT": "Compiling report",
}

BRAND_MARK = "\n".join(
    (
        "█   █ ████  █   █  ███  █   █  ████ █████  ████",
        "█  █  █   █  █ █  █   █ ██  █ █     █     █    ",
        "███   ████    █   █   █ █ █ █  ███  ████  █    ",
        "█  █  █  █    █   █   █ █  ██     █ █     █    ",
        "█   █ █   █   █    ███  █   █ ████  █████  ████",
    )
)

BRAND_SMALL = r"""
  K R Y O N S E C
""".strip("\n")

HELP_TEXT = (
    "Shortcuts: Enter send · Shift+Enter newline · Ctrl+P commands · "
    "Shift+Tab mode · Ctrl+←/→ sessions · Ctrl+N new session · Ctrl+Q quit.\n"
    "Commands: /help /cve /search /read /ls /write /workspace /mode /theme /quit"
)


def _textual_theme_name(mode: str) -> str:
    return f"kryonsec-workspace-{mode}"


def _workspace_textual_theme(mode: str, tokens: ThemeTokens) -> Theme:
    """A Textual theme whose every semantic colour is the mode's monochrome
    design, so default widget chrome (scrollbars, selections, buttons) can
    never reintroduce accent colors. Purple rides on ``accent`` in Mode B and
    is applied to the wordmark explicitly."""
    ansi = _css_color  # map native ANSI spellings to Textual's names
    purple = ansi(tokens.brand if mode == "purple" else tokens.accent)
    return Theme(
        name=_textual_theme_name(mode),
        primary=ansi(tokens.accent),
        secondary=purple,
        warning=ansi(tokens.warning),
        error=ansi(tokens.error),
        success=ansi(tokens.success),
        accent=purple,
        foreground=ansi(tokens.text),
        background=ansi(tokens.background),
        surface=ansi(tokens.surface),
        panel=ansi(tokens.surface),
        boost=ansi(tokens.border),
        dark=True,
        variables={
            "input-selection-background": ansi(tokens.border),
            "input-selection-foreground": ansi(tokens.text),
        },
    )


# ---- small widgets ------------------------------------------------------


class Composer(TextArea):
    """Multiline prompt input. Enter sends; Shift+Enter inserts a newline."""

    class Submitted(Message):
        pass

    def __init__(self, **kw: Any) -> None:
        kw.setdefault("placeholder", "Ask anything — /help for commands")
        super().__init__(**kw)

    async def _on_key(self, event: events.Key) -> None:
        if event.key == "enter":
            event.prevent_default()
            event.stop()
            self.post_message(self.Submitted())
            return
        if event.key in {"shift+enter", "ctrl+enter", "alt+enter"}:
            event.prevent_default()
            event.stop()
            self.insert("\n")
            return
        await super()._on_key(event)

    def take_text(self) -> str:
        value = self.text
        self.clear()
        return value


class TabItem(Static):
    """One clickable session tab in the top bar."""

    class Pressed(Message):
        def __init__(self, index: int) -> None:
            super().__init__()
            self.index = index

    def __init__(self, index: int, label: str, *, active: bool, action: bool = False) -> None:
        self.tab_index = index
        classes = "tab-action" if action else ("tab-item active" if active else "tab-item")
        super().__init__(Text(label), markup=False, classes=classes)
        self.can_focus = False

    def on_click(self, event: events.Click) -> None:
        event.stop()
        self.post_message(self.Pressed(self.tab_index))


class UserBlock(Static):
    def __init__(self, content: str) -> None:
        text = Text()
        text.append("YOU\n", style="bold")
        text.append(content or "(empty message)", style="")
        super().__init__(text, markup=False, classes="user-block")


class AssistantBlock(Vertical):
    def __init__(self, content: str) -> None:
        super().__init__(classes="assistant-block")
        self._content = content

    def compose(self) -> ComposeResult:
        yield Static(Text("KRYONSEC", style="bold"), classes="role-label")
        yield Markdown(self._content or "(empty response)", classes="message-markdown")


class NoticeBlock(Static):
    def __init__(self, content: str) -> None:
        text = Text()
        text.append("· ", style="dim")
        text.append(content, style="dim")
        super().__init__(text, markup=False, classes="notice-block")


# ---- command palette ----------------------------------------------------


class CommandPalette(ModalScreen[str | None]):
    """Ctrl+P palette; selection is returned to the app.

    Options are built per controller state: rename and close belong to Mode
    A sessions, the Kryonsec Memory shortcut belongs to Mode B, and stacked
    per-tab entries let one dialog reach other sessions as well.
    """

    BINDINGS = [
        Binding("escape", "dismiss_palette", "Close", show=False),
    ]

    BASE_COMMANDS = [
        ("New session", "new"),
        ("Switch mode", "mode"),
        ("Show help", "help"),
        ("Appearance help", "theme"),
        ("Quit", "quit"),
    ]

    def __init__(self, controller: WorkspaceController | None = None) -> None:
        super().__init__()
        options = list(self.BASE_COMMANDS)
        if controller is None:
            self._options = options
            return
        if controller.mode == "copilot":
            session_entries = [
                ("Rename session…", "rename"),
                ("Close session", "close"),
            ]
            for index, tab in enumerate(controller.sessions):
                label = _short(tab.title, 34)
                session_entries.append(
                    (f"Rename session {index + 1}: {label}", f"rename:{index + 1}")
                )
                session_entries.append(
                    (f"Close session {index + 1}: {label}", f"close:{index + 1}")
                )
            options = [*session_entries, *options]
        else:
            options.insert(2, ("Open Kryonsec Memory", "memory"))
        self._options = options

    def compose(self) -> ComposeResult:
        with Vertical(id="palette-box"):
            yield Static(Text("COMMAND PALETTE", style="bold"), classes="palette-title")
            yield Static(
                Text("↑/↓ select · Enter run · Esc close", style="dim"),
                classes="palette-hint",
            )
            yield OptionList(
                *[Option(label, id=key) for label, key in self._options],
                id="palette-list",
            )

    def on_mount(self) -> None:
        self.query_one("#palette-list", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(event.option.id)

    def action_dismiss_palette(self) -> None:
        self.dismiss(None)


# ---- approval dialogs ---------------------------------------------------


class ApprovalScreen(ModalScreen[bool]):
    """Fail-closed approval gate shared by file, review, and post-exploit."""

    BINDINGS = [
        Binding("a", "approve", "Approve", show=True),
        Binding("y", "approve", "Approve", show=False),
        Binding("r", "deny", "Deny", show=True),
        Binding("n", "deny", "Deny", show=False),
        Binding("escape", "deny", "Deny", show=False, priority=True),
        Binding("enter", "deny", "Deny", show=False, priority=True),
    ]

    def __init__(self, gate: ApprovalGate) -> None:
        super().__init__()
        self.gate = gate

    def on_mount(self) -> None:
        # No button may own Enter. Enter and Escape always deny.
        for button in self.query(Button):
            button.can_focus = False

    def compose(self) -> ComposeResult:
        with Vertical(id="approval-box"):
            yield Static(self._title(), classes="approval-title", markup=False)
            yield Static(self._body(), classes="approval-body", markup=False)
            with Horizontal(id="approval-actions"):
                yield Button("Approve  A", id="approve", compact=True)
                yield Button("Deny  R", id="deny", compact=True)

    def _title(self) -> Text:
        label = {
            "file": "FILE ACCESS APPROVAL",
            "human_review": "GATE 2 · HUMAN REVIEW",
            "post_exploit": "GATE 3 · POST-EXPLOIT APPROVAL",
        }.get(self.gate.gate, "APPROVAL REQUIRED")
        return Text(label, style="bold")

    def _body(self) -> Text:
        gate = self.gate
        text = Text()
        if gate.gate == "file":
            props = gate.hypotheses[0].get("properties", {}) if gate.hypotheses else {}
            text.append("Operation     ", style="dim")
            text.append(f"{safe(props.get('title'), 80)}\n")
            text.append("Resolved path ", style="dim")
            text.append(f"{safe(props.get('target_asset'), 500)}\n")
            requested = props.get("requested_path")
            if requested and requested != props.get("target_asset"):
                text.append("Requested     ", style="dim")
                text.append(f"{safe(requested, 500)}\n")
            text.append("Reason        ", style="dim")
            text.append(f"{safe(props.get('rationale') or 'not provided', 500)}\n\n")
            text.append("Enter, Esc, or closing this dialog denies access.\n", style="dim")
            return text
        if gate.gate == "human_review":
            if not gate.hypotheses:
                text.append("No hypotheses were produced. Nothing is approved.\n")
                return text
            hypothesis = gate.hypotheses[min(gate.index, len(gate.hypotheses) - 1)]
            props = hypothesis.get("properties", {}) or {}
            text.append(
                f"Hypothesis {gate.index + 1} of {len(gate.hypotheses)}\n\n",
                style="bold",
            )
            text.append(f"{safe(hypothesis.get('label') or 'hypothesis', 160)}\n\n", style="bold")
            for label, value in (
                ("Title", props.get("title") or "—"),
                ("Target", props.get("target_asset") or "—"),
                ("Confidence", props.get("confidence") or "—"),
                ("CVSS", props.get("cvss_vector") or "not estimated"),
                ("Tools", ", ".join(str(v) for v in props.get("tools", []) or []) or "none"),
                ("Evidence", props.get("evidence") or props.get("rationale") or "—"),
            ):
                text.append(f"{label:<12}", style="dim")
                text.append(f"{safe(value, 500)}\n")
            text.append("\nApproving authorizes only this proposed testing.\n", style="dim")
            text.append("It does not authorize post-exploitation.\n", style="dim")
            return text
        text.append("A shell was obtained on the target.\n\n")
        text.append(
            "Evidence collection only: process, filesystem, network, and secret discovery.\n"
        )
        text.append("Nothing destructive and no controlled impact.\n\n", style="dim")
        text.append("Evidence: ", style="dim")
        text.append(f"{safe(gate.shell_evidence, 300) or 'not provided'}\n")
        return text

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(event.button.id == "approve")

    def action_approve(self) -> None:
        self.dismiss(True)

    def action_deny(self) -> None:
        self.dismiss(False)


class RenameScreen(ModalScreen[str | None]):
    """Small rename dialog, prepopulated with the current tab title.

    Enter confirms, Esc cancels, and empty names are refused inline. The
    returned value is a display title only; the caller decides persistence.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False, priority=True),
    ]

    def __init__(self, current: str) -> None:
        super().__init__()
        self.current = current

    def compose(self) -> ComposeResult:
        with Vertical(id="rename-box"):
            yield Static(Text("RENAME SESSION", style="bold"), classes="rename-title")
            yield Static(
                Text("Enter confirm · Esc cancel · empty names are refused", style="dim"),
                classes="rename-hint",
            )
            yield Input(value=self.current, id="rename-input", max_length=120)
            yield Static("", id="rename-error", markup=False)

    def on_mount(self) -> None:
        self.query_one("#rename-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        value = " ".join((event.value or "").split())
        if not value:
            self.query_one("#rename-error", Static).update(
                Text("! name cannot be empty", style="bold")
            )
            return
        self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class MemoryEntry(Static):
    """Clickable, keyboard-focusable Kryonsec Memory shortcut (Mode B only).

    Activation posts :class:`MemoryEntry.Activated`; the app then launches
    the existing read-only loopback viewer on that explicit user action.
    """

    class Activated(Message):
        pass

    def __init__(self) -> None:
        text = Text()
        text.append("\n")
        text.append(" MEMORY\n", style="bold")
        text.append("▸ Kryonsec Memory — open viewer\n")
        super().__init__(text, markup=False, classes="memory-entry", id="memory-entry")
        self.can_focus = True
        self.display = False

    def on_click(self, event: events.Click) -> None:
        event.stop()
        self.post_message(self.Activated())

    async def _on_key(self, event: events.Key) -> None:
        if event.key in {"enter", "space"}:
            event.stop()
            event.prevent_default()
            self.post_message(self.Activated())
            return
        await super()._on_key(event)


# ---- the application ----------------------------------------------------


class UiChanged(Message):
    def __init__(self, reason: str) -> None:
        super().__init__()
        self.reason = reason


class QuitRequested(Message):
    pass


class KryonsecApp(App[None]):
    """One persistent screen for both Kryonsec modes."""

    TITLE = "Kryonsec"
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (100, "-wide")]
    BINDINGS = [
        Binding("ctrl+p", "command_palette", "Commands", show=True, priority=True),
        Binding("shift+tab", "toggle_mode", "Mode", show=True, priority=True),
        Binding("ctrl+n", "new_tab", "New", show=True, priority=True),
        Binding("ctrl+left", "prev_tab", "Prev tab", show=False, priority=True),
        Binding("ctrl+right", "next_tab", "Next tab", show=False, priority=True),
        Binding("ctrl+r", "rename_session", "Rename", show=False, priority=True),
        Binding("ctrl+w", "close_session", "Close tab", show=False, priority=True),
        Binding("ctrl+q", "quit_app", "Quit", show=True, priority=True),
        Binding("ctrl+c", "interrupt", "Stop/Quit", show=False, priority=True),
    ]

    def __init__(
        self,
        cfg: KryonsecConfig,
        controller: WorkspaceController,
        *,
        theme: ThemeTokens | None = None,
    ) -> None:
        self.cfg = cfg
        self.controller = controller
        self._truecolor = terminal_capabilities(sys.stdout).get("truecolor", False)
        # The workspace palette is mode-driven; a saved theme preference can
        # no longer bring accent colors back into it.
        self.tokens = theme or workspace_tokens(
            controller.mode, truecolor=self._truecolor
        )
        self._mode_shown = controller.mode
        self.CSS = _build_css(self.tokens)
        self._approval_open = False
        self._tabs_signature: tuple[Any, ...] | None = None
        self._conversation_signature: tuple[Any, ...] | None = None
        self._mode_shown = controller.mode
        super().__init__()
        # Textual themes drive every default widget colour (scrollbars,
        # selections, buttons); a monochrome theme per mode keeps chrome
        # consistent with the mode-driven palette.
        for branch in ("copilot", "purple"):
            self.register_theme(
                _workspace_textual_theme(
                    branch, workspace_tokens(branch, truecolor=self._truecolor)
                )
            )
        self.theme = _textual_theme_name(controller.mode)
        self.controller.set_change_callback(self._controller_changed)

    # ---- lifecycle -----------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Static(
                Text("◆ KRYONSEC", style=f"bold {self.tokens.brand}"),
                id="brand",
                markup=False,
            )
            with HorizontalScroll(id="tabstrip"):
                pass
            yield Static("", id="topmode", markup=False)
        with Horizontal(id="body"):
            with Vertical(id="main"):
                with VerticalScroll(id="conversation"):
                    yield Static(self._empty_state(), id="empty-state", markup=False)
                    yield Vertical(id="message-list")
                    yield Static("", id="inline-activity", markup=False)
                yield Static("", id="purple-view", markup=False)
                yield Static("", id="notice-line", markup=False)
                with Vertical(id="composer-area"):
                    with Horizontal(id="composer-meta-row"):
                        yield Static("", id="composer-meta", markup=False)
                        yield Static("", id="composer-hints", markup=False)
                    yield Composer(id="composer")
            with VerticalScroll(id="sidebar"):
                yield Static("", id="sidebar-content", markup=False)
                yield MemoryEntry()
        yield Static("", id="statusbar", markup=False)

    async def on_mount(self) -> None:
        await self._refresh_all(force=True)
        self.set_interval(1.0, self._tick)
        self.call_after_refresh(self._focus_composer)

    def on_unmount(self) -> None:
        self.controller.set_change_callback(lambda _reason: None)
        self.controller.close()

    def _focus_composer(self) -> None:
        try:
            self.query_one("#composer", Composer).focus()
        except Exception:
            pass

    def _controller_changed(self, reason: str) -> None:
        # Textual's post_message is thread-safe, so worker threads can report
        # observations without touching widgets.
        if reason == "quit":
            self.post_message(QuitRequested())
        else:
            self.post_message(UiChanged(reason))

    def on_quit_requested(self, _event: QuitRequested) -> None:
        self.action_quit_app()

    # ---- message pump --------------------------------------------------

    async def on_ui_changed(self, event: UiChanged) -> None:
        mode_changed = self._mode_shown != self.controller.mode
        if mode_changed:
            # Apply the mode-driven palette immediately on every mode switch.
            self._apply_mode_palette()
        await self._refresh_all(force=mode_changed)
        if event.reason in {"approval", "purple"}:
            self._maybe_show_approval()

    def _apply_mode_palette(self) -> None:
        mode = self.controller.mode
        if mode == self._mode_shown:
            return
        self._mode_shown = mode
        self.tokens = workspace_tokens(mode, truecolor=self._truecolor)
        self.CSS = _build_css(self.tokens)
        self.theme = _textual_theme_name(mode)
        self.refresh_css()
        try:
            self.query_one("#brand", Static).update(
                Text("◆ KRYONSEC", style=f"bold {self.tokens.brand}")
            )
            self.query_one("#empty-state", Static).update(self._empty_state())
        except Exception:
            pass  # compose may not have run yet

    def _tick(self) -> None:
        # Time-dependent panels and late MCP connections update in place; the
        # conversation itself is not rebuilt on a timer.
        self._refresh_sidebar()
        self._refresh_status()
        self._refresh_composer_meta()
        self._refresh_inline_activity()
        self._refresh_purple()
        self._maybe_show_approval()
        self._tick_count = getattr(self, "_tick_count", 0) + 1
        if self._tick_count % 30 == 0:
            # Re-check real runtime availability every ~30 s (rate-limited and
            # threaded inside the controller).
            self.controller.refresh_runtime_status()

    async def _refresh_all(self, *, force: bool = False) -> None:
        await self._refresh_tabs(force=force)
        self._refresh_topmode()
        self._refresh_main(force=force)
        self._refresh_sidebar()
        self._refresh_composer_meta()
        self._refresh_status()
        self._refresh_notice()

    async def _refresh_tabs(self, *, force: bool = False) -> None:
        controller = self.controller
        if controller.mode == "copilot":
            entries = [(tab.title, tab.short_id) for tab in controller.sessions]
            active = controller.session_index
            action_label = "+ New session"
        else:
            entries = [(tab.title, tab.short_id) for tab in controller.engagements]
            active = controller.engagement_index
            action_label = "+ New engagement"
        signature = (controller.mode, tuple(entries), active)
        if not force and signature == self._tabs_signature:
            return
        self._tabs_signature = signature
        strip = self.query_one("#tabstrip", HorizontalScroll)
        await strip.remove_children()
        widgets: list[TabItem] = []
        for index, (title, short_id) in enumerate(entries):
            label = f"{index + 1}  {_short(title, 24)}"
            widgets.append(TabItem(index, label, active=index == active))
        widgets.append(
            TabItem(len(entries), action_label, active=False, action=True)
        )
        await strip.mount_all(widgets)

    def _refresh_topmode(self) -> None:
        mode = self.controller.mode
        label = "MODE A · COPILOT" if mode == "copilot" else "MODE B · PURPLE TEAM"
        self.query_one("#topmode", Static).update(
            Text(f" {label} ", style=f"bold {self.tokens.text}")
        )

    def _refresh_main(self, *, force: bool = False) -> None:
        mode = self.controller.mode
        conversation = self.query_one("#conversation", VerticalScroll)
        purple = self.query_one("#purple-view", Static)
        conversation.display = mode == "copilot"
        purple.display = mode == "purple"
        if mode == "copilot":
            self._refresh_conversation(force=force)
            self._refresh_inline_activity()
        else:
            self._refresh_purple()

    def _refresh_conversation(self, *, force: bool = False) -> None:
        controller = self.controller
        tab = controller.active_session()
        messages = controller.display_messages(tab)
        signature = (id(tab), tuple((m.role, m.content) for m in messages))
        if not force and signature == self._conversation_signature:
            return
        self._conversation_signature = signature
        self.run_worker(self._mount_messages(tab, messages), exclusive=False)

    async def _mount_messages(self, tab: Any, messages: list[Any]) -> None:
        empty = self.query_one("#empty-state", Static)
        message_list = self.query_one("#message-list", Vertical)
        empty.display = not messages
        message_list.display = bool(messages)
        await message_list.remove_children()
        widgets: list[Any] = []
        for message in messages:
            if message.role == "assistant":
                widgets.append(AssistantBlock(message.content))
            elif message.role == "user":
                widgets.append(UserBlock(message.content))
            else:
                widgets.append(NoticeBlock(message.content))
        if widgets:
            await message_list.mount_all(widgets)
        try:
            self.query_one("#conversation", VerticalScroll).scroll_end(animate=False)
        except Exception:
            pass

    def _refresh_inline_activity(self) -> None:
        widget = self.query_one("#inline-activity", Static)
        if self.controller.mode != "copilot":
            widget.display = False
            return
        rows = self.controller.copilot_tools()
        if not rows:
            widget.display = False
            return
        widget.display = True
        widget.update(self._activity_text(rows))

    def _refresh_purple(self) -> None:
        if self.controller.mode != "purple":
            return
        self.query_one("#purple-view", Static).update(self._purple_text())

    def _refresh_notice(self) -> None:
        widget = self.query_one("#notice-line", Static)
        notice = self.controller.notice
        widget.display = bool(notice)
        if notice:
            widget.update(Text(f" ! {notice}", style=self.tokens.warning))

    def _refresh_composer_meta(self) -> None:
        controller = self.controller
        text = Text()
        if controller.mode == "copilot":
            tab = controller.active_session()
            used, maximum = controller.context_usage(tab)
            text.append(" session ", style="dim")
            text.append(_short(tab.title, 24), style=f"bold {self.tokens.text}")
            text.append("  ", style="dim")
            text.append(f"{used:,} / {maximum:,}", style=self.tokens.muted)
            text.append(" tokens", style="dim")
        else:
            view = controller.purple_view
            text.append(" target ", style="dim")
            if view is None:
                text.append("new", style=f"bold {self.tokens.text}")
            else:
                snapshot = view.snapshot()
                text.append(_short(snapshot["target"], 40), style=f"bold {self.tokens.text}")
                text.append("   state ", style="dim")
                text.append(
                    snapshot["current_state"] or "ready",
                    style=self.tokens.running if not snapshot["outcome"] else self.tokens.success,
                )
        self.query_one("#composer-meta", Static).update(text)
        # Hints share the row with the session line, so pick the longest
        # variant the leftover width can hold without clipping either one.
        try:
            width = self.query_one("#composer-meta-row").size.width
        except Exception:
            width = 0
        width = width or _columns(self)
        room = width - len(text.plain) - 3
        variants = (
            "Enter send  ·  Shift+Enter newline  ·  Ctrl+P",
            "Enter send  ·  Shift+Enter nl  ·  Ctrl+P",
            "Enter send  ·  Ctrl+P",
            "Enter send",
        )
        hint = next((item for item in variants if len(item) <= room), "Enter send")
        self.query_one("#composer-hints", Static).update(Text(hint, style="dim"))

    def _refresh_sidebar(self) -> None:
        mode = self.controller.mode
        text = self._purple_sidebar() if mode == "purple" else self._copilot_sidebar()
        self.query_one("#sidebar-content", Static).update(text)
        try:
            self.query_one("#memory-entry", MemoryEntry).display = mode == "purple"
        except Exception:
            pass

    def _refresh_status(self) -> None:
        controller = self.controller
        text = Text()
        text.append(" ")
        wide = _columns(self) >= 100
        sep = "  ·  " if wide else " · "
        if controller.mode == "copilot":
            mode = "MODE A · COPILOT" if wide else "MODE A"
        else:
            mode = "MODE B · PURPLE" if wide else "MODE B"
        text.append(mode, style=f"bold {self.tokens.text}")
        text.append(sep, style="dim")
        if controller.mode == "copilot":
            model = str(self.cfg.general_chat_model)
            label = f"{controller.provider_label()} / {model}" if wide else model
            text.append(_short(label, 34 if wide else 20), style=self.tokens.text)
        elif wide:
            # live identity of what the engine is doing right now
            view = controller.purple_view
            label = "engine idle"
            style = self.tokens.muted
            if view is not None:
                snapshot = view.snapshot()
                state = snapshot["current_state"]
                if state:
                    label = self._agent_of_state(state).lower()
                    style = self.tokens.text
            text.append(_short(label, 28), style=style)
        text.append(sep, style="dim")
        text.append(_short(str(self.cfg.workspace), 26 if wide else 12), style=self.tokens.muted)
        text.append(sep, style="dim")
        if controller.mode == "copilot":
            used, maximum = controller.context_usage()
            if wide:
                text.append(f"{used:,}/{maximum:,} tokens", style=self.tokens.muted)
            else:
                text.append(f"{used}/{max(1, maximum // 1000)}k tok", style=self.tokens.muted)
        else:
            view = controller.purple_view
            if view is not None:
                snapshot = view.snapshot()
                stamp = elapsed(snapshot["started_at"], snapshot["finished_at"])
                state = snapshot["current_state"].lower() or "waiting"
                running_tool = next(
                    (row for row in reversed(snapshot["tools"]) if row["status"] == "running"),
                    None,
                )
                label = f"{state} · {running_tool['name']}" if running_tool else state
                text.append(_short(label, 34 if wide else 20), style=self.tokens.text)
                if wide:
                    text.append(sep, style="dim")
                text.append(f"elapsed {stamp}" if wide else stamp, style=self.tokens.text)
            else:
                text.append("no engagement", style=self.tokens.muted)
        text.append(sep, style="dim")
        text.append("status ", style="dim")
        status = controller.run_status()
        text.append(status, style=self.tokens.success if status == "ready" else self.tokens.warning)
        self.query_one("#statusbar", Static).update(text)

    # ---- composer and actions -----------------------------------------

    def on_composer_submitted(self, _event: Composer.Submitted) -> None:
        composer = self.query_one("#composer", Composer)
        value = composer.take_text()
        if not value.strip():
            return
        self.run_worker(self._submit(value), exclusive=False)

    async def _submit(self, value: str) -> None:
        await self.controller.submit(value)
        self.call_after_refresh(self._focus_composer)

    def action_command_palette(self) -> None:
        self.push_screen(CommandPalette(self.controller), self._palette_result)

    def _palette_result(self, choice: str | None) -> None:
        if not choice:
            return
        if choice.startswith("rename:"):
            self.action_rename_session(int(choice.partition(":")[2]) - 1)
        elif choice.startswith("close:"):
            self.action_close_session(int(choice.partition(":")[2]) - 1)
        elif choice == "new":
            self.action_new_tab()
        elif choice == "rename":
            self.action_rename_session()
        elif choice == "close":
            self.action_close_session()
        elif choice == "memory":
            self.action_open_memory()
        elif choice == "mode":
            self.run_worker(self.controller.switch_mode(), exclusive=False)
        elif choice == "help":
            self.controller.add_system_message(HELP_TEXT)
        elif choice == "theme":
            self.controller.add_system_message(
                "Workspace colors follow the active mode: Mode A is pure "
                "black/white/gray; Mode B is monochrome with the purple "
                "KRYONSEC wordmark. `/theme <name>` only affects other "
                "Kryonsec surfaces (kryonsec · tokyonight · dracula)."
            )
        elif choice == "quit":
            self.action_quit_app()
        self._focus_composer()

    def action_new_tab(self) -> None:
        if self.controller.mode == "copilot":
            self.controller.new_session()
        else:
            self.controller.new_engagement_placeholder()
        self._focus_composer()

    def action_prev_tab(self) -> None:
        self.controller.switch_tab(-1)

    def action_next_tab(self) -> None:
        self.controller.switch_tab(1)

    def action_rename_session(self, index: int | None = None) -> None:
        controller = self.controller
        if controller.mode != "copilot":
            controller.notify(
                "Engagement tabs keep their immutable identifiers; only Copilot sessions can be renamed."
            )
            self._refresh_notice()
            return
        if index is None:
            index = controller.session_index
        if not (0 <= index < len(controller.sessions)):
            return
        tab = controller.sessions[index]
        current = tab.custom_title or tab.title
        self.push_screen(RenameScreen(current), self._rename_result(index))

    def _rename_result(self, index: int):
        def callback(name: str | None) -> None:
            if not name:
                return  # cancelled — the original title stays untouched
            self.controller.rename_session(index, name)
            self._focus_composer()

        return callback

    def action_close_session(self, index: int | None = None) -> None:
        controller = self.controller
        if index is None:
            index = (
                controller.session_index
                if controller.mode == "copilot"
                else controller.engagement_index
            )
        if index is None:
            return
        controller.close_tab(int(index))

    def action_open_memory(self) -> None:
        controller = self.controller
        if controller.mode != "purple":
            controller.notify("Kryonsec Memory is available in Mode B only.")
            self._refresh_notice()
            return
        self.run_worker(self._open_memory(), exclusive=True)

    async def _open_memory(self) -> None:
        url = await asyncio.to_thread(self.controller.open_memory_browser)
        if not url:
            return  # the controller already turned the failure into a notice
        self.controller.add_system_message(
            f"Kryonsec Memory is serving {url} — read-only, loopback-only.\n"
            "This is the same viewer `kryonsec memory` runs; the workspace stays in the terminal."
        )

    def on_tab_item_pressed(self, event: TabItem.Pressed) -> None:
        event.stop()
        if event.index >= self.controller.tab_count():
            self.action_new_tab()
        else:
            self.controller.activate_tab(event.index)
        self._focus_composer()

    def on_memory_entry_activated(self, _event: MemoryEntry.Activated) -> None:
        self.action_open_memory()

    def action_toggle_mode(self) -> None:
        self.run_worker(self.controller.switch_mode(), exclusive=False)

    def action_interrupt(self) -> None:
        if self.controller.busy:
            self.controller.stop_requested = True
            self.controller.cancel_approvals()
            if self.controller.mode == "copilot":
                self.controller.notify(
                    "Stop requested; the active turn will end at the next safe boundary."
                )
            else:
                self.controller.notify(
                    "Approval cancelled. Purple Team finishes the current state before it can stop."
                )
            return
        self.action_quit_app()

    def action_quit_app(self) -> None:
        if self.controller.busy:
            self.controller.notify(
                "Quit is held until the active operation reaches a safe boundary."
            )
            return
        self.exit()

    # ---- approvals -----------------------------------------------------

    def _maybe_show_approval(self) -> None:
        gate = self.controller.approval
        if gate is None or self._approval_open:
            return
        self._approval_open = True
        self.push_screen(ApprovalScreen(gate), self._approval_result)

    def _approval_result(self, approved: bool | None) -> None:
        self._approval_open = False
        self.controller.decide_approval(bool(approved))
        self.call_after_refresh(self._maybe_show_approval)
        self.call_after_refresh(self._focus_composer)

    # ---- rendering helpers --------------------------------------------

    def _empty_state(self) -> Text:
        text = Text()
        text.append("\n\n")
        mark = BRAND_MARK if _columns(self) >= 92 else BRAND_SMALL
        for line in mark.splitlines():
            text.append(line + "\n", style=f"bold {self.tokens.brand}")
        text.append("\n")
        text.append("security workspaces for your terminal\n", style=self.tokens.muted)
        text.append("start a conversation below · Ctrl+P for commands\n", style="dim")
        return text

    def _activity_text(self, rows: list[Any]) -> Text:
        text = Text()
        text.append("\n")
        for row in rows[-8:]:
            style = {
                "running": self.tokens.running,
                "completed": self.tokens.success,
                "failed": self.tokens.error,
                "skipped": self.tokens.muted,
            }.get(row.status, self.tokens.muted)
            duration = f" · {row.duration:.1f}s" if row.duration is not None else ""
            text.append(f"  {status_mark(row.status)} ", style=style)
            text.append(row.name, style=f"bold {style}")
            text.append(f"  {row.status}{duration}\n", style="dim")
            if row.detail:
                text.append(f"    {_short(row.detail, 150)}\n", style="dim")
        return text

    def _purple_text(self) -> Text:
        view = self.controller.purple_view
        text = Text()
        if view is None:
            text.append("\n\n")
            text.append("  PURPLE TEAM\n", style=f"bold {self.tokens.text}")
            text.append("  deterministic, bounded, human-approved testing\n\n", style="dim")
            text.append("  Type an authorized target below to begin.\n", style=self.tokens.muted)
            text.append("  Approvals and sandbox checks remain fail-closed.\n", style="dim")
            return text
        snapshot = view.snapshot()
        current = snapshot["current_state"]
        text.append("\n  PURPLE TEAM  ", style=f"bold {self.tokens.text}")
        text.append(f"engagement {snapshot['engagement_id']}\n", style="dim")
        text.append("  target      ", style="dim")
        text.append(f"{snapshot['target']}\n", style=f"bold {self.tokens.text}")
        text.append("  sandbox     ", style="dim")
        sandbox_style = self.tokens.success if snapshot["sandbox_status"] in {"ready", "recorded"} else self.tokens.error
        text.append(f"{snapshot['sandbox_status']}\n", style=sandbox_style)
        detail = snapshot.get("sandbox_detail")
        if detail:
            text.append(f"              {_short(detail, 150)}\n", style="dim")
        text.append("  stage       ", style="dim")
        text.append(f"{STATE_ACTION.get(current, '—')}\n", style=self.tokens.text)
        text.append("  agent       ", style="dim")
        text.append(f"{self._agent_of_state(current)}\n", style=self.tokens.text)
        text.append("  elapsed     ", style="dim")
        text.append(f"{elapsed(snapshot['started_at'], snapshot['finished_at'])}\n\n")

        text.append("  WORKFLOW · 10 STATES\n", style=f"bold {self.tokens.text}")
        completed = set(snapshot["completed_states"])
        failed = set(snapshot.get("failed_states", []))
        durations = snapshot.get("state_duration") or {}
        started_map = snapshot.get("state_started") or {}
        finished_at = snapshot["finished_at"]
        for index, state in enumerate(PURPLE_STATES, 1):
            if state in failed:
                status = "failed"
            elif state == snapshot["current_state"]:
                status = "running"
            elif state in completed:
                status = "completed"
            else:
                status = "pending"
            style = {
                "running": self.tokens.running,
                "completed": self.tokens.success,
                "failed": self.tokens.error,
            }.get(status, self.tokens.pending)
            timing = durations.get(state)
            if timing is None and status == "running" and finished_at is None:
                began = started_map.get(state)
                if began is not None:
                    timing = max(0.0, time.monotonic() - began)
            timing_label = f"{timing:.0f}s" if isinstance(timing, (int, float)) else ""
            text.append(f"  {status_mark(status)} {index:02d} ", style=style)
            label = state.replace("_", " ")
            text.append(f"{label:<13}", style="bold" if status == "running" else style)
            if timing_label:
                text.append(f" {timing_label:>6}", style="dim")
            text.append(f" {status}\n", style="dim")

        text.append("\n  LIVE ACTIVITY\n", style=f"bold {self.tokens.text}")
        activity = snapshot.get("activity") or []
        if not activity:
            text.append("  no activity yet — events appear as the engine runs\n", style="dim")
        for row in activity[-20:]:
            text.append("  ")
            text.append(f"{self._activity_stamp(row, snapshot['started_at'])}", style="dim")
            text.append(" ")
            mark, style = self._activity_mark(row)
            text.append(f"{mark} ", style=style)
            agent = self._agent_of_state(row.get("state") or "")
            if agent and agent != "—":
                text.append(f"{_short(agent, 14):<14}", style="dim")
            text.append(f"{row.get('summary') or ''}\n", style=self.tokens.text if mark == "!" else "dim")

        counts = snapshot["counts"]
        verified = sum(1 for row in snapshot["findings"] if row[1] == "verified")
        text.append("\n  FINDINGS & EVIDENCE\n", style=f"bold {self.tokens.text}")
        text.append(f"  assets {counts['subdomains'] + counts['endpoints']}", style="dim")
        text.append(f"   hypotheses {counts['hypotheses']}", style="dim")
        text.append(f"   findings {counts['findings']}", style="dim")
        text.append(f"   evidence {counts['evidence']}\n", style="dim")
        text.append(f"  verified {verified}", style=self.tokens.success)
        text.append(f"   possible {counts['findings'] - verified}\n", style=self.tokens.warning)
        for label, standing, severity in snapshot["findings"][-5:]:
            style = self.tokens.success if standing == "verified" else self.tokens.warning
            text.append(f"  {status_mark('completed' if standing == 'verified' else 'waiting')} ", style=style)
            text.append(f"{label} [{severity}]\n", style=style)

        tool = next(
            (row for row in reversed(snapshot["tools"]) if row["status"] == "running"),
            None,
        ) or (snapshot["tools"][-1] if snapshot["tools"] else None)
        if tool is not None:
            text.append("\n  CURRENT OPERATION\n", style=f"bold {self.tokens.text}")
            tool_style = {
                "running": self.tokens.running,
                "completed": self.tokens.success,
                "failed": self.tokens.error,
            }.get(tool["status"], self.tokens.muted)
            duration = f"{tool['duration']:.1f}s" if isinstance(tool.get("duration"), (int, float)) else "running"
            text.append("  agent    ", style="dim")
            text.append(f"{self._agent_of_state(tool.get('state') or current)}\n", style=self.tokens.text)
            text.append("  task     ", style="dim")
            text.append(f"{STATE_ACTION.get(tool.get('state') or current, '—')}\n", style=self.tokens.text)
            text.append("  tool     ", style="dim")
            text.append(f"{tool['name']}\n", style=f"bold {tool_style}")
            text.append("  command  ", style="dim")
            argv = [item for item in tool.get("argv") or [] if item]
            if argv:
                # The backend's own argv, redacted at capture — the UI never
                # constructs commands.
                text.append(f"{_short(display_command(tool['name'], argv), 200)}\n", style=self.tokens.text)
            else:
                text.append(f"{_short(tool['name'], 40)}\n", style="dim")
            text.append("  status   ", style="dim")
            text.append(f"{tool['status']} · {duration}\n", style=tool_style)
            if tool.get("detail"):
                text.append("  outcome  ", style="dim")
                text.append(f"{_short(tool['detail'], 200)}\n", style="dim")

        notices = snapshot["notices"]
        if notices:
            text.append("\n  NOTICES\n", style=f"bold {self.tokens.text}")
            for notice in notices[-5:]:
                text.append(f"  ! {_short(notice, 220)}\n", style="bold")
        if snapshot["outcome"]:
            text.append("\n  ENGAGEMENT ", style=f"bold {self.tokens.text}")
            style = self.tokens.success if snapshot["outcome"] == "completed" else self.tokens.error
            text.append(f"{snapshot['outcome'].upper()}\n", style=f"bold {style}")
            if snapshot["halt_reason"]:
                text.append(f"  reason: {snapshot['halt_reason']}\n", style=self.tokens.error)
            if snapshot["report_path"]:
                text.append(f"  report: {snapshot['report_path']}\n", style=self.tokens.success)
        return text

    def _activity_stamp(self, row: dict, started_at: float | None) -> str:
        seconds = row.get("ts")
        if started_at is None or not isinstance(seconds, (int, float)):
            return "--:--  "
        return f"{elapsed(started_at, seconds):>8}"

    def _activity_mark(self, row: dict) -> tuple[str, str]:
        summary = str(row.get("summary") or "")
        if summary.startswith("engagement completed"):
            return "✓", self.tokens.success
        if summary.startswith(("engagement failed", "engagement halted", "engagement interrupted")):
            return "×", self.tokens.error
        if summary.startswith("started") or summary.startswith("launched"):
            return "●", self.tokens.running
        if summary.startswith(("finished", "stage completed")):
            return "✓", self.tokens.success
        if summary.startswith("failed"):
            return "×", self.tokens.error
        if summary.startswith("skipped"):
            return "·", self.tokens.muted
        return "!", self.tokens.warning

    # ---- sidebar -------------------------------------------------------

    def _sidebar_header(self, text: Text, title: str) -> None:
        text.append("\n")
        text.append(f" {title}\n", style=f"bold {self.tokens.accent_bright}")

    def _sidebar_row(self, text: Text, label: str, value: str, style: str = "") -> None:
        text.append(f" {label:<11}", style="dim")
        text.append(f"{value}\n", style=style or self.tokens.text)

    def _copilot_sidebar(self) -> Text:
        controller = self.controller
        tab = controller.active_session()
        text = Text()
        self._sidebar_header(text, "SESSION")
        self._sidebar_row(text, "name", _short(tab.title, 18), self.tokens.text)
        self._sidebar_row(text, "id", tab.short_id, "dim")
        used, maximum = controller.context_usage(tab)
        self._sidebar_row(text, "context", f"{used:,} / {maximum:,}", self.tokens.info)
        text.append(" ")
        text.append(_bar(used, maximum), style=self.tokens.accent_bright)
        text.append("\n")

        self._sidebar_header(text, "MODEL")
        self._sidebar_row(text, "provider", controller.provider_label(), self.tokens.text)
        self._sidebar_row(text, "model", _short(self.cfg.general_chat_model, 30), self.tokens.text)

        self._sidebar_header(text, "MCP SERVERS")
        statuses = controller.mcp_statuses()
        if not statuses:
            self._sidebar_row(text, "status", "none configured", "dim")
        for status in statuses:
            state = str(status.get("status") or "starting")
            style = {
                "connected": self.tokens.success,
                "disconnected": self.tokens.error,
                "starting": self.tokens.warning,
            }.get(state, self.tokens.muted)
            text.append(f" {status_mark(state)} ", style=style)
            text.append(f"{_short(str(status.get('name') or 'server'), 24)}", style=f"bold {style}")
            text.append(f" — {state}\n", style=style)
            detail = safe(status.get("detail") or "", 40)
            if detail:
                text.append(f"   {detail}\n", style="dim")

        self._sidebar_header(text, "RUNTIME")
        self._sidebar_row(text, "Docker", "not used by Copilot", "dim")
        self._sidebar_row(text, "workspace", _short(str(self.cfg.workspace), 30), self.tokens.muted)
        self._sidebar_row(text, "tools", f"{len(self.cfg.enabled_tools)} enabled", self.tokens.text)
        status = controller.run_status()
        self._sidebar_row(
            text,
            "status",
            status,
            self.tokens.success if status == "ready" else self.tokens.warning,
        )

        rows = controller.copilot_tools(tab)
        if rows:
            self._sidebar_header(text, "ACTIVITY")
            for row in rows[-5:]:
                style = {
                    "running": self.tokens.running,
                    "completed": self.tokens.success,
                    "failed": self.tokens.error,
                }.get(row.status, self.tokens.muted)
                text.append(f" {status_mark(row.status)} ", style=style)
                text.append(f"{_short(row.name, 26)}\n", style=style)
        return text

    def _agent_of_state(self, state: str) -> str:
        """The operator-facing identity of a workflow stage."""
        if state in SECURITY_AGENT_STATES:
            return AGENT_LABELS[state]
        return {"INIT": "engine", "HUMAN_REVIEW": "operator", "HALT": "halted"}.get(
            state, state.replace("_", " ").lower() if state else "—"
        )

    def _runtime_style(self, value: str) -> str:
        if value in {"connected", "ready"}:
            return self.tokens.success
        if value in {"unavailable", "disconnected", "failed"}:
            return self.tokens.error
        if value in {"checking", "starting", "waiting"}:
            return self.tokens.warning
        return self.tokens.muted

    def _purple_sidebar(self) -> Text:
        controller = self.controller
        view = controller.purple_view
        runtime = controller.runtime_status_summary()
        text = Text()
        self._sidebar_header(text, "ENGAGEMENT")
        if view is None:
            self._sidebar_row(text, "status", "waiting for target", self.tokens.muted)
            self._sidebar_row(text, "stage", "—", "dim")
            self._sidebar_row(text, "agent", "—", "dim")
            agents_snapshot = {
                "current_state": "",
                "completed_states": [],
                "failed_states": [],
                "tools": [],
            }
        else:
            snapshot = view.snapshot()
            current = snapshot["current_state"]
            outcome = snapshot["outcome"]
            finished = snapshot["finished_at"] is not None
            state_style = (
                self.tokens.success if outcome in {"completed"} else
                self.tokens.error if outcome in {"failed", "halted", "interrupted"} else
                self.tokens.running if current else
                self.tokens.muted
            )
            self._sidebar_row(text, "target", _short(snapshot["target"], 18), self.tokens.text)
            self._sidebar_row(text, "id", snapshot["engagement_id"], "dim")
            self._sidebar_row(text, "state", _short(current or "ready", 16), state_style)
            self._sidebar_row(text, "elapsed", elapsed(snapshot["started_at"], snapshot["finished_at"]), self.tokens.text)
            self._sidebar_row(text, "stage", _short(STATE_ACTION.get(current, "—"), 20), self.tokens.muted)
            self._sidebar_row(text, "agent", self._agent_of_state(current), state_style if not finished else self.tokens.muted)
            agents_snapshot = snapshot

        self._sidebar_header(text, "RUNTIME")
        self._sidebar_row(text, "Docker", runtime.get("docker", "unknown"), self._runtime_style(runtime.get("docker", "unknown")))
        if runtime.get("docker_detail"):
            text.append(f"   {_short(runtime['docker_detail'], 26)}\n", style="dim")
        if view is not None:
            # Prefer the engagement's own real sandbox_check observation.
            sandbox_status = snapshot["sandbox_status"]
            sandbox_detail = snapshot.get("sandbox_detail") or ""
        else:
            sandbox_status = runtime.get("sandbox", "unknown")
            sandbox_detail = runtime.get("sandbox_detail", "")
        self._sidebar_row(text, "Sandbox", sandbox_status, self._runtime_style(sandbox_status))
        if sandbox_detail:
            text.append(f"   {_short(sandbox_detail, 26)}\n", style="dim")
        self._sidebar_row(text, "Memory viewer", "on demand", self.tokens.muted)
        mcp_row = controller.mcp_statuses()
        if mcp_row:
            connected = sum(1 for row in mcp_row if row.get("status") == "connected")
            label = f"{connected}/{len(mcp_row)} connected" if connected else str(mcp_row[0].get("status") or "not connected")
            self._sidebar_row(text, "MCP", _short(label, 16), self._runtime_style("connected" if connected else label))
        else:
            self._sidebar_row(text, "MCP", "none configured", self.tokens.muted)
        self._sidebar_row(text, "workspace", _short(str(self.cfg.workspace), 28), self.tokens.muted)
        if mcp_row:
            self._sidebar_header(text, "CONNECTIONS")
            for row in mcp_row:
                status = str(row.get("status") or "unknown")
                style = self._runtime_style(status)
                text.append(f" {status_mark(status)} ", style=style)
                text.append(f"{_short(str(row.get('name') or 'server'), 24):<24}", style=self.tokens.text)
                text.append(f"{_short(status, 12)}\n", style="dim")

        self._sidebar_header(text, "AGENTS · 8")
        completed = set(agents_snapshot["completed_states"])
        failed = set(agents_snapshot.get("failed_states", []))
        current_state = agents_snapshot["current_state"]
        running_tool = next(
            (row for row in reversed(agents_snapshot["tools"]) if row["status"] == "running"),
            None,
        )
        last_tool = agents_snapshot["tools"][-1] if agents_snapshot["tools"] else None
        for state in SECURITY_AGENT_STATES:
            if state in failed:
                status = "failed"
            elif state == current_state:
                status = "running"
            elif state in completed:
                status = "completed"
            else:
                status = "idle"
            style = {
                "running": self.tokens.running,
                "completed": self.tokens.success,
                "failed": self.tokens.error,
            }.get(status, self.tokens.muted)
            text.append(f" {status_mark(status)} ", style=style)
            text.append(f"{AGENT_LABELS[state]:<14}", style=f"bold {style}" if status == "running" else style)
            text.append(f"{status}\n", style=style)
            if status == "running":
                operation = STATE_ACTION.get(state, "")
                if running_tool and running_tool.get("state") == state:
                    operation = f"{running_tool['name']} · {operation}"
                if operation:
                    text.append(f"   {_short(operation, 26)}\n", style="dim")
            elif status == "completed" and last_tool is not None and last_tool.get("state") == state:
                detail = last_tool.get("detail") or ""
                if detail:
                    summary = f"{last_tool['name']}: {detail}"
                    text.append(
                        f"   {status_mark(last_tool['status'])} {_short(summary, 26)}\n",
                        style="dim",
                    )

        tool = running_tool or (agents_snapshot["tools"][-1] if agents_snapshot["tools"] else None)
        self._sidebar_header(text, "TOOL · COMMAND")
        if tool is None:
            text.append(" · no tool activity yet\n", style="dim")
        else:
            tool_style = {
                "running": self.tokens.running,
                "completed": self.tokens.success,
                "failed": self.tokens.error,
            }.get(tool["status"], self.tokens.muted)
            duration = f"{tool['duration']:.1f}s" if isinstance(tool.get("duration"), (int, float)) else "…"
            text.append(f" {status_mark(tool['status'])} ", style=tool_style)
            text.append(f"{tool['name']:<12}", style=f"bold {tool_style}")
            text.append(f"{tool['status']} {duration}\n", style="dim")
            argv = [item for item in tool.get("argv") or [] if item]
            command = display_command(tool["name"], argv) if argv else (tool.get("detail") or "")
            if command:
                text.append(f"   {_short(command, 30)}\n", style="dim")

        if controller.approval is not None:
            text.append("\n ! approval · waiting\n", style=self.tokens.warning)

        orch = agents_snapshot.get("orchestrator") if view is not None else None
        budget = getattr(orch, "budget", None) if orch is not None else None
        if budget is not None:
            self._sidebar_header(text, "BUDGET")
            self._sidebar_row(text, "tokens", f"{budget.used_tokens:,} / {budget.max_tokens:,}", self.tokens.text)
            self._sidebar_row(text, "cost", f"${budget.used_cost_usd:.2f} / ${budget.max_cost_usd:.2f}", self.tokens.text)
            self._sidebar_row(text, "time", f"{budget.elapsed_s:.0f}s / {budget.max_time_s}s", self.tokens.text)

        if view is not None:
            counts = agents_snapshot["counts"]
            verified = sum(1 for row in agents_snapshot["findings"] if row[1] == "verified")
            self._sidebar_header(text, "FINDINGS")
            self._sidebar_row(text, "verified", str(verified), self.tokens.success)
            self._sidebar_row(text, "possible", str(counts["findings"] - verified), self.tokens.warning)
            self._sidebar_row(text, "evidence", str(counts["evidence"]), self.tokens.text)
        return text


# ---- helpers ------------------------------------------------------------


def _short(value: str, limit: int) -> str:
    value = " ".join(str(value or "").split())
    if len(value) <= limit:
        return value
    return value[: max(1, limit - 1)] + "…"


def _bar(used: int, maximum: int, width: int = 18) -> str:
    maximum = max(1, maximum)
    filled = min(width, max(0, round(width * used / maximum)))
    return "█" * filled + "░" * (width - filled)


def _columns(app: App[Any]) -> int:
    try:
        return int(app.size.width)
    except Exception:
        return 120


def _css_color(value: str) -> str:
    """Textual spells ANSI bright names ``ansi_bright_*``."""
    if value.startswith("bright_"):
        return "ansi_" + value
    return value


def _build_css(tokens: ThemeTokens) -> str:
    # Textual CSS has its own ANSI naming.  The same tokens feed Rich text, so
    # sanitize a copy only for the stylesheet instead of changing the theme.
    class _CssTokens:
        pass

    t = _CssTokens()
    for name, value in vars(tokens).items():
        setattr(t, name, _css_color(value) if isinstance(value, str) else value)
    return dedent(
        f"""
        Screen {{
            background: {t.background};
            color: {t.text};
            layers: base;
        }}

        #topbar {{
            height: 1;
            background: {t.surface};
            color: {t.muted};
        }}
        #brand {{
            width: 12;
            padding: 0 1;
            content-align: left middle;
            color: {t.brand};
            text-style: bold;
        }}
        #tabstrip {{
            width: 1fr;
            height: 1;
            background: {t.surface};
            scrollbar-size: 0 0;
        }}
        #topmode {{
            width: auto;
            height: 1;
            content-align: right middle;
            background: {t.surface};
        }}
        .tab-item {{
            width: auto;
            height: 1;
            padding: 0 1;
            color: {t.muted};
            background: {t.surface};
        }}
        .tab-item:hover {{
            color: {t.text};
            background: {t.surface_high};
        }}
        .tab-item.active {{
            color: {t.background};
            background: {t.accent};
            text-style: bold;
        }}
        .tab-action {{
            width: auto;
            height: 1;
            padding: 0 1;
            color: {t.accent_bright};
            background: {t.surface};
            text-style: bold;
        }}
        .tab-action:hover {{
            background: {t.surface_high};
        }}

        #body {{
            height: 1fr;
            background: {t.background};
        }}
        #main {{
            width: 1fr;
            height: 1fr;
            padding: 0 1;
            background: {t.background};
        }}
        #conversation {{
            height: 1fr;
            padding: 0 1;
            background: {t.background};
            scrollbar-size-vertical: 1;
        }}
        #empty-state {{
            height: 1fr;
            width: 1fr;
            content-align: center middle;
            text-align: center;
        }}
        #message-list {{
            height: auto;
            width: 1fr;
        }}
        .user-block {{
            width: 1fr;
            height: auto;
            margin: 1 0 0 0;
            padding: 0 1;
            color: {t.text};
            background: {t.background};
        }}
        .assistant-block {{
            width: 1fr;
            height: auto;
            margin: 1 0 0 0;
            padding: 0 1;
        }}
        .role-label {{
            height: 1;
            color: {t.accent_bright};
            text-style: bold;
        }}
        .message-markdown {{
            margin: 0;
            padding: 0;
            background: {t.background};
        }}
        .notice-block {{
            width: 1fr;
            height: auto;
            padding: 0 1;
            color: {t.muted};
        }}
        #inline-activity {{
            height: auto;
            padding: 0 1 1 1;
        }}

        #purple-view {{
            height: 1fr;
            width: 1fr;
            padding: 0 1;
            background: {t.background};
            overflow-y: auto;
        }}

        #notice-line {{
            height: 1;
            padding: 0 1;
            color: {t.warning};
        }}
        #composer-area {{
            height: auto;
            width: 1fr;
            padding: 1 0 0 0;
            background: {t.background};
        }}
        #composer-meta-row {{
            height: 1;
            width: 1fr;
        }}
        #composer-meta {{
            width: 1fr;
            height: 1;
            padding: 0 1;
            color: {t.muted};
        }}
        #composer-hints {{
            width: auto;
            height: 1;
            padding: 0 1 0 0;
            color: {t.muted};
        }}
        #composer {{
            height: 5;
            border: tall {t.accent};
            background: {t.surface_high};
            color: {t.text};
            padding: 0 1;
        }}
        #composer:focus {{
            border: tall {t.accent_bright};
        }}

        #statusbar {{
            height: 1;
            background: {t.surface};
            color: {t.muted};
        }}

        #sidebar {{
            width: 34;
            height: 1fr;
            background: {t.surface};
            border-left: solid {t.border};
            padding: 0 1;
            scrollbar-size-vertical: 1;
        }}
        #sidebar-content {{
            width: 1fr;
            height: auto;
        }}
        .memory-entry {{
            height: auto;
            padding: 0 0 0 0;
            color: {t.text};
            background: {t.surface};
        }}
        .memory-entry:hover {{
            color: {t.text};
            background: {t.surface_high};
        }}
        .memory-entry:focus {{
            text-style: reverse;
        }}

        Screen.-narrow #sidebar {{
            display: none;
        }}
        Screen.-narrow #main {{
            padding: 0;
        }}

        CommandPalette {{
            align: center middle;
            background: {t.background} 70%;
        }}
        #palette-box {{
            width: 64;
            height: auto;
            max-height: 20;
            border: round {t.accent};
            background: {t.surface};
            padding: 0 1;
        }}
        .palette-title {{
            height: 1;
            color: {t.accent_bright};
            text-style: bold;
        }}
        .palette-hint {{
            height: 1;
            color: {t.faint};
        }}
        #palette-list {{
            width: 1fr;
            height: auto;
            max-height: 14;
            background: {t.surface};
        }}
        #palette-list > .option-list--option-highlighted {{
            background: {t.accent};
            color: {t.background};
        }}

        ApprovalScreen {{
            align: center middle;
            background: {t.background} 80%;
        }}
        #approval-box {{
            width: 78;
            height: auto;
            max-height: 26;
            border: round {t.warning};
            background: {t.surface};
            padding: 1 2;
        }}
        .approval-title {{
            height: 1;
            color: {t.warning};
            text-style: bold;
        }}
        .approval-body {{
            height: auto;
            margin: 1 0;
        }}
        #approval-actions {{
            height: auto;
            align-horizontal: right;
        }}
        #approval-actions Button {{
            margin-left: 2;
            background: {t.surface_high};
            color: {t.text};
            border: tall {t.border};
        }}
        #approval-actions Button:hover {{
            background: {t.border};
            color: {t.text};
        }}

        ScrollBar {{
            background: {t.surface};
            scrollbar-color: {t.border};
            scrollbar-color-hover: {t.muted};
            scrollbar-color-active: {t.muted};
        }}

        RenameScreen {{
            align: center middle;
            background: {t.background} 80%;
        }}
        #rename-box {{
            width: 64;
            height: auto;
            border: round {t.border};
            background: {t.surface};
            padding: 1 2;
        }}
        .rename-title {{
            height: 1;
            color: {t.text};
            text-style: bold;
        }}
        .rename-hint {{
            height: 1;
            color: {t.muted};
        }}
        #rename-input {{
            width: 1fr;
            height: 3;
            border: tall {t.border};
            background: {t.surface_high};
            color: {t.text};
        }}
        #rename-input:focus {{
            border: tall {t.accent_bright};
        }}
        #rename-error {{
            height: 1;
            color: {t.text};
        }}
        """
    ).strip()


__all__ = [
    "ApprovalScreen",
    "CommandPalette",
    "Composer",
    "KryonsecApp",
    "MemoryEntry",
    "RenameScreen",
    "TabItem",
]
