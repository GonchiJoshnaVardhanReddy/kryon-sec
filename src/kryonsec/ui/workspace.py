"""Backend controller for the persistent terminal workspace.

The controller owns the same Copilot and Purple Team operations the CLI has
always owned; it is deliberately free of any terminal widget import.  A UI
adapter (Textual in ``ui.app``) reads its snapshots and subscribes to
``on_change``.  Backends run in worker threads and report observations; they
never print into the terminal.

Safety boundaries are unchanged: approvals stay fail-closed, Purple Team
transitions and audit writes stay in their existing modules, and a rendering
failure cannot alter a backend result.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..config import KryonsecConfig
from ..command_registry import (
    PURPLE_BUSY_SAFE,
    command_name,
    commands_text,
    help_text,
    lookup,
)
from ..copilot.session import GeneralSession
from ..model_catalog import (
    current_model_view,
    discover_models,
    provider_label as model_provider_label,
    switch_model,
)
from ..secrets import redact
from . import questions as _questions
from .session_store import EngagementStore, EngagementTab, SessionStore, SessionTab
from .state import (
    ApprovalGate,
    DisplayMessage,
    PurpleToolRow,
    PurpleWorkspaceState,
    elapsed,
    safe,
)

log = logging.getLogger(__name__)


class OperationCancelled(Exception):
    """Raised from an observation callback at a safe boundary."""


# Purple commands that stay usable while an engagement is running come from
# the central registry (`PURPLE_BUSY_SAFE`).  They are read-only or
# presentation-only; `/models use` re-checks the engagement lock in its
# handler and refuses to switch mid-run.


@dataclass
class CopilotActivity:
    """One tool call shown inline with the conversation."""

    name: str
    detail: str = ""
    status: str = "running"
    started_at: float = 0.0
    duration: float | None = None


class _LivePurpleState(PurpleWorkspaceState):
    """Purple snapshot that tells the UI when it changed."""

    def __init__(self, target: str, engagement_id: str, notify: Callable[[str], None], **kw: Any) -> None:
        super().__init__(target, engagement_id, **kw)
        self._notify = notify

    def on_state(self, state: str) -> None:
        super().on_state(state)
        self._notify("purple")

    def on_state_complete(self, state: str) -> None:
        super().on_state_complete(state)
        self._notify("purple")

    def on_audit(self, entry: dict) -> None:
        super().on_audit(entry)
        self._notify("purple")

    def on_notice(self, message: str) -> None:
        super().on_notice(message)
        self._notify("purple")

    def finish(self, outcome: str, **kw: Any) -> None:
        super().finish(outcome, **kw)
        self._notify("purple")


def _audit_seconds(value: Any) -> float | None:
    """Parse an audit ``ts`` (ISO-8601) into POSIX seconds.

    Missing or malformed timestamps return None rather than raising: old
    chains predate the field, and a replay must still render them.
    """
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return None


class WorkspaceController:
    """Presentation-agnostic owner of sessions, modes, and backend calls."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        *,
        session_store: SessionStore,
        engagement_store: EngagementStore,
        system_prompt: str,
        mcp_toolbox: Any = None,
        mcp_registry: Any = None,
        initial_sessions: list[SessionTab] | None = None,
        initial_engagements: list[EngagementTab] | None = None,
        on_change: Callable[[str], None] | None = None,
    ) -> None:
        self.cfg = cfg
        self.cfg.ensure_dirs()
        self.session_store = session_store
        self.engagement_store = engagement_store
        self.system_prompt = system_prompt
        self.mcp_toolbox = mcp_toolbox
        self.mcp_registry = mcp_registry
        self._on_change = on_change or (lambda reason: None)
        self.sessions: list[SessionTab] = initial_sessions or []
        if not self.sessions:
            self.sessions = [session_store.new_tab()]
        self.session_index = 0
        self.engagements: list[EngagementTab] = initial_engagements or []
        self.engagement_index: int | None = 0 if self.engagements else None
        self.purple_view: PurpleWorkspaceState | None = None
        self.mode_holder = ["copilot"]
        self.notice = ""
        self.busy = False
        # True for the whole life of a live engagement run — set when the
        # worker starts, cleared when it ends.  Unlike `busy` it is never
        # touched by the /mode presentation hack, so it is the honest
        # "is an engagement running" answer used to refuse /engage.
        self.engagement_running = False
        # One question may be answered at a time; a second is refused with
        # a notice rather than queued or dropped silently.
        self._question_in_flight = False
        self.stop_requested = False
        self.approval: ApprovalGate | None = None
        self.transient: dict[int, list[DisplayMessage]] = {}
        self.tools_by_tab: dict[int, list[CopilotActivity]] = {}
        self.last_error: str | None = None
        self._closed = False
        self._lock = threading.RLock()
        # Real runtime availability, collected by _collect_runtime_status() in
        # a background thread. Starts "unknown" and is never faked; the
        # sidebar renders exactly whatever the checks returned.
        self.runtime_status: dict[str, str] = {
            "docker": "unknown",
            "docker_detail": "",
            "sandbox": "unknown",
            "sandbox_detail": "",
        }
        self._runtime_checked_at = 0.0
        self._runtime_thread: threading.Thread | None = None

    # ---- notifications -------------------------------------------------

    def set_change_callback(self, callback: Callable[[str], None]) -> None:
        self._on_change = callback

    def _changed(self, reason: str) -> None:
        try:
            self._on_change(reason)
        except Exception:
            log.debug("UI change callback failed", exc_info=True)

    def notify(self, message: str, *, reason: str = "notice") -> None:
        value = safe(message, 500)
        if not value:
            return
        self.notice = value
        self._changed(reason)

    def clear_notice(self) -> None:
        if self.notice:
            self.notice = ""
            self._changed("notice")

    def add_system_message(self, message: str) -> None:
        """Append a presentation-only system line to the active view."""
        self._add_transient("system", message)

    # ---- session tabs --------------------------------------------------

    @property
    def mode(self) -> str:
        return self.mode_holder[0]

    def active_session(self) -> SessionTab:
        return self.sessions[self.session_index]

    def active_engagement(self) -> EngagementTab | None:
        if self.engagement_index is None:
            return None
        if not (0 <= self.engagement_index < len(self.engagements)):
            return None
        return self.engagements[self.engagement_index]

    def tab_count(self) -> int:
        return len(self.sessions) if self.mode == "copilot" else len(self.engagements)

    def new_session(self) -> None:
        if self.busy:
            self.notify("Create a new tab after the active operation reaches a safe boundary.")
            return
        tab = self.session_store.new_tab()
        self.sessions.append(tab)
        self.session_index = len(self.sessions) - 1
        self.transient[id(tab)] = []
        self.notice = ""
        self._changed("tabs")

    def new_engagement_placeholder(self) -> None:
        if self.busy:
            self.notify("Start a new engagement after the active operation reaches a safe boundary.")
            return
        self.engagement_index = None
        self.purple_view = None
        self.notice = "Type an authorized target to start an engagement."
        self._changed("tabs")

    def activate_tab(self, index: int) -> None:
        if self.busy:
            self.notify("Tab switching is disabled while work is active.")
            return
        if self.mode == "copilot":
            if index < 0 or index >= len(self.sessions):
                return
            self.session_index = index
        else:
            if index < 0 or index >= len(self.engagements):
                return
            self.engagement_index = index
            self.load_engagement_view(self.engagements[index])
        self.notice = ""
        self._changed("tabs")

    def switch_tab(self, direction: int) -> None:
        if self.busy:
            self.notify("Tab switching is disabled while work is active.")
            return
        count = self.tab_count()
        if count <= 1:
            return
        if self.mode == "copilot":
            self.session_index = (self.session_index + direction) % count
        else:
            current = self.engagement_index or 0
            self.engagement_index = (current + direction) % count
            self.load_engagement_view(self.engagements[self.engagement_index])
        self._changed("tabs")

    def rename_session(self, index: int, name: str) -> bool:
        """Give one tab a display title — Mode A sessions and Mode B tabs.

        Renaming changes presentation only.  Mode A: the stored message
        history, record id, and timestamps are untouched.  Mode B: the
        engagement id, the recorded target, and every audit event are
        untouched; the title is stored as display_title.json beside the
        audit chain.  Returns True when the rename was applied.
        """
        cleaned = " ".join(str(name or "").split())
        if not cleaned:
            self.notify("Name cannot be empty.")
            return False
        if self.mode == "copilot":
            if not (0 <= index < len(self.sessions)):
                return False
            tab = self.sessions[index]
            tab.custom_title = cleaned[:120]
            if tab.session.messages:
                try:
                    self.session_store.save(tab)
                except Exception as exc:
                    self.notify(f"Renamed in view, but storage failed: {safe(exc, 200)}")
            self._changed("tabs")
            return True
        if not (0 <= index < len(self.engagements)):
            return False
        tab = self.engagements[index]
        tab.custom_title = cleaned[:120]
        if tab.path is not None:
            try:
                if not self.engagement_store.rename(tab.engagement_id, tab.custom_title):
                    self.notify("Renamed in view, but the engagement folder could not be updated.")
            except Exception as exc:
                self.notify(f"Renamed in view, but storage failed: {safe(exc, 200)}")
        # A live engagement tab has no directory yet; the title rides in
        # memory and is re-stored when the run finishes (start_engagement).
        self._changed("tabs")
        return True

    def close_tab(self, index: int) -> None:
        """Remove one tab from the workspace; stored history is never deleted.

        Closing is refused while an operation or a pending approval is
        active. Closing a tab is never an approval, a cancellation of a
        security gate, or authorization to stop backend execution.
        """
        if self.busy:
            self.notify(
                "Closing a tab is disabled while an operation is active; wait for a safe boundary."
            )
            return
        if self.approval is not None:
            self.notify(
                "An approval is pending; approve or deny it before closing a tab."
            )
            return
        if self.mode == "copilot":
            if not (0 <= index < len(self.sessions)):
                return
            tab = self.sessions.pop(index)
            with self._lock:
                self.transient.pop(id(tab), None)
                self.tools_by_tab.pop(id(tab), None)
            if self.sessions:
                self.session_index = min(index, len(self.sessions) - 1)
            else:
                replacement = self.session_store.new_tab()
                self.sessions = [replacement]
                self.session_index = 0
                self.transient[id(replacement)] = []
                self.notice = "All sessions closed — a clean new session is ready."
            self._changed("tabs")
            return
        # Mode B: engagement tabs are read-only views of stored audit runs.
        if not (0 <= index < len(self.engagements)):
            return
        self.engagements.pop(index)
        if self.engagements:
            self.engagement_index = min(index, len(self.engagements) - 1)
            self.load_engagement_view(self.engagements[self.engagement_index])
        else:
            self.engagement_index = None
            self.purple_view = None
            self.notice = "No engagement tabs — type an authorized target to start one."

    # ---- memory browser ------------------------------------------------

    def open_memory_browser(self, *, open_browser: bool = True) -> str | None:
        """Launch the existing read-only memory browser on explicit demand.

        The same loopback server `kryonsec memory` runs is reused — no new
        HTTP server and no shell command.  The URL is returned so the UI can
        show it; a failure is reported as a notice and never breaks the
        workspace.  Engagement data is read by the shared viewer, never
        written here.
        """
        if self.mode != "purple":
            return None
        from .. import cli

        try:
            url = cli._start_memory_browser(self.cfg)
        except Exception as exc:
            self.notify(
                f"Kryonsec Memory could not start: {type(exc).__name__}: {safe(exc, 200)}"
            )
            return None
        if not url:
            self.notify("Kryonsec Memory could not start (the loopback listener refused).")
            return None
        if open_browser:
            try:
                import webbrowser

                webbrowser.open(url)
            except Exception:
                pass  # the URL is always shown; the browser is optional
        return url

    # ---- mode ----------------------------------------------------------

    async def switch_mode(self) -> None:
        from ..tui import set_mode

        if self.busy or self.engagement_running:
            self.notify(
                "Mode switching is disabled until the active operation reaches a safe boundary."
            )
            return
        target = "purple" if self.mode == "copilot" else "copilot"
        notice_holder = [self.notice]
        changed = await asyncio.to_thread(
            lambda: set_mode(
                self.mode_holder,
                notice_holder,
                self.cfg,
                target,
                busy=False,
            )
        )
        self.notice = notice_holder[0]
        if not changed:
            self._changed("notice")
            return
        if target == "purple":
            try:
                self.engagements = await asyncio.to_thread(self.engagement_store.list_tabs)
            except Exception as exc:
                self.engagements = []
                self.notify(f"Engagement history unavailable: {type(exc).__name__}")
            self.engagement_index = 0 if self.engagements else None
            self.purple_view = None
            if self.engagements:
                self.load_engagement_view(self.engagements[0])
            # Refresh the Mode B runtime panel with real checks in the
            # background; the sidebar updates as soon as they finish.
            self.refresh_runtime_status(force=True)
        else:
            self.purple_view = None
        self._changed("mode")

    # ---- Copilot dispatch ---------------------------------------------

    async def submit(self, text: str) -> None:
        value = (text or "").strip()
        if not value:
            return
        command = value.lower()
        # A plain sentence while an engagement view is open is a read-only
        # question about that engagement.  It never starts, stops, or
        # changes an engagement, and it is deliberately allowed while the
        # engagement is busy: the worker thread keeps running.
        if (
            self.mode == "purple"
            and self.purple_view is not None
            and not command.startswith("/")
            and command not in ("quit", "exit", "q")
        ):
            await self._answer_purple_question(value)
            return
        if self.busy:
            # A small allowlist of purple commands stays available while an
            # engagement runs; everything else waits for a safe boundary.
            spec = lookup(value)
            if self.mode == "purple" and (
                command in ("quit", "exit", "q")
                or (spec is not None and spec.name in PURPLE_BUSY_SAFE)
            ):
                await self._dispatch_purple(value)
                return
            self.notify("The current operation is still running.")
            return
        self.busy = True
        self.stop_requested = False
        self.notice = ""
        self._changed("busy")
        try:
            if self.mode == "copilot":
                await self._dispatch_copilot(value)
            else:
                await self._dispatch_purple(value)
        except asyncio.CancelledError:
            self.notify("Operation cancelled at a safe boundary.")
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            log.exception("full-screen operation failed")
            self._add_transient("system", f"Operation failed ({type(exc).__name__}): {safe(exc, 260)}")
        finally:
            self.busy = False
            self.stop_requested = False
            self._changed("busy")

    async def _dispatch_copilot(self, text: str) -> None:
        command = text.lower()
        name = command_name(text)
        tab = self.active_session()
        spec = lookup(text)
        if spec is not None and not spec.available_in("copilot"):
            self._add_transient(
                "system",
                f"{spec.name} is a Purple Team command. Switch with /mode when no "
                "engagement is running.",
            )
            return
        if command in ("/quit", "/exit", "exit", "quit", "q"):
            self._changed("quit")
            return
        if name == "/help":
            self._add_transient("system", help_text("copilot"))
            return
        if name == "/commands":
            self._add_transient("system", commands_text("copilot"))
            return
        if name == "/mode":
            self.busy = False
            await self.switch_mode()
            return
        if name == "/models":
            await self._command_models(text)
            return
        if name == "/mcp":
            self._command_mcp(text)
            return
        if name == "/skills":
            self._command_skills(text)
            return
        if name == "/sessions":
            await self._command_sessions(text)
            return
        if name == "/theme" or name.startswith("/theme"):
            await self._handle_theme(text)
            return
        if name == "/workspace":
            self._add_transient("system", str(self.cfg.workspace))
            return
        if name == "/rename":
            await self._command_rename(text, "session")
            return
        if name == "/cve":
            cve_id = text.partition(" ")[2].strip()
            if not cve_id:
                self._add_transient("system", "Use /cve <CVE-ID>.")
                return
            await self._command_cve(cve_id)
            return
        if name == "/search":
            query = text.partition(" ")[2].strip()
            if not query:
                self._add_transient("system", "Use /search <query>.")
                return
            await self._command_search(query, tab)
            return
        if name == "/read":
            path = text.partition(" ")[2].strip()
            if not path:
                self._add_transient("system", "Use /read <path>.")
                return
            await self._command_read(path, tab)
            return
        if name == "/ls":
            path = text.partition(" ")[2].strip()
            await self._command_list(path, tab)
            return
        if name == "/write":
            value = text[7:] if len(text) > 6 else ""
            if not value:
                self._add_transient("system", "Use /write <path> then the content.")
                return
            await self._command_write(value, tab)
            return
        if name:
            self._add_transient(
                "system",
                f"{name} is not a command here. Use /commands to see what is available.",
            )
            return

        tab.session.add("user", text)
        self._changed("messages")
        try:
            await asyncio.to_thread(self._compact_session, tab.session)
        except Exception as exc:
            self._add_transient("system", f"Compaction skipped ({type(exc).__name__}).")
        await self._run_agent(tab, text)

    def _compact_session(self, session: GeneralSession) -> None:
        asyncio.run(session.maybe_compact())

    async def _run_agent(self, tab: SessionTab, user_text: str) -> None:
        from ..copilot.agent import build_toolbox, run_agent
        from ..copilot.tools import FileTools
        from ..llm import LlmUnavailable, chat

        file_tools = FileTools(self.cfg, approver=self.request_file_approval)
        extra = self.agent_mcp_extra()
        toolbox = await asyncio.to_thread(build_toolbox, self.cfg, file_tools, extra or None)
        self._set_activity(tab, "thinking")

        def on_tool(name: str, args: dict) -> None:
            _guard()
            self._tool_started(tab, name, args)

        def on_round() -> None:
            _guard()
            self._set_activity(tab, "thinking")

        def _guard() -> None:
            if self.stop_requested:
                raise OperationCancelled()

        try:
            reply = await asyncio.to_thread(
                run_agent,
                self.cfg,
                tab.session.as_llm_messages(self.system_prompt),
                toolbox,
                self.cfg.general_chat_model,
                on_tool,
                on_round,
            )
        except OperationCancelled:
            self._add_transient("system", "Operation cancelled at a safe boundary.")
            self._set_activity(tab, "ready")
            return
        except Exception as exc:
            self._add_transient("system", f"Tools unavailable ({type(exc).__name__}); using plain chat.")
            try:
                reply = await asyncio.to_thread(
                    chat,
                    self.cfg,
                    tab.session.as_llm_messages(self.system_prompt),
                    self.cfg.general_chat_model,
                )
            except LlmUnavailable as exc:
                hint = {
                    "ollama": "Start Ollama and pull the configured model, or run `kryonsec setup`.",
                    "bedrock": "Check Bedrock model access and region, then run `kryonsec setup`.",
                    "openai_compatible": "Check the configured endpoint, model name, and API key.",
                }.get(self.cfg.provider, "Check the provider key or network, then run `kryonsec setup`.")
                self._add_transient("system", f"LLM unavailable: {safe(exc, 300)}\n{hint}")
                tab.session.messages.pop()
                return
            except Exception as exc:
                self._add_transient("system", f"Chat failed ({type(exc).__name__}): {safe(exc, 260)}")
                tab.session.messages.pop()
                return

        tab.session.add("assistant", reply or "")
        with self._lock:
            for row in self.tools_by_tab.get(id(tab), []):
                if row.status == "running":
                    row.status = "completed"
                    row.detail = "result returned to agent"
                    row.duration = max(0.0, time.monotonic() - row.started_at)
        self._set_activity(tab, "ready")
        try:
            await asyncio.to_thread(self.session_store.save, tab)
        except Exception as exc:
            self._add_transient("system", f"Session could not be saved: {safe(exc, 220)}")
        self._changed("messages")

    def _tool_started(self, tab: SessionTab, name: str, args: dict) -> None:
        detail = ", ".join(f"{key}={safe(value, 50)}" for key, value in args.items())
        row = CopilotActivity(
            name=safe(name, 80),
            detail=detail,
            status="running",
            started_at=time.monotonic(),
        )
        with self._lock:
            self.tools_by_tab.setdefault(id(tab), []).append(row)
        self._changed("tools")

    def _set_activity(self, tab: SessionTab, status: str) -> None:
        # The busy/thinking state is derived from controller.busy; the tab
        # identity is kept so a future per-tab spinner can be added without
        # changing this contract.
        self._changed("activity")

    def _add_transient(self, role: str, content: str) -> None:
        value = safe(content, 12000)
        if not value:
            return
        if self.mode == "copilot":
            tab = self.active_session()
            with self._lock:
                self.transient.setdefault(id(tab), []).append(DisplayMessage(role, value))
            self._changed("messages")
        else:
            if self.purple_view is not None:
                self.purple_view.on_notice(value)
            else:
                self.notify(value)

    # ---- commands ------------------------------------------------------

    async def _command_rename(self, text: str, noun: str) -> None:
        new_name = text.partition(" ")[2].strip()
        index = (
            self.session_index
            if self.mode == "copilot"
            else self.engagement_index
        )
        if index is None:
            self._add_transient(
                "system", f"Open a {noun} tab first — there is nothing to rename."
            )
            return
        if not new_name:
            self._add_transient(
                "system",
                f"Use /rename <new name> to title the current {noun} tab "
                "(Ctrl+P → Rename opens a dialog).",
            )
            return
        self.rename_session(index, new_name)

    async def _command_sessions(self, text: str) -> None:
        """List workspace tabs; an optional number switches to one."""
        parts = text.split()
        target = parts[1] if len(parts) > 1 else ""
        if self.mode == "purple":
            try:
                self.engagements = await asyncio.to_thread(
                    self.engagement_store.list_tabs
                )
            except Exception as exc:
                self.notify(f"Engagement history unavailable: {type(exc).__name__}")
                return
            # Busy-safe feedback: the status line confirms the refresh even
            # while the engagement worker keeps running.
            self.notify(f"Loaded {len(self.engagements)} stored engagement(s).")
            self._changed("tabs")
            entries = self.engagements
            current = self.engagement_index
            noun = "engagement"
        else:
            entries = self.sessions
            current = self.session_index
            noun = "session"
        if target.isdigit():
            index = int(target) - 1
            if 0 <= index < len(entries):
                self.activate_tab(index)
                return
            self._add_transient("system", f"No {noun} {target}.")
            return
        lines = [f"{noun.upper()}S · {len(entries)}"]
        for index, entry in enumerate(entries):
            marker = "▸" if index == current else " "
            title = getattr(entry, "title", "") or "(untitled)"
            lines.append(f" {marker} {index + 1:>2}  {safe(title, 60)}")
        if target:
            lines.append(f"Use /sessions <number> to open one.")
        self._add_transient("system", "\n".join(lines))

    async def _command_models(self, text: str) -> None:
        """Show or switch models using only what the provider really lists."""
        parts = text.split()
        sub = parts[1].lower() if len(parts) > 1 else "current"
        if sub in ("list", "ls"):
            provider = parts[2].lower() if len(parts) > 2 else self.cfg.provider
            await self._models_list(provider)
            return
        if sub == "current":
            view = current_model_view(self.cfg)
            self._add_transient(
                "system",
                "MODEL\n"
                f"  active          {model_provider_label(view['provider'])} · {view['model']}\n"
                f"  local fallback  {view['local_fallback']}\n"
                f"  search          {view['search_model']}\n"
                f"  compaction      {view['compaction_model']}\n"
                "Switch with /models use <provider> <model>; /models list shows real availability.",
            )
            return
        if sub == "use":
            if len(parts) < 4:
                self._add_transient(
                    "system",
                    "Use /models use <provider> <model>. "
                    "Providers: openai · ollama · bedrock · openai_compatible.",
                )
                return
            if self.mode == "purple" and self.engagement_running:
                self.notify(
                    "A model switch is refused while an engagement is running; "
                    "finish the engagement, then switch."
                )
                return
            provider = parts[2].lower()
            model = " ".join(parts[3:]).strip()
            ok, message = await asyncio.to_thread(
                switch_model, self.cfg, provider, model
            )
            if not ok:
                self.notify(message)
                return
            self.notify(message)
            self._changed("models")
            return
        if sub == "save":
            try:
                await asyncio.to_thread(self.cfg.save)
            except Exception as exc:
                self.notify(f"Config could not be saved ({type(exc).__name__}).")
                return
            self.notify("Model configuration saved.")
            return
        self._add_transient(
            "system",
            "Use /models · /models current · /models list [provider] · "
            "/models use <provider> <model> · /models save.",
        )

    async def _models_list(self, provider: str) -> None:
        models, reason = await asyncio.to_thread(discover_models, self.cfg, provider)
        label = model_provider_label(provider)
        if models is None:
            self._add_transient("system", f"Models · {label}\n  {reason}")
            return
        if not models:
            self._add_transient(
                "system",
                f"Models · {label}\n  No models are available from this provider.",
            )
            return
        lines = [f"MODELS · {label} · {len(models)}"]
        for model in models[:40]:
            lines.append(f"  {model}")
        if len(models) > 40:
            lines.append(f"  … and {len(models) - 40} more")
        lines.append(f"Use /models use {provider} <model>.")
        self._add_transient("system", "\n".join(lines))

    def _mcp_rows(self) -> list[dict[str, Any]]:
        """Merge configured servers with the live, presentation-only status."""
        statuses = {
            str(row.get("name") or ""): row
            for row in self.mcp_statuses()
            if str(row.get("name") or "")
        }
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for server in self.cfg.mcp_servers:
            name = str(server.get("name") or "server")
            seen.add(name)
            status_row = statuses.get(name, {})
            if not server.get("enabled", True):
                status = "disabled"
                detail = "disabled in config.toml; no process was started"
                tools = 0
            else:
                status = str(status_row.get("status") or "not started")
                detail = str(status_row.get("detail") or "")
                tools = int(status_row.get("tools") or 0)
            policy = (
                self.mcp_registry.policy_for(name)
                if self.mcp_registry is not None
                else None
            )
            rows.append(
                {
                    "name": name,
                    "status": status,
                    "detail": redact(safe(detail, 160))[0],
                    "tools": tools,
                    "trust": getattr(policy, "trust", "policy unavailable"),
                    "allow_all": bool(getattr(policy, "allow_all_tools", False)),
                    "allow_tools": sorted(getattr(policy, "allow_tools", ())),
                }
            )
        # A live connection the config no longer names is still shown: the
        # process exists, and hiding it would be a lie.
        for name, row in statuses.items():
            if name in seen:
                continue
            rows.append(
                {
                    "name": name,
                    "status": str(row.get("status") or "unknown"),
                    "detail": redact(safe(row.get("detail") or "", 160))[0],
                    "tools": int(row.get("tools") or 0),
                    "trust": "policy unavailable",
                    "allow_all": False,
                    "allow_tools": [],
                }
            )
        return rows

    @staticmethod
    def _mcp_status_label(status: str, detail: str = "") -> str:
        """Human label for the toolbox's real status vocabulary.

        ``disconnected`` is the toolbox's catch-all for "was not connected".
        A failure reason is shown as FAILED; a connection that is simply not
        up (no failure text) stays DISCONNECTED.  Nothing here invents a
        state the toolbox did not report.
        """
        raw = str(status or "").strip().lower()
        if raw == "disconnected":
            failure = (
                "timed out", "timeout", "exited", "failed", "error",
                "not found", "refused", "denied", "unavailable",
            )
            return "FAILED" if any(word in detail.lower() for word in failure) else "DISCONNECTED"
        return {
            "starting": "CONNECTING",
            "connected": "CONNECTED",
            "blocked": "BLOCKED",
            "disabled": "DISABLED",
            "not started": "NOT STARTED",
        }.get(raw, raw.upper() or "UNKNOWN")

    def _command_mcp(self, text: str) -> None:
        """Read-only MCP status. Never executes a tool or starts a server."""
        parts = text.split()
        sub = parts[1].lower() if len(parts) > 1 else "list"
        if sub in ("list", "status"):
            rows = self._mcp_rows()
            if not rows:
                self._add_transient(
                    "system",
                    "No MCP servers configured. Mode A MCP is optional; "
                    "Mode B never uses MCP.",
                )
                return
            lines = ["MCP · READ-ONLY STATUS"]
            for row in rows:
                label = self._mcp_status_label(row["status"], row["detail"])
                allowed = (
                    "all tools"
                    if row["allow_all"]
                    else (", ".join(row["allow_tools"]) or "none")
                )
                lines.append("")
                lines.append(f"  {row['name']}  {label}  tools={row['tools']}")
                lines.append(f"    trust={row['trust']}  authorized={allowed}")
                if row["detail"]:
                    lines.append(f"    {row['detail']}")
                if label in {"FAILED", "DISCONNECTED", "BLOCKED", "NOT STARTED"}:
                    lines.append(
                        f"    next: check config.toml and the MCP policy; "
                        f"/mcp tools {row['name']}"
                    )
            self._add_transient("system", "\n".join(lines))
            return
        if sub == "tools":
            server = parts[2] if len(parts) > 2 else ""
            if not server:
                self._add_transient("system", "Use /mcp tools <server>.")
                return
            self._mcp_tools(server)
            return
        self._add_transient("system", "Use /mcp · /mcp list · /mcp status · /mcp tools <server>.")

    def _mcp_tools(self, server: str) -> None:
        row = next((r for r in self._mcp_rows() if r["name"] == server), None)
        if row is None:
            self._add_transient("system", f"No MCP server named {server!r}.")
            return
        if row["status"] != "connected":
            self._add_transient(
                "system",
                f"{server} is {self._mcp_status_label(row['status'], row['detail'])}; "
                "no tools are advertised. No process was started by this command.",
            )
            return
        names: list[str] = []
        box = self.mcp_toolbox
        for connection in getattr(box, "connections", []) or []:
            if getattr(connection, "name", "") != server:
                continue
            names = sorted(
                key.removeprefix("mcp_") for key in getattr(connection, "entry", {})
            )
            break
        if not names:
            self._add_transient(
                "system",
                f"{server} is connected but advertises no tools right now.",
            )
            return
        policy = (
            self.mcp_registry.policy_for(server)
            if self.mcp_registry is not None
            else None
        )
        lines = [f"MCP TOOLS · {server} · {len(names)}"]
        for name in names[:60]:
            allowed = bool(policy and policy.allows(name))
            lines.append(f"  {'✓' if allowed else '·'} {name}  {'authorized' if allowed else 'not authorized'}")
        if len(names) > 60:
            lines.append(f"  … and {len(names) - 60} more")
        lines.append("Names only — tool schemas and server text are untrusted and not executed here.")
        self._add_transient("system", "\n".join(lines))

    def _command_skills(self, text: str) -> None:
        """Read the real packaged skill registry; never invent an entry."""
        from ..purple.skills import SkillError, load_packaged_skills

        parts = text.split()
        sub = parts[1].lower() if len(parts) > 1 else "list"
        try:
            registry = load_packaged_skills()
        except SkillError as exc:
            self._add_transient("system", f"Skill registry unavailable: {safe(exc, 200)}")
            return
        if sub == "info":
            name = parts[2] if len(parts) > 2 else ""
            if not name:
                self._add_transient("system", "Use /skills info <name>.")
                return
            skill = registry.get(name)
            if skill is None:
                self._add_transient(
                    "system",
                    f"No packaged skill named {name!r}. Use /skills to list them.",
                )
                return
            self._add_transient(
                "system",
                f"SKILL · {skill.name}\n"
                f"  version     {skill.version}\n"
                f"  category    {skill.category}\n"
                f"  stages      {', '.join(sorted(skill.stages))}\n"
                f"  source      {skill.source} (packaged, reviewed)\n"
                f"  mode        Mode B specialist knowledge only\n"
                f"  status      loaded · knowledge-only · not executable\n"
                f"  purpose     {skill.description}",
            )
            return
        if sub not in ("list", ""):
            self._add_transient("system", "Use /skills · /skills list · /skills info <name>.")
            return
        skills = registry.to_dict()["skills"]
        if not skills:
            self._add_transient(
                "system",
                "No skills installed. Packaged skills ship with Kryonsec; "
                "this build has none.",
            )
            return
        lines = [f"SKILLS · {len(skills)} packaged · knowledge-only · not executable"]
        for skill in skills:
            lines.append("")
            lines.append(f"  {skill['name']} v{skill['version']}  ·  {skill['category']}")
            lines.append(f"    {safe(skill['description'], 180)}")
            lines.append(f"    stages: {', '.join(skill['stages'])}  ·  source: {skill['source']}")
        lines.append("")
        lines.append("Mode B specialists read these as reference material; nothing here executes.")
        self._add_transient("system", "\n".join(lines))

    async def _command_cve(self, cve_id: str) -> None:
        from ..copilot.cve import lookup_cve

        try:
            record = await asyncio.to_thread(lookup_cve, self.cfg, cve_id)
        except Exception as exc:
            self._add_transient("system", safe(exc, 260))
            return
        if not record:
            self._add_transient("system", "CVE not found or the NVD is unreachable.")
            return
        description = safe(record.get("description") or "", 1200)
        self._add_transient(
            "assistant",
            f"# {record.get('id', cve_id)}\n"
            f"Severity: {record.get('severity') or '?'}  ·  "
            f"CVSS: {record.get('cvss_score') or '?'}\n\n{description}",
        )

    async def _command_search(self, query: str, tab: SessionTab) -> None:
        from ..copilot.websearch import search_web

        results = await asyncio.to_thread(search_web, self.cfg, query)
        if results is None:
            self._add_transient("system", "Search failed (offline or blocked).")
            return
        if not results:
            self._add_transient("system", "No results.")
            return
        lines = [f"# Web results · {len(results)} found"]
        for result in results:
            lines.append(
                f"- {result.get('title', '')}: {result.get('snippet', '')} "
                f"({result.get('url', '')})"
            )
        content = "\n".join(lines)
        self._add_transient("assistant", content)
        tab.session.add("user", f"[web search results for: {query}]\n" + "\n".join(lines[1:]))
        await asyncio.to_thread(self.session_store.save, tab)

    async def _command_read(self, path: str, tab: SessionTab) -> None:
        from ..copilot.tools import FileTools

        try:
            content = await asyncio.to_thread(
                FileTools(self.cfg, approver=self.request_file_approval).read_file,
                path,
            )
        except Exception as exc:
            self._add_transient("system", safe(exc, 260))
            return
        tab.session.add("user", f"[file contents of {path}]\n{content}")
        self._add_transient("system", f"Read {path} ({len(content)} chars) — added to context.")
        await asyncio.to_thread(self.session_store.save, tab)

    async def _command_list(self, path: str, tab: SessionTab) -> None:
        from ..copilot.tools import FileTools

        try:
            entries = await asyncio.to_thread(
                FileTools(self.cfg, approver=self.request_file_approval).list_directory,
                path,
            )
        except Exception as exc:
            self._add_transient("system", safe(exc, 260))
            return
        self._add_transient("system", "\n".join(safe(entry, 300) for entry in entries))

    async def _command_write(self, value: str, tab: SessionTab) -> None:
        from ..copilot.tools import FileTools

        path, separator, content = value.partition("\n")
        if not separator:
            self._add_transient("system", "Use /write <path> followed by a newline and the file content.")
            return
        try:
            await asyncio.to_thread(
                FileTools(self.cfg, approver=self.request_file_approval).write_file,
                path.strip(),
                content,
            )
        except Exception as exc:
            self._add_transient("system", safe(exc, 260))
            return
        self._add_transient("system", f"Wrote {safe(path.strip(), 240)}")

    async def _handle_theme(self, text: str) -> None:
        from .prefs import UiPreferences, save_ui_preferences

        name = text.partition(" ")[2].strip().lower()
        if not name:
            self._add_transient("system", "Themes: kryonsec · tokyonight · dracula. Use /theme <name>.")
            return
        if name not in {"kryonsec", "tokyonight", "dracula"}:
            self._add_transient("system", f"Unknown theme: {name}")
            return
        await asyncio.to_thread(save_ui_preferences, self.cfg.home, UiPreferences(theme=name))
        self._add_transient(
            "system",
            f"Theme preference {name} saved for other Kryonsec surfaces. The workspace "
            "colors always follow the active mode: Mode A is monochrome; Mode B is monochrome "
            "with the purple Kryonsec wordmark.",
        )

    # ---- Purple dispatch ----------------------------------------------

    async def _answer_purple_question(self, question: str) -> None:
        """Answer one read-only question about the open engagement.

        This cannot start an engagement, run a tool, or change the workflow:
        it reads only the presentation snapshot the state object already
        reduced from real audit events, and asks the chat model to explain
        it with no tools attached.  Serialized: one answer at a time, and
        a second question is refused with an honest notice.
        """
        view = self.purple_view
        if view is None:
            return
        if self._question_in_flight:
            view.on_notice(
                "One question at a time — the previous answer is still being prepared."
            )
            self._changed("activity")
            return
        self._question_in_flight = True
        try:
            view.add_question(question)
            snapshot = view.snapshot()
            self._changed("activity")
            try:
                answer = await asyncio.to_thread(
                    _questions.answer_question, self.cfg, snapshot, question
                )
            except Exception as exc:
                # Presentation must never break the engagement; the
                # deterministic summary is still a real, bounded answer.
                answer = (
                    f"(local summary — the answer helper failed: {type(exc).__name__})\n"
                    + _questions.engagement_plain_summary(snapshot)
                )
            view.add_answer(question, answer)
        finally:
            self._question_in_flight = False
        self._changed("activity")

    async def _dispatch_purple(self, text: str) -> None:
        command = text.lower()
        name = command_name(text)
        spec = lookup(text)
        if spec is not None and not spec.available_in("purple"):
            self._add_transient(
                "system",
                f"{spec.name} is a Copilot command. Switch with /mode when no "
                "engagement is running.",
            )
            return
        if command in ("/quit", "/exit", "exit", "quit", "q"):
            self._changed("quit")
            return
        if name == "/help":
            self._add_transient("system", help_text("purple"))
            return
        if name == "/commands":
            self._add_transient("system", commands_text("purple"))
            return
        if name == "/models":
            await self._command_models(text)
            return
        if name == "/mcp":
            self._command_mcp(text)
            return
        if name == "/skills":
            self._command_skills(text)
            return
        if name == "/mode":
            if self.engagement_running:
                # Never let the busy-clearing hack below run while a worker
                # thread is live: switching modes mid-engagement would
                # orphan the run's presentation state.
                self.notify(
                    "An engagement is still running; wait for it to finish before switching modes."
                )
                return
            self.busy = False
            await self.switch_mode()
            return
        if name == "/theme":
            await self._handle_theme(text)
            return
        if name == "/workspace":
            self._add_transient("system", str(self.cfg.workspace))
            return
        if name == "/engage":
            target = text.partition(" ")[2].strip()
            if self.engagement_running:
                self.notify(
                    "An engagement is already running; wait for it to finish, then use /engage again."
                )
                return
            if not target:
                self._add_transient(
                    "system", "Use /engage <authorized target> to start a new engagement."
                )
                return
            await self.start_engagement(target)
            return
        if name == "/report":
            await self._show_report(text)
            return
        if name == "/rename":
            await self._command_rename(text, "engagement")
            return
        if name == "/sessions":
            await self._command_sessions(text)
            return
        if name:
            self._add_transient(
                "system",
                f"{name} is not a command here. Use /commands to see what is available.",
            )
            return
        # Plain text with no engagement view open starts an engagement
        # (the placeholder screen's documented behaviour).  With a view
        # open, plain text never reaches here — submit() routes it to the
        # read-only question path instead.
        await self.start_engagement(text.strip())

    async def _show_report(self, text: str) -> None:
        """Tell the operator where the report is, optionally open it."""
        view = self.purple_view
        path = (view.report_path if view is not None else None) or ""
        parts = text.split()
        want_open = len(parts) > 1 and parts[1].lower() == "open"
        if not path:
            self._add_transient("system", "No report has been saved for this engagement yet.")
            return
        if want_open:
            opened = await asyncio.to_thread(self._open_report_in_browser, path)
            if not opened:
                self._add_transient(
                    "system", f"Could not open the report; it is saved at: {path}"
                )
                return
            self._add_transient("system", f"Opened report: {path}")
            return
        self._add_transient("system", f"Report saved at: {path}")

    @staticmethod
    def _open_report_in_browser(target: str) -> bool:
        """Open one saved report file; a failure is reported, never faked."""
        try:
            import webbrowser
            from pathlib import Path

            path = Path(target).expanduser().resolve()
            if not path.is_file():
                return False
            return bool(webbrowser.open(path.as_uri()))
        except Exception:
            return False

    async def start_engagement(self, target: str) -> None:
        # The runner performs the authoritative target, license, sandbox, and
        # scope checks. The controller creates only a presentation snapshot.
        engagement_id = uuid.uuid4().hex[:8]
        view = _LivePurpleState(
            target,
            engagement_id,
            self._changed,
            sandbox_status="checking",
        )
        with self._lock:
            self.purple_view = view
        self.engagements = [
            tab for tab in self.engagements if tab.engagement_id != engagement_id
        ]
        self.engagements.insert(
            0,
            EngagementTab(
                engagement_id=engagement_id,
                target=safe(target, 180),
                status="running",
                path=None,
            ),
        )
        self.engagement_index = 0
        self._changed("purple")
        self.refresh_runtime_status(force=True)

        from .. import cli

        def worker() -> int:
            try:
                return cli._run_purple(
                    self.cfg,
                    target,
                    engagement_id=engagement_id,
                    memory_browser=False,
                    ui=view,
                    output=False,
                    human_reviewer=self.request_human_review,
                    post_exploit_approver=self.request_post_exploit,
                    stop_requested=lambda: self.stop_requested,
                )
            except KeyboardInterrupt:
                view.finish("interrupted", halt_reason="keyboard_interrupt")
                raise
            except BaseException as exc:
                view.finish("failed", halt_reason=type(exc).__name__)
                view.on_notice(f"Engagement failed: {safe(exc, 240)}")
                log.exception("full-screen Purple engagement failed")
                return 1

        self.engagement_running = True
        try:
            code = await asyncio.to_thread(worker)
            try:
                refreshed = await asyncio.to_thread(self.engagement_store.list_tabs)
            except Exception:
                refreshed = []
            for record in refreshed:
                if record.engagement_id == engagement_id:
                    # An operator-given display title survives the run: the
                    # refreshed record is re-read from disk, so re-apply it
                    # and re-store it now that the directory exists.
                    previous_title = self.engagements[0].custom_title
                    if previous_title:
                        record.custom_title = previous_title
                        try:
                            self.engagement_store.rename(engagement_id, previous_title)
                        except Exception:
                            pass
                    self.engagements[0] = record
                    break
            if view.outcome is None and code != 0:
                view.finish("failed", halt_reason=f"exit_{code}")
            if self.engagements:
                self.engagements[0].status = view.outcome or "running"
                self.engagements[0].last_state = view.current_state
            self._changed("purple")
        finally:
            self.engagement_running = False

    def load_engagement_view(self, tab: EngagementTab) -> None:
        view = _LivePurpleState(
            tab.target,
            tab.engagement_id,
            self._changed,
            sandbox_status="recorded",
        )
        view.started_at = time.monotonic()
        events = self.engagement_store.read_events(tab)
        for event in events:
            event_name = event.get("event")
            if event_name == "state_enter":
                view.on_state(str(event.get("state") or ""))
            view.on_audit(event)
            if event_name == "engagement_finished":
                recorded_failed = event.get("failed_states")
                view.finish(
                    str(event.get("outcome") or "recorded"),
                    halt_reason=str(event.get("reason") or "") or None,
                    failed_states=(
                        recorded_failed if isinstance(recorded_failed, list) else None
                    ),
                )
        if (
            view.current_state
            and view.current_state not in view.completed_states
            and view.current_state not in view.failed_states
            and view.outcome
        ):
            view.on_state_complete(view.current_state)
        self._apply_recorded_timing(view, events)
        with self._lock:
            self.purple_view = view

    @staticmethod
    def _apply_recorded_timing(
        view: _LivePurpleState, events: list[dict[str, Any]]
    ) -> None:
        """Make a replay report the run's real clock, not the app's.

        ``started_at``/``finished_at`` are monotonic readings of *this*
        process, so a reopened engagement used to report how long it had
        been open rather than how long it ran, and every state duration was
        zero. The audit chain already carries a wall-clock ``ts`` on each
        entry; derive the duration and the per-state spans from those. A
        chain old enough to have no ``ts`` keeps the old fallback.
        """
        stamps: list[float] = []
        state_starts: list[tuple[str, float]] = []
        finished_at: float | None = None
        for event in events:
            at = _audit_seconds(event.get("ts"))
            if at is None:
                continue
            stamps.append(at)
            name = event.get("event")
            if name == "state_enter":
                state = str(event.get("state") or "")
                if state:
                    state_starts.append((state, at))
            elif name == "engagement_finished":
                finished_at = at
        if not stamps:
            return
        end = finished_at if finished_at is not None else stamps[-1]
        view.recorded_duration = max(0.0, end - stamps[0])
        for index, (state, started) in enumerate(state_starts):
            next_at = (
                state_starts[index + 1][1]
                if index + 1 < len(state_starts)
                else end
            )
            view.state_duration[state] = max(0.0, next_at - started)

    # ---- approvals -----------------------------------------------------

    def request_file_approval(self, request: Any) -> bool:
        """Synchronous callback used by FileTools, with a fail-closed wait."""
        gate = ApprovalGate(gate="file")
        gate.hypotheses = [
            {
                "label": "file access",
                "properties": {
                    "title": f"{getattr(request, 'action', 'access')} file",
                    "target_asset": getattr(request, "path", ""),
                    "requested_path": getattr(request, "requested_path", "") or "",
                    "confidence": "operator decision",
                    "rationale": getattr(request, "reason", ""),
                    "tools": [],
                },
            }
        ]
        self._install_approval(gate)
        gate.done.wait()
        return bool(gate.result)

    def request_human_review(self, hypotheses: list[dict]) -> set[str]:
        gate = ApprovalGate(gate="human_review", hypotheses=list(hypotheses))
        self._install_approval(gate)
        gate.done.wait()
        return set(gate.approved)

    def request_post_exploit(self, shell_evidence: str = "") -> bool:
        gate = ApprovalGate(gate="post_exploit", shell_evidence=safe(shell_evidence, 300))
        self._install_approval(gate)
        gate.done.wait()
        return bool(gate.result)

    def _install_approval(self, gate: ApprovalGate) -> None:
        with self._lock:
            if self._closed:
                gate.result = False
                gate.done.set()
                return
            self.approval = gate
        self._changed("approval")

    def decide_approval(self, approved: bool) -> None:
        """Apply one explicit operator decision; Enter/Esc always deny."""
        gate = self.approval
        if gate is None:
            return
        if gate.gate in {"file", "post_exploit"}:
            gate.result = bool(approved)
            with self._lock:
                self.approval = None
            gate.done.set()
            self._changed("approval")
            return
        if approved and gate.hypotheses:
            label = str(gate.hypotheses[gate.index].get("label", ""))
            if label:
                gate.approved.add(label)
        gate.index += 1
        if gate.index >= len(gate.hypotheses):
            with self._lock:
                self.approval = None
            gate.done.set()
        self._changed("approval")

    def cancel_approvals(self) -> None:
        gate = self.approval
        if gate is not None:
            gate.result = False
            with self._lock:
                self.approval = None
            gate.done.set()

    def close(self) -> None:
        with self._lock:
            self._closed = True
        self.cancel_approvals()

    # ---- sidebar/status helpers ---------------------------------------

    def runtime_status_summary(self) -> dict[str, str]:
        """The last real runtime check results (never fabricated)."""
        with self._lock:
            return dict(self.runtime_status)

    def refresh_runtime_status(self, *, force: bool = False) -> None:
        """Kick a real runtime availability check in a background thread.

        Checks are rate-limited to one per 20 s unless forced; results are
        stored and reported through the normal change callback. Callers never
        block, and the Textual thread never runs docker itself.
        """
        if self._closed:
            return
        with self._lock:
            thread = self._runtime_thread
            if thread is not None and thread.is_alive():
                return  # a check is already running
            due = time.monotonic() - self._runtime_checked_at > 20.0
            if not (force or due):
                return
        worker = threading.Thread(
            target=self._collect_runtime_status,
            name="kryonsec-runtime-check",
            daemon=True,
        )
        self._runtime_thread = worker
        worker.start()

    def _collect_runtime_status(self) -> dict[str, str]:
        """Blocking real checks; runs on a worker thread only."""
        if self._closed:
            return {}
        docker_status, docker_detail = "unknown", ""
        try:
            from ..purple.runtime_checks import docker_server_ok

            ok, reason = docker_server_ok()
            docker_status = "connected" if ok else "unavailable"
            docker_detail = safe(reason, 120)
        except Exception as exc:
            docker_detail = safe(f"check failed: {exc}", 120)
        sandbox_status, sandbox_detail = "unknown", ""
        try:
            from ..purple.runner import sandbox_available

            ok, reason = sandbox_available(self.cfg.sandbox_image)
            sandbox_status = "ready" if ok else "unavailable"
            sandbox_detail = safe(reason, 120)
        except Exception as exc:
            sandbox_detail = safe(f"check failed: {exc}", 120)
        with self._lock:
            self.runtime_status.update(
                docker=docker_status,
                docker_detail=docker_detail,
                sandbox=sandbox_status,
                sandbox_detail=sandbox_detail,
            )
            self._runtime_checked_at = time.monotonic()
        self._changed("runtime")
        return dict(self.runtime_status)

    def agent_mcp_extra(self) -> "dict | None":
        """The MCP entries exposed to the agent loop: ONLY the five
        policy-controlled registry discovery operations. Every real tool
        execution flows through ``McpRegistry.call_mcp_tool`` — trust
        policy, allowance, approval gate, schema validation, and audit
        are enforced at that single choke point. A legacy toolbox's raw
        catalog snapshot must NEVER feed the agent toolbox: it would
        expose server tools with no authorization and no audit."""
        reg = getattr(self, "mcp_registry", None)
        return reg.llm_tools() if reg is not None else None

    def mcp_statuses(self) -> list[dict[str, Any]]:
        box = self.mcp_toolbox
        if box is not None and hasattr(box, "statuses"):
            try:
                return list(box.statuses())
            except Exception:
                return []
        return [
            {
                "name": safe(server.get("name") or "server", 40),
                "status": "not started",
                "detail": "connection not started",
                "tools": 0,
            }
            for server in self.cfg.mcp_servers
            if server.get("enabled", True)
        ]

    def copilot_tools(self, tab: SessionTab | None = None) -> list[CopilotActivity]:
        tab = tab or self.active_session()
        with self._lock:
            return list(self.tools_by_tab.get(id(tab), []))

    def display_messages(self, tab: SessionTab | None = None) -> list[DisplayMessage]:
        tab = tab or self.active_session()
        with self._lock:
            values = list(tab.session.messages)
            values.extend(self.transient.get(id(tab), []))
        return [
            DisplayMessage(
                role=getattr(message, "role", "system"),
                content=safe(getattr(message, "content", ""), 12000),
            )
            for message in values
        ]

    def context_usage(self, tab: SessionTab | None = None) -> tuple[int, int]:
        tab = tab or self.active_session()
        return int(tab.session.token_estimate), int(self.cfg.max_session_tokens)

    def run_status(self) -> str:
        if self.approval is not None:
            return "approval required"
        if self.busy:
            return "working"
        return "ready"

    def provider_label(self) -> str:
        return {
            "openai": "OpenAI",
            "ollama": "Ollama",
            "bedrock": "AWS Bedrock",
            "openai_compatible": "OpenAI-compatible",
        }.get(self.cfg.provider, safe(self.cfg.provider or "not configured", 30))


__all__ = ["CopilotActivity", "WorkspaceController"]
