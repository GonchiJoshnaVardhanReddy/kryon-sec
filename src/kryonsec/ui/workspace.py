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
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..config import KryonsecConfig
from ..copilot.session import GeneralSession
from ..secrets import redact
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
        """Give one Copilot session a display title.

        Renaming changes presentation only: the stored message history,
        record id, and timestamps are untouched. ``EngagementTab`` titles in
        Mode B derive from immutable engagement records, so rename is scoped
        to Mode A. Returns True when the rename was applied.
        """
        if self.mode != "copilot":
            self.notify(
                "Engagement tabs keep their immutable identifiers; only Copilot sessions can be renamed."
            )
            return False
        if not (0 <= index < len(self.sessions)):
            return False
        cleaned = " ".join(str(name or "").split())
        if not cleaned:
            self.notify("Session name cannot be empty.")
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

        if self.busy:
            self.notify("Mode switching is disabled until the active operation reaches a safe boundary.")
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
        if self.busy:
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
        tab = self.active_session()
        if command in ("/quit", "/exit", "exit", "quit", "q"):
            self._changed("quit")
            return
        if command == "/help":
            self._add_transient(
                "system",
                "Commands: /cve <id> · /search <query> · /read <path> · /ls <path> · "
                "/write <path>\\ncontent · /workspace · /mode · /theme · /quit\n"
                "Shortcuts: Enter send · Shift+Enter newline · Ctrl+P commands · "
                "Shift+Tab mode · Ctrl+←/→ sessions · Ctrl+N new session.",
            )
            return
        if command == "/mode":
            self.busy = False
            await self.switch_mode()
            return
        if command.startswith("/theme"):
            await self._handle_theme(text)
            return
        if command == "/workspace":
            self._add_transient("system", str(self.cfg.workspace))
            return
        if command.startswith("/cve "):
            await self._command_cve(text[5:].strip())
            return
        if command.startswith("/search "):
            await self._command_search(text[8:].strip(), tab)
            return
        if command.startswith("/read "):
            await self._command_read(text[6:].strip(), tab)
            return
        if command.startswith("/ls "):
            await self._command_list(text[4:].strip(), tab)
            return
        if command.startswith("/write "):
            await self._command_write(text[7:], tab)
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

    async def _dispatch_purple(self, text: str) -> None:
        command = text.lower()
        if command in ("/quit", "/exit", "exit", "quit", "q"):
            self._changed("quit")
            return
        if command == "/help":
            self._add_transient(
                "system",
                "Purple Team: type an authorized target to start. /mode returns to Copilot. /quit exits.",
            )
            return
        if command == "/mode":
            self.busy = False
            await self.switch_mode()
            return
        if command.startswith("/theme"):
            await self._handle_theme(text)
            return
        if command == "/sessions":
            try:
                self.engagements = await asyncio.to_thread(self.engagement_store.list_tabs)
            except Exception as exc:
                self.notify(f"Engagement history unavailable: {type(exc).__name__}")
                return
            self.notify(f"Loaded {len(self.engagements)} stored engagement(s).")
            self._changed("tabs")
            return
        if command.startswith("/"):
            self._add_transient("system", "That command is not available in Purple Team mode.")
            return
        await self.start_engagement(text.strip())

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
                )
            except KeyboardInterrupt:
                view.finish("interrupted", halt_reason="keyboard_interrupt")
                raise
            except BaseException as exc:
                view.finish("failed", halt_reason=type(exc).__name__)
                view.on_notice(f"Engagement failed: {safe(exc, 240)}")
                log.exception("full-screen Purple engagement failed")
                return 1

        code = await asyncio.to_thread(worker)
        try:
            refreshed = await asyncio.to_thread(self.engagement_store.list_tabs)
        except Exception:
            refreshed = []
        for record in refreshed:
            if record.engagement_id == engagement_id:
                self.engagements[0] = record
                break
        if view.outcome is None and code != 0:
            view.finish("failed", halt_reason=f"exit_{code}")
        if self.engagements:
            self.engagements[0].status = view.outcome or "running"
            self.engagements[0].last_state = view.current_state
        self._changed("purple")

    def load_engagement_view(self, tab: EngagementTab) -> None:
        view = _LivePurpleState(
            tab.target,
            tab.engagement_id,
            self._changed,
            sandbox_status="recorded",
        )
        view.started_at = time.monotonic()
        for event in self.engagement_store.read_events(tab):
            event_name = event.get("event")
            if event_name == "state_enter":
                view.on_state(str(event.get("state") or ""))
            view.on_audit(event)
            if event_name == "engagement_finished":
                view.finish(
                    str(event.get("outcome") or "recorded"),
                    halt_reason=str(event.get("reason") or "") or None,
                )
        if view.current_state and view.current_state not in view.completed_states and view.outcome:
            view.on_state_complete(view.current_state)
        with self._lock:
            self.purple_view = view

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
