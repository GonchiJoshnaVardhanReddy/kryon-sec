"""Contracts for the persistent Textual terminal workspace.

These tests never start an LLM, Docker, MCP server, or Purple Team tool.  They
drive the same controller and widgets the interactive CLI uses, with synthetic
state and a temporary session database.
"""

from __future__ import annotations

import asyncio
import io
import sys
from pathlib import Path

import pytest
from textual.containers import Vertical
from textual.widgets import Static

from kryonsec.command_registry import PURPLE_BUSY_SAFE, commands_for
from kryonsec.config import KryonsecConfig
from kryonsec.copilot.mcp_registry import REGISTRY_TOOL_KEYS
from kryonsec.copilot.session import Message
from kryonsec.storage import reset_engine
from kryonsec.ui.app import (
    ApprovalScreen,
    BrandBanner,
    CommandPalette,
    Composer,
    KryonsecApp,
    MemoryEntry,
    ModelPickerScreen,
    RenameScreen,
    SuggestionMenu,
)
from kryonsec.ui.runtime import interactive_terminal_available
from kryonsec.ui.session_store import EngagementStore, SessionStore
from kryonsec.ui.state import (
    AGENT_LABELS,
    PURPLE_STATES,
    SECURITY_AGENT_STATES,
    ApprovalGate,
    PurpleWorkspaceState,
)
from kryonsec.ui.theme import resolve_theme, workspace_tokens
from kryonsec.ui.workspace import CopilotActivity, WorkspaceController

pytest.importorskip("textual")


@pytest.fixture()
def workspace(tmp_path):
    reset_engine()
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    cfg.database_url = f"sqlite:///{tmp_path / 'sessions.db'}"
    store = SessionStore(cfg)
    store.ensure_schema()
    controller = WorkspaceController(
        cfg,
        session_store=store,
        engagement_store=EngagementStore(cfg),
        system_prompt="test prompt",
    )
    yield controller
    controller.close()
    reset_engine()


def _app(controller: WorkspaceController, *, truecolor: bool = True) -> KryonsecApp:
    """Build the app with the mode-driven workspace palette, like the CLI."""
    return KryonsecApp(
        controller.cfg,
        controller,
        theme=workspace_tokens(controller.mode, truecolor=truecolor),
    )


def _hex_channels(value: str) -> tuple[int, int, int] | None:
    if not value.startswith("#") or len(value) != 7:
        return None
    return int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16)


def _monochrome(value: str) -> bool:
    channels = _hex_channels(value)
    return channels is not None and len(set(channels)) == 1


PURE_PURPLE = "#a855f7"


# ---- MCP authorization wiring (regression: no legacy catalog bypass) ---------

class _LegacySnapshotToolbox:
    """Duck-typed legacy McpToolbox: ``snapshot()`` exposes a server's
    RAW catalog without any policy. Whatever it may return must never
    reach the agent toolbox through the workspace controller."""

    def __init__(self) -> None:
        self.snapshot_called = 0

    def snapshot(self) -> dict:
        self.snapshot_called += 1
        return {"raw_catalog_tool": (None, None)}

    def statuses(self) -> list[dict]:
        return []


class _FakeMcpRegistry:
    """Duck-typed McpRegistry: ``llm_tools()`` exposes ONLY the five
    policy-controlled discovery operations."""

    def __init__(self) -> None:
        self.llm_tools_called = 0

    def llm_tools(self) -> dict:
        self.llm_tools_called += 1
        return {key: (None, None) for key in REGISTRY_TOOL_KEYS}


def test_agent_mcp_extra_registry_only(tmp_path):
    """With a registry wired, the agent loop entry set is exactly the
    registry's five operations — even when a legacy toolbox is also
    present (its snapshot is never consulted)."""
    reset_engine()
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    cfg.database_url = f"sqlite:///{tmp_path / 'sessions.db'}"
    store = SessionStore(cfg)
    store.ensure_schema()
    legacy = _LegacySnapshotToolbox()
    registry = _FakeMcpRegistry()
    controller = WorkspaceController(
        cfg,
        session_store=store,
        engagement_store=EngagementStore(cfg),
        system_prompt="test prompt",
        mcp_toolbox=legacy,
        mcp_registry=registry,
    )
    try:
        extra = controller.agent_mcp_extra()
        assert set(extra) == set(REGISTRY_TOOL_KEYS)
        assert registry.llm_tools_called == 1
        assert legacy.snapshot_called == 0
    finally:
        controller.close()
        reset_engine()


def test_agent_mcp_extra_fail_closed_without_registry(tmp_path):
    """No registry wired -> None. A legacy toolbox present on its own
    must not turn into a catalog exposure, and its snapshot() stays
    untouched."""
    reset_engine()
    cfg = KryonsecConfig(home=tmp_path / "home2", workspace=tmp_path / "workspace2")
    cfg.database_url = f"sqlite:///{tmp_path / 'sessions2.db'}"
    store = SessionStore(cfg)
    store.ensure_schema()
    legacy = _LegacySnapshotToolbox()
    controller = WorkspaceController(
        cfg,
        session_store=store,
        engagement_store=EngagementStore(cfg),
        system_prompt="test prompt",
        mcp_toolbox=legacy,
    )
    try:
        assert controller.agent_mcp_extra() is None
        assert legacy.snapshot_called == 0
    finally:
        controller.close()
        reset_engine()


async def _render_text(widget) -> str:
    return str(widget.render())


def test_session_store_round_trip_drives_real_tabs(workspace):
    tab = workspace.sessions[0]
    tab.session.add("user", "Investigate the authentication flow")
    tab.session.add("assistant", "I will inspect the configured workspace.")
    record_id = workspace.session_store.save(tab)

    loaded = workspace.session_store.list_tabs()
    assert record_id
    assert loaded[0].record_id == record_id
    assert loaded[0].session.messages[0].content == "Investigate the authentication flow"
    assert loaded[0].title == "Investigate the authentication flow"


def test_top_bar_renders_stored_sessions_and_new_action(workspace):
    tab = workspace.sessions[0]
    tab.session.messages = [Message("user", "Review a CVE")]
    workspace.session_store.save(tab)
    workspace.sessions = workspace.session_store.list_tabs()
    workspace.session_index = 0

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            items = list(app.query("#tabstrip > .tab-item, #tabstrip > .tab-action"))
            labels = [await _render_text(item) for item in items]
            assert any("Review a CVE" in label for label in labels)
            assert any("+ New session" in label for label in labels)
            assert any("active" in item.classes for item in items if "tab-item" in item.classes)

    asyncio.run(scenario())


def test_mcp_sidebar_uses_runtime_status_not_configured_defaults(workspace):
    class FakeMcp:
        def statuses(self):
            return [
                {"name": "GitHub", "status": "connected", "detail": "2 tool(s) available"},
                {"name": "Filesystem", "status": "disconnected", "detail": "process exited"},
            ]

    workspace.mcp_toolbox = FakeMcp()

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            text = await _render_text(app.query_one("#sidebar-content"))
            assert "GitHub" in text and "connected" in text
            assert "Filesystem" in text and "disconnected" in text
            # Docker is a runtime field, never conflated with MCP servers.
            assert "Docker" in text
            assert "not used by Copilot" in text

    asyncio.run(scenario())


def test_purple_sidebar_lists_eight_agents_not_ten_states(workspace):
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = PurpleWorkspaceState(
        "authorized.example", "eng-1", sandbox_status="ready"
    )

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            text = await _render_text(app.query_one("#sidebar-content"))
            assert len(SECURITY_AGENT_STATES) == 8
            assert "AGENTS · 8" in text
            for state in SECURITY_AGENT_STATES:
                assert AGENT_LABELS[state] in text
            assert "INIT" not in text
            assert "HUMAN_REVIEW" not in text

    asyncio.run(scenario())


def test_purple_centre_shows_target_timeline_and_tools(workspace):
    workspace.mode_holder[0] = "purple"
    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    view.on_state("RECON_PASSIVE")
    view.on_state_complete("RECON_PASSIVE")
    view.on_state("HYPOTHESIZE")
    view.on_audit(
        {
            "event": "tool_spawn",
            "tool": "subfinder",
            "state": "HYPOTHESIZE",
        }
    )
    view.findings = [("Reflected XSS on /search", "verified", "high")]
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            text = await _render_text(app.query_one("#purple-view"))
            assert "authorized.example" in text
            assert "WORKFLOW · 10 STATES" in text
            assert all(state.replace("_", " ") in text for state in PURPLE_STATES)
            assert "subfinder" in text
            assert "HYPOTHESIZE" in text
            assert "Reflected XSS on /search [high]" in text
            assert "verified [high]" not in text

    asyncio.run(scenario())


def test_conversation_renders_markdown_and_inline_tools(workspace):
    tab = workspace.sessions[0]
    tab.session.add("user", "Summarise this finding")
    tab.session.add("assistant", "## Finding\n\nUse **parametrised** queries.")
    workspace.tools_by_tab[id(tab)] = [
        CopilotActivity(name="read_file", detail="README.md", status="completed", duration=0.2)
    ]

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.pause()
            assert len(app.query("#message-list UserBlock")) == 1
            assert len(app.query("#message-list AssistantBlock")) == 1
            activity = await _render_text(app.query_one("#inline-activity"))
            assert "read_file" in activity
            assert "completed" in activity

    asyncio.run(scenario())


def test_composer_shows_keyboard_hints_on_wide_terminals(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            hints = await _render_text(app.query_one("#composer-hints"))
            assert "Enter send" in hints
            assert "Ctrl+P" in hints

    asyncio.run(scenario())


def test_command_palette_opens_and_closes(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("ctrl+p")
            await pilot.pause()
            assert isinstance(app.screen, CommandPalette)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, CommandPalette)

    asyncio.run(scenario())


# ---- live slash autocomplete ------------------------------------------------


def test_typing_slash_opens_the_registry_menu_and_filters_live(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            menu = app.query_one("#suggestion-menu", SuggestionMenu)
            composer.focus()
            composer.insert("/")
            await pilot.pause()
            assert menu.display is True
            assert composer.suggestion_active is True
            assert {option.id for option in menu.options} == {
                spec.name for spec in commands_for("copilot")
            }
            assert "/engage" not in {option.id for option in menu.options}

            composer.insert("mo")
            await pilot.pause()
            assert [option.id for option in menu.options] == ["/mode", "/models"]
            assert menu.highlighted == 0

    asyncio.run(scenario())


def test_autocomplete_arrow_keys_track_the_visible_list(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            menu = app.query_one("#suggestion-menu", SuggestionMenu)
            composer.focus()
            composer.insert("/mo")
            await pilot.pause()
            assert menu.highlighted == 0
            await pilot.press("down")
            await pilot.pause()
            assert menu.highlighted == 1
            assert menu.current().name == "/models"
            await pilot.press("down")
            await pilot.pause()
            assert menu.highlighted == 0
            await pilot.press("up")
            await pilot.pause()
            assert menu.highlighted == 1

    asyncio.run(scenario())


def test_tab_completes_and_escape_closes_without_sending(workspace):
    sent: list[str] = []

    async def fake_submit(text: str) -> None:
        sent.append(text)

    workspace.submit = fake_submit  # type: ignore[method-assign]

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            menu = app.query_one("#suggestion-menu", SuggestionMenu)
            composer.focus()
            composer.insert("/he")
            await pilot.pause()
            await pilot.press("tab")
            await pilot.pause()
            assert composer.text == "/help"
            assert menu.display is False
            assert sent == []

            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            assert sent == ["/help"]
            assert composer.text == ""

            composer.insert("/")
            await pilot.pause()
            assert menu.display is True
            await pilot.press("escape")
            await pilot.pause()
            assert menu.display is False
            assert composer.text == "/"

    asyncio.run(scenario())


def test_enter_on_a_bare_slash_never_starts_an_engagement(workspace):
    workspace.mode_holder[0] = "purple"

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            composer.focus()
            composer.insert("/")
            await pilot.pause()
            assert "/engage" in {option.id for option in app.query_one("#suggestion-menu", SuggestionMenu).options}
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            assert workspace.engagement_running is False
            assert workspace.purple_view is None
            assert workspace.busy is False

    asyncio.run(scenario())


def test_argument_commands_are_completed_never_executed(workspace):
    workspace.mode_holder[0] = "purple"

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            menu = app.query_one("#suggestion-menu", SuggestionMenu)
            composer.focus()
            composer.insert("/engage")
            await pilot.pause()
            assert [option.id for option in menu.options] == ["/engage"]
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            assert composer.text == "/engage "
            assert menu.display is False
            assert workspace.engagement_running is False
            assert workspace.purple_view is None
            assert workspace.busy is False

    asyncio.run(scenario())


def test_no_match_rows_are_disabled_and_never_send(workspace):
    sent: list[str] = []

    async def fake_submit(text: str) -> None:
        sent.append(text)

    workspace.submit = fake_submit  # type: ignore[method-assign]

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            menu = app.query_one("#suggestion-menu", SuggestionMenu)
            composer.focus()
            composer.insert("/zzzz")
            await pilot.pause()
            assert menu.display is True
            assert [option.id for option in menu.options] == ["__none__"]
            assert menu.options[0].disabled is True
            await pilot.press("enter")
            await pilot.pause()
            assert sent == []
            assert composer.text == "/zzzz"

    asyncio.run(scenario())


def test_busy_purple_menu_advertises_only_busy_safe_commands(workspace):
    workspace.mode_holder[0] = "purple"
    workspace.busy = True

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            composer.focus()
            composer.insert("/")
            await pilot.pause()
            shown = {option.id for option in app.query_one("#suggestion-menu", SuggestionMenu).options}
            expected = {
                spec.name
                for spec in commands_for("purple")
                if spec.name in PURPLE_BUSY_SAFE
            }
            assert shown == expected
            assert "/engage" not in shown
            assert "/mode" not in shown

    asyncio.run(scenario())


def test_suggestion_menu_stays_bounded_and_inside_the_terminal(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            composer.focus()
            composer.insert("/")
            await pilot.pause()
            menu = app.query_one("#suggestion-menu", SuggestionMenu)
            assert menu.display is True
            assert menu.size.width <= 80
            assert menu.size.height <= 11  # at most 8 rows plus the border
            assert composer.region.bottom <= app.size.height

    asyncio.run(scenario())


def test_shift_enter_still_inserts_a_newline_and_closes_the_menu(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            menu = app.query_one("#suggestion-menu", SuggestionMenu)
            composer.focus()
            composer.insert("/help")
            await pilot.pause()
            assert menu.display is True
            await pilot.press("shift+enter")
            await pilot.pause()
            assert "\n" in composer.text
            assert menu.display is False

    asyncio.run(scenario())


def test_new_session_shortcut_creates_a_real_tab(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            before = len(workspace.sessions)
            await pilot.press("ctrl+n")
            await pilot.pause()
            await pilot.pause()
            assert len(workspace.sessions) == before + 1
            assert len(app.query("#tabstrip > .tab-item, #tabstrip > .tab-action")) == before + 2

    asyncio.run(scenario())


def test_sidebar_collapses_below_wide_breakpoint(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert app.query_one("#sidebar").display is True
            await pilot.resize_terminal(80, 30)
            await pilot.pause()
            assert app.query_one("#sidebar").display is False
            await pilot.resize_terminal(120, 40)
            await pilot.pause()
            assert app.query_one("#sidebar").display is True

    asyncio.run(scenario())


def test_busy_mode_switch_is_blocked_without_calling_sandbox(workspace, monkeypatch):
    called = []
    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available",
        lambda image: called.append(image) or (True, "test"),
    )
    workspace.busy = True
    asyncio.run(workspace.switch_mode())
    assert workspace.mode_holder == ["copilot"]
    assert "safe boundary" in workspace.notice
    assert called == []


def test_mode_switch_refuses_when_sandbox_is_unavailable(workspace, monkeypatch):
    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available",
        lambda image: (False, "runsc not registered"),
    )
    asyncio.run(workspace.switch_mode())
    assert workspace.mode_holder == ["copilot"]
    assert "cannot switch to purple" in workspace.notice


def test_shift_tab_switches_mode_and_shows_eight_agents(workspace, monkeypatch):
    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available",
        lambda image: (True, "test"),
    )

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("shift+tab")
            for _ in range(4):
                await pilot.pause()
            assert workspace.mode == "purple"
            top = await _render_text(app.query_one("#topmode"))
            assert "MODE B" in top
            purple = await _render_text(app.query_one("#purple-view"))
            assert "PURPLE TEAM" in purple
            sidebar = await _render_text(app.query_one("#sidebar-content"))
            assert "AGENTS · 8" in sidebar
            for state in SECURITY_AGENT_STATES:
                assert AGENT_LABELS[state] in sidebar
            assert "INIT" not in sidebar
            assert "HUMAN_REVIEW" not in sidebar

    asyncio.run(scenario())


def test_approval_is_fail_closed_until_explicit_decision(workspace):
    gate = ApprovalGate(gate="file")
    workspace._install_approval(gate)
    workspace.decide_approval(False)
    assert gate.result is False
    assert gate.done.is_set()
    assert workspace.approval is None

    gate = ApprovalGate(gate="file")
    workspace._install_approval(gate)
    workspace.decide_approval(True)
    assert gate.result is True
    assert gate.done.is_set()

    gate = ApprovalGate(gate="post_exploit")
    workspace._install_approval(gate)
    workspace.cancel_approvals()
    assert gate.result is False
    assert gate.done.is_set()


def test_human_review_approval_advances_one_hypothesis_at_a_time(workspace):
    gate = ApprovalGate(
        gate="human_review",
        hypotheses=[{"label": "a"}, {"label": "b"}],
    )
    workspace._install_approval(gate)
    workspace.decide_approval(True)
    assert gate.approved == {"a"}
    assert gate.index == 1
    assert not gate.done.is_set()
    workspace.decide_approval(False)
    assert gate.approved == {"a"}
    assert gate.done.is_set()
    assert workspace.approval is None


def test_approval_modal_denies_on_escape(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            gate = ApprovalGate(
                gate="file",
                hypotheses=[
                    {
                        "properties": {
                            "title": "read outside workspace",
                            "target_asset": "/etc/passwd",
                            "rationale": "test",
                        }
                    }
                ],
            )
            workspace._install_approval(gate)
            app._maybe_show_approval()
            await pilot.pause()
            assert isinstance(app.screen, ApprovalScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert gate.result is False
            assert gate.done.is_set()
            assert workspace.approval is None

    asyncio.run(scenario())


def test_approval_modal_enter_denies_even_with_approve_button(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            gate = ApprovalGate(gate="post_exploit", shell_evidence="root shell")
            workspace._install_approval(gate)
            app._maybe_show_approval()
            await pilot.pause()
            assert isinstance(app.screen, ApprovalScreen)
            await pilot.press("enter")
            await pilot.pause()
            assert gate.result is False
            assert gate.done.is_set()

    asyncio.run(scenario())


def test_approval_modal_explicit_approve_still_works(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            gate = ApprovalGate(gate="file")
            workspace._install_approval(gate)
            app._maybe_show_approval()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            assert gate.result is True
            assert gate.done.is_set()

    asyncio.run(scenario())


def test_closing_app_denies_pending_approval(workspace):
    gate = ApprovalGate(gate="file")
    workspace._install_approval(gate)
    workspace.close()
    assert gate.result is False
    assert gate.done.is_set()


def test_stop_request_ends_copilot_turn_at_the_next_round(workspace, monkeypatch):
    tab = workspace.sessions[0]

    def fake_run_agent(cfg, messages, toolbox, model, on_tool, on_round):
        on_round()
        return "this reply must never be stored"

    monkeypatch.setattr("kryonsec.copilot.agent.run_agent", fake_run_agent)
    monkeypatch.setattr("kryonsec.copilot.agent.build_toolbox", lambda *a, **k: {})
    workspace.stop_requested = True
    asyncio.run(workspace._run_agent(tab, "hi"))
    text = " ".join(message.content for message in workspace.display_messages(tab))
    assert "cancelled at a safe boundary" in text
    assert "this reply must never be stored" not in text


def test_failed_engagement_exit_is_visible_and_stops_checking(workspace, monkeypatch):
    monkeypatch.setattr("kryonsec.cli._run_purple", lambda *a, **k: 3)
    asyncio.run(workspace.start_engagement("authorized.example"))
    view = workspace.purple_view
    assert view is not None
    assert view.outcome == "failed"
    assert view.halt_reason == "exit_3"
    assert workspace.engagements[0].status == "failed"


def test_non_tty_environment_does_not_claim_full_screen(monkeypatch):
    # pytest captures stdout, so the conservative check must choose the plain
    # fallback rather than trying to start a terminal application.
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    assert interactive_terminal_available() is False


# ---- mode-driven color system ------------------------------------------


def test_mode_a_tokens_are_entirely_monochrome():
    tokens = workspace_tokens("copilot", truecolor=True)
    assert tokens.brand == "#ffffff"
    for name, value in vars(tokens).items():
        if name in {"brand", "purple", "name", "mode"}:
            continue  # purple is excluded in Mode A rendering; brand is white
        if _hex_channels(value) is not None:
            assert _monochrome(value), f"{name}={value} is not monochrome"


def test_mode_b_tokens_use_purple_brand_only():
    tokens = workspace_tokens("purple", truecolor=True)
    assert tokens.brand == PURE_PURPLE
    for name, value in vars(tokens).items():
        if name == "brand" or _hex_channels(value) is None:
            continue
        if name != "purple":  # the purple token stays reserved; nothing renders it
            assert _monochrome(value), f"{name}={value} is not monochrome"
    # ANSI fallback stays readable on limited terminals.
    ansi = workspace_tokens("purple", truecolor=False)
    assert ansi.brand == "magenta"
    assert ansi.accent == "white"
    assert ansi.background == "black"


def test_app_starts_with_mode_palette_and_looks_monochrome(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert app.tokens.brand == "#ffffff"
            copilot_css = app.CSS
            assert PURE_PURPLE not in copilot_css
            assert "#ffffff" in copilot_css

    asyncio.run(scenario())


def test_brand_banner_is_expanded_on_startup_even_with_stored_messages(workspace):
    tab = workspace.sessions[0]
    tab.session.messages = [Message("user", "Review a CVE")]
    workspace.session_store.save(tab)
    workspace.sessions = workspace.session_store.list_tabs()
    workspace.session_index = 0

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            banner = app.query_one("#brand-banner", BrandBanner)
            rendered = str(banner.render())
            assert "██╗" in rendered
            assert "by rahasec" in rendered
            assert app.query_one("#message-list", Vertical).display is True

    asyncio.run(scenario())


def test_empty_state_no_longer_duplicates_the_wordmark(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            empty = str(app.query_one("#empty-state", Static).render())
            assert "██╗" not in empty
            assert "by rahasec" not in empty
            assert "Ctrl+P" in empty

    asyncio.run(scenario())


def test_brand_collapses_for_activity_and_expands_for_new_workspace(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            banner = app.query_one("#brand-banner", BrandBanner)
            assert "\n" in str(banner.render())

            app._set_brand_expanded(False)
            await pilot.pause()
            compact = str(banner.render())
            assert "KRYONSEC" in compact
            assert "by rahasec" in compact
            assert "██╗" not in compact

            app.action_new_tab()
            await pilot.pause()
            assert "██╗" in str(banner.render())

    asyncio.run(scenario())


def test_brand_steps_down_to_the_block_font_on_a_narrow_terminal(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(70, 24)) as pilot:
            await pilot.pause()
            banner = app.query_one("#brand-banner", BrandBanner)
            rendered = str(banner.render())
            assert "██╗" not in rendered
            assert "█" in rendered
            assert "by rahasec" in rendered
            assert max(len(line) for line in rendered.splitlines()) <= app._content_columns()

    asyncio.run(scenario())


def test_brand_banner_fits_the_supported_terminal_matrix(workspace):
    sizes = (
        (60, 15),
        (60, 24),
        (80, 15),
        (80, 24),
        (100, 15),
        (100, 24),
        (100, 36),
        (120, 24),
        (120, 36),
        (160, 15),
        (160, 36),
    )

    for width, height in sizes:
        async def scenario(width=width, height=height):
            app = _app(workspace)
            async with app.run_test(size=(width, height)) as pilot:
                await pilot.pause()
                banner = app.query_one("#brand-banner", BrandBanner)
                rendered = str(banner.render())
                lines = rendered.splitlines() or [""]
                assert max(len(line) for line in lines) <= width
                if height < 20:
                    # Short windows keep the one-line brand and the composer.
                    assert len(lines) == 1
                    assert "KRYONSEC" in rendered
                else:
                    assert "by rahasec" in rendered
                    assert "█" in rendered or "KRYONSEC" in rendered

        asyncio.run(scenario())


def test_mode_switch_applies_the_other_palette_immediately(workspace, monkeypatch):
    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available", lambda image: (True, "test")
    )
    monkeypatch.setattr(
        "kryonsec.ui.app.terminal_capabilities",
        lambda stream=None: {
            "tty": True,
            "truecolor": True,
            "unicode": True,
            "dumb": False,
        },
    )

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert workspace.mode == "copilot"
            assert app.tokens.brand == "#ffffff"
            await pilot.press("shift+tab")
            for _ in range(5):
                await pilot.pause()
            assert workspace.mode == "purple"
            assert app.tokens.brand == PURE_PURPLE
            assert app._mode_shown == "purple"
            topmode = app.query_one("#topmode", Static)
            assert "MODE B" in await _render_text(topmode)
            banner = app.query_one("#brand-banner", BrandBanner)
            styles = {str(span.style) for span in banner.render().spans}
            # Textual normalises the hex token to an rgb() style string.
            assert any("168,85,247" in style for style in styles)

    asyncio.run(scenario())


# ---- interactive /models picker ---------------------------------------------


def _open_model_picker(pilot, app):
    composer = app.query_one("#composer", Composer)
    composer.focus()
    composer.insert("/models")
    return pilot.press("enter")


def test_plain_models_opens_a_provider_picker_without_text_output(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_model_picker(pilot, app)
            await pilot.pause()
            assert isinstance(app.screen, ModelPickerScreen)
            screen = app.screen
            assert screen._step == "provider"
            assert [option.id for option in screen.query_one("#models-list").options] == [
                "provider:openai",
                "provider:ollama",
                "provider:bedrock",
                "provider:openai_compatible",
            ]
            assert workspace.transient.get(workspace.session_index, []) == []

    asyncio.run(scenario())


def test_plain_models_starts_on_the_current_provider(workspace, monkeypatch):
    """The row marked · current is the one Enter chooses.

    Regression: the list was always highlighted at row 0 (OpenAI), so a
    plain Enter on an Ollama/Bedrock/compatible config discovered the wrong
    provider while the UI said which one was actually in use.
    """
    workspace.cfg.provider = "ollama"
    discovered_for: list[str] = []

    def fake_discover(cfg, provider):
        discovered_for.append(provider)
        return ["llama3.2:3b"], ""

    monkeypatch.setattr("kryonsec.ui.app.discover_models", fake_discover)

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_model_picker(pilot, app)
            await pilot.pause()
            screen = app.screen
            listing = screen.query_one("#models-list")
            assert listing.highlighted == 1  # Ollama is the second provider
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            assert screen._step == "models"
            assert discovered_for == ["ollama"]

    asyncio.run(scenario())


def test_model_picker_filters_confirms_and_updates_the_sidebar(workspace, monkeypatch):
    discovered = ["gpt-4o", "gpt-4o-mini", "o3-mini"]
    calls: list[tuple[str, str]] = []

    def fake_discover(cfg, provider):
        assert "sk-test-secret" not in provider
        return discovered, ""

    def fake_switch(cfg, provider, model):
        calls.append((provider, model))
        cfg.provider = provider
        cfg.general_chat_model = model
        return True, f"Model set to {provider} · {model} and saved."

    monkeypatch.setattr("kryonsec.ui.app.discover_models", fake_discover)
    monkeypatch.setattr("kryonsec.ui.app.switch_model", fake_switch)

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_model_picker(pilot, app)
            await pilot.pause()
            screen = app.screen
            # Step 1: OpenAI is already highlighted.
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            assert screen._step == "models"
            listed = [option.id for option in screen.query_one("#models-list").options]
            assert listed == ["model:gpt-4o", "model:gpt-4o-mini", "model:o3-mini"]

            # Step 2: typing filters, arrows navigate.
            screen.query_one("#models-search").value = "mini"
            await pilot.pause()
            assert [
                option.id for option in screen.query_one("#models-list").options
            ] == ["model:gpt-4o-mini", "model:o3-mini"]
            await pilot.press("down")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            assert screen._step == "confirm"
            assert screen._selected == "o3-mini"

            # Step 3: confirm writes through the existing switch function.
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            assert calls == [("openai", "o3-mini")]
            assert not isinstance(app.screen, ModelPickerScreen)
            assert workspace.cfg.provider == "openai"
            assert workspace.cfg.general_chat_model == "o3-mini"
            assert "Model set to openai · o3-mini" in workspace.notice

            sidebar = await _render_text(app.query_one("#sidebar-content"))
            assert "o3-mini" in sidebar

    asyncio.run(scenario())


def test_model_picker_failure_keeps_the_previous_selection(workspace, monkeypatch):
    monkeypatch.setattr(
        "kryonsec.ui.app.discover_models",
        lambda cfg, provider: (["gpt-4o"], ""),
    )
    monkeypatch.setattr(
        "kryonsec.ui.app.switch_model",
        lambda cfg, provider, model: (False, "provider rejected the request"),
    )
    before = (workspace.cfg.provider, workspace.cfg.general_chat_model)

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_model_picker(pilot, app)
            await pilot.pause()
            screen = app.screen
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            await pilot.press("enter")  # choose gpt-4o
            await pilot.pause()
            await pilot.press("enter")  # confirm
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            assert isinstance(app.screen, ModelPickerScreen)
            assert screen._step == "confirm"
            status = str(screen.query_one("#models-status").render())
            assert "provider rejected the request" in status
            assert workspace.cfg.provider == before[0]
            assert workspace.cfg.general_chat_model == before[1]

    asyncio.run(scenario())


def test_model_picker_reports_discovery_failure_without_inventing_models(workspace, monkeypatch):
    workspace.cfg.openai_api_key = "sk-test-secret"
    monkeypatch.setattr(
        "kryonsec.ui.app.discover_models",
        lambda cfg, provider: (
            None,
            "No OpenAI API key is set. Run `kryonsec setup` or choose another provider.",
        ),
    )

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_model_picker(pilot, app)
            await pilot.pause()
            screen = app.screen
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()
            ids = [option.id for option in screen.query_one("#models-list").options]
            assert not any(str(value).startswith("model:") for value in ids)
            rendered = str(screen.query_one("#models-status").render())
            assert "No OpenAI API key is set" in rendered
            assert "sk-test-secret" not in rendered
            assert "sk-test-secret" not in str(screen.query_one("#models-subtitle").render())

    asyncio.run(scenario())


def test_models_picker_is_refused_during_a_live_engagement(workspace):
    workspace.mode_holder[0] = "purple"
    workspace.engagement_running = True
    before = (workspace.cfg.provider, workspace.cfg.general_chat_model)

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_model_picker(pilot, app)
            await pilot.pause()
            assert not isinstance(app.screen, ModelPickerScreen)
            assert "engagement is running" in workspace.notice
            assert (workspace.cfg.provider, workspace.cfg.general_chat_model) == before

    asyncio.run(scenario())


def test_models_text_subcommands_still_work_in_the_tui(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            composer = app.query_one("#composer", Composer)
            composer.focus()
            composer.insert("/models list")
            await pilot.pause()
            assert app.query_one("#suggestion-menu", SuggestionMenu).display is False
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            assert not isinstance(app.screen, ModelPickerScreen)
            assert composer.text == ""

    asyncio.run(scenario())


# ---- session renaming ---------------------------------------------------


def test_rename_updates_visible_tab_immediately(workspace):
    renamed = workspace.rename_session(0, "Recon notes")
    assert renamed is True
    assert workspace.sessions[0].title == "Recon notes"
    assert workspace.sessions[0].session.messages == []


def test_rename_rejects_empty_names(workspace):
    before = workspace.sessions[0].title
    assert workspace.rename_session(0, "   ") is False
    assert "cannot be empty" in workspace.notice
    assert workspace.sessions[0].title == before


def test_rename_persists_across_restart(workspace):
    tab = workspace.sessions[0]
    tab.session.messages = [Message("user", "Investigate the login service")]
    workspace.session_store.save(tab)
    assert workspace.rename_session(0, "Login review") is True

    reloaded = workspace.session_store.list_tabs()
    titles = [session.title for session in reloaded if session.record_id == tab.record_id]
    assert titles == ["Login review"]


def test_rename_screen_dialog_cancel_preserves_name(workspace):
    async def scenario():
        app = _app(workspace)
        results: list[str | None] = []
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await app.push_screen(RenameScreen("old title"), lambda value: results.append(value))
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            assert results == [None]
            assert workspace.sessions[0].custom_title is None

    asyncio.run(scenario())


def test_rename_screen_prepopulates_and_confirms(workspace):
    async def scenario():
        app = _app(workspace)
        results: list[str | None] = []
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await app.push_screen(RenameScreen("first draft"), lambda value: results.append(value))
            await pilot.pause()
            dialog = app.screen
            assert isinstance(dialog, RenameScreen)
            assert dialog.query_one("#rename-input").value == "first draft"
            # empty names are refused inline, then a real name confirms
            dialog.query_one("#rename-input").value = ""
            await pilot.press("enter")
            await pilot.pause()
            assert results == []
            error = str(dialog.query_one("#rename-error").render())
            assert "empty" in error
            dialog.query_one("#rename-input").value = "final title"
            await pilot.press("enter")
            await pilot.pause()
            assert results == ["final title"]

    asyncio.run(scenario())


def test_rename_engagement_tab_display_title_only(workspace):
    """Phase 2: engagement tabs get an operator display title.

    The rename is presentation-only: the engagement id, the recorded
    target, and the audit chain bytes are untouched; the title is stored
    beside the chain and read back by the store.
    """
    import json

    from kryonsec.ui.session_store import EngagementTab

    workspace.mode_holder[0] = "purple"
    engagement_dir = workspace.cfg.home / "engagements" / "abcd1234"
    engagement_dir.mkdir(parents=True)
    audit_path = engagement_dir / "audit.jsonl"
    audit_path.write_text(
        json.dumps(
            {
                "event": "engagement_created",
                "target": "example.com",
                "timestamp": "2026-11-18T00:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    audit_before = audit_path.read_bytes()
    tab = EngagementTab(
        engagement_id="abcd1234", target="example.com", path=engagement_dir
    )
    workspace.engagements = [tab]
    workspace.engagement_index = 0

    assert workspace.rename_session(0, "Web app check") is True
    assert tab.custom_title == "Web app check"
    assert tab.title == "Web app check"
    # immutable identifiers and the chain are untouched
    assert tab.engagement_id == "abcd1234"
    assert tab.target == "example.com"
    assert audit_path.read_bytes() == audit_before
    # the title is stored beside the chain and read back on the next load
    stored = (engagement_dir / "display_title.json").read_text(encoding="utf-8")
    assert "Web app check" in stored
    reloaded = EngagementStore(workspace.cfg).list_tabs()
    assert reloaded[0].custom_title == "Web app check"
    assert reloaded[0].target == "example.com"


def test_rename_engagement_without_directory_keeps_view_title(workspace):
    """A live tab (no folder yet) takes the title in memory only."""
    from kryonsec.ui.session_store import EngagementTab

    workspace.mode_holder[0] = "purple"
    tab = EngagementTab(engagement_id="livebeef", target="example.com", path=None)
    workspace.engagements = [tab]
    workspace.engagement_index = 0
    assert workspace.rename_session(0, "Running check") is True
    assert tab.custom_title == "Running check"
    assert not (workspace.cfg.home / "engagements").exists()


def test_rename_engagement_empty_name_refused(workspace):
    from kryonsec.ui.session_store import EngagementTab

    workspace.mode_holder[0] = "purple"
    tab = EngagementTab(engagement_id="abcd1234", target="example.com", path=None)
    workspace.engagements = [tab]
    workspace.engagement_index = 0
    assert workspace.rename_session(0, "   ") is False
    assert tab.custom_title is None


def test_rename_engagement_unknown_index_refused(workspace):
    workspace.mode_holder[0] = "purple"
    assert workspace.rename_session(3, "nope") is False


# ---- session closing -----------------------------------------------------


def _saved_tab(workspace, text: str):
    tab = workspace.session_store.new_tab()
    tab.session.messages = [Message("user", text)]
    tab.record_id = workspace.session_store.save(tab)
    return tab


def test_close_session_preserves_stored_history(workspace):
    tab = _saved_tab(workspace, "Keep this history forever")
    workspace.sessions = [tab]
    workspace.session_index = 0

    workspace.close_tab(0)

    rows = workspace.session_store.list_tabs(limit=10)
    assert any(row.record_id == tab.record_id for row in rows)
    assert any(
        message.content == "Keep this history forever"
        for row in rows
        for message in row.session.messages
    )


def test_close_active_tab_selects_another_valid_tab(workspace):
    first = _saved_tab(workspace, "first")
    second = _saved_tab(workspace, "second")
    third = _saved_tab(workspace, "third")
    workspace.sessions = [first, second, third]
    workspace.session_index = 2

    workspace.close_tab(2)
    assert workspace.session_index == 1
    assert workspace.active_session().record_id == second.record_id

    workspace.close_tab(1)
    assert workspace.session_index == 0
    assert workspace.active_session().record_id == first.record_id


def test_closing_final_tab_returns_clean_new_session(workspace):
    tab = _saved_tab(workspace, "only one")
    workspace.sessions = [tab]
    workspace.session_index = 0

    workspace.close_tab(0)

    assert len(workspace.sessions) == 1
    fresh = workspace.sessions[0]
    assert fresh.record_id is None
    assert fresh.session.messages == []
    assert fresh.title == "New session"
    assert workspace.session_index == 0


def test_close_tab_refused_while_operation_is_active(workspace):
    tab = _saved_tab(workspace, "busy one")
    workspace.sessions = [tab]
    workspace.session_index = 0
    workspace.busy = True

    workspace.close_tab(0)
    assert len(workspace.sessions) == 1
    assert "safe boundary" in workspace.notice


def test_close_tab_refused_while_approval_is_pending(workspace):
    tab = _saved_tab(workspace, "gated")
    workspace.sessions = [tab]
    workspace.session_index = 0
    gate = ApprovalGate(gate="file")
    workspace._install_approval(gate)

    workspace.close_tab(0)

    assert len(workspace.sessions) == 1
    # Closing must never act as an implicit denial of the security gate.
    assert workspace.approval is gate
    assert not gate.done.is_set()
    assert "approval is pending" in workspace.notice


def test_close_engagement_tab_keeps_audit_data(workspace):
    tab = workspace.session_store.new_tab()
    workspace.sessions = [tab]
    workspace.mode_holder[0] = "purple"
    # engagement tabs come from EngagementStore; close is list-only
    workspace.engagements = [
        type(
            "EngagementStub",
            (),
            {
                "engagement_id": "deadbeef",
                "target": "authorized.example",
                "status": "recorded",
                "last_state": "",
                "path": None,
                "started_at": "",
                "title": "authorized.example",
            },
        )()
    ]
    workspace.engagement_index = 0
    workspace.close_tab(0)
    assert workspace.engagements == []
    assert workspace.engagement_index is None
    assert workspace.purple_view is None


# ---- palette discoverability -------------------------------------------


def test_palette_exposes_rename_and_close_in_mode_a():
    options = CommandPalette(_make_controller_stub("copilot"))._options
    ids = [identifier for _, identifier in options]
    assert "rename" in ids and "close" in ids
    assert "memory" not in ids


def test_palette_lists_a_close_entry_for_every_session():
    stub = _make_controller_stub("copilot")

    class _Tab:
        def __init__(self, title: str) -> None:
            self.title = title

    stub.sessions = [_Tab("Email header triage notes"), _Tab("Recon flow")]
    options = CommandPalette(stub)._options
    ids = [identifier for _, identifier in options]
    labels = [label for label, _ in options]
    # each stored session gets its own close (and rename) entry
    assert ids.count("close:1") == 1 and ids.count("close:2") == 1
    assert "rename:1" in ids and "rename:2" in ids
    assert any("Close session 1: Email header triage notes" in label for label in labels)
    assert any("Close session 2: Recon flow" in label for label in labels)
    # the session list stays grouped before the general commands
    assert ids.index("close:1") < ids.index("new")
    assert "memory" not in ids


def test_palette_lists_close_entry_for_a_single_session():
    stub = _make_controller_stub("copilot")

    class _Tab:
        title = "Only session"

    stub.sessions = [_Tab()]
    options = CommandPalette(stub)._options
    ids = [identifier for _, identifier in options]
    labels = [label for label, _ in options]
    assert ids.count("close:1") == 1
    assert any("Close session 1: Only session" in label for label in labels)


def test_palette_exposes_memory_in_mode_b():
    options = CommandPalette(_make_controller_stub("purple"))._options
    ids = [identifier for _, identifier in options]
    assert "memory" in ids
    assert "rename" not in ids and "close" not in ids


def _make_controller_stub(mode_value: str):
    class _Stub:
        def __init__(self) -> None:
            self.mode = mode_value
            self.sessions: list = []

    return _Stub()


# ---- Kryonsec Memory shortcut ------------------------------------------


def test_memory_entry_visible_only_in_purple(workspace, monkeypatch):
    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available", lambda image: (True, "test")
    )

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            entry = app.query_one("#memory-entry", MemoryEntry)
            assert entry.display is False
            await pilot.press("shift+tab")
            for _ in range(5):
                await pilot.pause()
            assert workspace.mode == "purple"
            assert entry.display is True

    asyncio.run(scenario())


def test_memory_activation_uses_the_shared_viewers(monkeypatch, workspace):
    import webbrowser

    calls = []

    def fake_start(cfg, host="127.0.0.1", port=8899):
        calls.append("start")
        return "http://127.0.0.1:9001/"

    fake_open = lambda url, *a, **k: calls.append(("open", url)) or True
    monkeypatch.setattr("kryonsec.cli._start_memory_browser", fake_start)
    monkeypatch.setattr("webbrowser.open", fake_open)
    workspace.mode_holder[0] = "purple"

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_open_memory()
            for _ in range(8):
                await await_worker(app)
                await pilot.pause()
            joined = workspace.notice
            assert "http://127.0.0.1:9001/" in joined
            assert "read-only" in joined
            assert calls.count("start") == 1
            assert ("open", "http://127.0.0.1:9001/") in calls

    asyncio.run(scenario())


async def await_worker(app: KryonsecApp) -> None:
    await asyncio.sleep(0.05)


def test_memory_failure_is_reported_without_breaking_the_ui(monkeypatch, workspace):
    import webbrowser

    def failing_start(cfg, host="127.0.0.1", port=8899):
        return None

    monkeypatch.setattr("kryonsec.cli._start_memory_browser", failing_start)
    monkeypatch.setattr("webbrowser.open", lambda url, *a, **k: True)
    workspace.mode_holder[0] = "purple"

    result = asyncio.run(controller_call(workspace))
    assert result is None
    assert "could not start" in workspace.notice
    # the controller is still usable afterwards
    assert workspace.sessions


async def controller_call(workspace: WorkspaceController):
    return await asyncio.to_thread(workspace.open_memory_browser)


def test_memory_never_launches_on_mode_switch_or_startup(workspace, monkeypatch):
    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available", lambda image: (True, "test")
    )
    launched = []

    def guard(cfg, host="127.0.0.1", port=8899):
        launched.append("start")
        return None

    monkeypatch.setattr("kryonsec.cli._start_memory_browser", guard)

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("shift+tab")
            for _ in range(5):
                await pilot.pause()
            assert workspace.mode == "purple"

    asyncio.run(scenario())
    assert launched == []


# ---- Mode B live runtime and activity rendering -------------------------
#
# These tests feed the same observation callbacks the real runner/audit
# observer thread calls; nothing fabricates a "ready" state. The actual
# docker/sandbox collectors are decided by their real check functions, which
# are monkeypatched here the same way the mode gate already is.


def test_purple_runtime_panel_starts_unknown_and_reflects_real_checks(
    workspace, monkeypatch
):
    assert workspace.runtime_status_summary() == {
        "docker": "unknown",
        "docker_detail": "",
        "sandbox": "unknown",
        "sandbox_detail": "",
    }
    monkeypatch.setattr(
        "kryonsec.purple.runtime_checks.docker_server_ok",
        lambda: (False, "docker daemon unreachable"),
    )
    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available",
        lambda image: (False, "runsc not registered"),
    )
    workspace._collect_runtime_status()
    status = workspace.runtime_status_summary()
    assert status["docker"] == "unavailable"
    assert "docker daemon unreachable" in status["docker_detail"]
    assert status["sandbox"] == "unavailable"
    assert "runsc not registered" in status["sandbox_detail"]


def test_purple_runtime_sidebar_never_shows_fake_ready(workspace):
    workspace.mode_holder[0] = "purple"

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            text = await _render_text(app.query_one("#sidebar-content"))
            assert "RUNTIME" in text
            assert "unknown" in text
            # nothing is claimed connected or ready before a real check runs
            assert "connected" not in text
            assert "ready" not in text.replace("READY", "")
            assert "on demand" in text

    asyncio.run(scenario())


def test_purple_sandbox_status_comes_from_real_audit_events(workspace):
    view = PurpleWorkspaceState("authorized.example", "eng-1")
    view.on_audit(
        {
            "event": "sandbox_check",
            "available": False,
            "reason": "gVisor image mismatch",
        }
    )
    assert view.sandbox_status == "unavailable"
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            sidebar = await _render_text(app.query_one("#sidebar-content"))
            assert "unavailable" in sidebar
            assert "gVisor image mismatch" in sidebar

    asyncio.run(scenario())


def test_purple_connections_reflect_the_real_toolbox_state(workspace):
    class FakeMcp:
        def statuses(self):
            return [
                {"name": "GitHub", "status": "connected", "detail": "2 tool(s)"},
                {"name": "Filesystem", "status": "disconnected", "detail": "process exited"},
            ]

    workspace.mcp_toolbox = FakeMcp()
    workspace.mode_holder[0] = "purple"

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            text = await _render_text(app.query_one("#sidebar-content"))
            assert "1/2 connected" in text
            assert "GitHub" in text and "Filesystem" in text
            # the real per-server state, not a blanket "connected"
            assert "disconnected" in text

    asyncio.run(scenario())


def test_purple_active_agent_updates_from_state_events(workspace):
    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app._refresh_sidebar()
            sidebar = await _render_text(app.query_one("#sidebar-content"))
            assert "—\n" in sidebar  # no stage yet
            # backend observations arrive one at a time, like the real thread
            view.on_state("RECON_ACTIVE")
            view.on_audit(
                {
                    "event": "tool_spawn",
                    "tool": "nmap",
                    "state": "RECON_ACTIVE",
                    "argv": ["nmap", "-Pn", "-sV", "-p", "80,443", "authorized.example"],
                }
            )
            # a real run posts UiChanged from the observer thread; here the
            # observation callbacks are driven by hand, so force the repaint
            app._refresh_sidebar()
            await pilot.pause()
            sidebar = await _render_text(app.query_one("#sidebar-content"))
            assert "Active recon" in sidebar
            assert "running" in sidebar
            assert "nmap" in sidebar

    asyncio.run(scenario())


def test_purple_current_operation_shows_real_command_from_audit_argv(workspace):
    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    view.on_state("RECON_ACTIVE")
    view.on_audit(
        {
            "event": "tool_spawn",
            "tool": "nmap",
            "state": "RECON_ACTIVE",
            "argv": ["nmap", "-Pn", "-sV", "-p", "80,443", "authorized.example"],
        }
    )
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            purple = await _render_text(app.query_one("#purple-view"))
            assert "CURRENT OPERATION" in purple
            assert "nmap" in purple
            assert "nmap -Pn -sV -p 80,443 authorized.example" in purple
            assert "running" in purple

    asyncio.run(scenario())


def test_purple_last_completed_tool_is_shown_when_nothing_runs(workspace):
    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    view.on_state("RECON_ACTIVE")
    view.on_audit(
        {
            "event": "tool_spawn",
            "tool": "nmap",
            "state": "RECON_ACTIVE",
            "argv": ["nmap", "-Pn", "authorized.example"],
        }
    )
    view.on_audit(
        {
            "event": "tool_result",
            "tool": "nmap",
            "state": "RECON_ACTIVE",
            "ok": True,
            "exit_code": 0,
            "output_chars": 421,
        }
    )
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            purple = await _render_text(app.query_one("#purple-view"))
            sidebar = await _render_text(app.query_one("#sidebar-content"))
            assert "completed" in purple
            assert "421 chars" in purple
            assert "nmap" in sidebar and "completed" in sidebar

    asyncio.run(scenario())


def test_purple_command_display_redacts_secrets_from_argv(workspace):
    import kryonsec.ui.state as ui_state

    tool, argv = "curl", [
        "curl",
        "-H",
        "Authorization: Bearer abcdef0123456789abcdef0123456789",
        "https://authorized.example",
    ]
    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    view.on_state("RECON_ACTIVE")
    view.on_audit(
        {"event": "tool_spawn", "tool": tool, "state": "RECON_ACTIVE", "argv": argv}
    )
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            purple = await _render_text(app.query_one("#purple-view"))
            assert "abcdef0123456789abcdef0123456789" not in purple
            assert "SECRET" in purple

    asyncio.run(scenario())
    # and the shared formatter behaves the same way
    assert ui_state.display_command(tool, argv).count("«SECRET_") == 1


def test_purple_activity_stream_appends_real_events_in_order(workspace):
    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    view.on_state("RECON_PASSIVE")
    view.on_state_complete("RECON_PASSIVE")
    view.on_state("RECON_ACTIVE")
    view.on_audit(
        {
            "event": "tool_spawn",
            "tool": "nmap",
            "state": "RECON_ACTIVE",
            "argv": ["nmap", "-Pn", "authorized.example"],
        }
    )
    view.on_audit(
        {
            "event": "tool_result",
            "tool": "nmap",
            "state": "RECON_ACTIVE",
            "ok": True,
            "output_chars": 88,
        }
    )
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            purple = await _render_text(app.query_one("#purple-view"))
            launched = purple.index("launched nmap")
            finished = purple.index("finished nmap")
            assert launched < finished
            assert "started" in purple
            assert "stage completed" in purple

    asyncio.run(scenario())


def test_purple_findings_and_evidence_update_from_state_changes(workspace):
    class FakeGraph:
        def by_type(self, kind):
            if kind == "finding":
                return [
                    {
                        "label": "Basic auth over HTTP on /admin",
                        "properties": {"verified": True, "severity": "high"},
                    }
                ]
            return []

    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    view.graph = FakeGraph()
    assert view.snapshot()["counts"]["findings"] == 0
    view.on_state("VERIFY")
    view.on_state_complete("VERIFY")
    snapshot = view.snapshot()
    assert snapshot["counts"]["findings"] == 1
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            purple = await _render_text(app.query_one("#purple-view"))
            assert "findings 1" in purple
            assert "verified 1" in purple

    asyncio.run(scenario())


def test_purple_statusbar_tracks_running_tool_not_static_tagline(workspace):
    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            text = await _render_text(app.query_one("#statusbar"))
            assert "engine idle" in text
            assert "deterministic engine" not in text
            workspace.purple_view = view
            app._refresh_status()
            text = await _render_text(app.query_one("#statusbar"))
            assert "waiting" in text
            view.on_state("RECON_ACTIVE")
            view.on_audit(
                {
                    "event": "tool_spawn",
                    "tool": "nmap",
                    "state": "RECON_ACTIVE",
                    "argv": ["nmap", "-Pn", "authorized.example"],
                }
            )
            app._refresh_status()
            await pilot.pause()
            text = await _render_text(app.query_one("#statusbar"))
            assert "recon_active" in text
            assert "nmap" in text

    asyncio.run(scenario())


def test_purple_workflow_timeline_shows_stage_durations(workspace):
    import time as time_module

    view = PurpleWorkspaceState("authorized.example", "eng-1", sandbox_status="ready")
    view.on_state("RECON_PASSIVE")
    first = view.state_started["RECON_PASSIVE"]
    view.state_started["RECON_PASSIVE"] = first - 7.0  # the real clock would drift
    view.on_state_complete("RECON_PASSIVE")
    assert round(view.state_duration["RECON_PASSIVE"]) == 7
    workspace.mode_holder[0] = "purple"
    workspace.purple_view = view

    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            purple = await _render_text(app.query_one("#purple-view"))
            assert "7s" in purple

    asyncio.run(scenario())


# ---- palette reads the one command registry -----------------------------


def test_palette_offers_registry_commands_for_the_active_mode():
    copilot = CommandPalette(_make_controller_stub("copilot"))._options
    copilot_ids = [identifier for _, identifier in copilot]
    assert "run:/commands" in copilot_ids
    assert "run:/models" in copilot_ids
    assert "run:/mcp" in copilot_ids
    assert "run:/skills" in copilot_ids
    assert "run:/engage" not in copilot_ids
    assert "mode" in copilot_ids

    purple = CommandPalette(_make_controller_stub("purple"))._options
    purple_ids = [identifier for _, identifier in purple]
    assert "run:/engage" in purple_ids
    assert "run:/report" in purple_ids
    assert "run:/cve" not in purple_ids
    assert "memory" in purple_ids


def test_palette_run_entry_dispatches_through_the_workspace(workspace):
    async def scenario():
        app = _app(workspace)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app._palette_result("run:/commands")
            await pilot.pause()
            await pilot.pause()
            messages = workspace.display_messages()
            assert any("COMMANDS · Mode A" in m.content for m in messages)
            assert any("/models" in m.content for m in messages)

    asyncio.run(scenario())
