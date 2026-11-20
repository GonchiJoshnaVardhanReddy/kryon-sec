"""Workspace command handlers: /commands, /models, /mcp, /skills, /sessions.

No real model provider, Docker daemon, MCP server, or engagement runner is
touched.  Provider discovery and the skill registry are mocked; MCP status is
a presentation-only snapshot.
"""

from __future__ import annotations

import asyncio

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.mcp_registry import McpExecutionPolicy
from kryonsec.storage import reset_engine
from kryonsec.ui.session_store import EngagementStore, SessionStore
from kryonsec.ui.workspace import WorkspaceController


@pytest.fixture()
def controller(tmp_path, monkeypatch):
    reset_engine()
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    cfg.database_url = f"sqlite:///{tmp_path / 'sessions.db'}"
    cfg.provider = "openai"
    cfg.general_chat_model = "gpt-4o-mini"
    cfg.openai_api_key = "test-key"
    store = SessionStore(cfg)
    store.ensure_schema()
    value = WorkspaceController(
        cfg,
        session_store=store,
        engagement_store=EngagementStore(cfg),
        system_prompt="test prompt",
    )
    yield value
    value.close()
    reset_engine()


def _messages(controller: WorkspaceController) -> list[str]:
    return [message.content for message in controller.display_messages() if message.role == "system"]


def _submit(controller: WorkspaceController, text: str) -> None:
    asyncio.run(controller.submit(text))


# ---- command dispatch ----------------------------------------------------


def test_commands_lists_only_this_modes_real_commands(controller):
    _submit(controller, "/commands")
    text = "\n".join(_messages(controller))
    assert "COMMANDS · Mode A" in text
    assert "/models" in text
    assert "/engage" not in text


def test_help_stays_a_complement_to_commands(controller):
    _submit(controller, "/help")
    text = "\n".join(_messages(controller))
    assert "SHORTCUTS" in text
    assert "/commands" in text


def test_unknown_slash_command_never_reaches_the_model(controller, monkeypatch):
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("model must not run for an unknown command")

    monkeypatch.setattr(controller, "_run_agent", forbidden)
    _submit(controller, "/bogus")
    assert "not a command here" in "\n".join(_messages(controller))


def test_mode_a_refuses_mode_b_commands_without_starting_an_engagement(controller, monkeypatch):
    started = False

    async def record(_target: str) -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(controller, "start_engagement", record)
    _submit(controller, "/engage authorized.example")
    assert started is False
    assert "Purple Team command" in "\n".join(_messages(controller))


def test_rename_and_sessions_use_the_real_tabs(controller):
    _submit(controller, "/rename Alpha session")
    assert controller.active_session().title == "Alpha session"

    _submit(controller, "/sessions")
    text = "\n".join(_messages(controller))
    assert "SESSIONS · 1" in text
    assert "Alpha session" in text


# ---- /models -------------------------------------------------------------


def test_models_current_shows_the_active_route_and_fallbacks(controller):
    _submit(controller, "/models current")
    text = "\n".join(_messages(controller))
    assert "OpenAI · gpt-4o-mini" in text
    assert "local fallback" in text
    assert "compaction" in text


def test_models_list_uses_real_discovery(controller, monkeypatch):
    from kryonsec import model_catalog

    monkeypatch.setattr(
        model_catalog, "_openai_models", lambda key: [{"id": "gpt-4o"}]
    )
    _submit(controller, "/models list openai")
    text = "\n".join(_messages(controller))
    assert "gpt-4o" in text
    assert "OpenAI" in text


def test_models_use_switches_and_updates_the_sidebar_route(controller, monkeypatch):
    from kryonsec import model_catalog

    monkeypatch.setattr(
        model_catalog, "_openai_models", lambda key: [{"id": "gpt-4o"}]
    )
    changes: list[str] = []
    controller.set_change_callback(changes.append)

    _submit(controller, "/models use openai gpt-4o")
    assert controller.cfg.provider == "openai"
    assert controller.cfg.general_chat_model == "gpt-4o"
    assert "models" in changes
    assert "Model set to" in controller.notice


def test_models_use_refuses_mid_engagement_and_keeps_the_old_route(controller, monkeypatch):
    controller.mode_holder[0] = "purple"
    controller.engagement_running = True
    old = (controller.cfg.provider, controller.cfg.general_chat_model)

    _submit(controller, "/models use openai gpt-4o")

    assert (controller.cfg.provider, controller.cfg.general_chat_model) == old
    assert "refused while an engagement is running" in controller.notice


def test_models_use_never_prints_an_api_key(controller, monkeypatch):
    from kryonsec import model_catalog

    controller.cfg.openai_api_key = "sk-" + "a" * 32
    monkeypatch.setattr(model_catalog, "_openai_models", lambda key: None)
    _submit(controller, "/models use openai gpt-4o")
    visible = "\n".join(_messages(controller)) + controller.notice
    assert controller.cfg.openai_api_key not in visible


# ---- /mcp ----------------------------------------------------------------


class _StatusToolbox:
    def __init__(self, rows):
        self._rows = rows
        self.connections = []

    def statuses(self):
        return [dict(row) for row in self._rows]


class _Registry:
    def __init__(self, policies):
        self._policies = policies

    def policy_for(self, name):
        return self._policies.get(name, McpExecutionPolicy())


def test_mcp_with_no_servers_is_honest(controller):
    _submit(controller, "/mcp")
    text = "\n".join(_messages(controller))
    assert "No MCP servers configured" in text


def test_mcp_distinguishes_disabled_connected_blocked_and_failed(controller):
    controller.cfg.mcp_servers = [
        {"name": "off", "enabled": False, "command": "x"},
        {"name": "good", "enabled": True, "command": "x"},
        {"name": "guard", "enabled": True, "command": "x"},
        {"name": "broken", "enabled": True, "command": "x"},
    ]
    controller.mcp_toolbox = _StatusToolbox(
        [
            {"name": "good", "status": "connected", "detail": "2 tool(s) available", "tools": 2},
            {"name": "guard", "status": "blocked", "detail": "no startup authorization", "tools": 0},
            {"name": "broken", "status": "disconnected", "detail": "startup timed out", "tools": 0},
        ]
    )
    controller.mcp_registry = _Registry(
        {"good": McpExecutionPolicy(trust="allow", allow_tools=frozenset({"fetch"}))}
    )

    _submit(controller, "/mcp")
    text = "\n".join(_messages(controller))

    assert "off  DISABLED" in text
    assert "good  CONNECTED  tools=2" in text
    assert "guard  BLOCKED" in text
    assert "broken  FAILED" in text
    assert "trust=allow  authorized=fetch" in text
    assert "next: check config.toml" in text


def test_mcp_connection_without_a_failure_reason_is_disconnected(controller):
    controller.cfg.mcp_servers = [{"name": "idle", "enabled": True, "command": "x"}]
    controller.mcp_toolbox = _StatusToolbox(
        [{"name": "idle", "status": "disconnected", "detail": "", "tools": 0}]
    )
    _submit(controller, "/mcp status")
    assert "idle  DISCONNECTED" in "\n".join(_messages(controller))


def test_mcp_redacts_failure_details_before_display(controller):
    secret = "sk-" + "b" * 32
    controller.cfg.mcp_servers = [{"name": "leaky", "enabled": True, "command": "x"}]
    controller.mcp_toolbox = _StatusToolbox(
        [{"name": "leaky", "status": "disconnected", "detail": f"failed {secret}", "tools": 0}]
    )
    _submit(controller, "/mcp")
    text = "\n".join(_messages(controller))
    assert secret not in text
    assert "SECRET" in text


def test_mcp_tools_lists_names_and_policy_without_executing(controller):
    class _Connection:
        name = "good"
        entry = {"mcp_fetch": ({"function": {"name": "mcp_fetch"}}, object())}

    controller.cfg.mcp_servers = [{"name": "good", "enabled": True, "command": "x"}]
    controller.mcp_toolbox = _StatusToolbox(
        [{"name": "good", "status": "connected", "detail": "1 tool", "tools": 1}]
    )
    controller.mcp_toolbox.connections = [_Connection()]
    controller.mcp_registry = _Registry(
        {"good": McpExecutionPolicy(trust="allow", allow_tools=frozenset({"fetch"}))}
    )

    _submit(controller, "/mcp tools good")
    text = "\n".join(_messages(controller))
    assert "MCP TOOLS · good · 1" in text
    assert "✓ fetch  authorized" in text
    assert "not executed here" in text


def test_mcp_tools_refuses_before_starting_a_disconnected_server(controller):
    controller.cfg.mcp_servers = [{"name": "offline", "enabled": True, "command": "x"}]
    controller.mcp_toolbox = _StatusToolbox(
        [{"name": "offline", "status": "not started", "detail": "connection not started", "tools": 0}]
    )
    _submit(controller, "/mcp tools offline")
    text = "\n".join(_messages(controller))
    assert "NOT STARTED" in text
    assert "No process was started" in text


# ---- /skills -------------------------------------------------------------


def test_skills_lists_the_real_packaged_inventory(controller):
    _submit(controller, "/skills")
    text = "\n".join(_messages(controller))
    assert "SKILLS · 6 packaged" in text
    for name in (
        "counterevidence",
        "defensive_remediation",
        "evidence_quality",
        "recon_methodology",
        "severity_calibration",
        "verification_method",
    ):
        assert name in text
    assert "not executable" in text


def test_skills_info_reads_one_real_skill(controller):
    _submit(controller, "/skills info counterevidence")
    text = "\n".join(_messages(controller))
    assert "SKILL · counterevidence" in text
    assert "Mode B specialist knowledge only" in text
    assert "knowledge-only" in text


def test_skills_unknown_name_does_not_load_anything(controller):
    _submit(controller, "/skills info not-a-skill")
    assert "No packaged skill named" in "\n".join(_messages(controller))


def test_skills_empty_registry_says_so(controller, monkeypatch):
    from kryonsec.purple import skills

    monkeypatch.setattr(skills, "load_packaged_skills", lambda: skills.SkillRegistry([]))
    _submit(controller, "/skills")
    assert "No skills installed" in "\n".join(_messages(controller))
