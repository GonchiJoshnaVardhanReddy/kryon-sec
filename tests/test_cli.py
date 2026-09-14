"""CLI module tests: import safety + mode-colored banner.

Importing kryonsec.cli as a module catches syntax errors (an earlier
bug shipped `await` outside an async function — the suite never
imported cli.py, so every test was green while the CLI was broken).
"""

from kryonsec import cli


def test_cli_imports_clean() -> None:
    """The module must import (syntax/typing errors fail here, not at
    first `kryonsec` launch)."""
    import importlib

    importlib.reload(cli)
    assert callable(cli.main)


def test_banner_white_in_copilot() -> None:
    assert "[bold white]" in cli.banner_styled("copilot")


def test_banner_purple_in_purple_mode() -> None:
    assert "[bold magenta]" in cli.banner_styled("purple")


def test_banner_has_kryonsec_art() -> None:
    # box-drawing art, not an empty style wrapper
    assert "██╗" in cli.BANNER
    assert "███████╗" in cli.BANNER


# ---- M8: Ctrl+C must close the MCP toolbox from EVERY exit path -------
#
# The interrupt-during-LLM-call path used to skip mcp_toolbox.close():
# KeyboardInterrupt is not an Exception, so it flew past the per-turn
# handlers and out of _chat_loop — only /quit and the prompt-interrupt
# exit ran cleanup. Verified by repro (live MCP server + real console
# interrupt), then locked here at the unit level.

import asyncio

import pytest

from kryonsec.config import KryonsecConfig


class _StubQuery:
    """Fluent stub for the LTM query chain — returns no rows."""

    def filter(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def limit(self, *a, **k):
        return self

    def all(self):
        return []


class _StubDb:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def query(self, *a, **k):
        return _StubQuery()


class _StubToolbox:
    """Stands in for McpToolbox: counts close() and connects nothing."""

    def __init__(self):
        self.close_count = 0

    def connect_all(self):
        return {}

    def snapshot(self):
        return {}

    def close(self):
        self.close_count += 1


def _run_chat_loop(monkeypatch, tmp_path, *, replies, agent=None):
    """Drive cli._chat_loop with the outside world stubbed out.

    replies: what prompt_async yields, in order (loop exits after the
    last one via EOFError). agent: replacement run_agent (default: a
    plain reply).
    Returns (closed_count, persist_count, session_rows_saved).
    """
    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [{"name": "stub", "command": "x", "args": []}]

    toolbox = _StubToolbox()
    persist_calls = []
    replies = list(replies)
    raised = []

    monkeypatch.setattr(cli, "_persist_session", lambda cfg, session: persist_calls.append(1))
    monkeypatch.setattr("kryonsec.storage.init_db", lambda *a, **k: None)

    import kryonsec.storage as storage
    monkeypatch.setattr(storage, "get_session", lambda cfg: _StubDb())

    monkeypatch.setattr(
        "kryonsec.copilot.mcp_tools.McpToolbox", lambda cfg, on_notice=None: toolbox)

    class _Ps:
        async def prompt_async(self):
            if not replies:
                raise EOFError
            out = replies.pop(0)
            if isinstance(out, BaseException):
                raise out
            return out

    import kryonsec.tui as tui
    monkeypatch.setattr(tui, "make_prompt_session", lambda *a, **k: _Ps())

    import kryonsec.llm as llm
    monkeypatch.setattr(llm, "preload_litellm", lambda: None)

    if agent is None:
        def agent(messages, toolbox, model, **k):  # noqa: shadow
            return "ok"

    import kryonsec.copilot.agent as agent_mod
    monkeypatch.setattr(agent_mod, "run_agent", agent)
    monkeypatch.setattr(agent_mod, "build_toolbox", lambda cfg, ft, extra=None: {})

    import kryonsec.status as status_mod
    monkeypatch.setattr(status_mod, "StatusLine", lambda console: type(
        "S", (), {"show": lambda s, m: None, "hide": lambda s: None,
                  "running": lambda s, m: None})())

    import kryonsec.storage as storage2  # _persist_session path uses it too
    _orig = storage2.GeneralSession  # keep import inside _persist working

    try:
        asyncio.run(cli._chat_loop(cfg))
    except BaseException as e:  # the interrupt case lets it propagate
        raised.append(e)

    return toolbox.close_count, len(persist_calls), raised


def test_m8_interrupt_during_llm_closes_toolbox(monkeypatch, tmp_path):
    """Ctrl+C inside the agent call must still close the MCP servers."""
    def agent(*a, **k):
        raise KeyboardInterrupt

    closes, persists, raised = _run_chat_loop(
        monkeypatch, tmp_path, replies=["hello"], agent=agent)

    assert closes == 1, "M8 regression: interrupt during LLM call left MCP servers running"
    assert persists == 1, "session must still be persisted on interrupt"
    assert raised and isinstance(raised[0], KeyboardInterrupt)


def test_m8_quit_path_closes_exactly_once(monkeypatch, tmp_path):
    """/quit runs _exit via _print_goodbye AND the loop finally — the
    one-shot guard means the session persists exactly once."""
    closes, persists, raised = _run_chat_loop(
        monkeypatch, tmp_path, replies=["quit"])

    assert closes == 1
    assert persists == 1, "double _exit() must not persist the session twice"
    assert not raised


def test_m8_eof_path_closes_toolbox(monkeypatch, tmp_path):
    """Ctrl+C/EOF at the prompt closes the toolbox (pre-existing path,
    locked in so it cannot regress either)."""
    closes, persists, raised = _run_chat_loop(
        monkeypatch, tmp_path, replies=[KeyboardInterrupt()])

    assert closes == 1
    assert persists == 1
    assert not raised
