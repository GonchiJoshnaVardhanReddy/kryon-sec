"""Tests for MCP tool wiring (v1.1): schema conversion and the toolbox
wrapper — against fake tool/session objects, no real mcp import."""

import threading
import time

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.mcp_tools import McpToolbox, _ServerConnection, _schema


class FakeMcpTool:
    def __init__(self, name, description, input_schema):
        self.name = name
        self.description = description
        self.inputSchema = input_schema


class FakeListResult:
    def __init__(self, tools):
        self.tools = tools


class FakeSession:
    def __init__(self, tools, results):
        self._tools = tools
        self._results = results
        self.calls = []

    async def initialize(self):
        pass

    async def list_tools(self):
        return FakeListResult(self._tools)

    async def call_tool(self, name, kwargs):
        self.calls.append((name, kwargs))
        return self._results.get(name, "no result")


def test_schema_conversion_flat():
    tool = FakeMcpTool("fetch", "fetch a page", {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    })
    schema = _schema(tool)
    assert schema["type"] == "function"
    fn = schema["function"]
    assert fn["name"] == "fetch"
    assert fn["description"] == "fetch a page"
    assert fn["parameters"]["properties"]["url"]["type"] == "string"
    assert fn["parameters"]["required"] == ["url"]


def test_schema_conversion_empty_schema():
    tool = FakeMcpTool("ping", None, {})
    schema = _schema(tool)
    fn = schema["function"]
    assert fn["description"] == ""
    assert fn["parameters"]["properties"] == {}
    assert fn["parameters"]["required"] == []


def test_connect_all_skips_disabled_servers(tmp_path, monkeypatch):
    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [
        {"name": "off", "command": "x", "args": [], "env": {}, "enabled": False},
    ]
    tb = McpToolbox(cfg)
    attempted = []
    monkeypatch.setattr(
        tb, "_connect_one",
        lambda server: attempted.append(server) or (_ServerConnection(), False))
    assert tb.connect_all() == {}
    assert attempted == []  # disabled server never started


def test_missing_command_is_a_clear_error(tmp_path):
    """A command that is not on PATH fails with a plain 'not found'
    message, not a cryptic ENOENT (the uvx-in-WSL bug)."""
    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [{"name": "gone", "command": "no-such-bin-xyz", "args": []}]
    notices: list[str] = []
    tb = McpToolbox(cfg, on_notice=notices.append)

    entries = tb.connect_all()
    assert entries == {}
    assert any("not found on PATH" in n for n in notices)


def test_connect_all_survives_close_mid_connect(tmp_path, monkeypatch):
    """connect_all() runs on a daemon thread while the user may quit:
    close() during the connect loop must not crash it, and any server
    started after close() is torn down, not leaked."""
    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [{"name": "a", "command": "x", "args": []}]
    tb = McpToolbox(cfg)

    closed: list[_ServerConnection] = []

    def fake_connect_one(server):
        tb.close()  # user quits while this server is starting
        conn = _ServerConnection()
        monkeypatch.setattr(conn, "close", lambda: closed.append(conn))
        return conn, False

    monkeypatch.setattr(tb, "_connect_one", fake_connect_one)
    assert tb.connect_all() == {}
    assert len(closed) == 1  # the late server was torn down


def test_slow_server_tools_merge_late(tmp_path, monkeypatch):
    """A server slower than the 10s connect timeout is not dropped: its
    tools merge into the toolbox when they land, and the next snapshot()
    sees them (v1.1.1 silently dropped slow servers for the session)."""
    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [{"name": "slow", "command": "x", "args": []}]
    notices: list[str] = []
    tb = McpToolbox(cfg, on_notice=notices.append)

    conn = _ServerConnection()  # ready Event exists, not yet set
    monkeypatch.setattr(tb, "_connect_one", lambda server: (conn, True))

    assert tb.connect_all() == {}  # nothing known at connect time
    assert any("still starting" in n for n in notices)

    # the server finishes booting 15s "later": tools listed, ready set
    conn.entry["mcp_fetch"] = (
        {"type": "function", "function": {"name": "mcp_fetch"}}, lambda **kw: "ok")
    conn.ready.set()

    deadline = time.time() + 5
    while time.time() < deadline and not tb.snapshot():
        time.sleep(0.01)
    assert "mcp_fetch" in tb.snapshot()
    assert any("now available" in n for n in notices)


def test_dead_slow_server_notice(tmp_path, monkeypatch):
    """A slow server that never becomes ready is dropped WITH a visible
    notice — never a silent log line."""
    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [{"name": "hung", "command": "x", "args": []}]
    notices: list[str] = []
    tb = McpToolbox(cfg, on_notice=notices.append)

    conn = _ServerConnection()
    monkeypatch.setattr(tb, "_connect_one", lambda server: (conn, True))
    monkeypatch.setattr("kryonsec.copilot.mcp_tools.LATE_BOOT_TIMEOUT_S", 0.05)
    tb.connect_all()

    deadline = time.time() + 5
    while time.time() < deadline and not any("never became ready" in n for n in notices):
        time.sleep(0.01)
    assert any("never became ready" in n for n in notices)
    assert tb.snapshot() == {}


def test_build_mcp_toolbox_import_error_is_empty(tmp_path, monkeypatch):
    import kryonsec.copilot.mcp_tools as mod

    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [{"name": "fetch", "command": "x", "args": [], "env": {}}]
    # simulate the mcp package being absent
    monkeypatch.setattr(
        "builtins.__import__",
        lambda name, *a, **k: (_ for _ in ()).throw(ImportError(name)) if name == "mcp"
        else __import__(name, *a, **k))
    assert mod.build_mcp_toolbox(cfg) == {}
