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
    cfg.mcp_servers = [{"name": "gone", "command": "no-such-bin-xyz", "args": [],
                        "trust": "allow", "allow_tools": ["t"]}]
    notices: list[str] = []
    tb = McpToolbox(cfg, on_notice=notices.append)

    entries = tb.connect_all()
    assert entries == {}
    assert any("not found on PATH" in n for n in notices)


def test_missing_uvx_says_where_uvx_comes_from():
    """'install it' is not actionable for uvx — the user has to be told it
    ships with uv, and that uv has its own installer."""
    from kryonsec.copilot.mcp_tools import _missing_command_message

    message = _missing_command_message("uvx")
    assert "uvx" in message
    assert "astral.sh/uv" in message
    assert "log out and back in" in message  # the installed-but-not-on-PATH case


def test_every_mcp_preset_has_an_install_hint():
    """The wizard warns when a preset's command is missing, and the hint is
    the only actionable part of that warning — a preset added without one
    leaves the user with "not on PATH" and nothing to do about it. The
    installers also pre-install uv so the fetch preset works on a fresh
    machine; this is what keeps that promise honest as presets change."""
    from kryonsec.copilot.mcp_tools import command_install_hint
    from kryonsec.wizard import MCP_PRESETS

    assert MCP_PRESETS, "no presets to check — did they move?"
    for preset in MCP_PRESETS:
        first_token = preset["command"].split()[0]
        assert command_install_hint(first_token), (
            f"MCP preset {preset['name']!r} starts {first_token!r}, which has no "
            "entry in INSTALL_HINTS — the wizard cannot say how to install it"
        )


def test_missing_command_hint_survives_a_windows_path():
    from kryonsec.copilot.mcp_tools import (
        _missing_command_message,
        command_install_hint,
    )

    # a full Windows path still resolves to the uvx hint (basename match)
    assert command_install_hint(r"C:\Users\x\AppData\Local\uv\uvx.exe")
    # unknown tools still get the generic message, just without a hint
    assert command_install_hint("mystery-tool") is None
    assert "not found on PATH" in _missing_command_message("mystery-tool")


def test_connect_all_survives_close_mid_connect(tmp_path, monkeypatch):
    """connect_all() runs on a daemon thread while the user may quit:
    close() during the connect loop must not crash it, and any server
    started after close() is torn down, not leaked."""
    cfg = KryonsecConfig(home=tmp_path)
    cfg.mcp_servers = [{"name": "a", "command": "x", "args": [],
                        "trust": "allow", "allow_tools": ["t"]}]
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
    cfg.mcp_servers = [{"name": "slow", "command": "x", "args": [],
                        "trust": "allow", "allow_tools": ["t"]}]
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
    cfg.mcp_servers = [{"name": "hung", "command": "x", "args": [],
                        "trust": "allow", "allow_tools": ["t"]}]
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
    # context-manager shaped (M7): still usable, still empty, still closes
    with mod.build_mcp_toolbox(cfg) as tools:
        assert tools == {}


# ---- startup failure reporting -------------------------------------------
# A stdio server that dies at launch reported "unhandled errors in a TaskGroup
# (1 sub-exception)" — anyio's wrapper says nothing, the cause is on a leaf
# (or on the server's own stderr, which used to go to /dev/null). The user's
# filesystem server failed on WSL with exactly that useless line.


def test_describe_error_unwraps_exception_group():
    from kryonsec.copilot.mcp_tools import _describe_error

    inner = FileNotFoundError("npx: not found")
    try:
        raise ExceptionGroup("unhandled errors in a TaskGroup", [inner])
    except ExceptionGroup as group:
        described = _describe_error(group)

    assert "unhandled errors in a TaskGroup" not in described
    assert "FileNotFoundError" in described
    assert "npx: not found" in described


def test_describe_error_keeps_plain_exception_readable():
    from kryonsec.copilot.mcp_tools import _describe_error

    assert _describe_error(RuntimeError("boom")) == "RuntimeError: boom"
    assert _describe_error(RuntimeError("")) == "RuntimeError"


def test_describe_error_dedupes_repeated_leaves():
    from kryonsec.copilot.mcp_tools import _describe_error

    same = OSError("connection reset")
    try:
        raise ExceptionGroup("group", [same, same])
    except ExceptionGroup as group:
        assert _describe_error(group) == "OSError: connection reset"


def test_read_errlog_returns_last_lines():
    import tempfile

    from kryonsec.copilot.mcp_tools import _read_errlog

    with tempfile.TemporaryFile() as errlog:
        errlog.write(b"npm WARN deprecated x\n")
        errlog.write(b"npm error 404 Not Found - GET registry/y\n")
        # binary under the hood: the child writes bytes, not str
        assert "404 Not Found" in _read_errlog(errlog)


def test_read_errlog_never_raises():
    from kryonsec.copilot.mcp_tools import _read_errlog

    assert _read_errlog(None) == ""
    assert _read_errlog(object()) == ""  # not a file at all


def test_startup_failure_leads_with_the_servers_own_words():
    from kryonsec.copilot.mcp_tools import _startup_failure

    conn = _ServerConnection()
    conn.stderr_tail = "npm error 404 Not Found"
    conn.error = "ExceptionGroup: unhandled errors in a TaskGroup"
    message = _startup_failure(conn)
    assert message.startswith("npm error 404 Not Found")
    assert "TaskGroup" in message  # the exception is kept as context

    assert _startup_failure(_ServerConnection()) == "server exited during startup"


def test_dead_server_is_reported_with_its_stderr(tmp_path):
    """End to end through connect_all: a server whose command exists but
    dies immediately is reported with what it said, not with the wrapper."""
    import sys

    cfg = KryonsecConfig(home=tmp_path)
    # a real interpreter that exits non-zero and explains itself on stderr
    cfg.mcp_servers = [{
        "name": "dead",
        "command": sys.executable,
        "args": ["-c", "import sys; sys.stderr.write('boom: cannot start\\n'); sys.exit(3)"],
        "trust": "allow", "allow_tools": ["t"],
    }]
    notices: list[str] = []
    tb = McpToolbox(cfg, on_notice=notices.append)
    try:
        tb.connect_all()
    finally:
        tb.close()

    assert any("failed to start" in n for n in notices)
    # the bare anyio wrapper is never an acceptable explanation on its own —
    # that exact sentence was the whole of the old message
    assert not any(
        n.rstrip().endswith("unhandled errors in a TaskGroup (1 sub-exception)")
        for n in notices)


# --- mid-session death: stale tools must leave, status must say so ---------

def test_mid_session_death_unmerges_tools_and_reports(tmp_path):
    notices: list[str] = []
    tb = McpToolbox(KryonsecConfig(home=tmp_path), on_notice=notices.append)
    conn = _ServerConnection("dead")
    entry = ({"function": {"name": "mcp_x"}}, lambda **kw: "x")
    conn.entry["mcp_x"] = entry
    tb.connections.append(conn)   # registered live, as connect_all does
    tb._merge(conn.entry)
    assert "mcp_x" in tb.snapshot()

    # now the death path: capture + clear on the connection, then report
    conn.merged = dict(conn.entry)
    conn.error = "server exited (EOF)"
    conn.entry.clear()
    tb._on_connection_death(conn)

    assert "mcp_x" not in tb.snapshot(), "stale tool served from a dead server"
    status = {s["name"]: s for s in tb.statuses()}["dead"]
    assert status["status"] == "disconnected"
    assert "server exited" in status["detail"]
    assert any("no longer available" in n for n in notices)


def test_death_never_unmerges_another_servers_tool(tmp_path):
    """Same tool name on two servers: the collision rule keeps the FIRST;
    the second server's death must not remove the first's entry."""
    tb = McpToolbox(KryonsecConfig(home=tmp_path))
    first = _ServerConnection("a")
    first_entry = ({"function": {"name": "mcp_dup"}}, lambda **kw: "a")
    first.entry["mcp_dup"] = first_entry
    tb.connections.append(first)
    tb._merge(first.entry)

    second = _ServerConnection("b")
    second.entry["mcp_dup"] = ({"function": {"name": "mcp_dup"}},
                               lambda **kw: "b")
    tb.connections.append(second)
    # never merged (first wins), then it dies
    second.merged = dict(second.entry)
    second.error = "died"
    second.entry.clear()
    tb._on_connection_death(second)

    assert tb.snapshot()["mcp_dup"] is first_entry


def test_death_during_close_is_silent(tmp_path):
    """close() unwinds sessions too — no 'server exited' noise on teardown."""
    notices: list[str] = []
    tb = McpToolbox(KryonsecConfig(home=tmp_path), on_notice=notices.append)
    conn = _ServerConnection("dead")
    conn.entry["mcp_x"] = ({"function": {"name": "mcp_x"}}, lambda **kw: "x")
    tb.connections.append(conn)
    tb._merge(conn.entry)
    tb._closing = True
    conn.merged = dict(conn.entry)
    conn.entry.clear()
    tb._on_connection_death(conn)

    assert notices == []
    assert "mcp_x" in tb.snapshot()  # closing: snapshot dies with the toolbox


def test_connection_loss_detection():
    """The transport-death signal is distinguished from a tool's own
    error — only the former may mark a live server dead."""
    from kryonsec.copilot.mcp_tools import _is_connection_loss

    class FakeMcpError(Exception):
        def __init__(self, code, message):
            super().__init__(code, message)
            self.code = code
            self.message = message

    assert _is_connection_loss(FakeMcpError(-32000, "Connection closed"))
    assert _is_connection_loss(BrokenPipeError())
    assert _is_connection_loss(ConnectionResetError())

    class ClosedResourceError(Exception):
        pass

    assert _is_connection_loss(ClosedResourceError())

    # a tool's OWN error must never be read as a dead server
    assert not _is_connection_loss(FakeMcpError(-32000, "invalid input"))
    assert not _is_connection_loss(ValueError("bad argument"))
