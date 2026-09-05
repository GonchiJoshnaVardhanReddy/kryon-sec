"""Tests for MCP tool wiring (v1.1): schema conversion and the toolbox
wrapper — against fake tool/session objects, no real mcp import."""

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.mcp_tools import McpToolbox


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
    schema = McpToolbox._schema(tool)
    assert schema["type"] == "function"
    fn = schema["function"]
    assert fn["name"] == "fetch"
    assert fn["description"] == "fetch a page"
    assert fn["parameters"]["properties"]["url"]["type"] == "string"
    assert fn["parameters"]["required"] == ["url"]


def test_schema_conversion_empty_schema():
    tool = FakeMcpTool("ping", None, {})
    schema = McpToolbox._schema(tool)
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
    monkeypatch.setattr(tb, "_connect_one",
                        lambda server: attempted.append(server) or {})
    assert tb.connect_all() == {}
    assert attempted == []  # disabled server never started


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
