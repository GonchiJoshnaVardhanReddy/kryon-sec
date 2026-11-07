"""Phase 2A tests: the secure MCP tool registry.

Most tests run against duck-typed fakes of the connection objects (the
conventions of tests/test_mcp_tools.py). Three tests run the REAL
trusted fixture server (tests/mcp_fixture_server.py) over stdio —
deterministic, harmless, no network, no scans. The Mode B prohibition
tests scan the source tree instead of executing anything.
"""

import json
import sys
import threading
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.mcp_registry import (
    DEFAULT_MAX_OUTPUT_CHARS,
    MAX_HIT_DESCRIPTION_CHARS,
    UNTRUSTED_MARKER,
    McpApprovalRequest,
    McpPolicyError,
    McpRegistry,
    McpExecutionPolicy,
    REGISTRY_TOOL_KEYS,
    terminal_mcp_approver,
    validate_arguments,
)
from kryonsec.copilot.tool_audit import ToolAuditLog

FIXTURE = Path(__file__).parent / "mcp_fixture_server.py"
FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE"


# ---- fakes (duck-typed to _ServerConnection / McpToolbox) --------------------

class FakeConn:
    def __init__(self, name, tools):
        self.name = name
        self.entry = {f"mcp_{k}": v for k, v in tools.items()}
        self.ready = threading.Event()
        self.ready.set()


def tool_schema(name, description="", properties=None, required=None):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties or {},
                "required": required or [],
            },
        },
    }


def echo_tool(output="ECHOED"):
    return (tool_schema("echo", "Echo the text", {"text": {"type": "string"}},
                        ["text"]),
            lambda text="": output)


class FakeToolbox:
    def __init__(self, connections, statuses=None):
        self.connections = connections
        self._statuses = statuses or [
            {"name": c.name, "status": "connected",
             "detail": f"{len(c.entry)} tool(s)", "tools": len(c.entry)}
            for c in connections
        ]

    def statuses(self):
        return [dict(s) for s in self._statuses]

    def snapshot(self):
        return {}


def _cfg(home, rows):
    return KryonsecConfig(home=home, mcp_servers=rows)


def _registry(tmp_path, rows, connections, statuses=None, approver=None):
    cfg = _cfg(tmp_path, rows)
    box = FakeToolbox(connections, statuses)
    reg = McpRegistry(cfg, box, approver=approver)
    audit = reg.audit
    return reg, cfg, box, audit


def _events(audit):
    return [json.loads(line) for line in
            open(audit.path, encoding="utf-8") if line.strip()]


def _event_names(audit):
    return [e["event"] for e in _events(audit)]


# ---- policy parsing: fail-closed defaults -----------------------------------

def test_row_without_policy_is_discovery_only():
    """No policy keys -> trust disabled: nothing is callable, ever."""
    policy = McpExecutionPolicy.from_row({"name": "x", "command": "x"})
    assert policy.trust == "disabled"
    assert not policy.allows("echo")
    assert not policy.allow_all_tools


def test_explicit_policy_fields_round_trip():
    policy = McpExecutionPolicy.from_row({
        "name": "x", "trust": "allow", "allow_tools": ["echo", "add"]})
    assert policy.trust == "allow" and policy.allows("echo")
    assert not policy.allows("pong")          # unknown -> disabled
    wildcard = McpExecutionPolicy.from_row(
        {"name": "x", "trust": "ask", "allow_tools": ["*"]})
    assert wildcard.allow_all_tools


def test_policy_value_ranges_fail_closed():
    with pytest.raises(McpPolicyError):
        McpExecutionPolicy.from_row({"trust": "maybe"})
    with pytest.raises(McpPolicyError):
        McpExecutionPolicy.from_row({"call_timeout_s": 10_000})
    with pytest.raises(McpPolicyError):
        McpExecutionPolicy.from_row({"max_concurrent_calls": 99})
    with pytest.raises(McpPolicyError):
        McpExecutionPolicy.from_row({"allow_tools": 42})


def test_row_claiming_sandbox_is_refused():
    """A remote MCP server must never be describable as sandboxed."""
    with pytest.raises(McpPolicyError):
        McpExecutionPolicy.from_row({"sandboxed": True})
    with pytest.raises(McpPolicyError):
        McpExecutionPolicy.from_row({"policy": {"sandboxed": "yes"}})


# ---- discovery (fakes) -------------------------------------------------------

def test_list_connections_reports_trust(tmp_path):
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "command": "x", "trust": "allow",
         "allow_tools": ["echo"]},
        {"name": "b", "command": "y"},        # no policy -> disabled
    ], [FakeConn("a", {"echo": echo_tool()})])
    out = reg.list_mcp_connections()
    parsed = json.loads(out)
    by_name = {c["connection"]: c for c in parsed["connections"]}
    assert by_name["a"]["call_trust"] == "allow"
    assert by_name["b"]["call_trust"] == "disabled"
    assert "command" not in out and "env" not in out   # secrets never shown
    ok, reason = audit.verify()
    assert ok, reason
    assert "mcp_connection_listed" in _event_names(audit)


def test_search_is_bounded_and_redacted(tmp_path):
    noisy = "search helper " + FAKE_SECRET + " " + "y" * 500
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"]},
    ], [FakeConn("a", {"echo": (tool_schema("echo", noisy),
                                 lambda text="": "")})])
    parsed = json.loads(reg.search_mcp_tools("echo"))
    hit = parsed["hits"][0]
    assert hit["address"] == "a::echo"
    assert FAKE_SECRET not in hit["description"]
    assert len(hit["description"]) <= MAX_HIT_DESCRIPTION_CHARS + 8
    assert hit["callable"] is True
    assert "untrusted" in parsed["note"]


def test_schema_on_demand_and_refusals(tmp_path):
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"]},
    ], [FakeConn("a", {"echo": echo_tool()})])
    schema = json.loads(reg.get_mcp_tool_schema("a", "echo"))
    assert schema["parameters"]["properties"]["text"]["type"] == "string"
    assert schema["description"] == "Echo the text"

    refused = reg.get_mcp_tool_schema("a", "nonexistent")
    assert "error:" in refused
    assert "no tool" in refused
    assert "mcp_tool_refused" in _event_names(audit)

    # unknown connection, and a dead-server specific reason
    assert "unknown MCP connection" in reg.get_mcp_tool_schema(
        "ghost", "echo")
    dead_box = [dict(_default_status(), name="gone",
                     status="disconnected", detail="exited")]
    reg2, _, _, _ = _registry(
        tmp_path, [{"name": "gone", "command": "z"}],
        [], statuses=dead_box)
    assert "not usable" in reg2.get_mcp_tool_schema("gone", "echo")


def _default_status():
    return {"name": "", "status": "connected", "detail": "", "tools": 0}


def test_describe_hides_dead_tools_and_claims_no_sandbox(tmp_path):
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["*"]},
    ], [FakeConn("a", {"echo": echo_tool()})])
    out = reg.describe_mcp_connection("a")
    parsed = json.loads(out)
    assert parsed["healthy"] is True
    assert parsed["call_trust"] == "allow"
    assert "sandbox" not in out
    # a disconnected server advertises NO tools
    reg2, _, _, _ = _registry(
        tmp_path, [{"name": "gone", "command": "z"}],
        [], statuses=[dict(_default_status(), name="gone",
                           status="disconnected", detail="exited")])
    parsed2 = json.loads(reg2.describe_mcp_connection("gone"))
    assert parsed2["healthy"] is False and parsed2["tools"] == []


def test_duplicate_tool_names_are_addressed_per_connection(tmp_path):
    rows = [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"]},
        {"name": "b", "trust": "disabled"},
    ]
    conns = [FakeConn("a", {"echo": echo_tool("FROM_A")}),
             FakeConn("b", {"echo": echo_tool("FROM_B")})]
    reg, cfg, box, audit = _registry(tmp_path, rows, conns)
    # both connections HAVE an echo tool (duplicate name), but only a
    # is allowed to run it — and the call binds a's executor
    out = reg.call_mcp_tool("a", "echo", {"text": "x"})
    assert out.startswith("FROM_A")
    out_b = reg.call_mcp_tool("b", "echo", {"text": "x"})
    assert "not authorized" in out_b
    # search shows both, with honest callable flags
    hits = json.loads(reg.search_mcp_tools("echo"))["hits"]
    assert {h["address"] for h in hits} == {"a::echo", "b::echo"}
    calls = {h["address"]: h["callable"] for h in hits}
    assert calls == {"a::echo": True, "b::echo": False}


# ---- execution policies (fakes) ----------------------------------------------

def test_unknown_tool_defaults_to_disabled(tmp_path):
    """The mandate: a tool the policy did not name is never callable."""
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["other"]},
    ], [FakeConn("a", {"echo": echo_tool()})])
    out = reg.call_mcp_tool("a", "echo", {"text": "x"})
    assert "not authorized" in out and "disabled" in out
    assert "mcp_tool_refused" in _event_names(audit)
    ok, reason = audit.verify()
    assert ok, reason


def test_connection_without_policy_refuses_execution(tmp_path):
    """A server with no policy row cannot run anything (fail closed)."""
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "known", "trust": "allow", "allow_tools": ["*"]},
    ], [FakeConn("other", {"echo": echo_tool()})])
    out = reg.call_mcp_tool("other", "echo", {})
    assert "no execution policy" in out


def test_authorized_invocation_audits_untrusted_result(tmp_path):
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"]},
    ], [FakeConn("a", {"echo": echo_tool("ECHOED")})])
    out = reg.call_mcp_tool("a", "echo", {"text": "hi"})
    assert out.startswith("ECHOED")
    assert UNTRUSTED_MARKER in out
    names = _event_names(audit)
    assert "mcp_tool_invoked" in names
    # audit carries tool identity only: never argument values
    invoked = [e for e in _events(audit)
               if e["event"] == "mcp_tool_invoked"][0]
    assert invoked["argument_keys"] == ["text"]
    assert "hi" not in json.dumps(invoked)


def _ask_registry(tmp_path, approver):
    rows = [{"name": "a", "trust": "ask", "allow_tools": ["echo"]}]
    return _registry(tmp_path, rows, [FakeConn("a", {"echo": echo_tool()})],
                     approver=approver)


def test_ask_without_approver_wired_is_refused(tmp_path):
    reg, cfg, box, audit = _ask_registry(tmp_path, None)
    out = reg.call_mcp_tool("a", "echo", {"text": "x"})
    assert "no approval gate is wired" in out
    assert "mcp_tool_refused" in _event_names(audit)


def test_ask_with_approver_shows_keys_never_values(tmp_path):
    seen = []
    def approver(req):
        seen.append(req)
        return False
    reg, cfg, box, audit = _ask_registry(tmp_path, approver)
    out = reg.call_mcp_tool("a", "echo", {"text": "super-secret-value"})
    assert "not approved" in out
    assert seen[0].argument_keys == ["text"]      # keys only
    assert "super-secret-value" not in json.dumps(seen[0].__dict__)
    events = _events(audit)
    assert "mcp_tool_refused" in [e["event"] for e in events]
    # the audit of the refusal must not carry the secret value either
    refused = [e for e in events if e["event"] == "mcp_tool_refused"][0]
    assert "super-secret-value" not in json.dumps(refused)


def test_ask_approver_yes_then_executes(tmp_path):
    reg, cfg, box, audit = _ask_registry(
        tmp_path, lambda req: True)
    out = reg.call_mcp_tool("a", "echo", {"text": "hi"})
    assert out.startswith("ECHOED")
    assert "mcp_tool_approved" in _event_names(audit)


def test_approver_crash_refuses(tmp_path):
    def approver(req):
        raise RuntimeError("terminal blew up")
    reg, cfg, box, audit = _ask_registry(tmp_path, approver)
    assert "approval gate failed" in reg.call_mcp_tool(
        "a", "echo", {"text": "x"})


def test_schema_validation_failures(tmp_path):
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"]},
    ], [FakeConn("a", {"echo": echo_tool()})])
    assert "missing required" in reg.call_mcp_tool("a", "echo", {})
    assert "must be string" in reg.call_mcp_tool(
        "a", "echo", {"text": 42})
    assert "unexpected argument" in reg.call_mcp_tool(
        "a", "echo", {"text": "x", "extra": 1})
    refused = [e for e in _events(audit)
               if e["event"] == "mcp_tool_refused"]
    assert any("invalid arguments" in e.get("reason", "")
               for e in refused)
    assert validate_arguments(
        {"properties": {"a": {"type": "number"}}, "required": []},
        {"a": 3}) == ""
    assert validate_arguments({}, {"a": 3})  # no usable schema -> refused


def test_result_size_bounded(tmp_path):
    big = "Z" * (DEFAULT_MAX_OUTPUT_CHARS + 5000)
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"]},
    ], [FakeConn("a", {"echo": echo_tool(big)})])
    out = reg.call_mcp_tool("a", "echo", {"text": "x"})
    assert out.startswith("Z")
    assert "truncated at" in out
    assert len(out) <= DEFAULT_MAX_OUTPUT_CHARS + 200


def test_result_secrets_redacted_at_boundary(tmp_path):
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"]},
    ], [FakeConn("a", {"echo": echo_tool(
        f"result with {FAKE_SECRET} inside")})])
    out = reg.call_mcp_tool("a", "echo", {"text": "x"})
    assert FAKE_SECRET not in out
    assert "«SECRET_" in out or "SECRET" in out


def test_concurrency_cap_refuses_without_queueing(tmp_path):
    """max_concurrent_calls=1: a second concurrent call is REFUSED
    (deterministic), then the release unblocks the first."""
    release = threading.Event()
    held = threading.Event()

    def blocking_executor(text=""):
        held.set()
        release.wait(5)
        return "BLOCKED-THEN-DONE"

    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"],
         "max_concurrent_calls": 1},
    ], [FakeConn("a", {"echo": (
        tool_schema("echo", "e", {"text": {"type": "string"}}, ["text"]),
        blocking_executor)})])
    thread = threading.Thread(
        target=reg.call_mcp_tool, args=("a", "echo", {"text": "x"}),
        daemon=True)
    thread.start()
    assert held.wait(5), "first call never started"
    second = reg.call_mcp_tool("a", "echo", {"text": "y"})
    assert "concurrency cap" in second
    release.set()
    thread.join(10)
    assert not thread.is_alive()
    names = _event_names(audit)
    assert "mcp_tool_refused" in names


def test_policy_timeout_refuses_sloppy_tool(tmp_path):
    rows = [{"name": "a", "trust": "allow", "allow_tools": ["echo"],
             "call_timeout_s": 1}]
    def hung_tool(text=""):
        import time
        time.sleep(2.5)
        return "too late"
    reg, cfg, box, audit = _registry(tmp_path, rows, [FakeConn("a", {
        "echo": (tool_schema("echo", "e", {"text": {"type": "string"}},
                            ["text"]), hung_tool)})])
    out = reg.call_mcp_tool("a", "echo", {"text": "x"})
    assert "timed out" in out
    assert "mcp_tool_failed" in _event_names(audit)


def test_executor_crash_fails_not_kills(tmp_path):
    def broken(text=""):
        raise RuntimeError("server exploded")
    reg, cfg, box, audit = _registry(tmp_path, [
        {"name": "a", "trust": "allow", "allow_tools": ["echo"]},
    ], [FakeConn("a", {"echo": (
        tool_schema("echo", "e", {"text": {"type": "string"}}, ["text"]),
        broken)})])
    out = reg.call_mcp_tool("a", "echo", {"text": "x"})
    assert "failed" in out
    assert "mcp_tool_failed" in _event_names(audit)
    ok, reason = audit.verify()
    assert ok, reason


# ---- the five-tool toolbox surface ------------------------------------------

def test_llm_tools_is_exactly_the_five_operations(tmp_path):
    reg, cfg, box, audit = _registry(tmp_path, [], [])
    entries = reg.llm_tools()
    assert set(entries) == set(REGISTRY_TOOL_KEYS) == {
        "list_mcp_connections", "search_mcp_tools", "get_mcp_tool_schema",
        "describe_mcp_connection", "call_mcp_tool"}
    for key, (schema, executor) in entries.items():
        assert callable(executor)
        assert schema["function"]["name"] == key


def test_terminal_approver_never_consents_without_tty(monkeypatch):
    """Trust 'ask' + a non-tty stdin approves nothing (silence is never
    consent — same rule as the Gate-3 approver)."""
    import io
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    assert terminal_mcp_approver()(McpApprovalRequest(
        connection="a", tool="echo", argument_keys=[])) is False


# ---- the REAL fixture: full path over stdio ---------------------------------

def _fixture_row(**extra):
    row = {"name": "fixture", "command": sys.executable,
           "args": [str(FIXTURE)]}
    row.update(extra)
    return row


def test_real_fixture_authorized_round_trip(tmp_path):
    from kryonsec.copilot.mcp_tools import McpToolbox
    cfg = _cfg(tmp_path, [_fixture_row(trust="allow",
                                      allow_tools=["echo_upper", "add",
                                                   "big"])])
    box = McpToolbox(cfg)
    entries = box.connect_all()
    try:
        assert any("echo_upper" in k for k in entries)
        reg = McpRegistry(cfg, box, approver=terminal_mcp_approver())

        # 1. connection discovery
        listed = json.loads(reg.list_mcp_connections())
        conn = listed["connections"][0]
        assert conn["connection"] == "fixture"
        assert conn["status"] == "connected"
        assert conn["call_trust"] == "allow"

        # 2. tool search (neutral, bounded)
        hits = json.loads(reg.search_mcp_tools("uppercase"))["hits"]
        assert hits and hits[0]["tool"] == "echo_upper"
        assert hits[0]["callable"] is True

        # 3. on-demand schema
        schema = json.loads(reg.get_mcp_tool_schema("fixture", "add"))
        assert schema["parameters"]["properties"]["a"]["type"] == "number"

        # 4. authorized invocation
        out = reg.call_mcp_tool("fixture", "echo_upper",
                                {"text": "hello"})
        assert out.startswith("HELLO")
        assert UNTRUSTED_MARKER in out

        # 5. unknown-tool rejection: 'pong' exists on the server but is
        # not in this connection's allow list
        assert "not authorized" in reg.call_mcp_tool("fixture", "pong", {})

        # 6. schema validation failure (wrong type)
        assert "must be number" in reg.call_mcp_tool(
            "fixture", "add", {"a": "1", "b": 1})

        # 7. result-size bounding through the real server
        out = reg.call_mcp_tool("fixture", "big", {"n": 50_000})
        assert out.count("X") <= DEFAULT_MAX_OUTPUT_CHARS

        ok, reason = reg.audit.verify()
        assert ok, reason
    finally:
        box.close()


def test_real_fixture_untrusted_description_and_leaky_result(tmp_path):
    """Descriptions and results are data: the hostile description is
    bounded/redacted in search, the fake secret is redacted from the
    result, and nothing in either executes."""
    from kryonsec.copilot.mcp_tools import McpToolbox
    cfg = _cfg(tmp_path, [_fixture_row(trust="allow",
                                      allow_tools=["greet", "leaky"])])
    box = McpToolbox(cfg)
    entries = box.connect_all()
    try:
        reg = McpRegistry(cfg, box, approver=terminal_mcp_approver())
        hits = json.loads(reg.search_mcp_tools("greet"))["hits"]
        assert hits, "greet should be discoverable"
        description = hits[0]["description"]
        assert len(description) <= MAX_HIT_DESCRIPTION_CHARS + 8
        # the hostile text stays DATA — nothing followed it
        parses = json.loads(reg.describe_mcp_connection("fixture"))
        assert parses["healthy"] is True

        out = reg.call_mcp_tool("fixture", "leaky", {"text": "leak"})
        assert FAKE_SECRET not in out            # redacted at the boundary
        assert UNTRUSTED_MARKER in out           # framed as untrusted data
        ok, reason = reg.audit.verify()
        assert ok, reason
        # the audit never carries raw server results
        raw = open(reg.audit.path, encoding="utf-8").read()
        assert FAKE_SECRET not in raw
    finally:
        box.close()


def test_real_fixture_dead_server_fails_closed(tmp_path):
    from kryonsec.copilot.mcp_tools import McpToolbox
    notices = []
    cfg = _cfg(tmp_path, [{"name": "ghost",
                           "command": "kryonsec-not-a-real-command-xyz"}])
    box = McpToolbox(cfg, on_notice=notices.append)
    entries = box.connect_all()
    try:
        assert entries == {}                     # nothing to expose
        reg = McpRegistry(cfg, box, approver=terminal_mcp_approver())
        # row exists but carries no trust policy -> disabled default
        out = reg.call_mcp_tool("ghost", "echo", {})
        assert "not authorized" in out
        described = json.loads(reg.describe_mcp_connection("ghost"))
        assert described["healthy"] is False
        assert "kryonsec-not-a-real-command" not in json.dumps(described)
    finally:
        box.close()


# ---- Mode A / Mode B boundary (static, non-executing) ------------------------

def test_purple_never_imports_the_mcp_registry():
    """Mode B must not reach MCP integration — any purple module that
    imports the registry (or any of copilot's MCP machinery) fails here.
    (The single consciously-reviewed exception is enrichment->copilot.cve,
    unrelated to MCP.)"""
    purple = Path(__file__).parent.parent / "src" / "kryonsec" / "purple"
    offenders = []
    for path in purple.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if ("mcp_registry" in text or "copilot.mcp" in text
                or "from mcp " in text or "import mcp" in text):
            offenders.append(path.name)
    assert offenders == [], \
        f"Mode B modules import MCP machinery: {offenders}"


def test_registry_is_host_code_not_a_spawner():
    """The registry itself never spawns a process: it is a host-side
    policy/dispatch layer; the only thing it starts is nothing."""
    text = Path(
        __file__).parent.parent / "src" / "kryonsec" / "copilot" \
        / "mcp_registry.py"
    source = text.read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "Popen" not in source
    assert ".spawn(" not in source
