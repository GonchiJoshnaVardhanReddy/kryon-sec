"""Tests for the general agent tool loop (v1.1): dispatch, validation,
the loop itself with a fake litellm, and the iteration cap."""

import json

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.agent import (
    MAX_TOOL_ROUNDS,
    build_toolbox,
    execute_tool,
    run_agent,
)
from kryonsec.copilot.tools import FileTools


@pytest.fixture()
def cfg(tmp_path):
    c = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    c.ensure_dirs()
    return c


class FakeFunction:
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments


class FakeToolCall:
    def __init__(self, call_id: str, name: str, arguments: str):
        self.id = call_id
        self.function = FakeFunction(name, arguments)


class FakeMessage:
    def __init__(self, content, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class FakeResponse:
    def __init__(self, message):
        self.choices = [type("Choice", (), {"message": message})()]


def _patch_completion(monkeypatch, responses):
    """responses: list of FakeResponse, consumed in order."""
    calls = []

    def fake_completion(**kwargs):
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr("litellm.completion", fake_completion)
    return calls


# ---- execute_tool ---------------------------------------------------------

def test_execute_tool_unknown_name_is_an_error_message(cfg):
    tb = build_toolbox(cfg, FileTools(cfg))
    out = execute_tool(tb, "rm_rf", None)
    assert out.startswith("error: unknown tool")
    assert "rm_rf" in out


def test_execute_tool_missing_required_arg(cfg):
    tb = build_toolbox(cfg, FileTools(cfg))
    out = execute_tool(tb, "file_write", json.dumps({"path": "/tmp/x"}))
    assert out.startswith("error: missing required argument")
    assert "content" in out


def test_execute_tool_bad_json_is_missing_args(cfg):
    tb = build_toolbox(cfg, FileTools(cfg))
    out = execute_tool(tb, "file_write", "not json at all")
    assert "missing required argument" in out


def test_execute_tool_denied_write_is_error_message(cfg):
    tb = build_toolbox(cfg, FileTools(cfg, approver=lambda req: False))
    out = execute_tool(tb, "file_write",
                       json.dumps({"path": str(cfg.home / "x.txt"), "content": "hi"}))
    assert out.startswith("error: access denied")


def test_execute_tool_success(cfg):
    tb = build_toolbox(cfg, FileTools(cfg))
    out = execute_tool(tb, "file_write",
                       json.dumps({"path": str(cfg.workspace / "a.txt"), "content": "hi"}))
    assert "a.txt" in out


# ---- build_toolbox respects config ---------------------------------------

def test_toolbox_respects_enabled_tools(cfg):
    cfg.enabled_tools = ["web_search"]
    tb = build_toolbox(cfg, FileTools(cfg))
    assert set(tb) == {"web_search"}


def test_toolbox_all_tools_default(cfg):
    tb = build_toolbox(cfg, FileTools(cfg))
    assert "file_read" in tb and "file_write" in tb
    assert "web_search" in tb and "cve_lookup" in tb and "list_dir" in tb


def test_toolbox_extra_mcp_tools_win(cfg):
    fake_mcp_tool = ({"type": "function", "function": {"name": "mcp_fetch",
                      "parameters": {"type": "object", "properties": {}}}},
                     lambda **kw: "fetched")
    tb = build_toolbox(cfg, FileTools(cfg), extra={"mcp_fetch": fake_mcp_tool})
    assert tb["mcp_fetch"][0] is fake_mcp_tool[0]


# ---- run_agent loop --------------------------------------------------------

def test_run_agent_tool_round_then_answer(cfg, monkeypatch):
    """One tool call, then the final answer — the classic shape."""
    target = cfg.workspace / "hello.txt"
    target.write_text("file body here", encoding="utf-8")

    tool_call = FakeToolCall("call-1", "file_read", json.dumps({"path": str(target)}))
    responses = [
        FakeResponse(FakeMessage(None, [tool_call])),          # asks for the tool
        FakeResponse(FakeMessage("The file contains: file body here")),  # final
    ]
    calls = _patch_completion(monkeypatch, responses)

    tb = build_toolbox(cfg, FileTools(cfg))
    events = []
    reply = run_agent(cfg, [{"role": "user", "content": "read it"}], tb,
                      "gpt-4o-mini", on_tool=lambda n, a: events.append((n, a)))

    assert reply == "The file contains: file body here"
    assert events == [("file_read", {"path": str(target)})]
    # round 2 saw the tool result message
    msgs = calls[1]["messages"]
    tool_msgs = [m for m in msgs if m.get("role") == "tool"]
    assert len(tool_msgs) == 1
    assert "file body here" in tool_msgs[0]["content"]


def test_run_agent_no_tools_straight_answer(cfg, monkeypatch):
    responses = [FakeResponse(FakeMessage("just a normal answer"))]
    _patch_completion(monkeypatch, responses)
    tb = build_toolbox(cfg, FileTools(cfg))
    reply = run_agent(cfg, [{"role": "user", "content": "hi"}], tb, "gpt-4o-mini")
    assert reply == "just a normal answer"


def test_run_agent_calls_on_round_before_each_llm_call(cfg, monkeypatch):
    """on_round is the spinner re-arm hook: one call per LLM round."""
    tool_call = FakeToolCall(
        "call-1", "file_read",
        json.dumps({"path": str(cfg.workspace / "hello.txt")}))
    (cfg.workspace / "hello.txt").write_text("x", encoding="utf-8")
    responses = [
        FakeResponse(FakeMessage(None, [tool_call])),
        FakeResponse(FakeMessage("done")),
    ]
    _patch_completion(monkeypatch, responses)
    tb = build_toolbox(cfg, FileTools(cfg))
    rounds = []
    run_agent(cfg, [{"role": "user", "content": "read"}], tb, "gpt-4o-mini",
              on_round=lambda: rounds.append(1))
    assert len(rounds) == 2


def test_run_agent_unknown_tool_still_finishes(cfg, monkeypatch):
    """LLM hallucinates a tool name -> error message goes back to it,
    loop continues, final answer still produced."""
    bad_call = FakeToolCall("call-1", "launch_missiles", "{}")
    responses = [
        FakeResponse(FakeMessage(None, [bad_call])),
        FakeResponse(FakeMessage("I cannot do that")),
    ]
    calls = _patch_completion(monkeypatch, responses)
    tb = build_toolbox(cfg, FileTools(cfg))
    reply = run_agent(cfg, [{"role": "user", "content": "nuke"}], tb, "gpt-4o-mini")
    assert reply == "I cannot do that"
    tool_msgs = [m for m in calls[1]["messages"] if m.get("role") == "tool"]
    assert tool_msgs[0]["content"].startswith("error: unknown tool")


def test_run_agent_cap_forces_text_answer(cfg, monkeypatch):
    """A model that never stops calling tools hits the cap; the loop then
    forces a plain text answer via chat()."""
    call = FakeToolCall("c", "file_read",
                        json.dumps({"path": str(cfg.workspace / "hello.txt")}))
    forever = [FakeResponse(FakeMessage(None, [call]))] * MAX_TOOL_ROUNDS

    forced_answer = "the forced answer"
    monkeypatch.setattr(
        "kryonsec.copilot.agent.chat",
        lambda c, msgs, model: forced_answer)
    _patch_completion(monkeypatch, forever)

    (cfg.workspace / "hello.txt").write_text("x", encoding="utf-8")
    tb = build_toolbox(cfg, FileTools(cfg))
    reply = run_agent(cfg, [{"role": "user", "content": "loop"}], tb, "gpt-4o-mini")
    assert reply == "the forced answer"


# ---- credentials pass-through (config.toml keys must reach litellm) --------

def test_run_agent_passes_openai_api_key(cfg, monkeypatch):
    """A key stored by the wizard (config.toml) is handed to litellm
    explicitly — litellm only reads the env var otherwise (regression:
    'Missing credentials' after v1.1 removed .env loading)."""
    cfg.openai_api_key = "sk-from-toml"
    responses = [FakeResponse(FakeMessage("answer"))]
    calls = _patch_completion(monkeypatch, responses)
    tb = build_toolbox(cfg, FileTools(cfg))
    run_agent(cfg, [{"role": "user", "content": "hi"}], tb, "gpt-4o-mini")
    assert calls[0].get("api_key") == "sk-from-toml"


def test_run_agent_ollama_gets_api_base_not_key(cfg, monkeypatch):
    cfg.ollama_host = "localhost:11434"
    cfg.openai_api_key = "sk-irrelevant"
    responses = [FakeResponse(FakeMessage("answer"))]
    calls = _patch_completion(monkeypatch, responses)
    tb = build_toolbox(cfg, FileTools(cfg))
    run_agent(cfg, [{"role": "user", "content": "hi"}], tb, "ollama/llama3.1")
    assert calls[0].get("api_base", "").endswith(":11434")
    assert "api_key" not in calls[0]
