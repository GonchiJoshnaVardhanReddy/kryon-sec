"""General agent tool loop (v1.1): LLM function-calling for the copilot.

The LLM decides when to use a tool; plain Python executes it (same
"creative LLM, rigid system" rule as the Purple engine):
- only tools whose JSON schema is in the dispatch table exist — anything
  else the LLM names is rejected;
- every call is bounded (output chars, argument validation);
- the loop is capped (max 8 tool rounds) so a chatty model cannot spin.

Message shape follows the OpenAI tool-calling convention that litellm
normalizes across providers: assistant messages carry `tool_calls`,
tool results go back as role:"tool" messages.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from ..config import KryonsecConfig
from ..llm import chat
from .tools import FileAccessDenied, FileTools

log = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 8

# (schema, executor) registered per name; built by build_toolbox().
Toolbox = dict[str, tuple[dict, Callable[..., str]]]


# ---- JSON schemas (only these exist; anything else is rejected) -----------

TOOL_SCHEMAS = {
    "file_read": {
        "type": "function",
        "function": {
            "name": "file_read",
            "description": "Read a text file from disk. Outside the workspace "
                           "the user must approve. Returns the file content.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    "list_dir": {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List the entries of a directory. Outside the "
                           "workspace the user must approve.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    "file_write": {
        "type": "function",
            "function": {
            "name": "file_write",
            "description": "Write text to a file (creates parent directories). "
                           "Outside the workspace the user must approve.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    "web_search": {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web. Returns titled results with "
                           "snippets and URLs.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    "cve_lookup": {
        "type": "function",
        "function": {
            "name": "cve_lookup",
            "description": "Look up a CVE by id (e.g. CVE-2024-1234) in NVD.",
            "parameters": {
                "type": "object",
                "properties": {"cve_id": {"type": "string"}},
                "required": ["cve_id"],
            },
        },
    },
}


def build_toolbox(
    cfg: KryonsecConfig,
    file_tools: FileTools,
    extra: Toolbox | None = None,
) -> Toolbox:
    """The tools the agent may call: built-ins enabled in config plus any
    MCP tools (passed as `extra`, name -> (schema, executor))."""
    from .cve import lookup_cve
    from .websearch import search_web

    limit = cfg.max_tool_output_chars

    def bounded(fn: Callable[..., Any]) -> Callable[..., str]:
        def wrapper(*args: Any, **kwargs: Any) -> str:
            out = str(fn(*args, **kwargs))
            if len(out) > limit:
                out = out[:limit] + f"\n…[truncated at {limit} chars]"
            return out
        return wrapper

    toolbox: Toolbox = {}
    if "file_read" in cfg.enabled_tools:
        toolbox["file_read"] = (
            TOOL_SCHEMAS["file_read"], bounded(file_tools.read_file))
    if "file_write" in cfg.enabled_tools:
        toolbox["file_write"] = (
            TOOL_SCHEMAS["file_write"], bounded(file_tools.write_file))
    if "file_read" in cfg.enabled_tools or "file_write" in cfg.enabled_tools:
        toolbox["list_dir"] = (
            TOOL_SCHEMAS["list_dir"], bounded(file_tools.list_directory))
    if "web_search" in cfg.enabled_tools:
        toolbox["web_search"] = (
            TOOL_SCHEMAS["web_search"],
            bounded(lambda query: search_web(cfg, query) or []))
    if "cve_lookup" in cfg.enabled_tools:
        toolbox["cve_lookup"] = (
            TOOL_SCHEMAS["cve_lookup"], bounded(lookup_cve))
    if extra:
        toolbox.update(extra)
    return toolbox


def _parse_tool_args(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        args = json.loads(raw)
    except ValueError:
        return {}
    return args if isinstance(args, dict) else {}


def execute_tool(toolbox: Toolbox, name: str, raw_args: str | None) -> str:
    """Run one tool call. Unknown tool or a raising tool becomes an error
    MESSAGE for the LLM (the loop continues) — never an exception that
    kills the chat."""
    if name not in toolbox:
        return f"error: unknown tool {name!r} — available: {sorted(toolbox)}"
    schema, executor = toolbox[name]
    args = _parse_tool_args(raw_args)
    # required-argument check: rigid validation, no LLM goodwill assumed
    for req in schema["function"].get("parameters", {}).get("required", []):
        if not args.get(req):
            return f"error: missing required argument {req!r} for {name}"
    try:
        result = executor(**args)
    except FileAccessDenied as e:
        return f"error: access denied: {e}"
    except TypeError as e:
        return f"error: bad arguments for {name}: {e}"
    except Exception as e:
        return f"error: {name} failed: {e}"
    return str(result)


def run_agent(
    cfg: KryonsecConfig,
    messages: list[dict],
    toolbox: Toolbox,
    model: str,
    on_tool: Callable[[str, dict], None] | None = None,
    on_round: Callable[[], None] | None = None,
) -> str:
    """The tool-calling loop. messages is the full LLM message list
    (system + history); it is extended in place with assistant tool_call
    messages and role:"tool" results — the caller decides whether to keep
    them in session memory (we keep only the final text in STM).

    on_round: called before each LLM call (the CLI re-arms its spinner
    there); on_tool: called with each tool name + args before execution
    (the CLI hides the spinner there — tools may prompt for approval).
    """
    messages = list(messages)  # work on a copy; caller owns theirs
    import litellm

    from ..llm import _quiet_litellm, completion_kwargs

    _quiet_litellm()
    provider_kwargs = completion_kwargs(cfg, model, tools=True)

    for _ in range(MAX_TOOL_ROUNDS):
        if on_round:
            on_round()
        resp = litellm.completion(
            model=model,
            messages=messages,
            tools=[toolbox[n][0] for n in toolbox],
            tool_choice="auto",
            timeout=60,
            num_retries=0,
            **provider_kwargs,
        )
        message = resp.choices[0].message
        tool_calls = getattr(message, "tool_calls", None)

        if not tool_calls:
            return message.content or ""

        # re-serialize the assistant tool_call message for the next round
        messages.append({
            "role": "assistant",
            "content": message.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments or "",
                    },
                }
                for tc in tool_calls
            ],
        })
        for tc in tool_calls:
            name = tc.function.name
            args = _parse_tool_args(tc.function.arguments)
            if on_tool:
                on_tool(name, args)
            result = execute_tool(toolbox, name, tc.function.arguments)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })

    # cap reached without a final answer — force a plain-text wrap-up
    log.warning("agent hit the %d-round tool cap; forcing a text answer", MAX_TOOL_ROUNDS)
    messages.append({
        "role": "user",
        "content": "You have used all your tool turns. Answer now from what you have.",
    })
    return chat(cfg, messages, model)
