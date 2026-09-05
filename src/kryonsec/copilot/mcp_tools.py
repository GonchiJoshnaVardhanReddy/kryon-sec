"""MCP server wiring for the general agent (v1.1).

Each enabled MCP server from config.toml ([mcp] servers) is an stdio
server: kryonsec starts it, lists its tools, and exposes them to the
LLM agent alongside the built-in tools. A server that fails to start is
skipped with a console notice — it never blocks the chat.

The `mcp` package is imported lazily: base installs without MCP servers
pay no import cost.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ..config import KryonsecConfig

log = logging.getLogger(__name__)


class McpToolbox:
    """Holds live sessions for enabled MCP servers and exposes their
    tools in agent-toolbox format: name -> (schema, executor)."""

    def __init__(self, cfg: KryonsecConfig):
        self.cfg = cfg
        self.sessions: dict[str, Any] = {}  # server name -> ClientSession

    def connect_all(self) -> dict[str, tuple[dict, Any]]:
        """Start every enabled server; returns the toolbox entries
        (name -> (schema, executor)). Failures are logged and skipped."""
        toolbox: dict[str, tuple[dict, Any]] = {}
        servers = [s for s in self.cfg.mcp_servers if s.get("enabled", True)]
        for server in servers:
            try:
                tools = self._connect_one(server)
            except Exception as e:
                log.warning("MCP server %r failed to start: %s", server.get("name"), e)
                continue
            for name, (schema, executor) in tools.items():
                toolbox[f"mcp_{name}"] = (schema, executor)
        return toolbox

    def _connect_one(self, server: dict) -> dict[str, tuple[dict, Any]]:
        """Start one stdio server, list tools, build executors."""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        import anyio
        import shlex

        command = server["command"]
        parts = shlex.split(command) + list(server.get("args", []))
        params = StdioServerParameters(
            command=parts[0],
            args=parts[1:],
            env=server.get("env") or None,
        )

        entry = {}

        async def _bootstrap() -> None:
            # server stderr (npm warnings, startup banners) goes to
            # /dev/null — the chat stays clean; real failures surface as
            # "failed to start" in our own log
            import sys

            errlog = None
            try:
                errlog = open(os.devnull, "w")
            except OSError:
                pass
            try:
                async with stdio_client(params, errlog=errlog or sys.stderr) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        for tool in listed.tools:
                            entry[self._tool_name(tool)] = (
                                self._schema(tool),
                                self._executor(session, tool.name),
                            )
                        # keep the pipes open for the process lifetime
                        await anyio.sleep_forever()
            finally:
                if errlog:
                    errlog.close()

        # Run the server connection on a background thread so tool calls
        # can be synchronous from the (sync) agent loop.
        import threading

        self._thread = threading.Thread(target=self._run_bg, args=(_bootstrap,), daemon=True)
        self._thread.start()
        # wait briefly for the tool list to arrive
        import time

        for _ in range(50):  # up to ~5s
            if entry:
                break
            time.sleep(0.1)
        return entry

    def _run_bg(self, coro_factory):
        import anyio

        try:
            anyio.run(coro_factory)
        except Exception as e:  # server died / exited
            log.info("MCP background session ended: %s", e)

    @staticmethod
    def _tool_name(tool: Any) -> str:
        return getattr(tool, "name", "tool")

    @staticmethod
    def _schema(tool: Any) -> dict:
        import json as _json

        props = {}
        required: list[str] = []
        schema = getattr(tool, "inputSchema", None) or {}
        props = schema.get("properties", {})
        required = list(schema.get("required", []))
        return {
            "type": "function",
            "function": {
                "name": getattr(tool, "name", "tool"),
                "description": (getattr(tool, "description", "") or "")[:500],
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            },
        }

    def _executor(self, session: Any, tool_name: str):
        def call(**kwargs: Any) -> str:
            import anyio

            result = anyio.run(session.call_tool, tool_name, kwargs)
            parts = []
            for content in (getattr(result, "content", None) or []):
                text = getattr(content, "text", None)
                if text:
                    parts.append(text)
            return "\n".join(parts) if parts else str(result)
        return call

    def close(self) -> None:
        """Best-effort teardown (daemon threads die with the process)."""
        self.sessions.clear()


def build_mcp_toolbox(cfg: KryonsecConfig) -> dict[str, tuple[dict, Any]]:
    """Convenience wrapper: connect all enabled servers, return the
    toolbox entries (possibly empty)."""
    try:
        return McpToolbox(cfg).connect_all()
    except ImportError:
        log.info("mcp package not installed — MCP tools unavailable")
        return {}
    except Exception as e:
        log.warning("MCP connect failed: %s", e)
        return {}
