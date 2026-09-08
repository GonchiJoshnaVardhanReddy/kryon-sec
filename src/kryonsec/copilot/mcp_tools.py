"""MCP server wiring for the general agent (v1.1).

Each enabled MCP server from config.toml ([mcp] servers) is an stdio
server: kryonsec starts it, lists its tools, and exposes them to the
LLM agent alongside the built-in tools. A server that fails to start is
skipped with a console notice — it never blocks the chat.

The `mcp` package is imported lazily: base installs without MCP servers
pay no import cost.

Threading model: each server runs on its own daemon thread inside
anyio.run (asyncio backend). Tool executors marshal the call onto that
same loop with asyncio.run_coroutine_threadsafe — awaiting session
objects on a *different* loop raises "Future attached to a different
loop", so a fresh anyio.run per call (the v1.1 bug) is never done.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ..config import KryonsecConfig

log = logging.getLogger(__name__)

# one tool call may legitimately take a while (searches, generation) —
# but never hang the chat forever
TOOL_CALL_TIMEOUT_S = 120


class _ServerConnection:
    """One live stdio server: its background loop, stop event, entries."""

    def __init__(self) -> None:
        self.loop: Any = None            # the asyncio loop (anyio backend)
        self.stop_event: Any = None      # asyncio.Event set by close()
        self.ready: Any = None           # threading.Event: tools listed
        self.entry: dict[str, tuple[dict, Any]] = {}
        self.error: str = ""

    async def run(self, params: Any, errlog: Any) -> None:
        """Bootstrap + park: initialize, list tools, keep pipes open."""
        import asyncio

        from mcp import ClientSession
        from mcp.client.stdio import stdio_client

        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()
        try:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    for tool in listed.tools:
                        name = _tool_name(tool)
                        schema = _schema(tool)
                        # the schema name the LLM sees MUST equal the
                        # dispatch key — else every call is "unknown tool"
                        schema["function"]["name"] = f"mcp_{name}"
                        self.entry[f"mcp_{name}"] = (
                            schema, self._executor(session, tool.name),
                        )
                    self.ready.set()
                    await self.stop_event.wait()
        except Exception as e:  # server died / exited — tools die with it
            self.error = str(e)
            self.entry.clear()
            log.info("MCP background session ended: %s", e)
        finally:
            self.ready.set()  # unblock the waiting connect thread

    def _executor(self, session: Any, tool_name: str):
        def call(**kwargs: Any) -> str:
            import asyncio
            from concurrent.futures import TimeoutError as FutTimeout

            loop = self.loop
            if loop is None or loop.is_closed():
                return f"error: MCP server session is not running"
            coro = session.call_tool(tool_name, kwargs)
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            try:
                result = future.result(timeout=TOOL_CALL_TIMEOUT_S)
            except FutTimeout:
                future.cancel()
                return f"error: MCP tool {tool_name!r} timed out"
            parts = []
            for content in (getattr(result, "content", None) or []):
                text = getattr(content, "text", None)
                if text:
                    parts.append(text)
            return "\n".join(parts) if parts else str(result)
        return call

    def close(self) -> None:
        """Best-effort: exit the async contexts so the process ends."""
        loop, ev = self.loop, self.stop_event
        if loop is None or ev is None:
            return
        try:
            if not loop.is_closed():
                loop.call_soon_threadsafe(ev.set)
        except RuntimeError:  # loop already stopped
            pass


def _split_command(command: str) -> list[str]:
    """config command string -> argv list, Windows-safe.

    POSIX shlex eats backslashes (C:\\tools\\x.exe -> C:toolsx.exe), so on
    Windows we split in non-POSIX mode and strip the kept quotes.
    """
    import shlex

    if os.name == "nt":
        parts = [p.strip('"') for p in shlex.split(command, posix=False)]
        return [p for p in parts if p]
    return shlex.split(command)


class McpToolbox:
    """Holds live connections for enabled MCP servers and exposes their
    tools in agent-toolbox format: name -> (schema, executor)."""

    def __init__(self, cfg: KryonsecConfig):
        self.cfg = cfg
        self.connections: list[_ServerConnection] = []

    def connect_all(self) -> dict[str, tuple[dict, Any]]:
        """Start every enabled server; returns the toolbox entries
        (name -> (schema, executor)). Failures are logged and skipped."""
        toolbox: dict[str, tuple[dict, Any]] = {}
        servers = [s for s in self.cfg.mcp_servers if s.get("enabled", True)]
        for server in servers:
            try:
                conn = self._connect_one(server)
            except Exception as e:
                log.warning("MCP server %r failed to start: %s", server.get("name"), e)
                continue
            self.connections.append(conn)
            for name, tool_entry in conn.entry.items():
                if name in toolbox:
                    log.warning(
                        "MCP tool name collision on %r — keeping the first", name)
                    continue
                toolbox[name] = tool_entry
        return toolbox

    def _connect_one(self, server: dict) -> _ServerConnection:
        """Start one stdio server, list tools, build executors."""
        from mcp import StdioServerParameters

        import threading

        command = server["command"]
        parts = _split_command(command) + [
            str(a) for a in server.get("args", [])
        ]
        if not parts:
            raise ValueError("empty command")
        # bare names like 'npx' must resolve to the real .cmd/.exe on
        # Windows before CreateProcess sees them
        import shutil

        resolved = shutil.which(parts[0])
        if resolved:
            parts[0] = resolved
        params = StdioServerParameters(
            command=parts[0],
            args=parts[1:],
            env=server.get("env") or None,
        )

        # server stderr (npm warnings, startup banners) goes to
        # /dev/null — the chat stays clean; real failures surface as
        # "failed to start" in our own log
        errlog = None
        try:
            errlog = open(os.devnull, "w")
        except OSError:
            pass

        conn = _ServerConnection()
        self._thread = threading.Thread(
            target=self._run_bg, args=(conn, params, errlog), daemon=True)
        self._thread.start()
        # wait briefly for the tool list (or failure) to arrive
        if not conn.ready.wait(timeout=10):  # pragma: no cover — slow boots
            log.warning("MCP server %r: tool list timed out", server.get("name"))
        if conn.error and not conn.entry:
            raise RuntimeError(conn.error)
        return conn

    def _run_bg(self, conn: _ServerConnection, params: Any, errlog: Any) -> None:
        import anyio

        try:
            anyio.run(conn.run, params, errlog)
        except Exception as e:  # anyio itself failed to start
            conn.error = str(e)
            conn.ready.set()
            log.info("MCP background session ended: %s", e)
        finally:
            if errlog:
                errlog.close()

    def close(self) -> None:
        """Tear down every connection (ends the server processes)."""
        for conn in self.connections:
            conn.close()
        self.connections.clear()


def _tool_name(tool: Any) -> str:
    return getattr(tool, "name", "tool")


def _schema(tool: Any) -> dict:
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


def build_mcp_toolbox(cfg: KryonsecConfig) -> dict[str, tuple[dict, Any]]:
    """Convenience wrapper: connect all enabled servers, return the
    toolbox entries (possibly empty). The caller cannot close the
    servers afterwards — prefer McpToolbox directly for long sessions."""
    try:
        return McpToolbox(cfg).connect_all()
    except ImportError:
        log.info("mcp package not installed — MCP tools unavailable")
        return {}
    except Exception as e:
        log.warning("MCP connect failed: %s", e)
        return {}
