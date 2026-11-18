"""MCP server wiring for the general agent (v1.1).

Each enabled MCP server from config.toml ([mcp] servers) is an stdio
server: kryonsec starts it, lists its tools, and exposes them to the
LLM agent alongside the built-in tools. A server that fails to start is
skipped with a console notice — it never blocks the chat.

The `mcp` package is a REQUIRED dependency (the setup wizard offers MCP
presets, so a default install must run them), but it is still imported
lazily: sessions with no MCP servers configured pay no import cost. The
ImportError guard only covers broken/partial installs — it is not a
supported "base without mcp" configuration.

Threading model: each server runs on its own daemon thread inside
anyio.run (asyncio backend). Tool executors marshal the call onto that
same loop with asyncio.run_coroutine_threadsafe — awaiting session
objects on a *different* loop raises "Future attached to a different
loop", so a fresh anyio.run per call (the v1.1 bug) is never done.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import tempfile
import threading
from typing import Any, Callable, Iterator

from ..config import KryonsecConfig

log = logging.getLogger(__name__)

# one tool call may legitimately take a while (searches, generation) —
# but never hang the chat forever
TOOL_CALL_TIMEOUT_S = 120

# how long a slow server (cold npx cache, …) may still take AFTER the
# connect-timeout before we give up on it for the session
LATE_BOOT_TIMEOUT_S = 60

# how much of a server's own stderr we quote when it fails to start. A
# tool that dies at launch explains itself on its LAST lines (npm's 404,
# node's engine error); the first screenful is download progress.
STDERR_TAIL_LINES = 12


def _describe_error(exc: BaseException) -> str:
    """A readable reason from a possibly-nested exception.

    A server that dies while starting surfaces through anyio as an
    ExceptionGroup whose str() is the useless "unhandled errors in a
    TaskGroup (1 sub-exception)" — the reason is on a leaf, and the
    wrapper says nothing. Walk to the leaves and describe those. A plain
    exception keeps its own str(), so anything already legible is
    unchanged.
    """
    leaves: list[str] = []
    queue: list[BaseException] = [exc]
    while queue:
        current = queue.pop(0)
        nested = getattr(current, "exceptions", None)
        if nested:
            queue[0:0] = list(nested)
            continue
        text = str(current).strip()
        leaves.append(
            f"{type(current).__name__}: {text}" if text else type(current).__name__
        )
    if not leaves:
        return str(exc) or type(exc).__name__
    # dedupe, keeping order — a group often repeats the same leaf
    return "; ".join(dict.fromkeys(leaves))


def _is_connection_loss(exc: BaseException) -> bool:
    """True when the exception says the TRANSPORT died (not a tool error).

    mcp 2.x reports a closed server as a JSON-RPC error
    (``MCPError(-32000, 'Connection closed')``) instead of unwinding the
    session context, so this is what a mid-session death usually looks
    like from a call. anyio's closed-stream errors and broken pipes are
    the same condition from lower layers. A tool's OWN error keeps its
    own message and is never matched here.
    """
    text = str(exc)
    if getattr(exc, "code", None) == -32000 and \
            "connection closed" in text.lower():
        return True
    if type(exc).__name__ in (
            "ClosedResourceError", "BrokenResourceError", "EndOfStream"):
        return True
    return isinstance(exc, (BrokenPipeError, ConnectionResetError))


def _read_errlog(errlog: Any, tail_lines: int = STDERR_TAIL_LINES) -> str:
    """The last few lines a server wrote to stderr, or "".

    Only ever called once the server is gone: on the success path the
    subprocess is still appending, and seek(0) would make its next write
    overwrite the buffer from the start. Never raises — this runs on the
    failure path, where a second exception would hide the first.
    """
    if errlog is None:
        return ""
    try:
        errlog.flush()
        errlog.seek(0)
        raw = errlog.read()
    except Exception:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    return " / ".join(lines[-tail_lines:])


# How to get a command that isn't installed. Covers what the setup wizard's
# presets need: "install it" alone is not actionable when the answer is "that
# ships with uv" and the user has never heard of uv. Unknown commands fall
# back to the generic wording.
INSTALL_HINTS = {
    "uvx": "it comes with uv — curl -LsSf https://astral.sh/uv/install.sh | sh",
    "uv": "install it with: curl -LsSf https://astral.sh/uv/install.sh | sh",
    "npx": "it ships with Node.js — https://nodejs.org/",
    "node": "install it from https://nodejs.org/",
    "docker": "install it from https://docs.docker.com/engine/install/",
}


def command_install_hint(name: str) -> str | None:
    """Where to get `name`, or None when we have nothing useful to say.

    Public so the setup wizard can warn with the same words at setup time
    that the toolbox uses at start time.
    """
    # Split on both separators, not os.path.basename: a Windows path handled
    # on POSIX keeps its whole directory prefix (backslash is not a separator
    # there) and would match nothing. Then drop an executable suffix — the
    # command resolved from PATH is "uvx.exe" on Windows and "uvx" elsewhere,
    # and both mean uv.
    leaf = name.replace("\\", "/").rsplit("/", 1)[-1]
    return INSTALL_HINTS.get(os.path.splitext(leaf)[0].lower())


def _foreign_binary_reason(command: str, resolved: str) -> str | None:
    """Why a resolved command cannot work here, or None if it looks fine.

    WSL puts the Windows PATH on the Linux PATH, so on a machine with Node
    for Windows and none inside the distro, `npx` resolves to
    /mnt/c/Program Files/nodejs/npx.cmd. That is a real program and it
    starts — then it is handed Linux paths (`/home/you`) and a Linux working
    directory, and it fails several layers down with "CMD.EXE was started
    with the above path as the current directory ... UNC paths are not
    supported", which points at nothing. It cannot work: a Windows process
    cannot open a WSL path under the name the WSL-side config uses.

    Windows *drives* are the test, not the .exe suffix alone — the WSL
    interop shims (`cmd.exe`, `wsl.exe`) live in /usr/bin and are legitimate
    commands a user may configure on purpose.
    """
    if not sys.platform.startswith("linux"):
        return None
    if not resolved.startswith("/mnt/") or os.name == "nt":
        return None
    if os.path.splitext(resolved)[1].lower() not in (".exe", ".cmd", ".bat", ".ps1"):
        return None
    return (
        f"{command!r} resolves to the Windows program {resolved}, which cannot "
        "open Linux paths — install it inside this distro instead "
        "(e.g. sudo apt-get install -y nodejs npm)"
    )


def _missing_command_message(name: str) -> str:
    """Why a server could not start, and what to install.

    shutil.which only inspects OUR PATH, so a missing binary would otherwise
    surface much later as a cryptic ENOENT from deep inside the transport.
    The PATH note is included because the other common cause is a tool that
    IS installed but was added to PATH after this process started.
    """
    hint = command_install_hint(name)
    detail = f" — {hint}" if hint else ""
    return (
        f"command {name!r} not found on PATH{detail} "
        "(if you just installed it, log out and back in so PATH picks it up)"
    )


def _startup_failure(conn: _ServerConnection) -> str:
    """The most useful one-line reason a server failed to start.

    The server's own stderr usually names the cause and the exception does
    not (a missing npm package, a module that is not found, node too old),
    so it leads; the exception is kept as the fallback and as the second
    half when both exist. connect_all() puts this straight on the console,
    so it has to stand alone.
    """
    parts = [part for part in (conn.stderr_tail, conn.error) if part]
    return " — ".join(parts) if parts else "server exited during startup"


class _ServerConnection:
    """One live stdio server: its background loop, stop event, entries."""

    def __init__(self, name: str = "") -> None:
        self.name = name
        self.loop: Any = None            # the asyncio loop (anyio backend)
        self.stop_event: Any = None      # asyncio.Event set by close()
        self.ready = threading.Event()   # set once tools are listed (or the session ended)
        self.entry: dict[str, tuple[dict, Any]] = {}
        self.error: str = ""
        self.stderr_tail: str = ""       # its own last words, when it had any
        # what this connection contributed to the toolbox's merged view —
        # captured at death so the toolbox can UN-merge exactly these
        # entries (identity-checked, so a same-named tool from another
        # server that won the first-merge race is never clobbered)
        self.merged: dict[str, tuple[dict, Any]] = {}
        # set by the owning toolbox; called once when a live session dies
        self.on_death: "Callable[[_ServerConnection], None] | None" = None
        self._death_lock = threading.Lock()

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
            # the session is unwinding, so the process is on its way out and
            # its stderr is complete — read it before the file is closed
            self.stderr_tail = _read_errlog(errlog)
            self._mark_dead(e)
            log.info("MCP background session ended: %s", e)
        finally:
            self.ready.set()  # unblock the waiting connect thread

    def _mark_dead(self, error: Any) -> None:
        """Record a death ONCE: capture what this connection contributed
        to the toolbox view, clear the live entries, fire the callback.

        Two death signals exist and both land here: a transport-level
        exception unwinding run()'s session, and the client's own
        'Connection closed' error surfacing through a call (mcp 2.x
        turns the closed pipe into a JSON-RPC error WITHOUT unwinding
        the session context — the connection would otherwise sit
        'connected' forever). Idempotent and thread-safe: several
        executor threads may see the loss at once."""
        with self._death_lock:
            if self.error:      # already marked — one report only
                return
            self.error = _describe_error(error)
            self.merged = dict(self.entry)   # what we had contributed
            self.entry.clear()
        log.info("MCP server %r session died: %s", self.name, self.error)
        if self.on_death is not None:
            try:
                self.on_death(self)
            except Exception:  # the death cleanup must never raise
                log.exception("MCP on-death handler failed")

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
            except Exception as e:
                if _is_connection_loss(e):
                    # the transport is gone: mark it so no later call is
                    # told the server is 'connected'; the raise still
                    # reaches the registry's own failure audit
                    self._mark_dead(e)
                raise
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
    tools in agent-toolbox format: name -> (schema, executor).

    The toolbox is LIVE: a server slower than the 10s connect timeout
    (cold npx cache, …) keeps booting in the background, and its tools
    are merged in when they arrive — the next chat turn's snapshot()
    sees them. Callers take a snapshot per turn instead of holding the
    dict, so a background merge can never mutate a dict mid-iteration.
    """

    def __init__(
        self,
        cfg: KryonsecConfig,
        on_notice: Callable[[str], None] | None = None,
    ):
        self.cfg = cfg
        self.connections: list[_ServerConnection] = []
        self.tools: dict[str, tuple[dict, Any]] = {}
        self.on_notice = on_notice  # user-visible notices (CLI console)
        self._lock = threading.Lock()
        self._closing = False
        # Presentation-only status.  The UI reads this snapshot; it never
        # uses it to decide whether a tool may run.
        self._server_status: dict[str, dict[str, Any]] = {
            str(server.get("name", "?")): {
                "name": str(server.get("name", "?")),
                "status": "starting",
                "detail": "connecting",
                "tools": 0,
            }
            for server in self.cfg.mcp_servers
            if server.get("enabled", True)
        }

    def _notice(self, message: str) -> None:
        """Slow/dead servers must be VISIBLE, not just a log line."""
        if self.on_notice:
            try:
                self.on_notice(message)
            except Exception:
                log.exception("MCP notice callback failed")
        else:
            log.warning("%s", message)

    def snapshot(self) -> dict[str, tuple[dict, Any]]:
        """A thread-safe copy of the current tool entries."""
        with self._lock:
            return dict(self.tools)

    def connect_all(
        self,
        allow_start: "Callable[[dict], str] | None" = None,
    ) -> dict[str, tuple[dict, Any]]:
        """Start AUTHORIZED servers only; returns the tool entries known at
        connect time (late booters merge into snapshot() afterwards).
        Failures are logged, noticed, and skipped. Safe to call on a
        daemon thread — close() can interrupt it between servers.

        Startup is a policy checkpoint, not plumbing: starting a stdio
        server means launching a local program. ``allow_start`` is called
        with the raw server row BEFORE anything spawns — "" permits
        startup, a non-empty refusal reason blocks it and is shown in
        the connection status. When no authorizer is wired (stray
        callers), the BUILT-IN conservative gate applies
        (:func:`_startup_refusal`): only rows that explicitly authorize
        execution (trust 'ask'/'allow' with at least one tool allowance)
        may start — unknown/disabled connections never execute
        host-side programs.
        """
        if allow_start is None:
            allow_start = _startup_refusal
        servers = [s for s in self.cfg.mcp_servers if s.get("enabled", True)]
        for server in servers:
            torn_down = False
            if self._closing:
                return self.snapshot()
            name = server.get("name", "?")
            refusal = str(allow_start(server) or "")
            if refusal:
                # policy refusal BEFORE any process exists: the connection
                # stays visible (status 'blocked') but never runs anything
                detail = refusal[:160]
                with self._lock:
                    self._server_status[str(name)] = {
                        "name": str(name),
                        "status": "blocked",
                        "detail": detail,
                        "tools": 0,
                    }
                self._notice(
                    f"MCP server {name!r} not started: {detail}")
                continue
            try:
                conn, slow = self._connect_one(server)
                with self._lock:
                    if self._closing:  # close() raced us mid-connect
                        conn.close()
                        torn_down = True
                    elif conn.error and not conn.entry:
                        # died between the ready wake-up and registration —
                        # same outcome as a startup failure, never merged
                        raise RuntimeError(_startup_failure(conn))
                    else:
                        self.connections.append(conn)
            except Exception as e:
                # log at info: the user already sees the notice below —
                # a log.warning here made every failure print TWICE
                log.info("MCP server %r failed to start: %s", name, e)
                with self._lock:
                    self._server_status[str(name)] = {
                        "name": str(name),
                        "status": "disconnected",
                        "detail": str(e)[:160],
                        "tools": 0,
                    }
                self._notice(f"MCP server {name!r} failed to start: {e}")
                continue
            if torn_down:
                return dict(self.tools)  # plain copy: the lock is released
            self._merge(conn.entry)
            with self._lock:
                self._server_status[str(name)] = {
                    "name": str(name),
                    "status": "connected" if conn.entry else "starting",
                    "detail": (
                        f"{len(conn.entry)} tool(s) available"
                        if conn.entry else "server is still starting"
                    ),
                    "tools": len(conn.entry),
                }
            if slow:
                self._notice(
                    f"MCP server {name!r} is still starting — its tools "
                    "will appear when ready")
                threading.Thread(
                    target=self._wait_late, args=(conn, name), daemon=True,
                ).start()
        return self.snapshot()

    def _merge(self, entries: dict[str, tuple[dict, Any]]) -> None:
        with self._lock:
            for name, entry in entries.items():
                if name in self.tools:
                    log.warning(
                        "MCP tool name collision on %r — keeping the first", name)
                    continue
                self.tools[name] = entry

    def _on_connection_death(self, conn: "_ServerConnection") -> None:
        """A live server died mid-session: its merged tools leave the
        snapshot() view NOW and its status says what actually happened.

        Without this the toolbox kept serving stale entries from a dead
        process and the status stayed 'connected' — a tool call then
        surfaced a misleading 'connected but has no tool' refusal.
        Skipped entirely while close() is tearing the toolbox down, and
        for connections that never registered as live (a startup
        failure is already reported by connect_all's own path)."""
        if self._closing:
            return
        with self._lock:
            if conn not in self.connections:
                return  # never went live — connect_all reported the failure
            removed = 0
            for key, entry in conn.merged.items():
                if self.tools.get(key) is entry:
                    del self.tools[key]
                    removed += 1
            self._server_status[conn.name] = {
                "name": conn.name,
                "status": "disconnected",
                "detail": (f"server exited mid-session: "
                           f"{(conn.error or 'unknown error')[:140]}"),
                "tools": 0,
            }
        if removed:
            self._notice(
                f"MCP server {conn.name!r} exited — {removed} tool(s) "
                "no longer available")
        else:
            self._notice(
                f"MCP server {conn.name!r} exited mid-session")

    def _wait_late(self, conn: _ServerConnection, name: str) -> None:
        """Background waiter for a slow-boot server: register its tools
        when they land (v1.1.0 rebuilt the toolbox per turn, so late
        servers used to appear next message — this restores that without
        the per-turn process leak)."""
        if not conn.ready.wait(timeout=LATE_BOOT_TIMEOUT_S):
            with self._lock:
                self._server_status[str(name)] = {
                    "name": str(name),
                    "status": "disconnected",
                    "detail": "startup timed out",
                    "tools": 0,
                }
            self._notice(
                f"MCP server {name!r} never became ready — dropped for this session")
            return
        if conn.entry:
            self._merge(conn.entry)
            with self._lock:
                self._server_status[str(name)] = {
                    "name": str(name),
                    "status": "connected",
                    "detail": f"{len(conn.entry)} tool(s) available",
                    "tools": len(conn.entry),
                }
            self._notice(
                f"MCP server {name!r} ready — {len(conn.entry)} tool(s) now available")
        else:
            if conn.error:
                # the death handler already reported this exit — never a
                # second 'exited before listing any tools' notice on top
                return
            with self._lock:
                self._server_status[str(name)] = {
                    "name": str(name),
                    "status": "disconnected",
                    "detail": "server exited before listing tools",
                    "tools": 0,
                }
            self._notice(
                f"MCP server {name!r} exited before listing any tools")

    def _connect_one(self, server: dict) -> tuple[_ServerConnection, bool]:
        """Start one stdio server, list tools, build executors.

        Returns (connection, slow): slow=True when the tool list had not
        arrived within the connect timeout — the connection is kept and
        its tools merge in later via _wait_late."""
        from mcp import StdioServerParameters

        command = server["command"]
        parts = _split_command(command) + [
            str(a) for a in server.get("args", [])
        ]
        if not parts:
            raise ValueError("empty command")
        import shutil

        resolved = shutil.which(parts[0])
        if resolved:
            foreign = _foreign_binary_reason(parts[0], resolved)
            if foreign:
                raise RuntimeError(foreign)
            parts[0] = resolved
        else:
            # shutil.which checks OUR PATH; a missing binary surfaces later
            # as a cryptic ENOENT — say plainly what is missing instead
            raise RuntimeError(_missing_command_message(parts[0]))
        params = StdioServerParameters(
            command=parts[0],
            args=parts[1:],
            env=server.get("env") or None,
        )

        # The server's stderr is captured to an unlinked temp file instead of
        # being discarded. The chat still stays clean — nothing is echoed —
        # but a server that dies at launch can now be quoted. A bare
        # "unhandled errors in a TaskGroup (1 sub-exception)" names no cause;
        # npm/node put the actual reason ("404 Not Found", an engine
        # mismatch) on stderr, and it is the only place it exists.
        # TemporaryFile, not NamedTemporaryFile: already unlinked, so nothing
        # is left behind if we are killed. Binary: the child writes bytes.
        errlog = None
        try:
            errlog = tempfile.TemporaryFile()
        except OSError:
            pass

        conn = _ServerConnection(str(server.get("name", "?")))
        conn.on_death = self._on_connection_death
        # daemon thread, never joined — a local is enough (M6: a self._thread
        # attribute here was clobbered per server and read by nobody)
        thread = threading.Thread(
            target=self._run_bg, args=(conn, params, errlog), daemon=True)
        thread.start()
        # wait briefly for the tool list (or failure) to arrive; a server
        # that overruns it is NOT dropped — see _wait_late
        slow = not conn.ready.wait(timeout=10)
        if slow:
            log.warning("MCP server %r: tool list timed out", server.get("name"))
        if conn.error and not conn.entry:
            raise RuntimeError(_startup_failure(conn))
        return conn, slow

    def _run_bg(self, conn: _ServerConnection, params: Any, errlog: Any) -> None:
        import anyio

        try:
            anyio.run(conn.run, params, errlog)
        except Exception as e:  # anyio itself failed to start
            conn.error = _describe_error(e)
            conn.stderr_tail = _read_errlog(errlog)
            conn.ready.set()
            log.info("MCP background session ended: %s", e)
        finally:
            if errlog:
                errlog.close()

    def close(self) -> None:
        """Tear down every connection (ends the server processes).
        connect_all() may still be running on its daemon thread — set the
        flag first so it stops instead of appending to a list mid-clear.
        """
        self._closing = True
        for conn in list(self.connections):
            conn.close()
        self.connections.clear()

    def statuses(self) -> list[dict[str, Any]]:
        """Return actual configured-server connection states for the UI.

        This is deliberately a snapshot.  The terminal may display it, but no
        execution path consults it for authorization or tool selection.
        """
        with self._lock:
            return [dict(value) for value in self._server_status.values()]


def _startup_refusal(row: dict) -> str:
    """The built-in startup gate: "" = start permitted; otherwise the
    reason the row may not start a process.

    Startup rule (conservative, matches the registry's policy): a
    connection only launches its program when it EXPLICITLY authorizes
    execution — trust 'ask' or 'allow' AND at least one tool allowance
    (``allow_tools``, where ``["*"]`` counts). A row without a policy,
    with trust 'disabled', or with nothing allowed never starts a
    host-side program, even though its status remains visible.
    """
    trust = str(row.get("trust", "disabled"))
    allow = row.get("allow_tools", [])
    names = [
        str(t).strip() for t in allow if isinstance(allow, (list, tuple, set))
        and str(t).strip() and t != "*"]
    wildcard = isinstance(allow, (list, tuple, set, frozenset)) and "*" in allow
    if trust not in ("ask", "allow"):
        return ("no explicit startup authorization (trust must be 'ask' "
                "or 'allow') — server not started")
    if not names and not wildcard:
        return ("no allow_tools entry — starting requires explicitly "
                "authorized tools")
    return ""


def _tool_name(tool: Any) -> str:
    return getattr(tool, "name", "tool")


def _schema(tool: Any) -> dict:
    # mcp 1.x named the field inputSchema; 2.x renamed it input_schema —
    # accept both so a version bump cannot silently empty every
    # parameter schema (a tool then validates against "no parameters"
    # and every call with arguments is refused).
    raw = getattr(tool, "input_schema", None) or \
        getattr(tool, "inputSchema", None) or {}
    schema = raw if isinstance(raw, dict) else {}
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


@contextlib.contextmanager
def build_mcp_toolbox(cfg: KryonsecConfig) -> Iterator[dict[str, tuple[dict, Any]]]:
    """Convenience wrapper: connect all enabled servers and yield the
    toolbox entries (possibly empty). Context-manager shaped (M7): the
    servers are CLOSED on exit — the old bare-call form leaked every
    server process it started for the rest of the session.

        with build_mcp_toolbox(cfg) as tools:
            ...
    """
    toolbox: dict[str, tuple[dict, Any]] = {}
    box: McpToolbox | None = None
    try:
        box = McpToolbox(cfg)
        toolbox = box.connect_all()
    except ImportError:
        log.info("mcp package not installed — MCP tools unavailable")
    except Exception as e:
        log.warning("MCP connect failed: %s", e)
    try:
        yield toolbox
    finally:
        if box is not None:
            box.close()
