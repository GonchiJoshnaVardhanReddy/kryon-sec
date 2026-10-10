"""Kryonsec CLI entry point (spec v2.1.1 §1, §11).

Usage:
  kryonsec          start the interactive CLI (Copilot mode)
  kryonsec doctor   run preflight checks
  kryonsec --version
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import threading
import time

log = logging.getLogger(__name__)

from rich.console import Console
from rich.markdown import Markdown

from . import __version__
from .config import KryonsecConfig

# Glyphs that legacy code-page consoles (cp1252) can't encode crash Rich
# mid-print — mid-chat-turn. Detect once at import: UTF-8 consoles get the
# pretty arrows/checkmarks, everything else gets ASCII lookalikes.
def _console_supports_utf8() -> bool:
    import sys

    for stream in (sys.stdout, sys.stderr):
        try:
            "→✓└".encode(stream.encoding or "ascii")
        except (UnicodeEncodeError, LookupError, AttributeError):
            return False
    return True


_UTF8_OK = _console_supports_utf8()
ARROW = "→" if _UTF8_OK else "->"
OK_MARK = "✓" if _UTF8_OK else "+"
FAIL_MARK = "✗" if _UTF8_OK else "x"
TREE_BRANCH = "└─" if _UTF8_OK else "`-"

console = Console()
err_console = Console(stderr=True, style="red")

# messages exchanged in the current session (for the goodbye line)
_msg_count = [0]

BANNER = r"""██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗███████╗███████╗ ██████╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔════╝
█████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║███████╗█████╗  ██║
██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║╚════██║██╔══╝  ██║
██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║███████║███████║╚██████╗
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝"""


# fallback for legacy code-page consoles (cp1252 etc.) where the
# box-drawing art would raise UnicodeEncodeError at startup
BANNER_ASCII = """ .------.  .---.  .-----.  .---. .-.    .------.--------.
 |K .---/  | .-. \\ | .-.  \\ | |-.'| |    | .---'|  .--.  |
 |  .'|    | `-' | | `-'.  )| |-' `-'    | `--.| |  \\  |
 |  `-|    | .-. | | .-.  \\ | |    .     | .---'|  _  7
 `---'`-'  `-' `-' `-'  `--'`-'    `--.  `-'    `-' `--' KRYONSEC"""


def _active_banner() -> str:
    return BANNER if _UTF8_OK else BANNER_ASCII


def banner_styled(mode: str) -> str:
    """The banner, white in copilot mode, purple in purple team mode."""
    color = "magenta" if mode == "purple" else "white"
    return f"[bold {color}]{_active_banner()}[/bold {color}]"


def _print_banner(mode: str) -> None:
    """Re-print the banner whenever the mode flips (Shift+Tab or /mode)."""
    console.print(banner_styled(mode))


def welcome(cfg: "KryonsecConfig") -> str:
    """Startup screen: banner plus the facts a user actually needs before
    the first message — provider, model, workspace — so a wrong config is
    visible immediately, not three turns in."""
    provider = {
        "openai": "OpenAI",
        "bedrock": "AWS Bedrock",
        "openai_compatible": "OpenAI-compatible endpoint",
    }.get(cfg.provider, "Ollama (local)")
    return (
        f"{banner_styled('copilot')}\n"
        f"[bold cyan]v{__version__}[/bold cyan] — dual-mode cybersecurity CLI\n"
        f"[cyan]\\[COPILOT]>[/cyan] general assistant   "
        f"[magenta]\\[PURPLE]>[/magenta] purple team (Profile 2, Linux)\n"
        f"\n"
        f"[dim]provider:[/dim] {provider}   "
        f"[dim]model:[/dim] {cfg.general_chat_model}   "
        f"[dim]workspace:[/dim] {cfg.workspace}\n"
        f"\n"
        f"Type your question. [bold]/help[/bold] for commands — "
        f"[bold]Shift+Tab[/bold] switches mode."
    )


def _persist_session(cfg: KryonsecConfig, session: "GeneralSession") -> None:
    """Save the general session to storage (best effort — chat must not die
    because storage is down)."""
    try:
        from .storage import GeneralSession as GeneralSessionRow, get_session as db_session

        with db_session(cfg) as s:
            s.add(GeneralSessionRow(
                messages=[m.as_dict() for m in session.messages],
                token_count=session.token_estimate,
                ended_at=None,
            ))
            s.commit()
    except Exception as e:
        err_console.print(f"[yellow]session not persisted: {e}[/yellow]")


def _print_help() -> None:
    """Command reference, grouped by what the user is trying to do —
    not alphabetically. Quit/exit are listed last, not first."""
    from rich.table import Table

    t = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    t.add_column(style="bold cyan", no_wrap=True)  # command
    t.add_column(style="dim")                      # what it does
    for cmd_line, what in [
        ("/cve <id>", "look up a CVE (NVD, cached offline)"),
        ("/search <query>", "web search — results go into context"),
        ("/read <path>", "read a file (approval-gated outside workspace)"),
        ("/ls <path>", "list a directory (approval-gated outside workspace)"),
        ("/write <path>", "write text to a file in the workspace"),
        ("/workspace", "show the workspace path"),
        ("/mode", "switch mode (copilot / purple) — or press Shift+Tab"),
        ("/quit", "exit (or just: exit, quit, q)"),
    ]:
        t.add_row(cmd_line, what)
    console.print("[bold]Commands[/bold]\n")
    console.print(t)
    console.print()  # breathing room before the next prompt


def _print_goodbye(cleanup: "Callable[[], None] | None" = None) -> None:
    """Persist, tear down, and say goodbye with the exchange count —
    the user shouldn't wonder whether the session was saved."""
    if cleanup is not None:
        cleanup()
    console.print(f"\n[dim]session saved ({_msg_count[0]} messages) — bye[/dim]")


async def _chat_loop(cfg: KryonsecConfig) -> None:
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    from .copilot import GeneralSession
    from .copilot.tools import ApprovalRequest
    from .llm import LlmUnavailable, chat
    from .storage import GeneralUserLtm, get_session as db_session

    # create tables on first use — the chat must work out of the box
    try:
        from .storage import init_db
        init_db(cfg, include_purple=False)
    except Exception as e:
        err_console.print(f"[yellow]storage init failed: {e} — session will not be persisted[/yellow]")

    def _console_approve(req: ApprovalRequest) -> bool:
        from rich.panel import Panel

        verb = {"read": "Read", "list": "List", "write": "Write"}.get(
            req.action, req.action.capitalize())
        # req.path is the RESOLVED target (what the decision is about). When
        # the agent named something else — a workspace symlink pointing out of
        # the workspace — show both, or the user approves the wrong file.
        via = ""
        if req.requested_path:
            via = (
                f"\n[yellow]requested as[/yellow] [dim]{req.requested_path}[/dim]"
                f"\n[yellow]→ really[/yellow] [bold red]{req.path}[/bold red]"
            )
        console.print(Panel(
            f"[bold]{verb} this file?[/bold]\n"
            f"[cyan]{req.path}[/cyan]"
            f"{via}\n"
            f"[dim]why: {req.reason}[/dim]",
            title="[bold yellow]Approval required[/bold yellow]",
            border_style="yellow",
        ))
        answer = console.input(
            "[bold][A]pprove / [D]eny (Enter = Deny):[/bold] ")
        return answer.strip().lower().startswith("a")


    templates = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates)),
        undefined=StrictUndefined,
        autoescape=False,
    )

    # ---- load user preferences + LTM facts (User LTM) ---------------------
    prefs: dict = {"explain_mode": "technical"}
    user_facts: list[str] = []
    try:
        with db_session(cfg) as s:
            for row in (
                s.query(GeneralUserLtm)
                .filter(GeneralUserLtm.category == "preference")
                .order_by(GeneralUserLtm.access_count.desc())
                .limit(10)
                .all()
            ):
                prefs[row.key] = row.value
            for row in (
                s.query(GeneralUserLtm)
                .filter(GeneralUserLtm.category == "fact")
                .order_by(GeneralUserLtm.last_accessed.desc())
                .limit(15)
                .all()
            ):
                fact = row.value if isinstance(row.value, str) else str(row.value)
                user_facts.append(f"{row.key}: {fact}")
    except Exception as e:  # storage unavailable — chat still works in-memory
        err_console.print(f"[yellow]storage warning: {e} — session will not be persisted[/yellow]")

    system_prompt = env.get_template("system_prompt.jinja").render(
        workspace=str(cfg.workspace),
        explain_mode=str(prefs.get("explain_mode", "technical")),
        recent_topics=[],
        user_facts=user_facts,
    )

    session = GeneralSession(cfg=cfg)

    # ---- MCP: connect ONCE for the whole session (H9) — one subprocess
    # per server, torn down on exit. Rebuilding per chat turn leaked a
    # server process + thread per message. The toolbox is live: a slow
    # server's tools merge in when ready and the per-turn snapshot()
    # picks them up.
    # connect_all() blocks up to 10s PER slow server (cold npx/uvx cache)
    # — that used to sit between the banner and the first prompt. It now
    # runs in a daemon thread: the chat is usable immediately and MCP
    # tools appear (with a notice) when each server lands.
    mcp_toolbox = None
    if cfg.mcp_servers:
        from .copilot.mcp_tools import McpToolbox

        try:
            mcp_toolbox = McpToolbox(
                cfg,
                on_notice=lambda msg: err_console.print(f"[yellow]{msg}[/yellow]"))
            threading.Thread(
                target=mcp_toolbox.connect_all, name="mcp-connect", daemon=True,
            ).start()
        except Exception as e:
            err_console.print(f"[yellow]MCP unavailable: {e}[/yellow]")
            mcp_toolbox = None

    # ---- warm the litellm import while the user reads the banner -------
    # `import litellm` takes seconds and is lazy-loaded at the first LLM
    # call — preload it in the background so the first reply is fast.
    from .llm import preload_litellm

    preload_litellm()

    _exited = [False]

    def _exit() -> None:
        # one-shot: _print_goodbye runs it on the normal exit paths, the
        # finally around the chat loop runs it on interrupts — both can
        # fire for the same exit, and the session must persist exactly once
        if _exited[0]:
            return
        _exited[0] = True
        _persist_session(cfg, session)
        if mcp_toolbox is not None:
            mcp_toolbox.close()

    # mutable mode holder: "copilot" <-> "purple" via Shift+Tab or /mode
    _mode = ["copilot"]
    _notice = [""]  # one-line status shown above the prompt

    from .tui import make_prompt_session

    def _on_mode_change(new_mode: str) -> None:
        console.clear()  # repaint the banner in the new mode color
        _print_banner(new_mode)

    ps = make_prompt_session(_mode, _notice, cfg, on_change=_on_mode_change)

    try:
        while True:
            try:
                if ps is not None:
                    user_input = await ps.prompt_async()
                else:  # prompt_toolkit unavailable — plain input fallback
                    user_input = console.input(f"[cyan]\\[{_mode[0].upper()}]>[/cyan] ")
            except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
                _print_goodbye(_exit)
                return
            finally:
                _notice[0] = ""  # notices are one-shot

            text = user_input.strip()
            if not text:
                continue

            cmd = text.lower()
            if cmd in ("/quit", "/exit", "exit", "quit", "q"):
                _print_goodbye(_exit)
                return
            if cmd == "/help":
                _print_help()
                continue
            if cmd == "/mode":
                from .tui import set_mode

                target = "purple" if _mode[0] == "copilot" else "copilot"
                if set_mode(_mode, _notice, cfg, target):
                    console.clear()  # repaint the banner in the new mode color
                    _print_banner(_mode[0])
                if _notice[0]:
                    console.print(f"[cyan]{_notice[0]}[/cyan]")
                    if _mode[0] != "purple":
                        console.print("[yellow]staying in copilot[/yellow]")
                continue

            # ---- CVE lookup (spec §3.6) --------------------------------------
            if cmd.startswith("/cve "):
                from rich.console import Group
                from rich.panel import Panel
                from rich.table import Table
                from rich.text import Text

                from .copilot.cve import lookup_cve

                try:
                    record = lookup_cve(cfg, text[len("/cve "):].strip())
                except ValueError as e:
                    err_console.print(f"{e}")
                    continue
                if not record:
                    console.print(
                        "[yellow]not found (offline cache miss and NVD "
                        "unreachable — try again online)[/yellow]")
                    continue
                sev = str(record.get("severity") or "?").lower()
                sev_color = {"critical": "red", "high": "red",
                             "medium": "yellow", "low": "green"}.get(sev, "cyan")
                score = record.get("cvss_score")
                t = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
                t.add_column(style="bold")
                t.add_column()
                t.add_row("severity", f"[{sev_color}]{sev.upper()}[/]")
                t.add_row("CVSS", f"{score if score is not None else '?'}")
                refs = [r for r in (record.get("references") or []) if r]
                if refs:
                    t.add_row("refs", f"{len(refs)} reference(s)")
                # a Rich renderable must be a Panel child, never f-string
                # interpolated — str(Table) is an object repr, not the table
                console.print(Panel(
                    Group(t, Text(""), Text(record.get("description", "")[:500])),
                    title=f"[bold]{record['id']}[/bold]",
                    border_style=sev_color,
                ))
                continue

            # ---- web search (spec §3.7) --------------------------------------
            if cmd.startswith("/search "):
                from .copilot.websearch import search_web

                query = text[len("/search "):].strip()
                results = search_web(cfg, query)
                if results is None:
                    console.print("[yellow]search failed (offline or blocked — try again online)[/yellow]")
                    continue
                if not results:
                    console.print("[yellow]no results[/yellow]")
                    continue
                from rich.rule import Rule

                console.print(Rule(f"[bold]web results[/bold] — {len(results)} found"))
                for i, r in enumerate(results, 1):
                    console.print(
                        f"  [bold cyan]{i}.[/bold cyan] [bold]{r['title']}[/bold]")
                    console.print(f"     [dim]{r['snippet']}[/dim]")
                    console.print(f"     [blue]{r['url']}[/blue]\n")
                session.add("user", f"[web search results for: {query}]\n" + "\n".join(
                    f"- {r['title']}: {r['snippet']} ({r['url']})" for r in results))
                console.print("[green]results now in context — ask about them[/green]")
                continue

            # ---- file tools (spec §3.7) -------------------------------------
            try:
                if cmd == "/workspace":
                    console.print(f"[dim]{cfg.workspace}[/dim]")
                    continue
                if cmd.startswith("/read "):
                    from .copilot.tools import FileTools

                    path = text[len("/read "):].strip()
                    content = FileTools(cfg, approver=_console_approve).read_file(path)
                    session.add("user", f"[file contents of {path}]\n{content}")
                    console.print(f"[green]read {path} ({len(content)} chars) — now in context[/green]")
                    continue
                if cmd.startswith("/ls "):
                    from .copilot.tools import FileTools

                    path = text[len("/ls "):].strip()
                    entries = FileTools(cfg, approver=_console_approve).list_directory(path)
                    console.print("\n".join(entries))
                    continue
                if cmd.startswith("/write "):
                    from .copilot.tools import FileTools

                    # /write <path> then the next line is content
                    path = text[len("/write "):].strip()
                    content = console.input("[dim]content> [/dim]")
                    FileTools(cfg, approver=_console_approve).write_file(path, content)
                    console.print(f"[green]wrote {path}[/green]")
                    continue
            except Exception as e:
                err_console.print(f"{e}")
                continue

            # ---- purple mode: typed text is a target domain -------------------
            if _mode[0] == "purple":
                _run_purple(cfg, text, memory_browser=True)
                continue

            session.add("user", text)
            try:
                await session.maybe_compact()
            except Exception as e:
                # compaction is an optimization, not a chat dependency — a
                # broken compaction model must not kill the CLI mid-turn
                err_console.print(
                    f"[yellow]compaction skipped ({type(e).__name__})[/yellow]")
                log.warning("compaction failed: %s", e)

            # ---- the agent loop (v1.1): tools when the LLM asks --------------
            from .copilot.agent import build_toolbox, run_agent
            from .copilot.tools import FileTools
            from .status import StatusLine

            file_tools = FileTools(cfg, approver=_console_approve)
            mcp_extra = mcp_toolbox.snapshot() if mcp_toolbox is not None else None
            toolbox = build_toolbox(cfg, file_tools, extra=mcp_extra or None)

            status = StatusLine(console)

            def _show_tool(name: str, args: dict) -> None:
                # the spinner gives way: the tool may prompt for approval,
                # which needs the terminal
                status.hide()
                arg_preview = ", ".join(f"{k}={str(v)[:40]}" for k, v in (args or {}).items())
                console.print(f"  [dim]{TREE_BRANCH}[/dim] [cyan]{name}[/cyan][dim]({arg_preview})[/dim]")

            def _show_round() -> None:
                status.show(f"[cyan]copilot[/cyan] thinking…")

            try:
                reply = run_agent(
                    cfg, session.as_llm_messages(system_prompt), toolbox,
                    cfg.general_chat_model,
                    on_tool=_show_tool, on_round=_show_round,
                )
            except Exception as e:
                status.hide()
                # tool-calling unsupported by the model or provider hiccup —
                # fall back to the plain chat path (one short warning; the
                # full error goes to the log)
                err_console.print(
                    f"[yellow]tools unavailable ({type(e).__name__}) — plain chat[/yellow]")
                from .llm import chat

                try:
                    with status.running(f"[cyan]copilot[/cyan] thinking…"):
                        reply = chat(cfg, session.as_llm_messages(system_prompt), cfg.general_chat_model)
                except LlmUnavailable as e:
                    err_console.print(f"LLM unavailable: {e}")
                    hint = {
                        "ollama": (
                            "Start Ollama (`ollama serve`) and pull a model "
                            "(`ollama pull llama3.1`), or run `kryonsec setup` to "
                            "switch to OpenAI."
                        ),
                        "bedrock": (
                            "If the model is not allowed for your account, "
                            "enable it under Bedrock > Model access; if it is "
                            "a `global.` profile, try the region-prefixed one "
                            "(`us.`, `eu.`, …). Bedrock also does not serve "
                            "every model on the OpenAI-compatible endpoint "
                            "kryonsec calls — `kryonsec setup` lists the ones "
                            "that work."
                        ),
                        "openai_compatible": (
                            "Check the endpoint is reachable at the base URL "
                            "you configured, that the model name is spelled "
                            "the way the endpoint serves it, and the API key "
                            "if it needs one. The message above is the "
                            "endpoint's own reply. `kryonsec setup` re-probes "
                            "it and shows what it can do."
                        ),
                    }.get(
                        cfg.provider,
                        "Check your OpenAI key or network — or run "
                        "`kryonsec setup` to switch providers.",
                    )
                    console.print(f"[yellow]{hint}[/yellow]")
                    session.messages.pop()  # drop the unanswered user turn
                    continue
                except Exception as e:
                    # same contract as the primary path: no crash mid-turn —
                    # report, drop the unanswered turn, keep the session alive
                    status.hide()
                    err_console.print(
                        f"[red]chat failed ({type(e).__name__}): {e}[/red]")
                    log.exception("fallback chat failed")
                    session.messages.pop()
                    continue
            finally:
                status.hide()

            session.add("assistant", reply)
            _msg_count[0] += 1
            console.print(Markdown(reply))
            console.print("\n")  # a blank line separates the reply from the prompt
            _remember_facts(cfg, text, reply)  # best-effort LTM (never blocks chat)
    finally:
        # M8: Ctrl+C during an LLM call bypasses the /quit and
        # prompt-interrupt exits above — without this finally the
        # MCP server processes were never closed (repro-verified).
        _exit()


def _remember_facts(cfg: KryonsecConfig, user_text: str, reply: str) -> None:
    """Long-term memory (v1.1): after each exchange, ask the LLM for any
    durable fact about the user, save it to GeneralUserLtm. Best effort —
    any failure is silent (memory must never break the chat)."""
    try:
        from .llm import chat

        prompt = (
            "Does this exchange reveal a durable fact about the user "
            "(preference, role, ongoing project, environment)? If yes, reply "
            "with ONE line 'key: value' (short key, concrete value). "
            "Otherwise reply exactly: none\n\n"
            f"user: {user_text[:500]}\nassistant: {reply[:500]}"
        )
        out = chat(cfg, [{"role": "user", "content": prompt}],
                   cfg.general_search_model, temperature=0.0)
        out = (out or "").strip()
        if not out or out.lower().startswith("none"):
            return
        key, _, value = out.partition(":")
        key, value = key.strip()[:255], value.strip()
        if not key or not value:
            return
        from .storage import GeneralUserLtm as LtmRow, get_session as db_session

        with db_session(cfg) as s:
            existing = (
                s.query(LtmRow)
                .filter(LtmRow.category == "fact", LtmRow.key == key)
                .one_or_none()
            )
            if existing:
                existing.value = value  # refresh, keep access_count
            else:
                s.add(LtmRow(category="fact", key=key, value=value))
            s.commit()
    except Exception:
        pass  # memory is best-effort by design


def _run_memory(
    cfg: KryonsecConfig,
    host: str = "127.0.0.1",
    port: int = 8899,
    open_browser: bool = True,
) -> int:
    """Serve the read-only engagement memory browser on loopback.

    This command only reads: there is no flag here — and no route in the
    server behind it — that scans, edits the graph or contacts a target.
    """
    from .memory import is_loopback_host, serve

    if not is_loopback_host(host):
        err_console.print(
            f"[red]Refusing to bind {host}:[/red] the memory browser is "
            "loopback-only. For remote access, forward the port over SSH "
            "(ssh -L 8899:127.0.0.1:8899 you@host) rather than binding wider."
        )
        return 2

    return serve(cfg, host=host, port=port, open_browser=open_browser)


# The memory browser a purple engagement started, if any: (server, url).
# One per process — a second engagement in the same chat session is handed
# the first one's URL instead of binding another port.
_memory_browser: "tuple[Any, str] | None" = None


def _start_memory_browser(
    cfg: KryonsecConfig, host: str = "127.0.0.1", port: int = 8899,
) -> str | None:
    """Serve the read-only memory browser in the background; return its URL.

    The same server `kryonsec memory` runs, on a thread instead of in main.
    Started before an engagement rather than after it, because the browser
    reads what the run writes: the link is worth having while the run is
    still going. Returns None when the server cannot be built at all — a
    browser must never be able to stop an engagement, so every failure here
    is silent.
    """
    global _memory_browser
    if _memory_browser is not None:
        return _memory_browser[1]

    from .memory import create_server

    try:
        try:
            server = create_server(cfg, host, port)
        except OSError:
            # Taken — by `kryonsec memory`, or by another program entirely.
            # The same fallback serve() uses, minus its notice, which would
            # interleave with the live engagement panel.
            server = create_server(cfg, host, 0)
    except (OSError, ValueError):
        return None

    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://{host}:{server.server_address[1]}/"
    _memory_browser = (server, url)
    return url


def _wait_for_memory_browser(rc: int) -> int:
    """Hold the process open on the browser the engagement just printed.

    Only the `purple` subcommand calls this: it is the one entry point that
    ends, and ending closes the server the operator was told to open. The
    chat loop has no counterpart — it stays in its own loop, so the browser
    lives on for the rest of the session. Ctrl+C is how this stops, which is
    the key the engagement itself uses.
    """
    if _memory_browser is None:
        return rc

    server, url = _memory_browser
    console.print(f"\n[dim]memory browser serving {url} — Ctrl+C to stop[/dim]")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("[dim]memory browser stopped[/dim]")
    finally:
        server.shutdown()
        server.server_close()
    return rc


def _run_purple(
    cfg: KryonsecConfig,
    target_arg: str,
    engagement_id: str | None = None,
    code_folder: str | None = None,
    *,
    memory_browser: bool = False,
) -> int:
    """Run one Purple Team engagement on a target. Shared by the `purple`
    subcommand and the /mode toggle inside the chat loop.

    `memory_browser` is what those two callers pass: it prints the loopback
    URL of the read-only memory browser and leaves it serving. It is off by
    default so a caller driving this function directly gets no socket."""
    import uuid
    from pathlib import Path

    # STATE_INFO (the per-state tool inventory) is deliberately not imported:
    # the console shows what is running as it runs, so the inventory is no
    # longer printed anywhere. STATES is imported where it is used, below.
    from .engagement_id import is_valid_engagement_id
    from .purple.runner import (
        persist_graph,
        record_engagement_ending,
        safe_exception_type,
        safe_halt_code,
        sandbox_available,
        start_engagement,
    )
    from .purple.zonea import validate_target

    try:
        target = validate_target(target_arg)
    except ValueError as e:
        err_console.print(f"[red]Invalid target:[/red] {e}")
        return 2

    # --id is a PATH COMPONENT: it names cfg.home/engagements/<id>/ and is
    # passed to docker as a bind-mount source. Unvalidated, "--id ../../../tmp/x"
    # walked out of the engagements tree and "--id /etc" pointed the mount at
    # the host's /etc. Auto-generated ids are uuid4 hex, so a conservative
    # charset costs nothing and closes the traversal. The rule lives in
    # engagement_id so the memory browser validates an id the same way.
    if engagement_id is not None:
        if not is_valid_engagement_id(engagement_id):
            err_console.print(
                f"[red]Invalid engagement id:[/red] {engagement_id!r} — "
                "use letters, digits, dot, dash or underscore (max 64 chars)"
            )
            return 2

    # --code: blue-team scanners need a real folder; anything else is a
    # hard error (never silently scans the wrong thing)
    if code_folder:
        code_path = Path(code_folder).expanduser()
        if not code_path.is_dir():
            err_console.print(
                f"[red]--code path is not a folder:[/red] {code_folder}")
            return 2
        code_folder = str(code_path.resolve())

    sandbox_ok, sandbox_reason = sandbox_available(cfg.sandbox_image)
    if not sandbox_ok:
        console.print(f"[yellow]Sandbox not available:[/yellow] {sandbox_reason}")
        console.print("[yellow]Engagement will stop after passive recon (Zone A works everywhere).[/yellow]")
        if code_folder:
            console.print("[yellow]--code ignored: static scanners need the sandbox.[/yellow]")

    # an explicit --id must survive the run: re-running a named engagement
    # keeps the same audit/report dirs instead of getting a random id
    if not engagement_id:
        engagement_id = str(uuid.uuid4())[:8]

    from .purple.ui import (
        STATE_ACTION,
        PurpleUI,
        attach_purple_logging,
        detach_purple_logging,
    )

    ui = PurpleUI(console, target=target, engagement_id=engagement_id)
    # Precomputed so _progress can tell a state announcement (which the
    # panel already shows) from a subagent's event (which it does not).
    _STATE_ACTION_TEXTS = frozenset(STATE_ACTION.values())

    def _progress(msg: str) -> None:
        # loader() announces each state with its action phrase, which the
        # live panel is already showing — repeating it would be the exact
        # scrolling-noise this redesign removes. Everything else on this
        # channel comes from a subagent (exploit.py's scheme switch, an
        # allowlist rejection) and is a real event worth one line.
        if msg not in _STATE_ACTION_TEXTS:
            ui.on_notice(msg)

    # Attached before start_engagement, not after: start_engagement builds
    # the sandbox, and the sandbox warns at construction when the image is
    # not digest-pinned. Attached later, that warning was the first thing on
    # screen and arrived raw ("WARNING kryonsec.purple.sandbox: ...") ahead
    # of the engagement line, which is exactly the unfiltered-log look this
    # console replaces.
    log_handler, debug_log = attach_purple_logging(cfg.home, engagement_id, ui)

    # The engagement proper spans start_engagement -> orch.run ->
    # persist_graph, and this is the only boundary that covers every way it
    # can end: a clean finish, a halt with a reason, an unhandled exception,
    # and Ctrl+C. The inner try/finally is the existing UI teardown, left
    # exactly where it was so the live panel is down before anything else
    # runs — and so it still runs when start_engagement itself fails.
    #
    # The terminal event is written from the `finally` and from nowhere else,
    # so there is one writer and one place to reason about. That means it is
    # reached with an exception in flight, which is safe only because
    # record_engagement_ending never raises and never masks.
    orch = None
    outcome: str | None = None
    reason: str | None = None
    exception_type: str | None = None
    try:
        try:
            orch, audit, graph = start_engagement(
                cfg, engagement_id, target=target, progress=_progress,
                code_folder=code_folder,
            )
            # Two existing hooks, no new plumbing: the orchestrator announces
            # state transitions (before the subagent is built, so HUMAN_REVIEW's
            # prompt owns the terminal first), and the audit chain announces
            # tool activity.
            ui.graph = graph
            orch.on_state = ui.on_state
            audit.add_observer(ui.on_audit)

            console.print(
                f"[magenta]\\[PURPLE]>[/magenta] engagement {engagement_id} "
                f"target={target}")
            # Printed here, with the engagement line and before the live
            # panel owns the terminal, so it arrives as one readable line
            # rather than something the panel has to paint around.
            memory_url = _start_memory_browser(cfg) if memory_browser else None
            if memory_url:
                console.print(
                    f"[magenta]\\[PURPLE]>[/magenta] memory browser "
                    f"[cyan]{memory_url}[/cyan] [dim](read-only, loopback — "
                    "open it in a browser; it fills in as the run goes)[/dim]")
            console.print()
            ui.started_at = time.monotonic()
            ui.start()
            completed = orch.run()
        finally:
            ui.stop()
            detach_purple_logging(log_handler)

        # After the panel is down, so the warning is a plain readable line
        # and not something the live display has to paint around. An
        # interrupted engagement still never reaches this — the re-raise
        # below leaves the function — so its graph is still not persisted.
        # What Phase 4.2 added is that the interruption itself is now
        # recorded before it goes.
        graph_saved = persist_graph(cfg, engagement_id, graph, audit)
        if not graph_saved:
            err_console.print(
                "[yellow]graph memory not saved — the engagement itself is "
                "complete (audit chain, evidence and report are on disk); "
                "see the debug log[/yellow]")

        # Read after persist_graph, not before: a crash while saving the
        # graph is a failure of the run, and reading the halt reason earlier
        # would have already labelled it a clean finish. Interruption and
        # failure are the exception handlers' to decide, not this line's.
        outcome = "halted" if orch.halt_reason else "completed"
        reason = safe_halt_code(orch.halt_reason)
    except KeyboardInterrupt:
        # Recorded, then re-raised. The operator asked for the run to stop,
        # and it still stops — same traceback, same exit status as before
        # this phase existed.
        outcome, reason = "interrupted", "keyboard_interrupt"
        raise
    except BaseException as exc:
        outcome, reason = "failed", "unhandled_exception"
        exception_type = safe_exception_type(exc)
        raise
    finally:
        # orch is None only when start_engagement itself failed, which is
        # exactly "no state was ever entered". Otherwise the loop appends to
        # `completed` before each state runs, so the last entry is the last
        # state reached — including one that halted, and including one that
        # was interrupted part-way through.
        entered = list(orch.completed) if orch is not None else []
        record_engagement_ending(
            cfg, engagement_id,
            outcome=outcome or "failed",
            reason=reason,
            last_state=entered[-1] if entered else None,
            states_entered=len(entered),
            exception_type=exception_type,
        )

    _print_purple_summary(
        cfg, engagement_id, target, completed, orch, audit, graph,
        debug_log=debug_log, graph_saved=graph_saved,
    )
    return 0


def _print_purple_summary(
    cfg: KryonsecConfig,
    engagement_id: str,
    target: str,
    completed: list[str],
    orch: "Any",
    audit: "Any",
    graph: "Any",
    debug_log: "Any" = None,
    graph_saved: "Any" = None,
) -> None:
    """End-of-engagement summary: a verdict panel first, then the evidence.

    The panel answers "what happened?" in one glance — complete or halted,
    for how long, and what came out of it. The sections below it are the
    working detail; they are kept because a finding without its evidence is
    not actionable, but they are no longer the first thing on screen.
    """
    from rich.panel import Panel
    from rich.table import Table

    from .purple.orchestrator import STATES

    findings = graph.by_type("finding")
    verified = [n for n in findings if n["properties"].get("verified")]
    attempts = graph.by_type("exploit_attempt")
    hypotheses = graph.by_type("hypothesis")
    subdomains = [n["label"] for n in graph.by_type("subdomain")]

    engaged = bool(attempts)
    halted = bool(orch.halt_reason)

    evidence_dir = cfg.home / "engagements" / engagement_id / "evidence"
    evidence_count = 0
    if evidence_dir.is_dir():
        evidence_count = sum(1 for p in evidence_dir.rglob("*") if p.is_file())

    rows = Table.grid(padding=(0, 3))
    rows.add_column(style="dim", justify="right")
    rows.add_column()
    rows.add_row("Target", f"[bold]{target}[/bold]")
    rows.add_row("Duration", _elapsed_text(orch))
    rows.add_row("", "")
    if halted:
        rows.add_row("Completed", f"{len(completed)} / {len(STATES)} stages")
    rows.add_row("Verified findings", f"[red]{len(verified)}[/red]"
                 if verified else "0")
    rows.add_row("Hypotheses", str(len(hypotheses)))
    rows.add_row("Tool executions", str(len(attempts)))
    rows.add_row("Evidence artifacts", str(evidence_count))
    if graph_saved is not None:
        # Engagement memory, stated explicitly: the operator should never
        # have to guess whether this run is reloadable later.
        rows.add_row(
            "Graph memory",
            f"{len(graph.nodes)} nodes, {len(graph.edges)} edges — saved"
            if graph_saved else "[yellow]not saved[/yellow] (see debug log)",
        )

    report_path = cfg.home / "engagements" / engagement_id / "report.md"
    if report_path.exists():
        rows.add_row("", "")
        rows.add_row("Report", _short_path(report_path, cfg.home))
    if debug_log is not None:
        rows.add_row("Debug log", _short_path(debug_log, cfg.home))

    if halted:
        title = "[bold red]ENGAGEMENT HALTED[/bold red]"
        border = "red"
        detail = f"[red]{orch.halt_reason}[/red]"
        rows.add_row("", "")
        rows.add_row("Reason", detail)
    else:
        title = "[bold green]ENGAGEMENT COMPLETE[/bold green]"
        border = "green"

    console.print()
    console.print(Panel(rows, title=title, border_style=border, expand=False))

    # ---- the verdict, in one line ---------------------------------
    if halted:
        verdict = f"[red]HALTED[/red] — {orch.halt_reason}"
    elif verified:
        verdict = f"[red]{len(verified)} verified finding(s)[/red] on {target}"
    elif findings:
        verdict = (
            f"[yellow]{len(findings)} possible finding(s) — "
            "none independently verified[/yellow]")
    elif attempts:
        verdict = f"[green]no findings confirmed[/green] ({len(attempts)} tool runs)"
    else:
        verdict = f"[green]no testing performed[/green] (engagement stopped before EXPLOIT)"

    console.print(verdict)
    console.print(f"[dim]states: {f' {ARROW} '.join(completed) or '—'}[/dim]")

    if subdomains:
        console.print(f"\n[cyan]passive recon — {len(subdomains)} subdomains[/cyan]")
        for s in subdomains[:30]:
            console.print(f"  [dim]{s}[/dim]")
        if len(subdomains) > 30:
            console.print(f"  [dim]… and {len(subdomains) - 30} more[/dim]")
    if hypotheses:
        console.print(f"\n[cyan]hypotheses — {len(hypotheses)}[/cyan]")
        for n in hypotheses:
            p = n["properties"]
            mark = f"[green]{OK_MARK}[/green] " if p.get("approved") else "  "
            console.print(
                f"  {mark}[magenta]{n['label']}[/magenta] "
                f"[bold]{p.get('title', '')}[/bold] "
                f"[dim](confidence {p.get('confidence', 0):.1f}; "
                f"tools: {', '.join(p.get('tools', [])) or 'none'})[/dim]"
            )
    if attempts:
        console.print(f"\n[cyan]tool runs — {len(attempts)}[/cyan]")
        for n in attempts:
            p = n["properties"]
            verdict_icon = (f"[red]{FAIL_MARK} confirmed[/red]"
                            if p.get("confirmed") else "not confirmed")
            line = (f"  [magenta]{n['label']}[/magenta] "
                    f"[dim]exit {p.get('exit_code', '?')}[/dim] — {verdict_icon}")
            err = (p.get("error_excerpt") or "").strip()
            if err:
                line += f" [dim]({err[:80]})[/dim]"
            console.print(line)
    # approved but never executed: the operator approved these and the
    # runner had no tool template for them — must be visible, not silent
    approved = [n for n in hypotheses if n["properties"].get("approved")]
    attempted = {n["label"].split(":")[0] for n in attempts}
    skipped = [n["label"] for n in approved if n["label"] not in attempted]
    if skipped:
        console.print(f"\n[yellow]skipped (no runnable tool): {len(skipped)}[/yellow]")
        console.print(f"  [dim]{', '.join(skipped)}[/dim]")
    if findings:
        console.print(f"\n[green]findings — {len(findings)}[/green]")
        for n in findings:
            mark = "[bold]verified[/bold]" if n["properties"].get("verified") else ""
            console.print(f"  [magenta]{n['label']}[/magenta] {mark}")

    # engaged is computed above for the panel; keep the audit head last so
    # it stays the final, verifiable line of the run
    console.print(f"\n[dim]audit chain head: {audit.head_hash()[:16]}…[/dim]")


def _short_path(path: "Any", home: "Any") -> str:
    """A path under the kryonsec home, written as ~/… .

    Both paths in the summary live under the engagement directory, so the
    home prefix is the same on every line and carries no information. It is
    also what pushed the row past the panel width, and rich truncates from
    the right — which hid the one part worth reading, the filename.
    """
    text = str(path)
    prefix = str(home)
    if prefix and text.startswith(prefix):
        return "~" + text[len(prefix):]
    return text


def _elapsed_text(orch: "Any") -> str:
    """Wall-clock duration of the engagement, if the budget tracker ran."""
    seconds = getattr(getattr(orch, "budget", None), "elapsed_s", 0.0) or 0.0
    total = int(seconds)
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kryonsec", description=__doc__)
    parser.add_argument("--version", action="version", version=f"kryonsec {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("doctor", help="run preflight checks (storage, LLMs, Purple Team prerequisites)")

    sub.add_parser("setup", help="run the setup wizard (config.toml: LLM, tools, MCP)")

    purple = sub.add_parser("purple", help="start a Purple Team engagement (Profile 2, Linux only)")
    purple.add_argument("--target", required=True, help="authorized target (e.g. example.com)")
    purple.add_argument("--id", default=None, help="engagement id (default: auto-generated)")
    purple.add_argument(
        "--code", default=None, metavar="FOLDER",
        help="code folder for blue-team static scanning (mounted read-only "
             "into the sandbox)")

    memory = sub.add_parser(
        "memory",
        help="browse saved engagement memory in a browser (read-only, localhost)")
    memory.add_argument(
        "--host", default="127.0.0.1",
        help="bind address (loopback only; default: 127.0.0.1)")
    memory.add_argument(
        "--port", type=int, default=8899,
        help="port (default: 8899; if it is busy, a free one is picked)")
    memory.add_argument(
        "--no-browser", dest="open_browser", action="store_false",
        help="print the URL instead of opening a browser (headless boxes)")

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    from .config import load_config

    cfg = load_config()

    if args.command == "doctor":
        from .doctor import run_doctor

        return run_doctor(cfg)

    if args.command == "purple":
        return _wait_for_memory_browser(_run_purple(
            cfg, args.target, engagement_id=args.id, code_folder=args.code,
            memory_browser=True))

    if args.command == "memory":
        return _run_memory(
            cfg, host=args.host, port=args.port, open_browser=args.open_browser)

    if args.command == "setup":
        from .wizard import run_setup

        try:
            run_setup(cfg)
        except KeyboardInterrupt:
            console.print("\n[yellow]setup cancelled — run `kryonsec setup` anytime[/yellow]")
        except EOFError:
            # stdin isn't a terminal (piped, or a CI/detached shell) — input()
            # raised instead of reading an answer. Was an uncaught traceback.
            console.print(
                "\n[yellow]setup needs an interactive terminal — "
                "run `kryonsec setup` from a real shell[/yellow]"
            )
            return 1
        return 0

    # first run without a config -> wizard before the chat loop
    from .config import config_path

    if not config_path(cfg.home).is_file():
        console.print("[dim]no config found — running first-time setup\n[/dim]")
        from .wizard import run_setup

        try:
            run_setup(cfg)
        except KeyboardInterrupt:
            console.print("\n[yellow]setup cancelled[/yellow]")
            return 0
        except EOFError:
            # no terminal on stdin — the wizard can't ask anything. Fall
            # through: config isn't written, so there's nothing to start into.
            console.print(
                "\n[yellow]no terminal for first-time setup — "
                "run `kryonsec setup` in an interactive shell[/yellow]"
            )
            return 1
        if not config_path(cfg.home).is_file():
            return 0  # aborted before writing — nothing to start

    console.print(welcome(cfg))
    try:
        asyncio.run(_chat_loop(cfg))
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("")  # Ctrl+C during shutdown — exit cleanly
    return 0


if __name__ == "__main__":
    sys.exit(main())
