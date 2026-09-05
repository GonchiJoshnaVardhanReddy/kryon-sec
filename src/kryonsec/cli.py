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

from rich.console import Console
from rich.markdown import Markdown

from . import __version__
from .config import KryonsecConfig

console = Console()
err_console = Console(stderr=True, style="red")

BANNER = r"""██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗███████╗███████╗ ██████╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔════╝
█████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║███████╗█████╗  ██║
██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║╚════██║██╔══╝  ██║
██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║███████║███████║╚██████╗
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝"""


def banner_styled(mode: str) -> str:
    """The banner, white in copilot mode, purple in purple team mode."""
    color = "magenta" if mode == "purple" else "white"
    return f"[bold {color}]{BANNER}[/bold {color}]"


def _print_banner(mode: str) -> None:
    """Re-print the banner whenever the mode flips (Shift+Tab or /mode)."""
    console.print(banner_styled(mode))


WELCOME = f"""{banner_styled("copilot")}
[bold cyan]v{{version}}[/bold cyan] — dual-mode cybersecurity CLI
[cyan]\\[COPILOT]>[/cyan] general assistant   [magenta]\\[PURPLE]>[/magenta] purple team (Profile 2, Linux)

Type your question. [bold]/help[/bold] for commands, [bold]/quit[/bold] to exit.
"""


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


def _build_mcp_extra(cfg: KryonsecConfig) -> dict:
    """MCP tools as agent-toolbox entries; empty when none configured."""
    if not cfg.mcp_servers:
        return {}
    from .copilot.mcp_tools import build_mcp_toolbox

    return build_mcp_toolbox(cfg)


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
        console.print(
            f"\n[bold]Approval required[/bold] — read: {req.path}\n"
            f"[dim]reason: {req.reason}[/dim]"
        )
        answer = console.input("[bold][A]pprove / [D]eny:[/bold] ")
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

    # mutable mode holder: "copilot" <-> "purple" via Shift+Tab or /mode
    _mode = ["copilot"]
    _notice = [""]  # one-line status shown above the prompt

    from .tui import make_prompt_session

    def _on_mode_change(new_mode: str) -> None:
        console.clear()  # repaint the banner in the new mode color
        _print_banner(new_mode)

    ps = make_prompt_session(_mode, _notice, cfg, on_change=_on_mode_change)

    while True:
        try:
            if ps is not None:
                user_input = await ps.prompt_async()
            else:  # prompt_toolkit unavailable — plain input fallback
                user_input = console.input(f"[cyan]\\[{_mode[0].upper()}]>[/cyan] ")
        except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
            console.print("\n[dim]bye[/dim]")
            return
        finally:
            _notice[0] = ""  # notices are one-shot

        text = user_input.strip()
        if not text:
            continue

        cmd = text.lower()
        if cmd in ("/quit", "/exit", "exit", "quit", "q"):
            _persist_session(cfg, session)
            console.print("[dim]bye[/dim]")
            return
        if cmd == "/help":
            console.print(
                "[bold]Commands[/bold]\n"
                "  /help            show this help\n"
                "  /quit            exit (or just: exit, quit)\n"
                "  /mode            switch mode (copilot / purple) — or press Shift+Tab\n"
                "  /cve <id>        look up a CVE (NVD, cached)\n"
                "  /search <query>  web search — results go into context\n"
                "  /read <path>     read a file (approval-gated outside workspace)\n"
                "  /ls <path>       list a directory (approval-gated outside workspace)\n"
                "  /write <path>    write text to a file in the workspace\n"
                "  /workspace       show the workspace path\n"
            )
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
            from .copilot.cve import lookup_cve

            try:
                record = lookup_cve(cfg, text[len("/cve "):].strip())
            except ValueError as e:
                err_console.print(f"{e}")
                continue
            if not record:
                console.print("[yellow]not found (offline cache miss and NVD unreachable — try again online)[/yellow]")
                continue
            score = record.get("cvss_score")
            console.print(
                f"[bold]{record['id']}[/bold] "
                f"[red]severity: {record.get('severity') or '?'}[/red] "
                f"[dim]CVSS: {score if score is not None else '?'}[/dim]"
            )
            console.print(record.get("description", "")[:500])
            if record.get("references"):
                console.print("[dim]refs: " + ", ".join(r for r in record["references"] if r) + "[/dim]")
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
            for r in results:
                console.print(f"[bold]{r['title']}[/bold]")
                console.print(f"[dim]{r['snippet']}[/dim]")
                console.print(f"[blue]{r['url']}[/blue]\n")
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
                FileTools(cfg).write_file(path, content)
                console.print(f"[green]wrote {path}[/green]")
                continue
        except Exception as e:
            err_console.print(f"{e}")
            continue

        # ---- purple mode: typed text is a target domain -------------------
        if _mode[0] == "purple":
            _run_purple(cfg, text)
            continue

        session.add("user", text)
        await session.maybe_compact()

        # ---- the agent loop (v1.1): tools when the LLM asks --------------
        from .copilot.agent import build_toolbox, run_agent
        from .copilot.tools import FileTools
        from .status import StatusLine

        file_tools = FileTools(cfg, approver=_console_approve)
        try:
            mcp_extra = _build_mcp_extra(cfg)
        except Exception as e:
            err_console.print(f"[yellow]MCP unavailable: {e}[/yellow]")
            mcp_extra = {}
        toolbox = build_toolbox(cfg, file_tools, extra=mcp_extra or None)

        status = StatusLine(console)

        def _show_tool(name: str, args: dict) -> None:
            # the spinner gives way: the tool may prompt for approval,
            # which needs the terminal
            status.hide()
            arg_preview = ", ".join(f"{k}={str(v)[:40]}" for k, v in (args or {}).items())
            console.print(f"  [dim]> using {name}({arg_preview})…[/dim]")

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
                hint = (
                    "Start Ollama (`ollama serve`) and pull a model "
                    "(`ollama pull llama3.1`), or run `kryonsec setup` to "
                    "switch to OpenAI."
                    if cfg.provider == "ollama"
                    else "Check your OpenAI key or network — or run "
                    "`kryonsec setup` to switch providers."
                )
                console.print(f"[yellow]{hint}[/yellow]")
                session.messages.pop()  # drop the unanswered user turn
                continue
        finally:
            status.hide()

        session.add("assistant", reply)
        console.print(Markdown(reply))
        console.print()
        _remember_facts(cfg, text, reply)  # best-effort LTM (never blocks chat)


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


def _run_purple(cfg: KryonsecConfig, target_arg: str) -> int:
    """Run one Purple Team engagement on a target. Shared by the `purple`
    subcommand and the /mode toggle inside the chat loop."""
    import uuid

    from .purple.orchestrator import STATES
    from .purple.runner import STATE_INFO, sandbox_available, start_engagement
    from .purple.zonea import validate_target
    from .status import StatusLine

    try:
        target = validate_target(target_arg)
    except ValueError as e:
        err_console.print(f"[red]Invalid target:[/red] {e}")
        return 2

    sandbox_ok, sandbox_reason = sandbox_available()
    if not sandbox_ok:
        console.print(f"[yellow]Sandbox not available:[/yellow] {sandbox_reason}")
        console.print("[yellow]Engagement will stop after passive recon (Zone A works everywhere).[/yellow]")

    engagement_id = str(uuid.uuid4())[:8]
    status_line = StatusLine(console)

    def _progress(msg: str) -> None:
        # while a state is running, the spinner carries the update;
        # between states it prints (state-entry lines stay in scrollback)
        if status_line.active:
            status_line.update(f"[magenta]purple {pct_holder[0]}%[/magenta] {msg}")
        else:
            console.print(f"  [magenta]>[/magenta] [bold]{msg}[/bold]")

    def _status_factory(state: str):
        n = STATES.index(state) + 1
        info = STATE_INFO.get(state, {})
        pct_holder[0] = int(100 * n / len(STATES))
        return status_line.running(
            f"[magenta]purple {pct_holder[0]}%[/magenta] "
            f"{info.get('agent', state)}: {info.get('does', '')[:60]}"
        )

    pct_holder = [0]

    orch, audit, graph = start_engagement(
        cfg, engagement_id, target=target, progress=_progress,
        status_factory=_status_factory,
    )
    console.print(f"[magenta]\\[PURPLE]>[/magenta] engagement {engagement_id} target={target}\n")
    completed = orch.run()
    status_line.stop_if_active()
    console.print(f"[green]states completed:[/green] {' -> '.join(completed)}")
    if orch.halt_reason:
        console.print(f"[red]halted:[/red] {orch.halt_reason}")
    subdomains = [n["label"] for n in graph.by_type("subdomain")]
    if subdomains:
        console.print(f"\n[cyan]passive recon found {len(subdomains)} subdomains:[/cyan]")
        for s in subdomains[:30]:
            console.print(f"  [dim]{s}[/dim]")
    hypotheses = graph.by_type("hypothesis")
    if hypotheses:
        console.print(f"\n[cyan]LLM proposed {len(hypotheses)} hypotheses:[/cyan]")
        for n in hypotheses:
            p = n["properties"]
            console.print(
                f"  [magenta]{n['label']}[/magenta] "
                f"[bold]{p.get('title', '')}[/bold] "
                f"[dim](confidence {p.get('confidence', 0):.1f}; "
                f"tools: {', '.join(p.get('tools', [])) or 'none'})[/dim]"
            )
    attempts = graph.by_type("exploit_attempt")
    if attempts:
        console.print(f"\n[cyan]tool runs executed: {len(attempts)}[/cyan]")
        for n in attempts:
            p = n["properties"]
            verdict = ("[red]confirmed[/red]" if p.get("confirmed")
                       else "not confirmed")
            line = (f"  [magenta]{n['label']}[/magenta] "
                    f"exit {p.get('exit_code', '?')} — {verdict}")
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
    findings = graph.by_type("finding")
    if findings:
        console.print(f"\n[green]confirmed findings: {len(findings)}[/green]")
        for n in findings:
            verified = n["properties"].get("verified")
            mark = " [bold]verified[/bold]" if verified else ""
            console.print(f"  [magenta]{n['label']}[/magenta]{mark}")
    console.print(f"\n[dim]audit chain head: {audit.head_hash()[:16]}…[/dim]")
    report_path = cfg.home / "engagements" / engagement_id / "report.md"
    if report_path.exists():
        console.print(f"[dim]report written: {report_path}[/dim]")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kryonsec", description=__doc__)
    parser.add_argument("--version", action="version", version=f"kryonsec {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("doctor", help="run preflight checks (storage, LLMs, Purple Team prerequisites)")

    sub.add_parser("setup", help="run the setup wizard (config.toml: LLM, tools, MCP)")

    purple = sub.add_parser("purple", help="start a Purple Team engagement (Profile 2, Linux only)")
    purple.add_argument("--target", required=True, help="authorized target (e.g. example.com)")
    purple.add_argument("--id", default=None, help="engagement id (default: auto-generated)")

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    from .config import load_config

    cfg = load_config()

    if args.command == "doctor":
        from .doctor import run_doctor

        return run_doctor(cfg)

    if args.command == "purple":
        return _run_purple(cfg, args.target)

    if args.command == "setup":
        from .wizard import run_setup

        try:
            run_setup(cfg)
        except KeyboardInterrupt:
            console.print("\n[yellow]setup cancelled — run `kryonsec setup` anytime[/yellow]")
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
        if not config_path(cfg.home).is_file():
            return 0  # aborted before writing — nothing to start

    console.print(WELCOME.format(version=__version__))
    try:
        asyncio.run(_chat_loop(cfg))
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("")  # Ctrl+C during shutdown — exit cleanly
    return 0


if __name__ == "__main__":
    sys.exit(main())
