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

WELCOME = """[bold cyan]Kryonsec v{version}[/bold cyan] — dual-mode cybersecurity CLI
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


async def _chat_loop(cfg: KryonsecConfig) -> None:
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    from .copilot import GeneralSession
    from .copilot.tools import ApprovalRequest
    from .llm import LlmUnavailable, chat
    from .storage import GeneralUserLtm, get_session as db_session

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

    # ---- load user preferences (User LTM) -------------------------------
    prefs: dict = {"explain_mode": "technical"}
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
    except Exception as e:  # storage unavailable — chat still works in-memory
        err_console.print(f"[yellow]storage warning: {e} — session will not be persisted[/yellow]")

    system_prompt = env.get_template("system_prompt.jinja").render(
        workspace=str(cfg.workspace),
        explain_mode=str(prefs.get("explain_mode", "technical")),
        recent_topics=[],
    )

    session = GeneralSession(cfg=cfg)

    while True:
        try:
            user_input = console.input("[cyan]\\[COPILOT]>[/cyan] ")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]bye[/dim]")
            return

        text = user_input.strip()
        if not text:
            continue

        cmd = text.lower()
        if cmd in ("/quit", "/exit"):
            _persist_session(cfg, session)
            console.print("[dim]bye[/dim]")
            return
        if cmd == "/help":
            console.print(
                "[bold]Commands[/bold]\n"
                "  /help            show this help\n"
                "  /quit            exit\n"
                "  /mode            show current mode\n"
                "  /read <path>     read a file (approval-gated outside workspace)\n"
                "  /ls <path>       list a directory (approval-gated outside workspace)\n"
                "  /write <path>    write text to a file in the workspace\n"
                "  /workspace       show the workspace path\n"
            )
            continue
        if cmd == "/mode":
            console.print("[cyan]mode: COPILOT[/cyan] (purple team requires Profile 2 — see `kryonsec doctor`)")
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

        session.add("user", text)
        await session.maybe_compact()

        try:
            reply = chat(cfg, session.as_llm_messages(system_prompt), cfg.general_chat_model)
        except LlmUnavailable as e:
            err_console.print(f"LLM unavailable: {e}")
            console.print(
                "[yellow]Start Ollama (`ollama serve`) and pull a model "
                "(`ollama pull llama3.1`), or set OPENAI_API_KEY.[/yellow]"
            )
            session.messages.pop()  # drop the unanswered user turn
            continue

        session.add("assistant", reply)
        console.print(Markdown(reply))
        console.print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kryonsec", description=__doc__)
    parser.add_argument("--version", action="version", version=f"kryonsec {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("doctor", help="run preflight checks (storage, LLMs, Purple Team prerequisites)")

    purple = sub.add_parser("purple", help="start a Purple Team engagement (Profile 2, Linux only)")
    purple.add_argument("--target", required=True, help="authorized target (e.g. example.com)")
    purple.add_argument("--id", default=None, help="engagement id (default: auto-generated)")

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    cfg = KryonsecConfig()

    if args.command == "doctor":
        from .doctor import run_doctor

        return run_doctor(cfg)

    if args.command == "purple":
        import uuid

        from .purple.runner import sandbox_available, start_engagement
        from .purple.zonea import validate_target

        try:
            target = validate_target(args.target)
        except ValueError as e:
            err_console.print(f"[red]Invalid target:[/red] {e}")
            return 2

        sandbox_ok, sandbox_reason = sandbox_available()
        if not sandbox_ok:
            console.print(f"[yellow]Sandbox not available:[/yellow] {sandbox_reason}")
            console.print("[yellow]Engagement will stop after passive recon (Zone A works everywhere).[/yellow]")

        engagement_id = args.id or str(uuid.uuid4())[:8]
        orch, audit, graph = start_engagement(cfg, engagement_id, target=target)
        console.print(f"[magenta]\\[PURPLE]>[/magenta] engagement {engagement_id} target={target}\n")
        completed = orch.run()
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
        console.print(f"\n[dim]audit chain head: {audit.head_hash()[:16]}…[/dim]")
        return 0

    console.print(WELCOME.format(version=__version__))
    asyncio.run(_chat_loop(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
