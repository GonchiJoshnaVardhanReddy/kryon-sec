"""Reusable Rich components for the unified Kryonsec workspace."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from rich.console import Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .. import __version__
from ..secrets import redact
from .theme import ThemeTokens


def provider_label(provider: str) -> str:
    return {
        "openai": "OpenAI",
        "ollama": "Ollama",
        "bedrock": "AWS Bedrock",
        "openai_compatible": "OpenAI-compatible",
    }.get(provider, provider or "not configured")


def header_panel(
    cfg: Any,
    *,
    mode: str,
    theme: ThemeTokens,
    session_id: str | None = None,
    engagement_id: str | None = None,
    status: str = "ready",
    sandbox_status: str | None = None,
) -> Panel:
    """Top-level identity and runtime context, without sensitive values."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style=theme.muted, justify="right", no_wrap=True)
    table.add_column(style=theme.text, overflow="ellipsis")
    mode_label = "MODE A · COPILOT" if mode == "copilot" else "MODE B · PURPLE TEAM"
    mode_style = theme.copilot if mode == "copilot" else theme.purple
    table.add_row("Mode", f"[{mode_style}]{mode_label}[/{mode_style}]")
    table.add_row("Provider", provider_label(str(getattr(cfg, "provider", ""))))
    table.add_row("Model", str(getattr(cfg, "general_chat_model", "—") or "—"))
    if session_id:
        table.add_row("Session", session_id)
    if engagement_id:
        table.add_row("Engagement", engagement_id)
    if sandbox_status:
        table.add_row("Sandbox", sandbox_status)
    table.add_row("Status", f"[{theme.success}]{status}[/{theme.success}]")
    return Panel(
        table,
        title=f"[bold {theme.accent}]KRYONSEC[/bold {theme.accent}] [dim]v{__version__}[/dim]",
        subtitle=f"[{mode_style}]{mode_label}[/{mode_style}]",
        border_style=mode_style,
        padding=(0, 1),
    )


def footer_text(mode: str, *, active: str = "idle", compact: bool = False) -> Text:
    """Keyboard guidance kept short enough for narrow terminals."""
    text = Text()
    text.append(f" {active}  ", style="bold")
    text.append("Shift+Tab mode  ·  Ctrl+P commands  ·  /help help", style="dim")
    if not compact:
        text.append("  ·  Ctrl+C interrupt  ·  Enter send", style="dim")
    return text


def conversation_panel(
    role: str,
    content: str,
    *,
    theme: ThemeTokens,
    label: str | None = None,
) -> Panel:
    """Render a safe user/assistant message with Markdown for responses."""
    safe, _ = redact(str(content or ""))
    if role == "assistant":
        body: Any = Markdown(safe or "(empty response)", code_theme="monokai")
        title = label or "assistant"
        border = theme.accent
    elif role == "user":
        body = Text(safe or "(empty message)", style=theme.text)
        title = label or "you"
        border = theme.copilot
    else:
        body = Text(safe, style=theme.muted)
        title = label or role
        border = theme.border
    return Panel(body, title=f"[bold]{title}[/bold]", border_style=border, padding=(0, 1))


@dataclass
class ToolActivityRow:
    name: str
    status: str
    detail: str = ""
    duration: str = ""


def tool_activity_panel(
    rows: Iterable[ToolActivityRow],
    *,
    theme: ThemeTokens,
    title: str = "TOOL ACTIVITY",
) -> Panel:
    rows = list(rows)
    if not rows:
        return Panel(Text("No tool activity yet", style=theme.muted), title=title, border_style=theme.border)
    table = Table(box=None, expand=True, padding=(0, 1), show_header=True, header_style=theme.muted)
    table.add_column("", width=2)
    table.add_column("Tool", no_wrap=True, overflow="ellipsis")
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", ratio=2, overflow="ellipsis")
    table.add_column("Time", justify="right", no_wrap=True)
    glyphs = {
        "running": "›",
        "completed": "✓",
        "failed": "!",
        "skipped": "·",
        "queued": "…",
        "returned": "·",
    }
    styles = {
        "running": theme.running,
        "completed": theme.completed,
        "failed": theme.error,
        "skipped": theme.skipped,
        "queued": theme.pending,
        "returned": theme.info,
    }
    for row in rows[-12:]:
        style = styles.get(row.status, theme.muted)
        table.add_row(
            Text(glyphs.get(row.status, "·"), style=style),
            Text(row.name, style="bold" if row.status == "running" else theme.text),
            Text(row.status, style=style),
            Text(redact(row.detail)[0], style=theme.muted),
            Text(row.duration, style=theme.muted),
        )
    return Panel(table, title=f"[bold]{title}[/bold]", border_style=theme.border)


def command_palette_panel(theme: ThemeTokens, commands: Mapping[str, str]) -> Panel:
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style=f"bold {theme.accent}", no_wrap=True)
    table.add_column(style=theme.muted)
    for command, description in commands.items():
        table.add_row(command, description)
    return Panel(table, title="[bold]COMMAND PALETTE[/bold]", border_style=theme.accent)


def approval_panel(
    *,
    action: str,
    requested_path: str,
    resolved_path: str,
    reason: str,
    theme: ThemeTokens,
) -> Panel:
    """Shared fail-closed file approval presentation."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style=theme.muted, justify="right")
    table.add_column(style=theme.text)
    table.add_row("Operation", action)
    table.add_row("Requested", redact(requested_path or resolved_path)[0])
    if requested_path and requested_path != resolved_path:
        table.add_row("Resolved", f"[bold {theme.error}]{redact(resolved_path)[0]}[/bold {theme.error}]")
    else:
        table.add_row("Resolved", redact(resolved_path)[0])
    table.add_row("Reason", redact(reason or "not provided")[0])
    table.add_row("Decision", f"[{theme.warning}]A approve[/{theme.warning}]  [dim]D deny · Enter denies[/dim]")
    return Panel(table, title=f"[bold {theme.warning}]APPROVAL REQUIRED[/bold {theme.warning}]", border_style=theme.warning)


def workflow_timeline(
    states: list[str],
    *,
    current: str,
    completed: set[str],
    theme: ThemeTokens,
    compact: bool = False,
) -> Panel:
    """Responsive, honest stage timeline for Purple Team."""
    labels = {s: s.replace("_", " ") for s in states}
    table = Table(box=None, expand=True, padding=(0, 1), show_header=False)
    if compact:
        table.add_column(no_wrap=True)
        parts: list[str] = []
        for state in states:
            if state == current:
                parts.append(f"[{theme.running}]› {labels[state]}[/{theme.running}]")
            elif state in completed:
                parts.append(f"[{theme.completed}]✓ {labels[state]}[/{theme.completed}]")
            else:
                parts.append(f"[{theme.pending}]· {labels[state]}[/{theme.pending}]")
        table.add_row("  ".join(parts))
    else:
        table.add_column("Stage", no_wrap=True)
        table.add_column("State", no_wrap=True)
        table.add_column("Meaning", ratio=2, overflow="ellipsis")
        for index, state in enumerate(states, 1):
            if state == current:
                mark, style, status = "›", theme.running, "running"
            elif state in completed:
                mark, style, status = "✓", theme.completed, "completed"
            else:
                mark, style, status = "·", theme.pending, "pending"
            table.add_row(
                Text(f"{mark} {index:02d}", style=style),
                Text(labels[state], style=f"bold {style}" if status == "running" else style),
                Text(status, style=style),
            )
    return Panel(table, title="[bold]WORKFLOW TIMELINE[/bold]", border_style=theme.border)
