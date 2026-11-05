"""Presentation helpers for the existing setup operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .theme import resolve_theme, terminal_capabilities


@dataclass
class WizardProgress:
    """A safe stepper; it never receives or prints credential values."""

    console: Console
    total: int = 5
    current: int = 0

    def __post_init__(self) -> None:
        capabilities = terminal_capabilities(getattr(self.console, "file", None))
        self.theme = resolve_theme(
            truecolor=capabilities.get("truecolor", False),
        )
        self.glyphs = ("✓", "›", "·") if capabilities.get("unicode", False) else ("+", ">", ".")

    def start(self) -> None:
        self.console.print(Panel(
            "Configure providers, tools, MCP, and optional recon sources.\n"
            "Credentials are masked and are never included in UI status lines.",
            title="[bold #a855f7]KRYONSEC ONBOARDING[/bold #a855f7]",
            subtitle="[dim]Ctrl+C cancels without changing incomplete configuration[/dim]",
            border_style=self.theme.accent,
        ))

    def step(self, number: int, label: str, detail: str = "") -> None:
        self.current = number
        table = Table.grid(padding=(0, 2))
        table.add_column(style=self.theme.accent, justify="right", no_wrap=True)
        table.add_column(style="bold")
        table.add_column(style=self.theme.muted, overflow="ellipsis")
        for index in range(1, self.total + 1):
            if index < number:
                mark, style = self.glyphs[0], self.theme.success
            elif index == number:
                mark, style = self.glyphs[1], self.theme.accent_bright
            else:
                mark, style = self.glyphs[2], self.theme.faint
            text = label if index == number else ""
            if index == number and detail:
                text = f"{text} — {detail}"
            table.add_row(f"{mark} {index}/{self.total}", text, "")
        self.console.print(Panel(table, border_style=self.theme.border, padding=(0, 1)))

    def done(self, message: str) -> None:
        self.console.print(f"[{self.theme.success}]✓[/] {message}")
