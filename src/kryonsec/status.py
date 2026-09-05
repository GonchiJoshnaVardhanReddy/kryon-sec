"""One-line spinner status: which agent is running and what tool.

Claude-Code-style activity line — a Rich spinner that can be re-labelled
while work is in flight (which state of a purple engagement, which tool
the copilot agent is calling) and hidden while the terminal is needed
for something else (an approval prompt).

Non-TTY (pipes, tests, CI): everything is a silent no-op — output stays
clean and nothing garbles.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from rich.console import Console


class StatusLine:
    """A single spinner status line owned by one console."""

    def __init__(self, console: Console) -> None:
        self._console = console
        self._status = None  # rich.status.Status while active

    @property
    def active(self) -> bool:
        return self._status is not None

    @contextmanager
    def running(self, text: str) -> Iterator["StatusLine"]:
        """Show the spinner with `text` for the duration of the block."""
        self.show(text)
        try:
            yield self
        finally:
            self.hide()

    def show(self, text: str) -> None:
        """Start the spinner (or re-label it if already running)."""
        if not self._console.is_terminal:
            return
        if self._status is not None:
            self._status.update(text)
            return
        self._status = self._console.status(text, spinner="dots")
        self._status.start()

    def update(self, text: str) -> None:
        """Re-label the running spinner (no-op when not running)."""
        if self._status is not None:
            self._status.update(text)

    def hide(self) -> None:
        """Stop the spinner; safe to call when not running. Restart with
        show() — pause/resume for approval prompts and tool output."""
        if self._status is not None:
            self._status.stop()
            self._status = None

    # alias: safety net for an exception unwinding past the context manager
    stop_if_active = hide
