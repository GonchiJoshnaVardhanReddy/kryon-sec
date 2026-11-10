"""Conservative runtime checks for the interactive terminal.

This module deliberately has no Textual import at module scope: the CLI can
ask whether the full-screen app is safe to start even when an older or partial
environment does not have Textual installed, and fall back to the plain loop.
"""

from __future__ import annotations

import os
import sys


def interactive_terminal_available() -> bool:
    """Return whether the full-screen Textual app can own this terminal.

    A false result is not an error. Pipes, CI, legacy encodings, `TERM=dumb`,
    and a missing Textual install all keep the readable non-interactive loop.
    """
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return False
        if sys.stdout.encoding and sys.stdout.encoding.lower() not in {
            "utf-8",
            "utf8",
            "cp65001",
        }:
            return False
        if os.environ.get("TERM", "").lower() == "dumb":
            return False
        from textual.app import App as _TextualApp

        return _TextualApp is not None
    except Exception:
        return False


__all__ = ["interactive_terminal_available"]
