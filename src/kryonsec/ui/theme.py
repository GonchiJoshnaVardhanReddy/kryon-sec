"""Kryonsec terminal theme tokens and capability detection.

Theme choices are presentation preferences only.  They never enter the
security or LLM configuration.  Rich receives named ANSI colours on limited
terminals and hex colours when truecolor is available.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ThemeTokens:
    """The small, shared visual vocabulary used by every terminal surface."""

    name: str
    mode: str
    accent: str
    accent_bright: str
    brand: str
    background: str
    surface: str
    surface_high: str
    text: str
    muted: str
    faint: str
    border: str
    success: str
    warning: str
    error: str
    info: str
    copilot: str
    purple: str
    code: str
    running: str
    completed: str
    pending: str
    skipped: str


_DARK_KRYONSEC = dict(
    brand="#a855f7",
    accent="#a855f7",
    accent_bright="#c084fc",
    background="#09090b",
    surface="#111118",
    surface_high="#1b1b25",
    text="#f4f4f5",
    muted="#a1a1aa",
    faint="#71717a",
    border="#3f3f46",
    success="#4ade80",
    warning="#facc15",
    error="#fb7185",
    info="#67e8f9",
    copilot="#22d3ee",
    purple="#c084fc",
    code="#e4e4e7",
    running="#22d3ee",
    completed="#4ade80",
    pending="#71717a",
    skipped="#a1a1aa",
)

_LIGHT_KRYONSEC = dict(
    brand="magenta",
    accent="magenta",
    accent_bright="bright_magenta",
    background="white",
    surface="bright_white",
    surface_high="white",
    text="black",
    muted="bright_black",
    faint="bright_black",
    border="bright_black",
    success="green",
    warning="yellow",
    error="red",
    info="cyan",
    copilot="cyan",
    purple="magenta",
    code="black",
    running="cyan",
    completed="green",
    pending="bright_black",
    skipped="bright_black",
)

_TOKYO_NIGHT = dict(
    brand="#bb9af7",
    accent="#bb9af7",
    accent_bright="#c0caf5",
    background="#16161e",
    surface="#1f2335",
    surface_high="#292e42",
    text="#c0caf5",
    muted="#a9b1d6",
    faint="#565f89",
    border="#3b4261",
    success="#9ece6a",
    warning="#e0af68",
    error="#f7768e",
    info="#7dcfff",
    copilot="#7dcfff",
    purple="#bb9af7",
    code="#c0caf5",
    running="#7dcfff",
    completed="#9ece6a",
    pending="#565f89",
    skipped="#a9b1d6",
)

_DRACULA = dict(
    brand="#bd93f9",
    accent="#bd93f9",
    accent_bright="#ff79c6",
    background="#282a36",
    surface="#303241",
    surface_high="#44475a",
    text="#f8f8f2",
    muted="#b8b8c5",
    faint="#6272a4",
    border="#6272a4",
    success="#50fa7b",
    warning="#f1fa8c",
    error="#ff5555",
    info="#8be9fd",
    copilot="#8be9fd",
    purple="#bd93f9",
    code="#f8f8f2",
    running="#8be9fd",
    completed="#50fa7b",
    pending="#6272a4",
    skipped="#b8b8c5",
)

_THEMES = {
    "kryonsec": (_DARK_KRYONSEC, _LIGHT_KRYONSEC),
    "tokyonight": (_TOKYO_NIGHT, _TOKYO_NIGHT),
    "dracula": (_DRACULA, _DRACULA),
}


# ---- workspace palette (mode-driven, not preference-driven) --------------
#
# The full-screen workspace no longer reads ui.json for its colours: Mode A is
# pure black/white/gray and Mode B is the same monochrome design with purple
# reserved exclusively for the KRYONSEC wordmark.  Saved theme preferences
# still exist for the other terminal surfaces, and `/theme` keeps writing
# them; they simply cannot override the required mode design here.

_MODE_A_TOKENS = dict(
    background="#0a0a0a",
    surface="#141414",
    surface_high="#1f1f1f",
    text="#f4f4f4",
    muted="#a3a3a3",
    faint="#6f6f6f",
    border="#3d3d3d",
    # Every "semantic" colour is monochrome; state is carried by the text
    # marks (✓ · ! · …) in `ui.state.status_mark`, never by colour alone.
    success="#f4f4f4",
    warning="#d4d4d4",
    error="#ffffff",
    info="#a3a3a3",
    copilot="#ffffff",
    purple="#a855f7",  # unused in Mode A rendering
    code="#e5e5e5",
    running="#f4f4f4",
    completed="#f4f4f4",
    pending="#737373",
    skipped="#a3a3a3",
    brand="#ffffff",
)
_MODE_A_TOKENS["accent"] = "#e5e5e5"
_MODE_A_TOKENS["accent_bright"] = "#ffffff"

_MODE_B_TOKENS = dict(_MODE_A_TOKENS)
_MODE_B_TOKENS["accent"] = "#e5e5e5"
_MODE_B_TOKENS["accent_bright"] = "#ffffff"
_MODE_B_TOKENS["brand"] = "#a855f7"  # Kryonsec wordmark only

_MODE_A_ANSI = dict(
    background="black",
    surface="black",
    surface_high="bright_black",
    text="white",
    muted="bright_black",
    faint="bright_black",
    border="bright_black",
    success="white",
    warning="white",
    error="bright_white",
    info="bright_black",
    copilot="white",
    purple="magenta",  # unused in Mode A rendering
    code="white",
    running="white",
    completed="white",
    pending="bright_black",
    skipped="bright_black",
    brand="bright_white",
)
_MODE_A_ANSI["accent"] = "white"
_MODE_A_ANSI["accent_bright"] = "bright_white"

_MODE_B_ANSI = dict(_MODE_A_ANSI)
_MODE_B_ANSI["brand"] = "magenta"


def workspace_tokens(
    mode: str = "copilot", *, truecolor: bool | None = None
) -> ThemeTokens:
    """Resolve the full-screen workspace palette for one Kryonsec mode.

    Mode A is entirely monochrome and Mode B is monochrome with purple
    reserved for the Kryonsec branding.  This deliberately ignores saved
    theme preferences so an old colour choice can never bring accents back
    into the workspace.
    """
    if truecolor is None:
        truecolor = terminal_capabilities().get("truecolor", False)
    if mode == "purple":
        tokens = dict(_MODE_B_TOKENS if truecolor else _MODE_B_ANSI)
    else:
        tokens = dict(_MODE_A_TOKENS if truecolor else _MODE_A_ANSI)
    return ThemeTokens(name=f"workspace-{mode}", mode="dark", **tokens)


def theme_names() -> tuple[str, ...]:
    """Return built-in theme names in stable menu order."""
    return tuple(_THEMES)


def terminal_capabilities(stream: Any | None = None) -> dict[str, bool]:
    """Describe only terminal capabilities relevant to rendering."""
    stream = stream or sys.stdout
    try:
        is_tty = bool(stream.isatty())
    except Exception:
        is_tty = False
    encoding = str(getattr(stream, "encoding", "") or "").lower()
    term = os.environ.get("TERM", "").lower()
    color = os.environ.get("COLORTERM", "").lower()
    truecolor = color in {"truecolor", "24bit"} or "direct" in term
    unicode_ok = encoding in {"utf-8", "utf8"} or not encoding
    return {
        "tty": is_tty,
        "truecolor": is_tty and truecolor,
        "unicode": unicode_ok,
        "dumb": term == "dumb",
    }


def _ansi_tokens(tokens: dict[str, str]) -> dict[str, str]:
    """Use portable ANSI names when a terminal cannot reliably show RGB."""
    return {
        "brand": "magenta",
        "accent": "magenta",
        "accent_bright": "bright_magenta",
        "background": "black",
        "surface": "black",
        "surface_high": "bright_black",
        "text": "white",
        "muted": "bright_black",
        "faint": "bright_black",
        "border": "bright_black",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "info": "cyan",
        "copilot": "cyan",
        "purple": "magenta",
        "code": "white",
        "running": "cyan",
        "completed": "green",
        "pending": "bright_black",
        "skipped": "bright_black",
    }


def resolve_theme(
    name: str = "kryonsec",
    mode: str = "dark",
    *,
    truecolor: bool | None = None,
) -> ThemeTokens:
    """Resolve a safe built-in theme; unknown values fall back to Kryonsec."""
    name = name if name in _THEMES else "kryonsec"
    mode = mode if mode in {"dark", "light", "system"} else "dark"
    if mode == "system":
        mode = "light" if os.environ.get("KRYONSEC_LIGHT") == "1" else "dark"
    dark, light = _THEMES[name]
    tokens = dict(light if mode == "light" else dark)
    if truecolor is None:
        truecolor = terminal_capabilities().get("truecolor", False)
    if not truecolor:
        tokens = _ansi_tokens(tokens)
    return ThemeTokens(name=name, mode=mode, **tokens)
