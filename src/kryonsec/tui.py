"""Terminal UI helpers (spec v2.1.1 §5.1): prompt_toolkit-based input
with a Shift+Tab mode toggle and the `[COPILOT]>` / `[PURPLE]>` prompt
indicator.

Kept separate from cli.py so the toggle logic is unit-testable without
a live terminal.
"""

from __future__ import annotations

from typing import Any

from .config import KryonsecConfig

# (style, text) fragments for prompt_toolkit formatted text
_COPILOT_STYLE = "fg:ansicyan bold"
_PURPLE_STYLE = "fg:ansimagenta bold"


def set_mode(
    mode: list[str],
    notice: list[str],
    cfg: KryonsecConfig,
    new_mode: str,
) -> bool:
    """Switch the active mode holder. Refuses (and says why in the
    notice line) when purple mode is requested but the sandbox is not
    available. Returns True when the mode actually changed."""
    if new_mode == mode[0]:
        return False
    if new_mode == "purple":
        from .purple.runner import sandbox_available

        ok, reason = sandbox_available(cfg.sandbox_image)
        if not ok:
            notice[0] = f"cannot switch to purple: {reason} — staying in copilot"
            return False
    mode[0] = new_mode
    notice[0] = (
        f"mode: {new_mode.upper()} — type a target domain to run an engagement"
        if new_mode == "purple"
        else "mode: COPILOT"
    )
    return True


def prompt_message(
    mode: list[str],
    notice: list[str],
) -> list[tuple[str, str]]:
    """The prompt line (re-evaluated on every render so Shift+Tab
    repaints it immediately): optional one-line notice above, then the
    mode-colored indicator."""
    fragments: list[tuple[str, str]] = []
    if notice[0]:
        fragments.append(("", f"{notice[0]}\n"))
    style = _COPILOT_STYLE if mode[0] == "copilot" else _PURPLE_STYLE
    fragments.append((style, f"[{mode[0].upper()}]> "))
    return fragments


def build_key_bindings(
    mode: list[str],
    notice: list[str],
    cfg: KryonsecConfig,
) -> Any:
    """Shift+Tab toggles copilot <-> purple without losing what's
    already typed (the buffer is untouched; only the prompt repaints)."""
    from prompt_toolkit.key_binding import KeyBindings

    kb = KeyBindings()

    @kb.add("s-tab")
    def _toggle(event: Any) -> None:
        target = "purple" if mode[0] == "copilot" else "copilot"
        set_mode(mode, notice, cfg, target)
        event.app.invalidate()  # repaint with the new indicator now

    return kb


def make_prompt_session(
    mode: list[str],
    notice: list[str],
    cfg: KryonsecConfig,
) -> Any | None:
    """The PromptSession driving chat input: history file, Shift+Tab
    bindings, and the mode-aware prompt. Returns None if
    prompt_toolkit is unavailable (caller falls back to plain input)."""
    try:
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.shortcuts import PromptSession
    except ImportError:
        return None

    cfg.home.mkdir(parents=True, exist_ok=True)
    return PromptSession(
        history=FileHistory(str(cfg.home / "chat_history")),
        key_bindings=build_key_bindings(mode, notice, cfg),
        message=lambda: prompt_message(mode, notice),
        enable_history_search=True,  # Ctrl+R / up-arrow prefix search
    )
