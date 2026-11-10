"""Shared terminal UI primitives for Kryonsec.

The UI package is deliberately presentation-only.  It owns terminal themes,
renderable components, user-interface preferences, and a small event bus.  It
does not own LLM calls, workflow transitions, approvals, or tool execution.
"""

from .events import UIEvent, UIEventBus
from .prefs import UiPreferences, load_ui_preferences, save_ui_preferences
from .theme import ThemeTokens, terminal_capabilities, theme_names, resolve_theme

__all__ = [
    "UIEvent",
    "UIEventBus",
    "UiPreferences",
    "ThemeTokens",
    "load_ui_preferences",
    "resolve_theme",
    "save_ui_preferences",
    "terminal_capabilities",
    "theme_names",
]
