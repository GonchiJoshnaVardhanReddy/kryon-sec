"""Non-critical, user-interface-only preferences."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .theme import theme_names


@dataclass
class UiPreferences:
    theme: str = "kryonsec"
    mode: str = "dark"

    def normalize(self) -> "UiPreferences":
        if self.theme not in theme_names():
            self.theme = "kryonsec"
        if self.mode not in {"dark", "light", "system"}:
            self.mode = "dark"
        return self


def preferences_path(home: Path) -> Path:
    return home / "ui.json"


def load_ui_preferences(home: Path) -> UiPreferences:
    """Read UI preferences without treating corruption as security config."""
    path = preferences_path(home)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return UiPreferences()
        theme = data.get("theme", {})
        if isinstance(theme, dict):
            return UiPreferences(
                theme=str(theme.get("name", "kryonsec")),
                mode=str(theme.get("mode", "dark")),
            ).normalize()
    except (OSError, ValueError, TypeError):
        pass
    return UiPreferences()


def save_ui_preferences(home: Path, preferences: UiPreferences) -> Path:
    """Atomically write only appearance choices; never write credentials."""
    preferences.normalize()
    home.mkdir(parents=True, exist_ok=True)
    path = preferences_path(home)
    fd, name = tempfile.mkstemp(prefix=".ui.", suffix=".tmp", dir=str(home))
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(
                {"theme": {"name": preferences.theme, "mode": preferences.mode}},
                handle,
                indent=2,
            )
            handle.write("\n")
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass
    return path
