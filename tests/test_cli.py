"""CLI module tests: import safety + mode-colored banner.

Importing kryonsec.cli as a module catches syntax errors (an earlier
bug shipped `await` outside an async function — the suite never
imported cli.py, so every test was green while the CLI was broken).
"""

from kryonsec import cli


def test_cli_imports_clean() -> None:
    """The module must import (syntax/typing errors fail here, not at
    first `kryonsec` launch)."""
    import importlib

    importlib.reload(cli)
    assert callable(cli.main)


def test_banner_white_in_copilot() -> None:
    assert "[bold white]" in cli.banner_styled("copilot")


def test_banner_purple_in_purple_mode() -> None:
    assert "[bold magenta]" in cli.banner_styled("purple")


def test_banner_has_kryonsec_art() -> None:
    # box-drawing art, not an empty style wrapper
    assert "██╗" in cli.BANNER
    assert "███████╗" in cli.BANNER
