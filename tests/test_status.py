"""Tests for the spinner status line."""

from io import StringIO

from rich.console import Console

from kryonsec.status import StatusLine


class FakeStatus:
    def __init__(self):
        self.text = ""
        self.started = 0
        self.stopped = 0
        self.updates: list[str] = []

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1

    def update(self, text):
        self.text = text
        self.updates.append(text)


class FakeConsole:
    is_terminal = True

    def __init__(self):
        self.last_status = None

    def status(self, text, spinner=None):
        s = FakeStatus()
        s.text = text
        s.updates.append(text)
        self.last_status = s
        return s


def test_show_starts_and_hide_stops():
    con = FakeConsole()
    line = StatusLine(con)
    assert not line.active
    line.show("working")
    assert line.active
    assert con.last_status.started == 1
    line.hide()
    assert not line.active
    assert con.last_status.stopped == 1


def test_show_while_running_relabels_not_restarts():
    con = FakeConsole()
    line = StatusLine(con)
    line.show("first")
    line.show("second")
    assert con.last_status.started == 1  # still the one status
    assert con.last_status.updates == ["first", "second"]


def test_running_context_manager_stops_on_exit():
    con = FakeConsole()
    line = StatusLine(con)
    with line.running("job"):
        assert line.active
        line.update("job 50%")
    assert not line.active
    assert con.last_status.stopped >= 1


def test_update_and_hide_are_noops_when_not_running():
    con = FakeConsole()
    line = StatusLine(con)
    line.update("nothing")  # must not raise
    line.hide()


def test_non_terminal_console_is_fully_silent():
    con = Console(file=StringIO(), force_terminal=False)
    line = StatusLine(con)
    assert not con.is_terminal
    line.show("anything")
    assert not line.active
    with line.running("job"):
        assert not line.active
    line.update("x")
    line.hide()


def test_cli_only_calls_methods_that_exist():
    """Guard against a deleted alias with a live caller.

    v1.3.1 removed the `stop_if_active = hide` alias believing it had no
    callers, but cli.py still called it — every completed purple engagement
    died with AttributeError before printing its summary. Adding a method to
    StatusLine is free; removing one has to fail here first.

    The guard is bound to the *variable*, not to one hard-coded name: cli.py
    names its instance `status` in the copilot loop and used to name it
    `status_line` in the purple path (purple now uses PurpleUI instead). A
    fixed `status_line\\.` pattern would have quietly stopped guarding
    anything the moment that rename happened, which is exactly the failure
    this test exists to catch.
    """
    import re
    from pathlib import Path

    cli = (Path(__file__).resolve().parents[1]
           / "src" / "kryonsec" / "cli.py").read_text(encoding="utf-8")
    variables = set(re.findall(r"(\w+)\s*=\s*StatusLine\(", cli))
    assert variables, "expected cli.py to construct a StatusLine somewhere"
    called = set()
    for name in variables:
        called |= set(re.findall(rf"\b{name}\.([A-Za-z_][A-Za-z0-9_]*)", cli))
    missing = sorted(called - set(dir(StatusLine)))
    assert not missing, (
        f"cli.py calls StatusLine methods that do not exist: {missing} "
        f"(StatusLine has: {sorted(m for m in dir(StatusLine) if not m.startswith('_'))})"
    )
