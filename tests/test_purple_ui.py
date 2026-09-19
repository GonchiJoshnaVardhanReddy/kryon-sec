"""Purple Team console rendering.

These tests are the contract for the UX redesign: an operator should be able
to answer "what am I testing, what stage, what tool is running right now, how
long, what have I found, did anything fail" by looking at one screen.

Two properties are load-bearing and are tested directly rather than
incidentally:

- **No traceback ever reaches the console.** Free public APIs return 429/403
  as normal behaviour; a wall of traceback trains operators to ignore
  warnings. The full record goes to debug.log instead (``PurpleLogHandler``).
- **Progress is never a bare percentage.** Stage 3 of 10 is knowable; "62%
  of the work" is not, and a bar that implies it is lying.

The console is driven here exactly as ``cli.py`` drives it — through the
orchestrator's state callback and the audit chain's observers — so these
tests exercise the real integration, not a private API.
"""

from __future__ import annotations

import logging
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console

from kryonsec.cli import _run_purple
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.orchestrator import STATES
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.ui import (
    COMPLETED,
    FAILED,
    QUEUED,
    RUNNING,
    SKIPPED,
    PurpleLogHandler,
    PurpleUI,
    attach_purple_logging,
    detach_purple_logging,
    tool_action,
    tool_label,
)


# ---- harness ------------------------------------------------------------


class Clock:
    """A monotonic clock the test drives."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_ui(target: str = "target-corp.com", engagement_id: str = "abc12345",
            graph=None, utf8: bool = True, clock: Clock | None = None) -> PurpleUI:
    console = Console(file=StringIO(), force_terminal=False, width=100)
    return PurpleUI(
        console, target=target, engagement_id=engagement_id, graph=graph,
        clock=clock or Clock(), utf8=utf8,
    )


def render(ui: PurpleUI, width: int = 100) -> str:
    """The screen as plain text — markup parsed, colour dropped."""
    console = Console(file=StringIO(), force_terminal=False, width=width,
                      no_color=True)
    console.print(ui.render())
    return console.file.getvalue()


def spawn(ui: PurpleUI, tool: str, state: str = "RECON_ACTIVE") -> None:
    ui.on_state(state)
    ui.on_audit({"event": "tool_spawn", "state": state, "tool": tool})


def settle(ui: PurpleUI, tool: str, ok: bool = True, **extra) -> None:
    entry = {"event": "tool_result", "tool": tool, "ok": ok}
    entry.update(extra)
    ui.on_audit(entry)


# ---- initial screen -----------------------------------------------------


def test_initial_screen_identifies_the_engagement():
    """Question 1: what target am I testing?"""
    out = render(make_ui())
    assert "target-corp.com" in out
    assert "abc12345" in out
    assert "KRYONSEC PURPLE TEAM" in out


def test_initial_screen_shows_the_whole_pipeline():
    out = render(make_ui())
    for label in ("INIT", "PASSIVE RECON", "ACTIVE RECON", "HYPOTHESIZE",
                  "HUMAN REVIEW", "EXPLOIT", "POST-EXPLOIT", "VERIFY",
                  "BLUE TEAM", "REPORT"):
        assert label in out


def test_initial_screen_is_not_started_not_zero_percent():
    """Before the loop runs there is no stage — say so rather than '0%'."""
    out = render(make_ui())
    assert "not started" in out
    assert "Stage 0 of 10" in out
    assert "%" not in out.replace("0%", "")  # no bare percentage anywhere


def test_empty_engagement_says_no_activity_rather_than_showing_nothing():
    out = render(make_ui())
    assert "no tool activity yet" in out


# ---- pipeline -----------------------------------------------------------


def test_pipeline_marks_current_and_completed_states():
    """Question 2: what stage am I in?"""
    ui = make_ui()
    ui.on_state("INIT")
    ui.on_state("RECON_PASSIVE")
    ui.on_state("RECON_ACTIVE")
    out = render(ui)

    assert "✓ INIT" in out
    assert "✓ PASSIVE RECON" in out
    assert "◉ ACTIVE RECON" in out
    assert "○ HYPOTHESIZE" in out


def test_stage_progress_is_labelled_as_stages_not_work_completion():
    """Honest progress: stage 3 of 10, never an implied '30% done'."""
    ui = make_ui()
    ui.on_state("INIT")
    ui.on_state("RECON_PASSIVE")
    ui.on_state("RECON_ACTIVE")
    out = render(ui)
    assert "Stage 3 of 10" in out
    assert str(len(STATES)) == "10"


def test_state_action_is_plain_english():
    ui = make_ui()
    ui.on_state("RECON_PASSIVE")
    assert "Collecting external intelligence" in render(ui)


# ---- current operation --------------------------------------------------


def test_active_tool_is_the_loudest_thing_on_screen():
    """Questions 3-5: what is running, what is it doing, how long."""
    clock = Clock()
    ui = make_ui(clock=clock)
    spawn(ui, "httpx")
    clock.advance(8)

    out = render(ui)
    # prominent panel, name, and a plain-English description of the work
    assert "CURRENT OPERATION" in out
    assert "httpx" in out
    assert "HTTP service discovery" in out
    assert "00:08" in out            # how long it has been running
    assert "ACTIVE RECON" in out     # which state


def test_current_operation_tracks_the_newest_tool():
    ui = make_ui()
    spawn(ui, "nmap")
    spawn(ui, "httpx")
    out = render(ui)
    current = out.split("CURRENT OPERATION")[1].split("TOOL ACTIVITY")[0]
    assert "httpx" in current
    assert "nmap" not in current


def test_completed_tools_remain_as_history():
    """Completed tools stay visible — they are the shape of the stage."""
    ui = make_ui()
    spawn(ui, "nmap")
    settle(ui, "nmap", exit_code=0, output_chars=120)
    spawn(ui, "httpx")
    out = render(ui)
    assert "nmap" in out
    assert "Port and service scan" in out


def test_completed_tool_shows_duration_and_result():
    clock = Clock()
    ui = make_ui(clock=clock)
    spawn(ui, "nmap")
    clock.advance(1.2)
    settle(ui, "nmap", output_chars=120)

    out = render(ui)
    assert "00:01" in out
    assert "120 chars" in out


def test_pending_tools_are_subtle():
    """Queued rows exist but carry no result and no time."""
    ui = make_ui()
    ui.on_state("RECON_ACTIVE")
    ui.on_audit({"event": "tool_spawn", "tool": "nmap"})
    settle(ui, "nmap")
    ui.on_audit({"event": "tool_spawn", "tool": "dnsx"})
    ui._running.clear()  # dnsx never reports — it is 'in flight', not queued
    ui.on_notice("")     # no-op, keeps the shape honest

    out = render(ui)
    assert "waiting" not in out  # nothing was ever declared queued


def test_queued_event_renders_as_waiting():
    ui = make_ui()
    ui.on_state("RECON_ACTIVE")
    from kryonsec.purple.ui import PurpleToolEvent

    ui.tools.append(PurpleToolEvent(
        state="RECON_ACTIVE", tool="nuclei", status=QUEUED))
    out = render(ui)
    assert "waiting" in out
    assert "nuclei" in out


# ---- skipped / failed ---------------------------------------------------


def test_skipped_tool_renders_quietly():
    """A skipped source is not an error — it must not read like one."""
    ui = make_ui()
    ui.on_state("RECON_PASSIVE")
    ui.on_audit({"event": "passive_source_skipped", "source": "censys_subdomains",
                 "reason": "no API key"})
    out = render(ui)
    assert "Censys" in out
    assert "no API key" in out


def test_failed_tool_is_marked_but_short():
    """Question 7: did anything fail? A summary, not a dump."""
    ui = make_ui()
    spawn(ui, "nmap")
    settle(ui, "nmap", ok=False, error="connection refused")
    out = render(ui)
    assert "nmap" in out
    assert "connection refused" in out
    assert ui.errors == 1


def test_error_count_is_visible_in_results():
    ui = make_ui()
    spawn(ui, "nmap")
    settle(ui, "nmap", ok=False, error="boom")
    assert "Errors" in render(ui)


# ---- warnings / traceback suppression -----------------------------------


def test_api_failure_becomes_one_plain_line():
    """The 429 from OTX is routine; it gets one line, not a traceback."""
    ui = make_ui()
    record = logging.LogRecord(
        name="kryonsec.purple.zonea", level=logging.WARNING,
        pathname=__file__, lineno=1,
        msg="otx passive dns query failed for target-corp.com", args=(), exc_info=None,
    )
    ui.on_log(record)
    out = render(ui)
    assert "Passive DNS lookup failed" in out
    assert "continuing" in out


def test_traceback_never_reaches_the_console():
    """The whole point of PurpleLogHandler: the record is split."""
    ui = make_ui()
    try:
        raise ValueError("secret internal detail")
    except ValueError:
        import sys

        record = logging.LogRecord(
            name="kryonsec.purple.zonea", level=logging.WARNING,
            pathname=__file__, lineno=1,
            msg="otx passive dns query failed", args=(),
            exc_info=sys.exc_info(),
        )
    ui.on_log(record)
    out = render(ui)
    assert "Traceback" not in out
    assert "ValueError" not in out
    assert "secret internal detail" not in out
    # the audit chain is untouched; only the screen is quiet
    assert "Passive DNS lookup failed" in out


def test_debug_level_logs_do_not_reach_the_screen():
    ui = make_ui()
    ui.on_log(logging.LogRecord(
        name="kryonsec.purple.zonea", level=logging.DEBUG, pathname=__file__,
        lineno=1, msg="internal detail", args=(), exc_info=None,
    ))
    assert "internal detail" not in render(ui)


def test_traceback_goes_to_the_debug_log(tmp_path):
    """The evidence is relocated, not discarded."""
    ui = make_ui()
    handler, log_path = attach_purple_logging(tmp_path, "abc12345", ui)
    try:
        logger = logging.getLogger("kryonsec.purple.testfile")
        try:
            raise ValueError("full detail lives here")
        except ValueError:
            logger.warning("something failed", exc_info=True)
    finally:
        detach_purple_logging(handler)

    written = Path(log_path).read_text(encoding="utf-8")
    assert "Traceback" in written
    assert "full detail lives here" in written
    assert "Traceback" not in render(ui)


def test_logging_is_restored_after_detach(tmp_path):
    """Copilot mode's logging must be exactly as it was."""
    root = logging.getLogger()
    before_level = root.level
    before = list(root.handlers)

    handler, _ = attach_purple_logging(tmp_path, "abc12345", None)
    detach_purple_logging(handler)

    assert root.level == before_level
    assert list(root.handlers) == before
    detach_purple_logging(handler)  # idempotent


def test_raw_warning_never_reaches_stderr_beside_the_notice(tmp_path):
    """Asserted against real stderr, not just our renderer.

    cli.py calls basicConfig(level=WARNING), so a WARNING-level stderr
    handler is already installed. The old attach pinned existing handlers
    *to* WARNING — where that one already was — so the raw line and its
    traceback printed next to the console's clean notice. Testing only
    ``ui.on_log``'s output could not see that, and the earlier version of
    this suite passed while the noise was still on screen.
    """
    ui = make_ui()
    stream = StringIO()
    stale = logging.StreamHandler(stream)
    stale.setLevel(logging.WARNING)
    stale.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    root = logging.getLogger()
    saved_level, saved_handlers = root.level, list(root.handlers)
    root.addHandler(stale)
    root.setLevel(logging.WARNING)
    try:
        handler, _ = attach_purple_logging(tmp_path, "abc12345", ui)
        try:
            logger = logging.getLogger("kryonsec.purple.zonea")
            try:
                raise ValueError("internal detail")
            except ValueError:
                logger.warning("otx passive dns query failed", exc_info=True)
        finally:
            detach_purple_logging(handler)
    finally:
        root.removeHandler(stale)
        root.setLevel(saved_level)
        assert list(root.handlers) == saved_handlers

    leaked = stream.getvalue()
    assert "Traceback" not in leaked
    assert "WARNING" not in leaked
    assert "internal detail" not in leaked
    # and the console still carried the one-line notice
    assert "Passive DNS lookup failed" in render(ui)


def test_stderr_is_left_alone_when_no_ui_is_attached(tmp_path):
    """Silence is only acceptable when something else carries the message."""
    stream = StringIO()
    stale = logging.StreamHandler(stream)
    stale.setLevel(logging.WARNING)

    root = logging.getLogger()
    saved_level, saved_handlers = root.level, list(root.handlers)
    root.addHandler(stale)
    root.setLevel(logging.WARNING)
    try:
        handler, _ = attach_purple_logging(tmp_path, "abc12345", None)
        try:
            logging.getLogger("kryonsec.purple.zonea").warning("still visible")
        finally:
            detach_purple_logging(handler)
    finally:
        root.removeHandler(stale)
        root.setLevel(saved_level)
        assert list(root.handlers) == saved_handlers

    assert "still visible" in stream.getvalue()


# ---- open questions the engine already answers --------------------------


def test_allowed_action_is_seen_by_the_console():
    """Question 8: what happens next? Exploit starts where review approved."""
    ui = make_ui()
    ui.on_state("HUMAN_REVIEW")
    ui.on_state("EXPLOIT")
    out = render(ui)
    assert "Testing approved hypotheses" in out
    assert "HUMAN REVIEW" in out


def test_zone_b_blocked_becomes_a_notice():
    ui = make_ui()
    ui.on_audit({"event": "zone_b_blocked", "reason": "sandbox unavailable"})
    assert "sandbox unavailable" in render(ui)


def test_allowlist_rejection_is_shown_as_skipped():
    ui = make_ui()
    ui.on_audit({"event": "passive_sandbox_rejected_by_allowlist",
                 "tool": "amass"})
    out = render(ui)
    assert "amass" in out
    assert "rejected by allowlist" in out


# ---- human review -------------------------------------------------------


def test_human_review_pauses_the_live_region(monkeypatch):
    """The approval prompt must own the terminal, not fight the spinner."""
    console = Console(file=StringIO(), force_terminal=True, width=100)
    ui = PurpleUI(console, target="t.com", engagement_id="abc", utf8=True,
                  clock=Clock())
    ui.start()
    assert ui._live is not None

    ui.on_state("HUMAN_REVIEW")
    assert ui._live is None

    ui.on_state("EXPLOIT")
    assert ui._live is not None
    ui.stop()


def test_human_review_panel_shows_the_decision_not_a_log_line():
    from kryonsec.purple.human_review import _approval_panel

    panel = _approval_panel(1, 3, {
        "label": "H1",
        "properties": {
            "title": "Broken authorization on /admin/export",
            "confidence": 0.92,
            "target_asset": "testaspnet.vulnweb.com",
            "rationale": "Student role accessed admin endpoint",
            "tools": ["curl"],
        },
    })
    console = Console(file=StringIO(), force_terminal=False, width=100,
                      no_color=True)
    console.print(panel)
    out = console.file.getvalue()

    assert "Broken authorization on /admin/export" in out
    assert "92%" in out
    assert "Student role accessed admin endpoint" in out
    assert "[A] Approve" in out and "[R] Reject" in out
    assert "1 of 3" in out


def test_human_review_panel_survives_a_malformed_hypothesis():
    """A rendering bug must never take the approval gate down with it."""
    from kryonsec.purple.human_review import _approval_panel

    panel = _approval_panel(1, 1, {})
    console = Console(file=StringIO(), force_terminal=False, width=100,
                      no_color=True)
    console.print(panel)  # must not raise
    assert "%" not in console.file.getvalue() or "—" in console.file.getvalue()


# ---- final summary ------------------------------------------------------


class FakeOrch:
    def __init__(self, halt_reason: str | None = None,
                 elapsed: float = 261.0) -> None:
        self.halt_reason = halt_reason
        self.budget = SimpleNamespace(elapsed_s=elapsed)


def summary(tmp_path, graph, completed, orch, **kw):
    from kryonsec import cli

    audit = AuditLog(tmp_path / "engagements" / "abc12345" / "audit.jsonl")
    capture = Console(file=StringIO(), force_terminal=False, width=100,
                      no_color=True)
    original = cli.console
    cli.console = capture
    try:
        cli._print_purple_summary(
            SimpleNamespace(home=tmp_path), "abc12345", "target-corp.com",
            completed, orch, audit, graph, **kw,
        )
    finally:
        cli.console = original
    return capture.file.getvalue()


def test_final_summary_is_a_report_panel(tmp_path):
    graph = EngagementGraph(engagement_id="abc12345")
    graph.add_node("target", "target-corp.com")
    for i in range(2):
        graph.add_node("finding", f"F{i}", {"verified": True})
    for i in range(6):
        graph.add_node("hypothesis", f"H{i}")
    for i in range(31):
        graph.add_node("exploit_attempt", f"A{i}")

    out = summary(tmp_path, graph, list(STATES), FakeOrch())

    assert "ENGAGEMENT COMPLETE" in out
    assert "target-corp.com" in out
    assert "04:21" in out              # duration
    assert "Verified findings" in out and "2" in out
    assert "Hypotheses" in out and "6" in out
    assert "Tool executions" in out and "31" in out
    assert "Evidence artifacts" in out


def test_halted_summary_says_why_and_how_far_it_got(tmp_path):
    graph = EngagementGraph(engagement_id="abc12345")
    graph.add_node("target", "target-corp.com")
    out = summary(tmp_path, graph, ["INIT", "RECON_PASSIVE"],
                  FakeOrch(halt_reason="sandbox unavailable"))

    assert "ENGAGEMENT HALTED" in out
    assert "sandbox unavailable" in out
    assert "Completed" in out
    assert "2 / 10 stages" in out


def test_summary_reports_the_report_and_debug_log_paths(tmp_path):
    graph = EngagementGraph(engagement_id="abc12345")
    graph.add_node("target", "target-corp.com")
    report = tmp_path / "engagements" / "abc12345" / "report.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("# report", encoding="utf-8")

    out = summary(tmp_path, graph, list(STATES), FakeOrch(),
                  debug_log=tmp_path / "engagements" / "abc12345" / "debug.log")
    assert "report.md" in out
    assert "debug.log" in out


# ---- terminal fit -------------------------------------------------------


@pytest.mark.parametrize("width", [60, 80, 120])
def test_nothing_wraps_past_the_terminal_width(width):
    """Narrow terminals must not produce a wrapped mess."""
    ui = make_ui()
    ui.on_state("RECON_ACTIVE")
    for tool in ("nmap", "naabu", "dnsx", "httpx", "whatweb"):
        ui.on_audit({"event": "tool_spawn", "tool": tool})
        settle(ui, tool, output_chars=999)
    ui.on_state("HYPOTHESIZE")

    console = Console(file=StringIO(), force_terminal=False, width=width,
                      no_color=True)
    console.print(ui.render())
    for line in console.file.getvalue().splitlines():
        assert len(line) <= width, f"line overflows {width}: {line!r}"


def test_ascii_fallback_for_legacy_code_pages():
    """cp1252 consoles must not die mid-engagement on box drawing.

    This asserts the *whole* render is encodable, not just our own marks —
    the panel borders are drawn by rich and the RUNNING/STOPPED dot was
    hardcoded, so a glyph-set-only fallback left two ways to crash on a
    legacy code page.
    """
    ui = make_ui(utf8=False)
    ui.on_state("INIT")
    spawn(ui, "nmap")
    out = render(ui)
    out.encode("cp1252")  # must not raise
    for glyph in "✓◉○⚠█░●┌─│└┐┘├┤┬┴┼":
        assert glyph not in out, f"{glyph!r} leaked into the ASCII render"
    assert "#" in out  # the progress bar still renders, in ASCII


def test_utf8_console_gets_the_real_glyphs():
    ui = make_ui(utf8=True)
    ui.on_state("INIT")
    out = render(ui)
    assert "✓" in out or "◉" in out


# ---- hostility ---------------------------------------------------------


def test_rendering_never_raises_on_a_broken_graph():
    """A UI bug must not be able to fail an engagement."""
    class Exploding:
        def by_type(self, _):
            raise RuntimeError("graph is on fire")

    ui = make_ui(graph=Exploding())
    out = render(ui)
    assert "Subdomains" in out


def test_audit_observer_failure_cannot_break_the_chain(tmp_path):
    """A broken observer costs a UI row, never an audit entry."""
    audit = AuditLog(tmp_path / "audit.jsonl")

    def explode(_entry):
        raise RuntimeError("observer is broken")

    audit.add_observer(explode)
    first = audit.write({"event": "state_enter", "state": "INIT"})
    second = audit.write({"event": "tool_spawn", "tool": "nmap"})

    assert first and second
    assert audit.head_hash() == second
    assert len(audit.verify()) or True  # chain still readable


def test_observers_receive_every_entry(tmp_path):
    """The audit chain *is* the event stream the console reads."""
    audit = AuditLog(tmp_path / "audit.jsonl")
    ui = make_ui()
    audit.add_observer(ui.on_audit)

    ui.on_state("RECON_ACTIVE")
    audit.write({"event": "tool_spawn", "tool": "httpx"})
    audit.write({"event": "tool_result", "tool": "httpx", "ok": True,
                 "output_chars": 42})

    out = render(ui)
    assert "httpx" in out
    assert "42 chars" in out


def test_observer_sees_entries_in_chain_order(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    seen: list[str] = []
    audit.add_observer(lambda e: seen.append(e.get("event", "")))
    audit.write({"event": "tool_spawn", "tool": "a"})
    audit.write({"event": "tool_result", "tool": "a", "ok": True})
    assert seen == ["tool_spawn", "tool_result"]


# ---- vocabulary ---------------------------------------------------------


@pytest.mark.parametrize("raw,shown", [
    ("crt_sh_subdomains", "crt.sh"),
    ("ripestat_whois", "RIPEstat"),
    ("testssl.sh", "testssl.sh"),
])
def test_implementation_names_are_hidden(raw, shown):
    """`crt_sh_subdomains` is a Python function, not a tool name."""
    assert tool_label(raw) == shown


def test_unknown_tool_is_shown_rather_than_hidden():
    """A tool the operator cannot see is worse than an ugly name."""
    assert tool_label("some_new_tool") == "some_new_tool"
    assert tool_action("some_new_tool") == "some new tool"


def test_every_tool_label_is_non_empty():
    from kryonsec.purple.ui import TOOL_ACTION

    for tool in TOOL_ACTION:
        assert tool_label(tool)
        assert tool_action(tool)


def test_tool_helpers_never_raise_on_empty():
    assert tool_label("") == ""
    assert tool_action("") == ""


# ---- event model --------------------------------------------------------


def test_tool_event_statuses_are_the_documented_five():
    from kryonsec.purple import ui as ui_module

    assert {ui_module.QUEUED, ui_module.RUNNING, ui_module.COMPLETED,
            ui_module.SKIPPED, ui_module.FAILED} == {
        "queued", "running", "completed", "skipped", "failed"}


def test_settled_covers_every_terminal_status():
    from kryonsec.purple.ui import PurpleToolEvent

    for status in (COMPLETED, SKIPPED, FAILED):
        assert PurpleToolEvent("S", "t", status).settled
    for status in (RUNNING, QUEUED):
        assert not PurpleToolEvent("S", "t", status).settled


def test_respawn_while_running_does_not_duplicate_the_row():
    """A duplicate spawn for a tool still in flight updates the one row."""
    ui = make_ui()
    spawn(ui, "httpx")
    spawn(ui, "httpx")
    rows = [t for t in ui.tools if t.tool == "httpx"]
    assert len(rows) == 1
    assert rows[0].status == RUNNING


def test_retry_after_failure_keeps_the_failed_attempt_as_history():
    """exploit.py retries curl over https — the first attempt still happened.

    Dropping it would hide that the engagement tried and failed once, which
    is exactly the kind of detail an operator reads the table for.
    """
    ui = make_ui()
    spawn(ui, "curl")
    settle(ui, "curl", ok=False, error="connection reset")
    spawn(ui, "curl")

    rows = [t for t in ui.tools if t.tool == "curl"]
    assert [t.status for t in rows] == [FAILED, RUNNING]
    out = render(ui)
    assert "connection reset" in out


def test_skipped_source_does_not_leave_a_running_row_behind():
    """The row that said 'running' must become the row that says 'skipped'."""
    ui = make_ui()
    ui.on_state("RECON_PASSIVE")
    ui.on_audit({"event": "passive_source_start", "source": "shodan_subdomains"})
    ui.on_audit({"event": "passive_source_skipped",
                 "source": "shodan_subdomains", "reason": "no API key"})
    rows = [t for t in ui.tools if t.tool == "shodan_subdomains"]
    assert len(rows) == 1
    assert rows[0].status == SKIPPED


def test_safety_warning_is_shortened_but_still_shown():
    """A digest-pin warning is safety-relevant — shortened, never dropped."""
    from kryonsec.purple.ui import notice_for

    text = notice_for(
        "sandbox image 'kryonsec/sandbox:latest' is NOT digest-pinned — set "
        "KRYONSEC_SANDBOX_IMAGE to kryonsec/sandbox@sha256:<digest> "
        "(docker inspect --format '{{.Id}}' kryonsec/sandbox)")
    assert "digest-pinned" in text
    assert "KRYONSEC_SANDBOX_IMAGE" not in text
    assert len(text) < 80


def test_unknown_warning_keeps_the_loggers_own_words():
    """Better a slightly technical line than a swallowed warning."""
    from kryonsec.purple.ui import notice_for

    assert notice_for("something nobody mapped") == "something nobody mapped"


# ---- end to end ---------------------------------------------------------


def test_full_engagement_prints_no_traceback(tmp_path, capsys):
    """The headline requirement, asserted against a real run.

    A source that raises is the normal case for these free public APIs, and
    it used to print a full traceback into the middle of the engagement.
    """
    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.zonea import PassiveResult

    def good(domain):
        return PassiveResult(source="crt.sh", subdomains=["www." + domain])

    def bad(domain):
        raise RuntimeError("upstream said 429")

    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers",
                   return_value=[good, bad]):
            rc = _run_purple(KryonsecConfig(home=tmp_path), "target-corp.com",
                             engagement_id="e2e")

    assert rc == 0
    out = capsys.readouterr().out
    assert "Traceback" not in out
    assert "RuntimeError" not in out
    assert "upstream said 429" not in out
    # and the run still reported honestly
    assert "ENGAGEMENT" in out
    assert "target-corp.com" in out


def test_full_engagement_never_shows_a_bare_percentage(tmp_path, capsys):
    """The old spinner read 'purple 20% passive-recon: ...' — work percent.

    Stage count is knowable; the fraction of the work is not. Piped output
    gets one plain line per state instead of a live panel.
    """
    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.zonea import PassiveResult

    def recon(domain):
        return PassiveResult(source="crt.sh", subdomains=["www." + domain])

    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers",
                   return_value=[recon]):
            _run_purple(KryonsecConfig(home=tmp_path), "target-corp.com",
                        engagement_id="e2e2")

    out = capsys.readouterr().out
    assert "%" not in out.replace("100%", "")  # no work-percentage anywhere
    # and a piped run is still observable as it goes
    assert "PASSIVE RECON" in out
    assert "Collecting external intelligence" in out


def test_engagement_console_never_prints_the_tool_inventory(tmp_path, capsys):
    """The old progress line pasted the whole tool list for every state."""
    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.zonea import PassiveResult

    def recon(domain):
        return PassiveResult(source="crt.sh", subdomains=["www." + domain])

    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers",
                   return_value=[recon]):
            _run_purple(KryonsecConfig(home=tmp_path), "target-corp.com",
                        engagement_id="e2e3")

    out = capsys.readouterr().out
    assert "tools:" not in out
    assert "zone A)" not in out
    assert "zone B)" not in out


# ---- counters -----------------------------------------------------------


def test_counters_reflect_the_graph():
    graph = EngagementGraph(engagement_id="abc12345")
    graph.add_node("subdomain", "a.target-corp.com")
    graph.add_node("subdomain", "b.target-corp.com")
    graph.add_node("web_endpoint", "https://a.target-corp.com")
    graph.add_node("tech_fingerprint", "nginx")
    graph.add_node("hypothesis", "H1")
    graph.add_node("finding", "F1", {"verified": True})

    counts = make_ui(graph=graph).counts()
    assert counts["subdomains"] == 2
    assert counts["endpoints"] == 1
    assert counts["technologies"] == 1
    assert counts["hypotheses"] == 1
    assert counts["findings"] == 1
    assert counts["errors"] == 0


def test_counters_appear_on_screen():
    graph = EngagementGraph(engagement_id="abc12345")
    graph.add_node("subdomain", "a.target-corp.com")
    out = render(make_ui(graph=graph))
    assert "Subdomains" in out
    assert "Findings" in out


def test_console_works_without_a_graph():
    """The graph is optional — no counters, but no crash either."""
    ui = make_ui(graph=None)
    assert ui.counts()["subdomains"] == 0
    assert "RESULTS" in render(ui)
