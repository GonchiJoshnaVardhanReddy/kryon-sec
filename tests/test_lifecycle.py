"""Engagement lifecycle (Phase 4.2): the single terminal event.

Before this phase an engagement had no recorded ending. Two endings were
visible only by inference — ``report_written`` meant it finished,
``zone_b_blocked`` meant it stopped — and a budget stop or a Ctrl+C wrote
neither, so a reader could not tell a run that had crashed from one that was
still going.

These tests pin the replacement: exactly one ``engagement_finished`` per run,
on every path, carrying a safe code rather than free text, and never
disturbing the exception that was already in flight when it was written.
"""

import json
from contextlib import ExitStack, contextmanager
from unittest.mock import MagicMock, patch

import pytest

from kryonsec import cli
from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.orchestrator import STATES
from kryonsec.purple.runner import (
    record_engagement_ending,
    safe_exception_type,
    safe_halt_code,
)

_TERMINAL = "engagement_finished"


# ---- helpers --------------------------------------------------------------


def _chain_path(home, engagement_id):
    return home / "engagements" / engagement_id / "audit.jsonl"


def _read_chain(home, engagement_id):
    """Every entry in the chain, in order."""
    text = _chain_path(home, engagement_id).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _read_ending(home, engagement_id):
    endings = [e for e in _read_chain(home, engagement_id)
               if e.get("event") == _TERMINAL]
    assert len(endings) == 1, f"expected exactly one ending, got {len(endings)}"
    return endings[0]


def _seed_chain(home, engagement_id, **fields):
    """Stand in for what start_engagement writes before the loop runs."""
    entry = {"event": "engagement_created", "target": "acme.example"}
    entry.update(fields)
    AuditLog(_chain_path(home, engagement_id)).write(entry)


class _Orch:
    """A PurpleOrchestrator with only the attributes the CLI boundary reads."""

    def __init__(self, *, completed=(), halt_reason=None, raises=None):
        self.completed = list(completed)
        self.halt_reason = halt_reason
        self.on_state = None
        self._raises = raises

    def run(self):
        if self._raises is not None:
            raise self._raises
        return self.completed


@contextmanager
def _stubbed_run(home, *, orch, persist=True):
    """Drive the real _run_purple with the runner and the console stubbed.

    Only the boundary itself is under test, so everything the boundary calls
    is replaced: the runner (so an outcome can be forced without building a
    sandbox), the console (so a passing run prints nothing), and the summary
    (presentation, and deliberately outside the boundary).
    """
    cfg = KryonsecConfig(home=home)
    with ExitStack() as stack:
        stack.enter_context(
            patch("kryonsec.purple.zonea.validate_target",
                  return_value="acme.example"))
        stack.enter_context(
            patch("kryonsec.purple.runner.sandbox_available",
                  return_value=(True, "ok")))
        stack.enter_context(
            patch("kryonsec.purple.runner.start_engagement",
                  return_value=(orch, MagicMock(), MagicMock())))
        stack.enter_context(
            patch("kryonsec.purple.runner.persist_graph",
                  return_value=persist))
        stack.enter_context(
            patch("kryonsec.purple.ui.PurpleUI", return_value=MagicMock()))
        stack.enter_context(
            patch("kryonsec.purple.ui.attach_purple_logging",
                  return_value=(None, None)))
        stack.enter_context(patch("kryonsec.purple.ui.detach_purple_logging"))
        stack.enter_context(patch("kryonsec.cli._print_purple_summary"))
        stack.enter_context(patch("kryonsec.cli.console"))
        stack.enter_context(patch("kryonsec.cli.err_console"))
        yield cfg


# ---- the code mapping -----------------------------------------------------


@pytest.mark.parametrize("reason,expected", [
    (None, None),
    ("", None),
    ("budget_exhausted", "budget_exhausted"),
    ("purple_team_requires_profile2 (Linux + Docker + gVisor)",
     "profile2_required"),
    # A sandbox probe message quotes an image reference and names missing
    # tools. It is free text and must never be passed through verbatim.
    ("sandbox image not found locally: kryonsec/sandbox:latest",
     "zone_b_blocked"),
    ("docker CLI not found or daemon unreachable", "zone_b_blocked"),
    ("gVisor (runsc) runtime not registered with Docker", "zone_b_blocked"),
])
def test_halt_reasons_become_fixed_codes(reason, expected):
    assert safe_halt_code(reason) == expected


def test_a_sandbox_message_never_reaches_the_chain(tmp_path):
    """The specific string that would leak an image reference."""
    cfg = KryonsecConfig(home=tmp_path)
    _seed_chain(tmp_path, "e-1")

    record_engagement_ending(
        cfg, "e-1", outcome="halted",
        reason=safe_halt_code("sandbox image not found locally: /srv/img:1"),
    )

    assert "sandbox image" not in json.dumps(_read_ending(tmp_path, "e-1"))


def test_an_exception_type_is_its_class_name():
    assert safe_exception_type(OSError("x")) == "OSError"
    assert safe_exception_type(None) is None


def test_a_dynamically_named_class_is_refused():
    """A class built with type() can be named anything, including a path."""
    hostile = type("evil/../../etc/passwd", (Exception,), {})
    assert safe_exception_type(hostile()) is None


# ---- the writer -----------------------------------------------------------


def test_the_ending_records_its_evidence(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    _seed_chain(tmp_path, "e-1")

    assert record_engagement_ending(
        cfg, "e-1", outcome="halted", reason="budget_exhausted",
        last_state="HYPOTHESIZE", states_entered=4,
    ) is True

    ending = _read_ending(tmp_path, "e-1")
    assert ending["outcome"] == "halted"
    assert ending["reason"] == "budget_exhausted"
    assert ending["last_state"] == "HYPOTHESIZE"
    assert ending["states_entered"] == 4


def test_the_ending_is_written_exactly_once(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    _seed_chain(tmp_path, "e-1")

    assert record_engagement_ending(cfg, "e-1", outcome="completed") is True
    assert record_engagement_ending(cfg, "e-1", outcome="completed") is False

    # _read_ending asserts there is exactly one.
    _read_ending(tmp_path, "e-1")


def test_an_unknown_outcome_is_never_written_verbatim(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    _seed_chain(tmp_path, "e-1")

    record_engagement_ending(cfg, "e-1", outcome="banana")

    assert _read_ending(tmp_path, "e-1")["outcome"] == "failed"


def test_no_chain_means_no_engagement_and_no_ending(tmp_path):
    """The three `return 2` paths never opened a chain, and must not leave a
    directory behind whose only content is a death certificate."""
    cfg = KryonsecConfig(home=tmp_path)

    assert record_engagement_ending(cfg, "never-ran", outcome="failed") is False
    assert not (tmp_path / "engagements" / "never-ran").exists()


def test_a_damaged_chain_is_refused_without_raising(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    path = _chain_path(tmp_path, "e-bad")
    AuditLog(path).write({"event": "engagement_created"})
    torn = path.read_text(encoding="utf-8") + "half-written-json"
    path.write_text(torn, encoding="utf-8")

    assert record_engagement_ending(cfg, "e-bad", outcome="completed") is False
    # Refusing means refusing to touch it: the chain is byte-identical.
    assert path.read_text(encoding="utf-8") == torn


def test_the_chain_still_verifies_after_the_ending(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    _seed_chain(tmp_path, "e-1")

    record_engagement_ending(
        cfg, "e-1", outcome="failed", reason="unhandled_exception",
        last_state="VERIFY", states_entered=8, exception_type="OSError",
    )

    ok, why = AuditLog(_chain_path(tmp_path, "e-1")).verify()
    assert ok, why


def test_the_ending_carries_no_path_and_no_message(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    _seed_chain(tmp_path, "e-1")

    record_engagement_ending(
        cfg, "e-1", outcome="failed", reason="unhandled_exception",
        last_state="VERIFY", states_entered=8, exception_type="OSError",
    )

    blob = json.dumps(_read_ending(tmp_path, "e-1"))
    assert str(tmp_path) not in blob
    assert "/" not in blob and "\\" not in blob


# ---- the boundary: all four outcomes --------------------------------------


def test_a_finished_run_is_recorded_as_completed(tmp_path):
    _seed_chain(tmp_path, "e-done")
    orch = _Orch(completed=list(STATES))

    with _stubbed_run(tmp_path, orch=orch) as cfg:
        assert cli._run_purple(cfg, "acme.example", engagement_id="e-done") == 0

    ending = _read_ending(tmp_path, "e-done")
    assert ending["outcome"] == "completed"
    assert ending["last_state"] == "REPORT"
    assert ending["states_entered"] == len(STATES)
    assert "reason" not in ending


def test_a_halted_run_is_recorded_with_its_code(tmp_path):
    _seed_chain(tmp_path, "e-halt")
    orch = _Orch(
        completed=["INIT", "RECON_PASSIVE", "RECON_ACTIVE"],
        halt_reason="budget_exhausted",
    )

    with _stubbed_run(tmp_path, orch=orch) as cfg:
        assert cli._run_purple(cfg, "acme.example", engagement_id="e-halt") == 0

    ending = _read_ending(tmp_path, "e-halt")
    assert ending["outcome"] == "halted"
    assert ending["reason"] == "budget_exhausted"
    assert ending["last_state"] == "RECON_ACTIVE"


def test_an_interrupt_is_recorded_and_still_propagates(tmp_path):
    """Ctrl+C must be recorded *and* must still stop the run."""
    _seed_chain(tmp_path, "e-int")
    orch = _Orch(completed=["INIT", "RECON_PASSIVE"],
                 raises=KeyboardInterrupt())

    with _stubbed_run(tmp_path, orch=orch) as cfg:
        with pytest.raises(KeyboardInterrupt):
            cli._run_purple(cfg, "acme.example", engagement_id="e-int")

    ending = _read_ending(tmp_path, "e-int")
    assert ending["outcome"] == "interrupted"
    assert ending["reason"] == "keyboard_interrupt"
    assert ending["last_state"] == "RECON_PASSIVE"


def test_a_failure_is_recorded_without_its_message(tmp_path):
    _seed_chain(tmp_path, "e-fail")
    boom = RuntimeError("connection to postgresql://user:pw@host/db failed")
    orch = _Orch(completed=["INIT"], raises=boom)

    with _stubbed_run(tmp_path, orch=orch) as cfg:
        with pytest.raises(RuntimeError):
            cli._run_purple(cfg, "acme.example", engagement_id="e-fail")

    ending = _read_ending(tmp_path, "e-fail")
    assert ending["outcome"] == "failed"
    assert ending["exception_type"] == "RuntimeError"
    # The message said where the database was and what the password was.
    blob = json.dumps(ending)
    assert "postgresql" not in blob
    assert "pw" not in blob


def test_a_crash_before_the_loop_records_no_state(tmp_path):
    """start_engagement failing means nothing was ever entered."""
    _seed_chain(tmp_path, "e-early")

    class _Boom:
        def __call__(self, *a, **k):
            raise OSError("image pull failed")

    with ExitStack() as stack:
        cfg = KryonsecConfig(home=tmp_path)
        stack.enter_context(
            patch("kryonsec.purple.zonea.validate_target",
                  return_value="acme.example"))
        stack.enter_context(
            patch("kryonsec.purple.runner.sandbox_available",
                  return_value=(True, "ok")))
        stack.enter_context(
            patch("kryonsec.purple.runner.start_engagement", new=_Boom()))
        stack.enter_context(
            patch("kryonsec.purple.ui.PurpleUI", return_value=MagicMock()))
        stack.enter_context(
            patch("kryonsec.purple.ui.attach_purple_logging",
                  return_value=(None, None)))
        stack.enter_context(patch("kryonsec.purple.ui.detach_purple_logging"))
        stack.enter_context(patch("kryonsec.cli.console"))
        stack.enter_context(patch("kryonsec.cli.err_console"))
        with pytest.raises(OSError):
            cli._run_purple(cfg, "acme.example", engagement_id="e-early")

    ending = _read_ending(tmp_path, "e-early")
    assert ending["outcome"] == "failed"
    assert ending["exception_type"] == "OSError"
    assert ending["states_entered"] == 0
    assert "last_state" not in ending


# ---- the damaged chain must not replace the original exception ------------


def test_a_damaged_chain_does_not_replace_the_original_exception(tmp_path):
    """The whole point of the never-raise contract: the operator pressed
    Ctrl+C, and what they get must still be a KeyboardInterrupt — not an
    audit error raised from the cleanup path."""
    path = _chain_path(tmp_path, "e-dmg")
    AuditLog(path).write({"event": "engagement_created"})
    with path.open("a", encoding="utf-8") as handle:
        handle.write("half-written-json")
    damaged = path.read_text(encoding="utf-8")

    orch = _Orch(completed=["INIT"], raises=KeyboardInterrupt())

    with _stubbed_run(tmp_path, orch=orch) as cfg:
        with pytest.raises(KeyboardInterrupt) as caught:
            cli._run_purple(cfg, "acme.example", engagement_id="e-dmg")

    assert type(caught.value) is KeyboardInterrupt
    assert path.read_text(encoding="utf-8") == damaged


# ---- backward compatibility with the reader -------------------------------


def test_an_old_chain_without_an_ending_still_summarizes(tmp_path):
    """Chains written before Phase 4.2 have no terminal event. The browser's
    derivation is unchanged, so they must read exactly as they did."""
    from kryonsec.memory import data as memory_data

    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(_chain_path(tmp_path, "e-old"))
    audit.write({"event": "engagement_created", "target": "acme.example"})
    audit.write({"event": "state_enter", "state": "REPORT"})
    audit.write({"event": "report_written", "path": "x"})

    summary = memory_data._audit_summary(cfg, "e-old")
    assert summary["status"] == "complete"
    assert summary["report_written"] is True


def test_an_old_halting_chain_still_summarizes_as_halted(tmp_path):
    from kryonsec.memory import data as memory_data

    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(_chain_path(tmp_path, "e-old-halt"))
    audit.write({"event": "engagement_created", "target": "acme.example"})
    audit.write({"event": "state_enter", "state": "RECON_ACTIVE"})
    audit.write({"event": "zone_b_blocked", "state": "RECON_ACTIVE",
                 "reason": "requires Linux"})

    assert memory_data._audit_summary(cfg, "e-old-halt")["status"] == "halted"


def test_the_new_event_does_not_change_the_derived_status(tmp_path):
    """Phase 4.2 does not touch the browser: an engagement that completed
    still reads as complete once the ending is appended."""
    from kryonsec.memory import data as memory_data

    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(_chain_path(tmp_path, "e-new"))
    audit.write({"event": "engagement_created", "target": "acme.example"})
    audit.write({"event": "report_written", "path": "x"})
    record_engagement_ending(cfg, "e-new", outcome="completed",
                             last_state="REPORT", states_entered=10)

    summary = memory_data._audit_summary(cfg, "e-new")
    assert summary["status"] == "complete"
