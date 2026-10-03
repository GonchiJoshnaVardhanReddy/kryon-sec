"""Phase 4.5B: one execution, one identity, one ending.

An engagement id names a *directory*, and ``--id`` lets an operator run the
same name again. The chain in that directory is append-only, so it ends up
holding several executions one after another; the graph rows and ``report.md``
next to it are replaced in place. Before this phase the engine asked "does
this chain contain an ending?" and the browser summarised the whole file — so
a second run could be refused its own ending (inheriting the first run's
terminal status) and could be read with the first run's status, state count
and report on screen beside its own graph.

These tests pin the replacement at both ends:

* the engine stamps every run with its own ``run_id`` and asks whether the
  *current* run has an ending;
* the browser reads one run at a time, and says when an artifact on disk came
  from an earlier run rather than presenting it as the current one's.

A chain written before this phase has no run id at all. That is a single
anonymous run, and it has to keep reading — and keep accepting exactly one
ending — exactly as it did before.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.memory import data, load_engagement
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.graph_store import save_graph
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.storage import get_purple_session, init_purple_db, reset_engine

_RUN_ID = re.compile(r"run_[0-9a-f]{16}")
_CREATED = "engagement_created"
_FINISHED = "engagement_finished"


# ------------------------------------------------------------------ fixtures


@pytest.fixture()
def cfg(tmp_path):
    """The same embedded install the memory tests use: no DATABASE_URL, home
    and workspace redirected so nothing can touch the real ~/.kryonsec."""
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = None
    yield config
    reset_engine()


@pytest.fixture()
def sandbox(monkeypatch):
    """Zone B is unavailable, so ``start_engagement`` wires the run up without
    building a sandbox — enough to exercise the opening of a real chain."""
    monkeypatch.setattr(
        "kryonsec.purple.runner.sandbox_available",
        lambda *a, **k: (False, "no sandbox in this test"),
    )


# ------------------------------------------------------------------- helpers


def _chain_path(cfg, engagement_id: str) -> Path:
    return cfg.home / "engagements" / engagement_id / "audit.jsonl"


def _entries(cfg, engagement_id: str) -> list[dict]:
    text = _chain_path(cfg, engagement_id).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _raw_chain(cfg, engagement_id: str, lines: list[dict]) -> Path:
    """A chain on disk, written without hashes.

    The summary reader does not verify the chain — ``AuditLog.verify`` does —
    so the multi-run shapes under test can be stated directly. The tests that
    care about the chain's integrity build it through ``AuditLog`` instead.
    """
    path = _chain_path(cfg, engagement_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(json.dumps(line) + "\n")
    return path


def _append(cfg, engagement_id: str, *lines: dict) -> None:
    with open(_chain_path(cfg, engagement_id), "a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(json.dumps(line) + "\n")


def _start(cfg, engagement_id: str, target: str = "acme.example"):
    """Open a real run — the engine's own ``start_engagement``."""
    from kryonsec.purple.runner import start_engagement

    return start_engagement(cfg, engagement_id, target=target)


def _end(cfg, engagement_id: str, **kwargs) -> bool:
    from kryonsec.purple.runner import record_engagement_ending

    return record_engagement_ending(cfg, engagement_id, **kwargs)


def _summary(cfg, engagement_id: str) -> dict:
    return data._audit_summary(cfg, engagement_id)


def _meta(cfg, engagement_id: str) -> dict:
    init_purple_db(cfg)
    return load_engagement(cfg, engagement_id)["meta"]


def _graph(engagement_id: str, count: int) -> EngagementGraph:
    graph = EngagementGraph(engagement_id=engagement_id)
    for index in range(count):
        graph.add_node(
            "service", f"example.com:{index}/tcp", {"port": index},
            provenance={"source_type": "tool", "source": "nmap",
                        "agent": "RECON_ACTIVE"},
        )
    return graph


def _store(cfg, engagement_id: str, count: int) -> None:
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        save_graph(session, _graph(engagement_id, count))


def _write_report(cfg, engagement_id: str) -> None:
    path = cfg.home / "engagements" / engagement_id / "report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# report\n", encoding="utf-8")


def _created_ids(cfg, engagement_id: str) -> list[str | None]:
    return [e.get("run_id") for e in _entries(cfg, engagement_id)
            if e.get("event") == _CREATED]


def _endings(cfg, engagement_id: str) -> list[dict]:
    return [e for e in _entries(cfg, engagement_id)
            if e.get("event") == _FINISHED]


# ------------------------------------------------------- the identity itself


def test_new_run_id_is_a_bare_identifier_and_unique():
    """It lands in the chain and is copied back out again, so it has to
    survive the same narrow reading as every other chain field."""
    from kryonsec.purple.runner import new_run_id

    ids = {new_run_id() for _ in range(200)}
    assert len(ids) == 200
    for value in ids:
        assert _RUN_ID.fullmatch(value)
        assert data._ident(value) == value


def test_a_run_id_is_written_when_the_engagement_opens(cfg, sandbox):
    _start(cfg, "eng-open")

    created = _entries(cfg, "eng-open")[0]
    assert created["event"] == _CREATED
    assert _RUN_ID.fullmatch(created["run_id"])


def test_two_runs_under_one_id_get_distinct_run_ids(cfg, sandbox):
    _start(cfg, "eng-two")
    _start(cfg, "eng-two")

    first, second = _created_ids(cfg, "eng-two")
    assert first and second
    assert first != second


def test_each_run_records_its_own_ending(cfg, sandbox):
    """The first ending is the first run's; the second run is not refused
    because the file already holds one."""
    _start(cfg, "eng-each")
    assert _end(cfg, "eng-each", outcome="completed",
                last_state="REPORT", states_entered=10)

    _start(cfg, "eng-each")
    assert _end(cfg, "eng-each", outcome="interrupted",
                reason="keyboard_interrupt",
                last_state="RECON_PASSIVE", states_entered=1)

    created = _created_ids(cfg, "eng-each")
    endings = _endings(cfg, "eng-each")
    assert len(endings) == 2
    assert endings[0]["run_id"] == created[0]
    assert endings[1]["run_id"] == created[1]
    assert endings[0]["run_id"] != endings[1]["run_id"]
    assert endings[0]["outcome"] == "completed"
    assert endings[1]["outcome"] == "interrupted"


def test_audit_verification_survives_two_runs(cfg, sandbox):
    """Two runs' worth of entries, two endings, one intact hash chain."""
    _start(cfg, "eng-verify")
    assert _end(cfg, "eng-verify", outcome="completed", states_entered=10)
    _start(cfg, "eng-verify")
    assert _end(cfg, "eng-verify", outcome="failed", states_entered=0)

    ok, why = AuditLog(_chain_path(cfg, "eng-verify")).verify()
    assert ok, why


def test_the_guard_asks_about_the_current_run(cfg):
    """The unit the whole phase turns on: the ending that counts is the one
    belonging to the run the chain is currently on."""
    from kryonsec.purple.runner import _current_run

    path = _raw_chain(cfg, "eng-guard", [
        {"event": _CREATED, "run_id": "run_aaa"},
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "completed"},
        {"event": _CREATED, "run_id": "run_bbb"},
    ])
    assert _current_run(path) == ("run_bbb", False)

    _append(cfg, "eng-guard", {"event": _FINISHED, "run_id": "run_bbb",
                               "outcome": "failed"})
    assert _current_run(path) == ("run_bbb", True)


def test_a_refused_terminal_append_is_represented_honestly(cfg, sandbox):
    """Refusing means refusing to touch it: no second ending, no phantom
    run, and the browser reads the run exactly as it was."""
    _start(cfg, "eng-refused")
    assert _end(cfg, "eng-refused", outcome="completed",
                last_state="REPORT", states_entered=10)

    before = _chain_path(cfg, "eng-refused").read_bytes()
    assert _end(cfg, "eng-refused", outcome="failed") is False
    assert _chain_path(cfg, "eng-refused").read_bytes() == before

    summary = _summary(cfg, "eng-refused")
    assert summary["run_count"] == 1
    assert summary["status"] == "complete"
    assert summary["states_entered"] == 10
    assert len(_endings(cfg, "eng-refused")) == 1


def test_a_damaged_chain_is_still_refused_without_raising(cfg):
    path = _chain_path(cfg, "eng-damaged")
    AuditLog(path).write({"event": _CREATED, "run_id": "run_aaa"})
    torn = path.read_text(encoding="utf-8") + "half-written-json"
    path.write_text(torn, encoding="utf-8")

    assert _end(cfg, "eng-damaged", outcome="completed") is False
    assert path.read_text(encoding="utf-8") == torn


# --------------------------------------------------- the browser: one run only


def test_a_second_run_does_not_inherit_the_first_runs_status(cfg):
    """The exact mixture the phase forbids: a newer run read with an older
    run's ending, state count and report flag."""
    _raw_chain(cfg, "eng-inherit", [
        {"event": _CREATED, "target": "acme.example", "run_id": "run_aaa"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
        {"event": "state_enter", "state": "REPORT"},
        {"event": "report_written", "path": "report.md"},
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "completed",
         "last_state": "REPORT", "states_entered": 10},
        # run 2 has opened and reached its first state, and has not ended
        {"event": _CREATED, "target": "other.example", "run_id": "run_bbb"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
    ])

    summary = _summary(cfg, "eng-inherit")
    assert summary["run_count"] == 2
    assert summary["run_id"] == "run_bbb"
    assert summary["target"] == "other.example"
    # None of the first run's ending is inherited.
    assert summary["status"] == "incomplete"
    assert summary["lifecycle_recorded"] is False
    assert summary["outcome"] is None
    assert summary["states_entered"] == 0
    assert summary["last_state"] == "RECON_PASSIVE"
    assert summary["report_written"] is False
    # The state list is the current run's, not the union of both.
    assert summary["states"] == ["RECON_PASSIVE"]


def test_the_second_runs_ending_is_read_as_its_own(cfg):
    _raw_chain(cfg, "eng-second", [
        {"event": _CREATED, "target": "acme.example", "run_id": "run_aaa"},
        {"event": "state_enter", "state": "REPORT"},
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "completed",
         "last_state": "REPORT", "states_entered": 10},
        {"event": _CREATED, "target": "acme.example", "run_id": "run_bbb"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
        {"event": _FINISHED, "run_id": "run_bbb", "outcome": "interrupted",
         "reason": "keyboard_interrupt", "last_state": "RECON_PASSIVE",
         "states_entered": 1},
    ])

    summary = _summary(cfg, "eng-second")
    assert summary["status"] == "interrupted"
    assert summary["outcome"] == "interrupted"
    assert summary["reason"] == "keyboard_interrupt"
    assert summary["states_entered"] == 1
    assert summary["run_id"] == "run_bbb"


def test_an_earlier_runs_halt_reason_does_not_carry_over(cfg):
    _raw_chain(cfg, "eng-halt", [
        {"event": _CREATED, "run_id": "run_aaa"},
        {"event": "zone_b_blocked", "reason": "sandbox runtime unavailable"},
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "halted",
         "reason": "zone_b_blocked"},
        {"event": _CREATED, "run_id": "run_bbb"},
        {"event": "state_enter", "state": "INIT"},
    ])

    summary = _summary(cfg, "eng-halt")
    assert summary["status"] == "incomplete"
    assert summary["halt_reason"] is None
    assert summary["reason"] is None


# --------------------------------------------------- artifacts and their run


def test_a_newer_run_does_not_adopt_an_older_runs_graph(cfg):
    """The rows are replaced wholesale, so the graph on disk is always
    exactly one run's — and the browser has to say whose."""
    _raw_chain(cfg, "eng-graph", [
        {"event": _CREATED, "target": "acme.example", "run_id": "run_aaa"},
        {"event": "checkpoint_written", "state": "RECON_PASSIVE",
         "nodes": 3, "edges": 0},
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "completed"},
    ])
    _store(cfg, "eng-graph", count=3)          # the rows run 1 left behind

    # run 2 opens and ends without saving anything of its own
    _append(cfg, "eng-graph",
            {"event": _CREATED, "target": "acme.example", "run_id": "run_bbb"},
            {"event": _FINISHED, "run_id": "run_bbb", "outcome": "failed",
             "states_entered": 0})

    meta = _meta(cfg, "eng-graph")
    assert meta["run_id"] == "run_bbb"
    assert meta["status"] == "failed"
    assert meta["persisted"] is True           # rows exist...
    assert meta["graph_current"] is False      # ...but they are not this run's

    # run 2 saves its own graph: replaced, announced, and now attributed
    _store(cfg, "eng-graph", count=1)
    _append(cfg, "eng-graph",
            {"event": "checkpoint_written", "state": "INIT",
             "nodes": 1, "edges": 0})

    meta = _meta(cfg, "eng-graph")
    assert meta["graph_current"] is True
    assert meta["nodes"] == 1                  # the old three are gone, not merged


def test_a_report_from_an_earlier_run_is_not_presented_as_the_new_runs(cfg):
    _raw_chain(cfg, "eng-report", [
        {"event": _CREATED, "target": "acme.example", "run_id": "run_aaa"},
        {"event": "report_written", "path": "report.md"},
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "completed"},
    ])
    _write_report(cfg, "eng-report")

    # run 2 stops before REPORT, so the file on disk is still run 1's
    _append(cfg, "eng-report",
            {"event": _CREATED, "target": "acme.example", "run_id": "run_bbb"},
            {"event": _FINISHED, "run_id": "run_bbb", "outcome": "interrupted",
             "reason": "keyboard_interrupt", "states_entered": 1})

    meta = _meta(cfg, "eng-report")
    assert meta["report_available"] is True    # the file is there...
    assert meta["report_written"] is False     # ...but this run did not write it
    assert meta["report_current"] is False
    assert meta["status"] == "interrupted"

    # run 2 reaches REPORT: the file is overwritten and now its own
    _write_report(cfg, "eng-report")
    _append(cfg, "eng-report", {"event": "report_written", "path": "report.md"})

    meta = _meta(cfg, "eng-report")
    assert meta["report_current"] is True
    assert meta["report_written"] is True


def test_a_single_run_is_never_flagged_as_an_earlier_runs(cfg):
    """One run means there is nothing to confuse it with, so the attribution
    cells must not cry wolf on the ordinary case."""
    _raw_chain(cfg, "eng-single", [
        {"event": _CREATED, "target": "acme.example", "run_id": "run_aaa"},
        {"event": "checkpoint_written", "state": "REPORT", "nodes": 2, "edges": 0},
        {"event": "report_written", "path": "report.md"},
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "completed"},
    ])
    _store(cfg, "eng-single", count=2)
    _write_report(cfg, "eng-single")

    meta = _meta(cfg, "eng-single")
    assert meta["run_count"] == 1
    assert meta["graph_current"] is True
    assert meta["report_current"] is True


def test_graph_rows_are_replaced_not_merged_across_runs(cfg):
    """A reused id does not accumulate two graphs: the second save is the
    engagement's whole stored graph, which is what makes attributing it to a
    single run possible at all."""
    _store(cfg, "eng-replace", count=4)
    assert _meta(cfg, "eng-replace")["nodes"] == 4

    _store(cfg, "eng-replace", count=2)
    assert _meta(cfg, "eng-replace")["nodes"] == 2


# --------------------------------------------------- damage and attribution


def test_a_torn_line_never_makes_an_earlier_runs_artifacts_current(cfg, sandbox):
    """A damaged chain must not resurrect the run that came before it.

    Both runs here are real — two ``start_engagement`` calls and a real
    ending — so the file the reader walks is the one the engine writes, and
    only the tail is torn the way a crash leaves it. The engine refuses to
    chain onto that file. The reader summarises rather than verifies, so it
    still answers — and the answer has to be about the run that is current,
    with the graph rows and the report beside it named as the earlier run's
    rather than quietly presented as this one's. Losing a line can only ever
    cost a run its own facts, never lend it someone else's.
    """
    _start(cfg, "eng-torn", target="acme.example")
    assert _end(cfg, "eng-torn", outcome="completed",
                last_state="REPORT", states_entered=10)
    _store(cfg, "eng-torn", count=3)     # the graph run 1 left behind
    _write_report(cfg, "eng-torn")       # and its report

    _start(cfg, "eng-torn", target="acme.example")   # run 2 opens and gets no further
    second_run = _created_ids(cfg, "eng-torn")[1]    # read before the tail is torn

    path = _chain_path(cfg, "eng-torn")
    torn = path.read_text(encoding="utf-8") + '{"event": "state_enter"'
    path.write_text(torn, encoding="utf-8")

    # The engine will not append onto a damaged chain, so the torn file is
    # the last word on this engagement...
    assert _end(cfg, "eng-torn", outcome="failed") is False
    assert path.read_text(encoding="utf-8") == torn

    # ...and the browser still answers, for run 2 and only for run 2.
    meta = _meta(cfg, "eng-torn")
    assert meta["run_count"] == 2
    assert meta["run_id"] == second_run
    assert meta["audit_readable"] is True
    assert meta["audit_damaged_lines"] == 1
    assert meta["lifecycle_recorded"] is False
    assert meta["outcome"] is None
    assert meta["states_entered"] == 0
    assert meta["status"] == "incomplete"
    # Run 1's artifacts are on disk and are shown — the rows are the
    # engagement's only graph — but never as the current run's.
    assert meta["nodes"] == 3
    assert meta["report_available"] is True
    assert meta["report_written"] is False
    assert meta["graph_current"] is False
    assert meta["report_current"] is False


# ------------------------------------------- which run the ending belongs to


def test_an_ending_from_another_run_is_not_read_as_this_runs(cfg):
    """The endpoint of the phase: an ending counts for the run it belongs to.

    ``record_engagement_ending`` stamps the run id it reads from the chain,
    so this shape is not one the engine writes — an edited chain or two
    interleaved runs can still hold it. The reader has to be able to say no:
    run 2 reached one state and recorded no ending, and an ending stamped
    with run 1's id cannot give it an outcome, a state count, a halt reason
    or a status.
    """
    from kryonsec.purple.runner import _current_run

    path = _raw_chain(cfg, "eng-mismatch", [
        {"event": _CREATED, "target": "acme.example", "run_id": "run_aaa"},
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "completed",
         "last_state": "REPORT", "states_entered": 10},
        {"event": _CREATED, "target": "acme.example", "run_id": "run_bbb"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
        # run 1's ending, carrying run 1's id, inside run 2's segment
        {"event": _FINISHED, "run_id": "run_aaa", "outcome": "halted",
         "reason": "zone_b_blocked", "last_state": "REPORT",
         "states_entered": 3},
    ])

    summary = _summary(cfg, "eng-mismatch")
    assert summary["run_id"] == "run_bbb"
    assert summary["lifecycle_recorded"] is False
    assert summary["outcome"] is None
    assert summary["states_entered"] == 0
    assert summary["reason"] is None
    # From run 2's own state_enter, not from the ending's last_state.
    assert summary["last_state"] == "RECON_PASSIVE"
    assert summary["states"] == ["RECON_PASSIVE"]
    assert summary["status"] == "incomplete"
    # Read the same way the engine does, which is the point of the guard.
    assert _current_run(path) == ("run_bbb", False)


def test_an_ending_with_no_run_id_is_still_read(cfg):
    """The other side of that guard. Every ending recorded before Phase 4.5B
    has no run id, and remains the record of the run it closed."""
    _raw_chain(cfg, "eng-legacy-ending", [
        {"event": _CREATED, "target": "acme.example"},
        {"event": "state_enter", "state": "REPORT"},
        {"event": _FINISHED, "outcome": "completed", "last_state": "REPORT",
         "states_entered": 10},
    ])

    summary = _summary(cfg, "eng-legacy-ending")
    assert summary["run_id"] is None
    assert summary["run_count"] == 1
    assert summary["lifecycle_recorded"] is True
    assert summary["outcome"] == "completed"
    assert summary["last_state"] == "REPORT"
    assert summary["states_entered"] == 10
    assert summary["status"] == "complete"


# ------------------------------------------------------- legacy compatibility


def test_a_legacy_chain_without_run_ids_still_reads(cfg):
    """Every chain written before this phase. One anonymous run, read exactly
    as it was."""
    _raw_chain(cfg, "eng-legacy", [
        {"event": _CREATED, "target": "acme.example"},
        {"event": "state_enter", "state": "REPORT"},
        {"event": "report_written", "path": "report.md"},
    ])

    summary = _summary(cfg, "eng-legacy")
    assert summary["status"] == "complete"
    assert summary["lifecycle_recorded"] is False
    assert summary["run_id"] is None
    assert summary["run_count"] == 1
    assert summary["graph_current"] is True
    assert summary["report_current"] is True


def test_a_legacy_chain_gets_exactly_one_ending_with_no_run_id(cfg):
    """The ending written into a chain old enough to have no run id has the
    shape it had before this phase: the key is omitted, not written as null."""
    AuditLog(_chain_path(cfg, "eng-legacy-end")).write(
        {"event": _CREATED, "target": "acme.example"})

    assert _end(cfg, "eng-legacy-end", outcome="completed",
                last_state="REPORT", states_entered=10)

    ending = _endings(cfg, "eng-legacy-end")[0]
    assert "run_id" not in ending
    assert ending["outcome"] == "completed"

    # ...and a legacy run is still refused a second ending.
    assert _end(cfg, "eng-legacy-end", outcome="failed") is False
    assert len(_endings(cfg, "eng-legacy-end")) == 1


def test_a_run_id_is_validated_like_any_other_chain_field(cfg):
    """A run id read back out of a chain is copied into the entry the engine
    writes, so it is an identifier or it is nothing — never free text."""
    from kryonsec.purple.runner import _run_id_of

    assert _run_id_of({"run_id": "run_ab"}) == "run_ab"
    assert _run_id_of({"run_id": "../etc/passwd"}) is None
    assert _run_id_of({"run_id": 7}) is None
    assert _run_id_of({}) is None


def test_a_hostile_run_id_is_never_copied_into_the_ending(cfg):
    AuditLog(_chain_path(cfg, "eng-hostile-end")).write(
        {"event": _CREATED, "target": "acme.example",
         "run_id": r"C:\Users\gonch\.kryonsec"})

    assert _end(cfg, "eng-hostile-end", outcome="completed") is True

    ending = _endings(cfg, "eng-hostile-end")[0]
    assert "run_id" not in ending
    assert "Users" not in json.dumps(ending)


def test_a_hostile_run_id_does_not_reach_the_browser(cfg):
    _raw_chain(cfg, "eng-hostile", [
        {"event": _CREATED, "target": "acme.example",
         "run_id": r"C:\Users\gonch\.kryonsec"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
    ])

    summary = _summary(cfg, "eng-hostile")
    assert summary["run_id"] is None
    assert "Users" not in json.dumps(summary)
