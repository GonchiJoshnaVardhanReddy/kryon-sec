"""Phase 4.3: the Security Graph survives an interrupted engagement.

Before this phase the graph lived in RAM until the loop reached HALT, so a
crash, a Ctrl-C or a reboot at any earlier moment lost every reconnaissance
result the engagement had accumulated. The Phase 4.1 audit named that as the
gap; this covers the fix.

The fix is a checkpoint: the graph is written to engagement storage after
every state, through the same ``save_graph`` the end-of-run persist already
used. **Nothing reads a checkpoint back.** Resume is a later phase, and the
absence of it is asserted here as deliberately as the presence of the
snapshot — a checkpoint is a record, not a cursor.

Two properties carry the design, and most of what follows tests one of them:

* **Atomicity.** ``save_graph`` deletes and re-inserts inside a single
  transaction committed once at the end, so a write that dies part-way
  leaves the *previous* checkpoint rather than half of a new one.
* **Redaction.** Every node and edge is redacted on the way in, so a
  credential that happened to be observed during recon is not what an
  interrupted run leaves sitting in the engagement database.

Nothing here drives the sandbox: the loop test uses the same two-tier gating
as ``test_runner.py``, so it exercises a real engagement on a machine with no
gVisor.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.graph_store import load_graph, save_graph
from kryonsec.purple.orchestrator import (
    HALT,
    PurpleOrchestrator,
    SubagentResult,
)
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.runner import (
    checkpoint_graph,
    persist_graph,
    start_engagement,
)
from kryonsec.purple.zonea import PassiveResult
from kryonsec.storage import (
    get_purple_session,
    init_purple_db,
    reset_engine,
)
from kryonsec.storage.models import Checkpoint, StmNode


@pytest.fixture()
def cfg(tmp_path):
    """The embedded install: no DATABASE_URL, so engagement storage is the
    dedicated file. Workspace is redirected so the fixture never writes to
    the real home directory."""
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = None
    yield config
    reset_engine()


def _audit(cfg: KryonsecConfig, engagement_id: str) -> AuditLog:
    return AuditLog(cfg.home / "engagements" / engagement_id / "audit.jsonl")


def _events(audit: AuditLog) -> list[dict]:
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _only(events: list[dict], name: str) -> list[dict]:
    return [e for e in events if e.get("event") == name]


def _graph(engagement_id: str = "e-1") -> EngagementGraph:
    graph = EngagementGraph(engagement_id=engagement_id)
    target = graph.add_node(
        "target", "example.com",
        provenance={"source_type": "config", "source": "engagement_config",
                    "agent": "RECON_PASSIVE"},
    )
    service = graph.add_node(
        "service", "example.com:443/tcp", {"port": 443, "service": "https"},
        provenance={"source_type": "tool", "source": "nmap",
                    "agent": "RECON_ACTIVE"},
    )
    graph.add_edge(
        target, "has_service", service, {"source": "nmap"},
        provenance={"source_type": "tool", "source": "nmap",
                    "agent": "RECON_ACTIVE"},
    )
    return graph


def _loaded(cfg: KryonsecConfig, engagement_id: str) -> EngagementGraph:
    with get_purple_session(cfg) as session:
        return load_graph(session, engagement_id)


def _fake_recon(domain):
    return PassiveResult(source="crt.sh", subdomains=["www." + domain])


def _run_loop(cfg, engagement_id, target="target-corp.com"):
    """One engagement, halting at RECON_ACTIVE as it does without a sandbox."""
    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers",
                   return_value=[_fake_recon]):
            orch, audit, graph = start_engagement(cfg, engagement_id, target=target)
            orch.run()
    return orch, audit, graph


# --- the snapshot is the graph ---------------------------------------------

def test_a_checkpoint_reads_back_as_the_live_graph(cfg):
    """A snapshot is worth nothing if it is not the graph.

    Deep equality rather than a spot check: a checkpoint that dropped
    provenance, reset a status or lost an edge would still "load", and the
    whole point is that an interrupted run keeps what the finished run had.
    """
    audit = _audit(cfg, "e-cp")
    graph = _graph("e-cp")
    graph.add_node("finding", "F1", {"verified": True},
                   provenance={"source_type": "tool", "source": "verify",
                               "agent": "VERIFY"})

    assert checkpoint_graph(cfg, "e-cp", graph, audit, "VERIFY") is True

    loaded = _loaded(cfg, "e-cp")
    assert loaded.engagement_id == "e-cp"
    assert loaded.nodes == graph.nodes
    assert loaded.edges == graph.edges
    # and the relationships still resolve, not just the rows
    service = loaded.by_type("service")[0]
    target = loaded.by_type("target")[0]
    assert loaded.has_edge(target, "has_service", service)


def test_a_checkpoint_of_an_empty_graph_is_an_empty_graph(cfg):
    """An engagement that has produced nothing yet is a real state, not an
    error: the checkpoint writes zero rows and reads back as empty."""
    audit = _audit(cfg, "e-empty")
    graph = EngagementGraph(engagement_id="e-empty")

    assert checkpoint_graph(cfg, "e-empty", graph, audit, "INIT") is True

    loaded = _loaded(cfg, "e-empty")
    assert loaded.nodes == [] and loaded.edges == []


def test_checkpoints_are_scoped_to_their_engagement(cfg):
    """The delete-and-replace is filtered by engagement id, so one
    engagement's checkpoint can never truncate another's."""
    audit = _audit(cfg, "e-a")
    first, second = _graph("e-a"), _graph("e-b")
    assert checkpoint_graph(cfg, "e-a", first, audit, "RECON_PASSIVE") is True
    assert checkpoint_graph(cfg, "e-b", second, _audit(cfg, "e-b"),
                            "RECON_PASSIVE") is True

    first.add_node("finding", "A1", {"verified": True})
    assert checkpoint_graph(cfg, "e-a", first, audit, "VERIFY") is True

    assert len(_loaded(cfg, "e-a").nodes) == 3
    assert len(_loaded(cfg, "e-b").nodes) == 2


# --- snapshots at every boundary -------------------------------------------

def test_successive_boundary_checkpoints_update_safely(cfg):
    """One checkpoint per state, each replacing the last.

    Replacing rather than appending is what keeps an interrupted run from
    reading as a graph with three copies of every node, and a node removed
    between states must actually leave the table.
    """
    audit = _audit(cfg, "e-steps")
    graph = _graph("e-steps")

    steps = [
        ("RECON_PASSIVE", None, 2),
        ("RECON_ACTIVE", "service", 3),
        ("HYPOTHESIZE", "hypothesis", 4),
    ]
    for state, kind, expected in steps:
        if kind:
            graph.add_node(kind, f"{kind}-1", {"step": state})
        assert checkpoint_graph(cfg, "e-steps", graph, audit, state) is True
        loaded = _loaded(cfg, "e-steps")
        assert len(loaded.nodes) == expected
        assert loaded.nodes == graph.nodes
        assert loaded.edges == graph.edges

    # the graph shrinks between states: the checkpoint follows it down
    graph.remove_node(graph.by_type("hypothesis")[0])
    assert checkpoint_graph(cfg, "e-steps", graph, audit, "HUMAN_REVIEW") is True
    loaded = _loaded(cfg, "e-steps")
    assert loaded.by_type("hypothesis") == []
    assert loaded.nodes == graph.nodes

    written = _only(_events(audit), "checkpoint_written")
    assert [e["state"] for e in written] == [
        "RECON_PASSIVE", "RECON_ACTIVE", "HYPOTHESIZE", "HUMAN_REVIEW",
    ]
    assert [e["nodes"] for e in written] == [2, 3, 4, 3]


def test_a_checkpoint_does_not_disturb_the_other_engagements_rows(cfg):
    """Covered above for the graph; this pins the row counts, which is what
    the delete statements would get wrong if the filter were dropped."""
    for engagement_id, count in [("e-x", 2), ("e-y", 3)]:
        graph = _graph(engagement_id)
        for i in range(count - 2):
            graph.add_node("finding", f"{engagement_id}-{i}", {})
        assert checkpoint_graph(cfg, engagement_id, graph,
                                _audit(cfg, engagement_id), "VERIFY") is True

    # re-checkpointing e-x must not touch e-y
    assert checkpoint_graph(cfg, "e-x", _graph("e-x"),
                            _audit(cfg, "e-x"), "REPORT") is True

    assert len(_loaded(cfg, "e-x").nodes) == 2
    assert len(_loaded(cfg, "e-y").nodes) == 3


# --- atomicity --------------------------------------------------------------

def test_a_write_that_dies_before_commit_leaves_the_previous_checkpoint(cfg, monkeypatch):
    """The interrupted write, at the worst possible moment.

    ``save_graph`` has by now deleted the old rows and inserted the new ones
    — the write is as far along as it can be without committing. Because the
    whole thing is one transaction, the failure rolls all of it back and the
    previous checkpoint is exactly what is left.
    """
    audit = _audit(cfg, "e-atomic")
    graph = _graph("e-atomic")
    assert checkpoint_graph(cfg, "e-atomic", graph, audit, "RECON_PASSIVE") is True
    before = _loaded(cfg, "e-atomic")

    def _power_cut(self):
        raise RuntimeError("power cut before commit")

    monkeypatch.setattr(Session, "commit", _power_cut)
    graph.add_node("finding", "F1", {"verified": True})
    assert checkpoint_graph(cfg, "e-atomic", graph, audit, "RECON_ACTIVE") is False
    monkeypatch.undo()

    # the failure really was at the commit, not before any row was touched
    failure = _only(_events(audit), "checkpoint_failed")
    assert len(failure) == 1
    assert "power cut before commit" in failure[0]["error"]

    after = _loaded(cfg, "e-atomic")
    assert after.nodes == before.nodes      # not a half-written graph
    assert after.edges == before.edges
    assert after.by_type("finding") == []


def test_a_failed_write_leaves_the_previous_checkpoint_reloadable(cfg, monkeypatch):
    """The same property from the outside: after a failed checkpoint the
    engagement is still readable by anything that reads it — the browser,
    the report, a later persist."""
    audit = _audit(cfg, "e-reload")
    graph = _graph("e-reload")
    assert checkpoint_graph(cfg, "e-reload", graph, audit, "RECON_PASSIVE") is True

    def _boom(_cfg):
        raise RuntimeError("disk is full")

    monkeypatch.setattr("kryonsec.storage.init_purple_db", _boom)
    assert checkpoint_graph(cfg, "e-reload", graph, audit, "RECON_ACTIVE") is False

    loaded = _loaded(cfg, "e-reload")
    assert [n["label"] for n in loaded.by_type("target")] == ["example.com"]
    assert [e["relationship"] for e in loaded.edges] == ["has_service"]


# --- redaction --------------------------------------------------------------

def _secret_graph(engagement_id: str) -> EngagementGraph:
    graph = EngagementGraph(engagement_id=engagement_id)
    graph.add_node(
        "service", "db.example.com:5432/tcp",
        {
            "banner": "PostgreSQL 15.4",
            "connection": "postgresql://appuser:hunter2sword@db.example.com/app",
            "note": "password=hunter2sword",
            "creds": ["Authorization: Bearer "
                      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"],
            "key_material": (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEowIBAAKCAQEAsecretkeymaterial\n"
                "-----END RSA PRIVATE KEY-----"
            ),
        },
        provenance={"source_type": "tool", "source": "nmap",
                    "agent": "RECON_ACTIVE",
                    "raw": "password=hunter2sword"},
    )
    return graph


def test_secret_shaped_values_are_not_persisted(cfg):
    """Read the raw column, not ``load_graph``.

    ``load_graph`` would happily hand back whatever was stored; the question
    is what was stored. A credential observed during recon must not be in
    the engagement database — and the boundary checkpoint is precisely the
    copy most likely to outlive the run that found it.
    """
    audit = _audit(cfg, "e-secret")
    graph = _secret_graph("e-secret")

    assert checkpoint_graph(cfg, "e-secret", graph, audit, "RECON_ACTIVE") is True

    with get_purple_session(cfg) as session:
        row = session.query(StmNode).filter(
            StmNode.engagement_id == "e-secret"
        ).one()

    blob = json.dumps(row.properties, sort_keys=True)
    assert "hunter2sword" not in blob
    assert "MIIEowIBAAKCAQEAsecretkeymaterial" not in blob
    assert "SECRET_" in blob

    # the observed facts that are not secrets are untouched
    assert row.properties["banner"] == "PostgreSQL 15.4"
    assert row.label == "db.example.com:5432/tcp"
    assert row.node_type == "service"
    assert row.status == "observed"
    assert row.provenance["agent"] == "RECON_ACTIVE"

    # provenance is walked too, not just properties
    assert "hunter2sword" not in json.dumps(row.provenance, sort_keys=True)


def test_redaction_does_not_rewrite_the_live_graph(cfg):
    """Redaction is a copy, not an edit.

    The engagement is still running. If the checkpoint rewrote the graph the
    run continues against, the report and every later state would reason
    about placeholders instead of observations.
    """
    audit = _audit(cfg, "e-live")
    graph = _secret_graph("e-live")
    before = json.dumps(graph.nodes, sort_keys=True)

    assert checkpoint_graph(cfg, "e-live", graph, audit, "RECON_ACTIVE") is True

    assert json.dumps(graph.nodes, sort_keys=True) == before
    props = graph.by_type("service")[0]["properties"]
    assert props["connection"] == (
        "postgresql://appuser:hunter2sword@db.example.com/app"
    )


def test_a_graph_with_nothing_secret_round_trips_unchanged(cfg):
    """Redaction is a no-op when no pattern matches, so every engagement
    that never saw a credential is stored and read back byte for byte."""
    audit = _audit(cfg, "e-clean")
    graph = _graph("e-clean")

    assert checkpoint_graph(cfg, "e-clean", graph, audit, "RECON_ACTIVE") is True

    loaded = _loaded(cfg, "e-clean")
    assert loaded.nodes == graph.nodes
    assert loaded.edges == graph.edges
    with get_purple_session(cfg) as session:
        row = session.query(StmNode).filter(
            StmNode.engagement_id == "e-clean"
        ).first()
        stored = json.dumps(row.properties, sort_keys=True)
    assert "SECRET_" not in stored
    assert row.size_bytes == next(
        n["size_bytes"] for n in graph.nodes if n["id"] == row.id
    )


# --- failure is visible -----------------------------------------------------

def test_a_checkpoint_failure_is_audited(cfg, monkeypatch):
    """A checkpoint that failed must not disappear, and must not be fatal:
    losing durability is bad, losing the engagement is worse."""
    audit = _audit(cfg, "e-fail")
    graph = _graph("e-fail")

    def _boom(_cfg):
        raise RuntimeError("disk is full")

    monkeypatch.setattr("kryonsec.storage.init_purple_db", _boom)
    assert checkpoint_graph(cfg, "e-fail", graph, audit, "VERIFY") is False

    failures = _only(_events(audit), "checkpoint_failed")
    assert len(failures) == 1
    assert failures[0]["engagement_id"] == "e-fail"
    assert failures[0]["state"] == "VERIFY"
    assert "disk is full" in failures[0]["error"]
    assert _only(_events(audit), "checkpoint_written") == []
    ok, reason = audit.verify()
    assert ok, reason


def test_a_checkpoint_does_not_store_paths_in_the_event(cfg, monkeypatch):
    """The chain is permanent and may be exported for the WORM anchor. A
    storage error quotes the local database path, which names the machine's
    user, so the audited wording carries a placeholder instead.

    The message itself is kept: "disk is full" is most of what the event is
    worth, and an operator cannot act on a bare exception class.
    """
    audit = _audit(cfg, "e-paths")
    graph = _graph("e-paths")

    def _boom(_cfg):
        raise RuntimeError(f"cannot open {cfg.home}\\purple.db")

    monkeypatch.setattr("kryonsec.storage.init_purple_db", _boom)
    assert checkpoint_graph(cfg, "e-paths", graph, audit, "VERIFY") is False

    entry = _only(_events(audit), "checkpoint_failed")[0]
    assert set(entry) == {"event", "engagement_id", "state", "error", "ts",
                          "prev_hash", "hash"}
    assert str(cfg.home) not in json.dumps(entry)
    assert "<home>" in entry["error"]
    assert "cannot open" in entry["error"]        # still diagnosable
    assert entry["error"].startswith("RuntimeError: ")
    ok, reason = audit.verify()
    assert ok, reason


def test_a_checkpoint_does_not_store_a_credential_from_the_error(cfg, monkeypatch):
    """A PostgreSQL failure can quote the connection URL, and the URL carries
    the password. The same detector that guards the LLM calls and the report
    runs over the audited message."""
    audit = _audit(cfg, "e-url")
    graph = _graph("e-url")

    def _boom(_cfg):
        raise RuntimeError(
            "could not connect: postgresql://appuser:hunter2sword@db:5432/app"
        )

    monkeypatch.setattr("kryonsec.storage.init_purple_db", _boom)
    assert checkpoint_graph(cfg, "e-url", graph, audit, "VERIFY") is False

    entry = _only(_events(audit), "checkpoint_failed")[0]
    assert "hunter2sword" not in json.dumps(entry)
    assert "SECRET_" in entry["error"]


def test_a_broken_chain_does_not_report_a_good_checkpoint_as_failed(cfg, monkeypatch):
    """The snapshot is the durable record, the audit line is the annotation.

    If a damaged chain made ``checkpoint_graph`` report failure, an operator
    would go looking for a storage problem that does not exist — and the
    actual problem (a chain that no longer verifies) would be the one thing
    the report did not say.
    """
    audit = _audit(cfg, "e-anno")
    graph = _graph("e-anno")

    def _boom(_entry):
        raise RuntimeError("chain is damaged")

    monkeypatch.setattr(AuditLog, "write", _boom)
    assert checkpoint_graph(cfg, "e-anno", graph, audit, "VERIFY") is True

    loaded = _loaded(cfg, "e-anno")
    assert [n["label"] for n in loaded.by_type("target")] == ["example.com"]


def test_a_checkpoint_uses_no_new_table(cfg):
    """The snapshot lives in the engagement graph tables. The ``checkpoints``
    table from the spec DDL stays unused: a cursor is resume's job, and
    writing one here would put a second, unverifiable source of truth about
    an interrupted run next to the audit chain."""
    audit = _audit(cfg, "e-noschema")
    assert checkpoint_graph(cfg, "e-noschema", _graph("e-noschema"), audit,
                            "RECON_PASSIVE") is True

    with get_purple_session(cfg) as session:
        assert session.query(Checkpoint).count() == 0


# --- the loop -----------------------------------------------------------------

def test_the_engagement_loop_checkpoints_after_every_state(cfg):
    """The wiring, end to end: every state that ran left a checkpoint behind,
    and the last one is the graph the run ended with."""
    orch, audit, graph = _run_loop(cfg, "e-loop")

    assert orch.completed[:3] == ["INIT", "RECON_PASSIVE", "RECON_ACTIVE"]
    written = _only(_events(audit), "checkpoint_written")
    assert [e["state"] for e in written] == orch.completed
    assert written[-1]["nodes"] == len(graph.nodes) > 0
    assert written[-1]["edges"] == len(graph.edges) > 0

    loaded = _loaded(cfg, "e-loop")
    assert loaded.nodes == graph.nodes
    assert loaded.edges == graph.edges
    assert [n["label"] for n in loaded.by_type("subdomain")] == [
        "www.target-corp.com"
    ]


def test_the_loop_checkpoints_before_the_halting_transition(cfg):
    """A halt is the exit most likely to leave work stranded. The last
    checkpoint fires after RECON_ACTIVE ran and before it becomes HALT, so
    what that state produced is on disk even though the run stopped."""
    orch, audit, graph = _run_loop(cfg, "e-halt")

    assert orch.state == HALT
    written = _only(_events(audit), "checkpoint_written")
    assert written[-1]["state"] == "RECON_ACTIVE"

    loaded = _loaded(cfg, "e-halt")
    assert len(loaded.nodes) == written[-1]["nodes"]


def test_a_checkpoint_listener_cannot_change_the_loop():
    """The listener is notified, never consulted.

    It runs inside the deterministic loop, so it must not be able to change
    where the engagement goes next — or whether it gets there. A listener
    that raises is the bluntest version of that: it must be ignored.
    """
    expected = ["INIT", "RECON_PASSIVE", "RECON_ACTIVE", "HYPOTHESIZE",
                "HUMAN_REVIEW", "BLUE_TEAM", "REPORT"]

    plain = PurpleOrchestrator("e-plain")
    plain.subagent_loader = lambda state: (lambda: SubagentResult(status="ok"))
    assert plain.run() == expected

    seen: list[str] = []

    def _explode(state: str) -> None:
        seen.append(state)
        raise RuntimeError("listener exploded")

    noisy = PurpleOrchestrator("e-noisy")
    noisy.subagent_loader = lambda state: (lambda: SubagentResult(status="ok"))
    noisy.on_state_complete = _explode
    assert noisy.run() == expected
    assert seen == expected
    assert noisy.state == HALT


def test_the_listener_sees_the_state_that_just_finished():
    """The boundary a snapshot is consistent at: the state's work is done and
    the transition has not happened, so ``orch.state`` still names the state
    whose graph this is."""
    observed: list[tuple[str, str, list[str]]] = []

    orch = PurpleOrchestrator("e-boundary")
    orch.subagent_loader = lambda state: (lambda: SubagentResult(status="ok"))

    def _record(state: str) -> None:
        observed.append((state, orch.state, list(orch.completed)))

    orch.on_state_complete = _record
    orch.run()

    assert observed
    for state, current, completed in observed:
        assert state == current          # not the next state
        assert completed[-1] == state    # already recorded as run


def test_a_halting_state_still_gets_its_checkpoint():
    """A state that halts the engagement has produced results too. The
    callback fires before the transition, so it is not skipped."""
    orch = PurpleOrchestrator("e-halted")
    orch.subagent_loader = lambda state: (
        lambda: SubagentResult(status="halted", halt_reason="test halt")
    )
    seen: list[str] = []
    orch.on_state_complete = seen.append
    orch.run()

    assert orch.state == HALT
    assert seen == ["INIT"]


# --- compatibility with what was already there ------------------------------

def test_both_storage_failure_events_sanitise_the_same_way(cfg, monkeypatch):
    """``checkpoint_failed`` and ``graph_persist_failed`` describe the same
    kind of failure, so they must describe it to the same standard — that is
    why they share one helper."""
    graph = _graph("e-drift")

    def _boom(_cfg):
        raise RuntimeError(f"cannot open {cfg.home}\\purple.db")

    monkeypatch.setattr("kryonsec.storage.init_purple_db", _boom)
    checkpoint = _audit(cfg, "e-drift")
    persist = _audit(cfg, "e-drift-persist")
    assert checkpoint_graph(cfg, "e-drift", graph, checkpoint, "VERIFY") is False
    assert persist_graph(cfg, "e-drift-persist", graph, persist) is False

    written = _only(_events(checkpoint), "checkpoint_failed")[0]
    end = _only(_events(persist), "graph_persist_failed")[0]
    assert written["error"] == end["error"]
    assert str(cfg.home) not in written["error"]


def test_persist_graph_still_runs_after_the_checkpoints(cfg):
    """The end-of-run persist is unchanged and still the last word: it writes
    the same graph, and the chain still verifies after both kinds of write."""
    _, audit, graph = _run_loop(cfg, "e-both")

    assert persist_graph(cfg, "e-both", graph, audit) is True

    events = [e["event"] for e in _events(audit)]
    assert events.count("checkpoint_written") == 3
    assert events[-1] == "graph_persisted"
    ok, reason = audit.verify()
    assert ok, reason

    assert _loaded(cfg, "e-both").nodes == graph.nodes


def test_save_graph_itself_is_unchanged_for_a_direct_caller(cfg):
    """``save_graph`` is a public storage function with callers of its own;
    the checkpoint is a new caller, not a new contract."""
    init_purple_db(cfg)
    graph = _graph("e-direct")
    with get_purple_session(cfg) as session:
        assert save_graph(session, graph) == (2, 1)
    with get_purple_session(cfg) as session:
        assert load_graph(session, "e-direct").nodes == graph.nodes


def test_the_audit_chain_is_untouched_by_a_checkpoint(cfg):
    """A checkpoint writes rows, not events it did not announce — and the
    announced events chain like every other event."""
    audit = _audit(cfg, "e-chain")
    graph = _graph("e-chain")
    for state in ["RECON_PASSIVE", "RECON_ACTIVE", "HYPOTHESIZE"]:
        assert checkpoint_graph(cfg, "e-chain", graph, audit, state) is True

    ok, reason = audit.verify()
    assert ok, reason
    entries = _events(audit)
    assert [e["event"] for e in entries] == ["checkpoint_written"] * 3
    assert all("prev_hash" in e and "hash" in e for e in entries)


def test_the_memory_browser_still_reads_a_checkpointed_engagement(cfg):
    """The browser is unchanged and keeps working. It now sees a partial
    graph for an interrupted run — which is the accepted trade — and still
    labels it correctly from the chain."""
    from kryonsec.memory import data as memory

    _run_loop(cfg, "e-browse")

    rows = {r["engagement_id"]: r for r in memory.list_engagements(cfg)}
    assert rows["e-browse"]["persisted"] is True
    assert rows["e-browse"]["nodes"] > 0
    assert rows["e-browse"]["status"] == "halted"

    one = memory.load_engagement(cfg, "e-browse")
    assert one["meta"]["persisted"] is True
    assert one["graph"]["nodes"], "the checkpoint made the graph visible"
    assert one["meta"]["report_written"] is False
