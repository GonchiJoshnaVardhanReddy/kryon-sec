"""Phase 4.4: the memory browser explains a lifecycle, not just a graph.

Before this phase the browser could only say whether an engagement had a
report. An engagement that was interrupted, or that died part-way, or that
was recorded by a version older than Phase 4.2, all looked the same: a graph
with no explanation. These tests hold the browser to the fuller account —
which is only worth having if it stays honest, so the same tests also pin the
two things that could quietly go wrong while adding it.

* **A field from the audit chain is untrusted.** The chain is a local file
  holding free text and, in the case of ``report_written``, a real filesystem
  path. Every value the browser renders has to pass the guard in
  ``memory.data``, or a status line becomes a way to read a path off the
  machine. Malformed lines have to be counted rather than raised.
* **The data layer still cannot write, and the browser still cannot act.**
  Reading a lifecycle is more code in the module that is supposed to be a
  window. The last section re-checks, by AST and by source, that it is still
  only a window: no insert, no update, no resume control, no new route.

The vocabularies are pinned together on purpose. The browser is not allowed
to import the engine — that is what the import allowlist enforces — so it
spells the four outcome words out again. A test here fails if the two copies
ever drift.
"""

from __future__ import annotations

import ast
import json
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.memory import create_server, data, list_engagements, load_engagement, viewer
from kryonsec.purple.graph_store import save_graph
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.storage import get_purple_session, init_purple_db, reset_engine

# ------------------------------------------------------------------ fixtures


@pytest.fixture()
def cfg(tmp_path):
    """The same embedded install tests/test_memory.py uses: no DATABASE_URL,
    home and workspace redirected so nothing can touch the real ~/.kryonsec."""
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = None
    yield config
    reset_engine()


class Response:
    def __init__(self, status: int, headers: dict, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body)


@pytest.fixture()
def server(cfg):
    srv = create_server(cfg, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def call(server, path: str, *, host: str | None = None,
         method: str = "GET") -> Response:
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"
    request = urllib.request.Request(url, method=method)
    if host is not None:
        request.add_header("Host", host)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return Response(response.status, dict(response.headers),
                            response.read())
    except urllib.error.HTTPError as exc:
        return Response(exc.code, dict(exc.headers), exc.read())


# ------------------------------------------------------------------- helpers


def _graph(engagement_id: str) -> EngagementGraph:
    graph = EngagementGraph(engagement_id=engagement_id)
    target = graph.add_node(
        "target", "example.com",
        provenance={"source_type": "config", "source": "engagement_config",
                    "agent": "RECON_PASSIVE"},
    )
    service = graph.add_node(
        "service", "example.com:443/tcp", {"port": 443},
        provenance={"source_type": "tool", "source": "nmap",
                    "agent": "RECON_ACTIVE"},
    )
    graph.add_edge(target, "has_service", service,
                   provenance={"source_type": "tool", "source": "nmap"})
    return graph


def _write_audit(cfg, engagement_id: str, lines: list[dict]) -> Path:
    """A minimal audit log on disk. No chain hashes: the summary reader does
    not verify the chain — ``AuditLog.verify`` does that, and the browser only
    reports that a chain could not be read, never that it is untrustworthy."""
    path = cfg.home / "engagements" / engagement_id / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(json.dumps(line) + "\n")
    return path


def _store(cfg, engagement_id: str) -> None:
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        save_graph(session, _graph(engagement_id))


def _write_report(cfg, engagement_id: str) -> None:
    path = cfg.home / "engagements" / engagement_id / "report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# report\n", encoding="utf-8")


def _summary(cfg, engagement_id: str) -> dict:
    """The summary as the list endpoint builds it."""
    for item in list_engagements(cfg):
        if item["engagement_id"] == engagement_id:
            return item
    raise AssertionError(f"{engagement_id} was not listed")


def _meta(cfg, engagement_id: str) -> dict:
    """The summary as the detail endpoint builds it.

    Touches storage first: the detail route answers only when the engagement
    database exists, and most of these tests are about the audit chain rather
    than about a graph. ``init_purple_db`` is idempotent.
    """
    init_purple_db(cfg)
    return load_engagement(cfg, engagement_id)["meta"]


def _finished(outcome: str, **extra) -> dict:
    return {"event": "engagement_finished", "outcome": outcome, **extra}


# --- the five endings, recorded ---------------------------------------------

def test_a_completed_engagement_reports_its_recorded_outcome(cfg):
    _store(cfg, "eng-done")
    _write_audit(cfg, "eng-done", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
        {"event": "state_enter", "state": "REPORT"},
        _finished("completed", states_entered=9, last_state="REPORT"),
    ])
    meta = _meta(cfg, "eng-done")
    assert meta["status"] == "complete"
    assert meta["lifecycle_recorded"] is True
    assert meta["outcome"] == "completed"
    assert meta["last_state"] == "REPORT"
    assert meta["states_entered"] == 9
    assert meta["reason"] is None


def test_a_halted_engagement_shows_both_the_code_and_the_plain_reason(cfg, server):
    """Two different facts: the engine's halt code, and the sandbox's own
    words for why the block happened. An operator wants both."""
    _store(cfg, "eng-halted")
    _write_audit(cfg, "eng-halted", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "zone_b_blocked", "reason": "sandbox runtime unavailable"},
        _finished("halted", reason="zone_b_blocked", last_state="RECON_ACTIVE",
                  states_entered=2),
    ])
    meta = call(server, "/api/engagements/eng-halted").json()["meta"]
    assert meta["status"] == "halted"
    assert meta["reason"] == "zone_b_blocked"
    assert meta["halt_reason"] == "sandbox runtime unavailable"


def test_an_interrupted_engagement_reads_as_interrupted(cfg):
    """Stopped by hand is its own ending. Before this phase it fell through
    to "incomplete", which reads like a bug rather than a decision."""
    _store(cfg, "eng-stopped-by-hand")
    _write_audit(cfg, "eng-stopped-by-hand", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
        _finished("interrupted", reason="keyboard_interrupt",
                  last_state="RECON_PASSIVE", states_entered=1),
    ])
    meta = _meta(cfg, "eng-stopped-by-hand")
    assert meta["status"] == "interrupted"
    assert meta["outcome"] == "interrupted"
    assert meta["reason"] == "keyboard_interrupt"


def test_a_failed_engagement_shows_its_exception_type_but_never_its_message(cfg, server):
    """The exception *type* is a diagnosis. The message is not in the chain
    either — Phase 4.2 stopped writing it — and this holds the line at the
    browser in case an older chain has one."""
    _store(cfg, "eng-broke")
    _write_audit(cfg, "eng-broke", [
        {"event": "engagement_created", "target": "example.com"},
        _finished("failed", reason="unhandled_exception",
                  exception_type="OperationalError", last_state="EXPLOIT",
                  states_entered=5,
                  message="connection to db.internal refused for user svc"),
    ])
    payload = call(server, "/api/engagements/eng-broke").json()
    assert payload["meta"]["status"] == "failed"
    assert payload["meta"]["exception_type"] == "OperationalError"
    # The extra key is not on the whitelist, so it never reaches the response.
    assert b"db.internal" not in json.dumps(payload).encode()


def test_every_outcome_the_engine_can_record_has_a_status(cfg):
    """One engagement per outcome, so a word added to the engine without a
    matching status here fails loudly rather than rendering as 'unknown'."""
    for index, (outcome, expected) in enumerate(sorted(data._OUTCOME_STATUS.items())):
        engagement_id = f"eng-outcome-{index}"
        _write_audit(cfg, engagement_id, [
            {"event": "engagement_created", "target": "example.com"},
            _finished(outcome, states_entered=1),
        ])
        assert _summary(cfg, engagement_id)["status"] == expected


# --- engagements from before endings were recorded ---------------------------

def test_a_legacy_completed_engagement_is_marked_as_inferred(cfg):
    """No ``engagement_finished`` event: the status still has to come out
    right, and the browser has to know it was inferred rather than recorded."""
    _write_audit(cfg, "eng-legacy-done", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "REPORT"},
        {"event": "report_written", "path": "report.md"},
    ])
    meta = _meta(cfg, "eng-legacy-done")
    assert meta["status"] == "complete"
    assert meta["lifecycle_recorded"] is False
    assert meta["outcome"] is None
    assert meta["reason"] is None
    assert meta["states_entered"] == 0


def test_a_legacy_halted_engagement_keeps_its_reason(cfg):
    _write_audit(cfg, "eng-legacy-halted", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "zone_b_blocked", "reason": "sandbox runtime unavailable"},
    ])
    meta = _meta(cfg, "eng-legacy-halted")
    assert meta["status"] == "halted"
    assert meta["halt_reason"] == "sandbox runtime unavailable"
    assert meta["lifecycle_recorded"] is False


def test_a_legacy_engagement_still_running_is_incomplete(cfg):
    _write_audit(cfg, "eng-legacy-running", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
    ])
    assert _meta(cfg, "eng-legacy-running")["status"] == "incomplete"


def test_a_chain_written_but_not_yet_used_is_unknown(cfg):
    """An empty chain is not the same as no chain: the engagement exists and
    has recorded nothing, which is a fact worth being able to tell apart."""
    _write_audit(cfg, "eng-empty", [])
    meta = _meta(cfg, "eng-empty")
    assert meta["audit_readable"] is True
    assert meta["audit_entries"] == 0
    assert meta["status"] == "unknown"


def test_an_outcome_this_version_does_not_know_falls_back_to_inference(cfg):
    """A chain written by a later version must still render. An unrecognised
    outcome is not an error — the older signals are still read."""
    _write_audit(cfg, "eng-future", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "report_written", "path": "report.md"},
        _finished("superseded", states_entered=4),
    ])
    meta = _meta(cfg, "eng-future")
    assert meta["outcome"] == "superseded"
    assert meta["lifecycle_recorded"] is True
    assert meta["status"] == "complete"      # inferred from report_written


# --- what artifacts exist ----------------------------------------------------

def test_a_partial_graph_with_no_report_is_reported_as_such(cfg):
    """The case the phase exists for: recon ran, the run was stopped by hand
    before REPORT, and what survives is a graph with no report."""
    _store(cfg, "eng-partial")
    _write_audit(cfg, "eng-partial", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
        {"event": "checkpoint_written", "state": "RECON_PASSIVE",
         "nodes": 2, "edges": 1},
        _finished("interrupted", reason="keyboard_interrupt",
                  last_state="RECON_PASSIVE", states_entered=1),
    ])
    meta = _meta(cfg, "eng-partial")
    assert meta["status"] == "interrupted"
    assert meta["persisted"] is True        # the graph is there
    assert meta["report_available"] is False  # the report is not
    assert meta["checkpoints"] == 1
    assert meta["last_checkpoint_state"] == "RECON_PASSIVE"
    assert meta["report_written"] is False


def test_a_report_file_on_disk_is_reported_separately_from_the_status(cfg):
    """Two facts, two fields. A report on disk does not promote the status,
    and a recorded completion with no file is visible as exactly that."""
    _write_audit(cfg, "eng-with-file", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
    ])
    _write_report(cfg, "eng-with-file")
    meta = _meta(cfg, "eng-with-file")
    assert meta["report_available"] is True
    assert meta["report_written"] is False
    assert meta["status"] == "incomplete"   # not upgraded by the file

    _write_audit(cfg, "eng-file-gone", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "report_written", "path": "report.md"},
    ])
    meta = _meta(cfg, "eng-file-gone")
    assert meta["report_written"] is True
    assert meta["report_available"] is False
    assert meta["status"] == "complete"


def test_the_report_path_is_never_read_out_of_the_chain(cfg):
    """``report_written.path`` is a real filesystem path. The browser builds
    the path it checks from the validated id instead."""
    _write_audit(cfg, "eng-one", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "report_written", "path": r"C:\Users\someone\.kryonsec\engagements\eng-one\report.md"},
    ])
    assert r"C:\Users" not in json.dumps(_meta(cfg, "eng-one"))


# --- storage trouble ---------------------------------------------------------

def test_a_failed_graph_write_is_reported(cfg):
    """Nothing reached the store, and the chain says why. The two are
    separate: the first is the fact, the second is the explanation."""
    _write_audit(cfg, "eng-nosave", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "REPORT"},
        {"event": "graph_persist_failed", "error": "OperationalError: disk full"},
    ])
    meta = _summary(cfg, "eng-nosave")
    assert meta["persist_failed"] is True
    assert meta["persisted"] is False
    assert meta["status"] == "incomplete"


def test_a_checkpoint_failure_is_counted_and_explained(cfg, server):
    """Phase 4.3 made a failed checkpoint observable in the chain. The
    browser is where an operator would look, so it has to say so — and it has
    to say that the graph is still the last good one, because that is the
    part that is easy to get wrong when reading a failure."""
    _store(cfg, "eng-ckpt")
    _write_audit(cfg, "eng-ckpt", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "checkpoint_written", "state": "RECON_PASSIVE",
         "nodes": 2, "edges": 1},
        {"event": "checkpoint_failed", "state": "HYPOTHESIZE",
         "error": "OperationalError: database is locked"},
        _finished("failed", reason="unhandled_exception",
                  exception_type="OperationalError", states_entered=3),
    ])
    meta = call(server, "/api/engagements/eng-ckpt").json()["meta"]
    assert meta["checkpoint_failures"] == 1
    assert meta["checkpoint_error"] == "OperationalError: database is locked"
    assert meta["checkpoints"] == 1
    assert meta["last_checkpoint_state"] == "RECON_PASSIVE"
    assert meta["persisted"] is True      # the last good snapshot survives

    listing = call(server, "/api/engagements").json()["engagements"][0]
    assert listing["checkpoint_failures"] == 1


def test_a_checkpoint_error_carrying_a_path_does_not_reach_the_page(cfg):
    _store(cfg, "eng-ckpt-path")
    _write_audit(cfg, "eng-ckpt-path", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "checkpoint_failed", "state": "REPORT",
         "error": f"OperationalError: unable to open database file "
                  f"({cfg.home}\\purple.db)"},
    ])
    meta = _meta(cfg, "eng-ckpt-path")
    assert str(cfg.home) not in meta["checkpoint_error"]
    assert "<home>" in meta["checkpoint_error"]
    assert "unable to open database file" in meta["checkpoint_error"]


# --- missing and damaged audit data -----------------------------------------

def test_an_engagement_with_no_chain_says_so_rather_than_guessing(cfg):
    """In the database with no audit chain beside it — what an engagement
    saved by an older version looks like once its directory is gone."""
    _store(cfg, "eng-no-chain")
    meta = _meta(cfg, "eng-no-chain")
    assert meta["audit_readable"] is None
    assert meta["audit_entries"] == 0
    assert meta["status"] == "unknown"
    assert meta["persisted"] is True


def test_a_chain_that_cannot_be_opened_is_reported_not_raised(cfg, monkeypatch):
    """A locked or unreadable file is a state to show. The exception text is
    not — it can carry the path."""
    _store(cfg, "eng-unreadable")
    _write_audit(cfg, "eng-unreadable", [
        {"event": "engagement_created", "target": "example.com"},
        _finished("completed", states_entered=1),
    ])

    real_open = open

    def refuse(path, *args, **kwargs):
        if str(path).endswith("audit.jsonl"):
            raise PermissionError(f"another process holds {path}")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(data, "open", refuse, raising=False)
    meta = _meta(cfg, "eng-unreadable")
    assert meta["audit_readable"] is False
    assert meta["status"] == "unknown"
    assert "another process" not in json.dumps(meta)
    assert str(cfg.home) not in json.dumps(meta)


def test_damaged_lines_are_counted_without_stopping_the_read(cfg):
    """``AuditLog.verify`` is what reports a broken chain. The browser still
    has to summarise one, and it has to say how much of it was unreadable."""
    path = _write_audit(cfg, "eng-damaged", [])
    path.write_text(
        "this is not json\n"
        + json.dumps({"event": "engagement_created", "target": "example.com"}) + "\n"
        + "[1, 2, 3]\n"
        + "\n"
        + json.dumps(_finished("interrupted", reason="keyboard_interrupt",
                               states_entered=2)) + "\n",
        encoding="utf-8",
    )
    meta = _meta(cfg, "eng-damaged")
    assert meta["audit_damaged_lines"] == 2
    assert meta["audit_entries"] == 4
    assert meta["status"] == "interrupted"     # the readable lines still work
    assert meta["target"] == "example.com"


def test_a_chain_of_nothing_but_damage_reports_no_lifecycle(cfg):
    path = _write_audit(cfg, "eng-garbage", [])
    path.write_text("garbage\nalso garbage\n", encoding="utf-8")
    meta = _meta(cfg, "eng-garbage")
    assert meta["audit_damaged_lines"] == 2
    assert meta["lifecycle_recorded"] is False
    assert meta["status"] == "unknown"


def test_a_truncated_last_line_is_counted_rather_than_raised(cfg):
    """What an interrupted write actually leaves: a final line that stops
    mid-record. The lines before it still have to be read."""
    path = _write_audit(cfg, "eng-binary", [
        {"event": "engagement_created", "target": "example.com"},
    ])
    with open(path, "a", encoding="utf-8") as handle:
        handle.write('{"event": "state_enter", "state": "RECON_PAS')
    meta = _meta(cfg, "eng-binary")
    assert meta["audit_readable"] is True
    assert meta["audit_entries"] == 2
    assert meta["audit_damaged_lines"] == 1
    assert meta["target"] == "example.com"


def test_a_byte_that_is_not_utf8_does_not_break_the_page(cfg):
    """A half-written character is the other shape of the same crash. The
    read decodes leniently, so one bad byte costs a byte rather than the
    engagement's whole history."""
    path = _write_audit(cfg, "eng-byte", [])
    path.write_bytes(b'{"event": "engagement_created", "target": "ex\xffample"}\n')
    meta = _meta(cfg, "eng-byte")
    assert meta["audit_readable"] is True
    assert meta["audit_entries"] == 1
    assert meta["target"] is not None
    assert "�" in meta["target"]


# --- free text and identifiers ----------------------------------------------

def test_a_reason_carrying_the_home_directory_does_not_reach_the_page(cfg):
    _write_audit(cfg, "eng-halted", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "zone_b_blocked",
         "reason": f"cannot start the sandbox from {cfg.home}\\sandbox"},
    ])
    meta = _meta(cfg, "eng-halted")
    assert str(cfg.home) not in meta["halt_reason"]
    assert "<home>" in meta["halt_reason"]
    assert "cannot start the sandbox" in meta["halt_reason"]


def test_a_reason_carrying_a_foreign_path_does_not_reach_the_page(cfg):
    _write_audit(cfg, "eng-foreign", [
        {"event": "zone_b_blocked",
         "reason": "refused to read /etc/kryonsec/policy.toml"},
    ])
    meta = _meta(cfg, "eng-foreign")
    assert "/etc/" not in meta["halt_reason"]
    assert "<path>" in meta["halt_reason"]


def test_a_secret_in_a_reason_is_masked_and_counted(cfg, server):
    """The path guard and the secret guard are different mechanisms on
    purpose: this one has to keep counting, because the count is the only
    signal the operator gets that a credential was recorded at all."""
    _store(cfg, "eng-secret-reason")
    _write_audit(cfg, "eng-secret-reason", [
        {"event": "zone_b_blocked",
         "reason": "sandbox rejected env AKIAIOSFODNN7EXAMPLE"},
    ])
    payload = call(server, "/api/engagements/eng-secret-reason").json()
    assert b"AKIAIOSFODNN7EXAMPLE" not in json.dumps(payload).encode()
    assert payload["redactions"] >= 1
    assert "«SECRET_" in payload["meta"]["halt_reason"]


def test_an_identifier_field_cannot_carry_free_text(cfg):
    """``last_state``, ``reason`` and ``exception_type`` are closed
    vocabularies. Anything that is not a bare word is dropped rather than
    rendered — including a path and a sentence."""
    _write_audit(cfg, "eng-hostile", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
        _finished("completed",
                  last_state=r"C:\Users\gonch\.kryonsec",
                  exception_type="ValueError: leaked detail",
                  reason="../../etc/passwd",
                  states_entered=True),
    ])
    meta = _meta(cfg, "eng-hostile")
    assert meta["last_state"] == "RECON_PASSIVE"   # the readable event wins
    assert meta["exception_type"] is None
    assert meta["reason"] is None
    assert meta["states_entered"] == 0             # True is not a count


def test_an_ordinary_hostname_is_still_shown_as_the_target(cfg):
    """The guard must not eat the value it is guarding. A dot is not a path,
    and a target is the most-read field on the page."""
    _write_audit(cfg, "eng-one", [
        {"event": "engagement_created", "target": "example.com"},
    ])
    assert _meta(cfg, "eng-one")["target"] == "example.com"


@pytest.mark.parametrize("raw, expected", [
    ("sandbox runtime unavailable", "sandbox runtime unavailable"),
    ("  spaced   out  ", "spaced out"),
    ("", None),
    ("   ", None),
    (None, None),
    (12345, None),
    (r"C:\Users\gonch\.kryonsec\purple.db", "<path>"),
    ("/var/lib/kryonsec/purple.db", "<path>"),
    (r"\\fileserver\evidence\run-1", "<path>"),
    ("a" * 500, "a" * 200),
])
def test_free_text_from_the_chain_is_reduced_to_a_status_line(cfg, raw, expected):
    assert data._text(raw, cfg.home) == expected


@pytest.mark.parametrize("raw, expected", [
    ("RECON_PASSIVE", "RECON_PASSIVE"),
    ("zone_b_blocked", "zone_b_blocked"),
    ("OperationalError", "OperationalError"),
    ("two words", None),
    ("trailing ", None),
    ("1leading_digit", None),
    ("a/b", None),
    ("", None),
    ("x" * 65, None),
    (None, None),
    (7, None),
])
def test_an_identifier_from_the_chain_is_a_bare_word_or_nothing(raw, expected):
    assert data._ident(raw) == expected


def test_free_text_strips_the_home_directory_before_matching_paths(cfg):
    """Order matters: redaction and pattern matching must not leave half a
    home directory behind for the other pass to miss."""
    text = f"failed under {cfg.home} and also /etc/hosts"
    cleaned = data._text(text, cfg.home)
    assert str(cfg.home) not in cleaned
    assert "/etc/" not in cleaned
    assert "<home>" in cleaned and "<path>" in cleaned


# --- the copies of the vocabulary cannot drift -------------------------------

def test_the_browser_and_the_engine_agree_on_the_outcome_words():
    """The memory package must not import the engine, so it spells the four
    outcomes out again. This is the test that makes that safe: add a word on
    either side and it fails here."""
    from kryonsec.purple import runner

    assert set(data._OUTCOME_STATUS) == set(runner.OUTCOMES)


def test_every_status_the_data_layer_can_report_is_styled_and_pilled():
    """A status the page has no pill for renders as an unstyled span, which
    is how `failed` sat unlit for two phases. Pin the front-end to the data
    layer's vocabulary instead."""
    css = _static("app.css")
    js = _static("app.js")

    styled = set(re.findall(r"\.pill-([a-z]+)\s*\{", css))
    pilled = set(re.findall(r"(\w+):\s*'pill-", js))

    # Everything _OUTCOME_STATUS can produce, plus the two words the
    # pre-4.2 inference can produce.
    expected = set(data._OUTCOME_STATUS.values()) | {"incomplete", "unknown"}
    assert expected - {"unknown"} <= styled
    assert expected - {"unknown"} <= pilled
    # `unknown` is deliberately the plain pill: no style of its own.
    assert "unknown" not in styled


def test_the_browser_reads_the_lifecycle_without_importing_the_engine():
    """The specific regression this phase invited. ``..purple.runner`` and
    ``..purple.orchestrator`` are not on the memory package's import
    allowlist, and the summary must not reach for them."""
    tree = ast.parse(Path(data.__file__).read_text(encoding="utf-8"),
                     filename=str(data.__file__))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add("." * (node.level or 0) + (node.module or ""))
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)

    assert not any("purple.runner" in name for name in imported)
    assert not any("purple.orchestrator" in name for name in imported)


# --- the window is still a window --------------------------------------------

def test_the_data_layer_still_writes_nothing():
    """More code in the read-only module is more chance of a write. There is
    no statement on a session that could change a row, and no DML helper
    imported to write one with."""
    source = Path(data.__file__).read_text(encoding="utf-8")
    for forbidden in ("session.add(", "session.commit(", "session.flush(",
                      "session.execute(", "session.delete(", "session.merge(",
                      "sqlalchemy.insert", "sqlalchemy.update",
                      "sqlalchemy.delete"):
        assert forbidden not in source, f"data.py contains {forbidden!r}"


def test_the_browser_still_offers_no_way_to_resume_an_engagement():
    """Phase 4.4 explains a lifecycle; it does not act on one. No resume
    control, and nothing that could quietly become one."""
    sources = {
        "memory/data.py": Path(data.__file__),
        "memory/viewer.py": Path(viewer.__file__),
        "memory/static/app.js": viewer.STATIC_DIR / "app.js",
        "memory/static/index.html": viewer.STATIC_DIR / "index.html",
    }
    for name, path in sources.items():
        source = path.read_text(encoding="utf-8")
        assert "resume" not in source.lower(), f"{name} mentions resume"


def test_the_lifecycle_fields_added_no_write_endpoint(server):
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = call(server, "/api/engagements/eng-one", method=method)
        assert response.status == 405
        assert "GET" in response.headers.get("Allow", "")


def test_the_lifecycle_is_readable_only_over_loopback(server):
    """The new fields travel on the same two routes as the old ones, behind
    the same Host check."""
    assert call(server, "/api/engagements", host="evil.example").status == 403
    assert call(server, "/api/engagements/eng-one", host="evil.example").status == 403


def test_the_lifecycle_text_is_set_as_text_never_as_html():
    """Every value here comes from a file on disk. The overview writes it
    with textContent, so a reason containing markup is shown, not run — and
    its one use of innerHTML only ever clears the grid."""
    block = _overview_block()
    assignments = re.findall(r"\.innerHTML\s*=\s*([^;]+);", block)
    assert assignments, "the panel clears its grid before rebuilding it"
    assert all(value.strip() in ("''", '""') for value in assignments), assignments
    assert "textContent" in block


def test_the_overview_still_shows_only_the_facts_it_was_given():
    """A guard against the panel growing decorative content: every cell is a
    label/value pair built from the payload, and the note is one string."""
    block = _overview_block()
    assert "state.current.meta" in block
    assert "Math.random" not in block


def test_every_field_the_overview_reads_is_one_the_data_layer_sends(cfg):
    """The panel and the summary are written in two languages. A field the
    page reads but the server never sends renders as an em dash forever, and
    a typo in a long list of new fields is exactly how that happens."""
    meta = _meta(cfg, "eng-nonexistent")
    used = set(re.findall(r"\bmeta\.(\w+)", _overview_block()))
    assert used, "the overview should read the payload"
    assert used <= set(meta), f"the page reads {sorted(used - set(meta))}"


# --- helpers -----------------------------------------------------------------

def _overview_block() -> str:
    """The body of ``renderOverview`` — the panel this phase changed."""
    js = _static("app.js")
    start = js.index("function renderOverview")
    return js[start:js.index("function selectEngagement")]


def _static(name: str) -> str:
    """A bundled asset, read the way the viewer serves it."""
    return (viewer.STATIC_DIR / name).read_text(encoding="utf-8")
