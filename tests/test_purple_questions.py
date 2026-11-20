"""Phase 1 contract: read-only questions about a Purple engagement.

An operator can ask "what is the recon agent doing?" at any time an
engagement view is open — before, during (while the worker thread keeps
running), and after the engagement ends.  Answering a question must
NEVER start, stop, or change an engagement and must NEVER execute a
tool: the answer is a plain chat completion over the presentation
snapshot, with a deterministic fallback when no model can answer.

Every test here is fully offline: the LLM boundary is stubbed, the
Purple worker is stubbed, and nothing touches Docker or the network.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.llm import LlmUnavailable, chat_local, is_loopback_endpoint
from kryonsec.storage import reset_engine
from kryonsec.ui.questions import (
    QUESTION_SYSTEM_PROMPT,
    answer_question,
    engagement_plain_summary,
)
from kryonsec.ui.session_store import EngagementStore, EngagementTab, SessionStore
from kryonsec.ui.workspace import WorkspaceController


@pytest.fixture()
def workspace(tmp_path):
    reset_engine()
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    cfg.database_url = f"sqlite:///{tmp_path / 'sessions.db'}"
    store = SessionStore(cfg)
    store.ensure_schema()
    controller = WorkspaceController(
        cfg,
        session_store=store,
        engagement_store=EngagementStore(cfg),
        system_prompt="test prompt",
    )
    # Every test in this file runs in Mode B: the operator has already
    # flipped with Shift+Tab before engagements are visible.
    controller.mode_holder[0] = "purple"
    yield controller
    controller.close()
    reset_engine()


def _recorded_chat(monkeypatch, reply: str = "The engine is fine."):
    """Replace the local chat with a deterministic offline one.

    Engagement questions are local-only, so ``chat_local`` is the path they
    take. ``chat`` is patched to the same fake so a regression that routes a
    question through the hosted router is visible in ``calls`` instead of
    reaching a real provider.
    """
    calls: list[dict] = []

    def fake_chat(cfg, messages, model=None, **kwargs):
        calls.append({
            "messages": messages,
            "model": model or cfg.local_model,
            "kwargs": kwargs,
        })
        return reply

    monkeypatch.setattr("kryonsec.llm.chat_local", fake_chat)
    monkeypatch.setattr("kryonsec.llm.chat", fake_chat)
    return calls


def _start_fake_engagement(workspace, monkeypatch, *, outcome: str | None = None):
    """Monkeypatch cli._run_purple; optionally let the fake finish a run."""
    calls: list[str] = []
    entered = threading.Event()
    release = threading.Event()

    def fake_run_purple(cfg, target, *, ui=None, **kwargs):
        calls.append(target)
        if ui is not None:
            # the engine announces its first state as soon as it starts
            ui.on_state("RECON_PASSIVE")
        entered.set()
        release.wait(timeout=10)
        if outcome and ui is not None:
            ui.finish(outcome)
        return 0

    monkeypatch.setattr("kryonsec.cli._run_purple", fake_run_purple)
    return calls, entered, release


# ---- the question never starts another engagement -------------------------


def test_plain_text_starts_engagement_only_without_view(workspace, monkeypatch):
    """No view open: plain text is the placeholder screen's start action."""
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        release.set()
        await task
        assert calls == ["authorized.example"]

    asyncio.run(scenario())


def test_plain_text_never_starts_engagement_when_view_open(workspace, monkeypatch):
    """With a view open, plain text is a question — never a new run."""
    calls, entered, release = _start_fake_engagement(
        workspace, monkeypatch, outcome="completed"
    )
    _recorded_chat(monkeypatch)

    async def scenario():
        task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        # engagement still running: a plain sentence must not queue a
        # second engagement and must produce an answer instead
        await workspace.submit("what is happening right now?")
        release.set()
        await task
        assert calls == ["authorized.example"], "a question started an engagement"
        qa = workspace.purple_view.snapshot()["qa"]
        assert len(qa) == 1
        assert qa[0]["q"].startswith("what is happening")
        assert qa[0]["a"]

    asyncio.run(scenario())


def test_question_while_engagement_running(workspace, monkeypatch):
    """The worker thread keeps running while an answer is prepared."""
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)
    chat_calls = _recorded_chat(monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        assert workspace.engagement_running is True
        await workspace.submit("what is the recon agent doing?")
        qa = workspace.purple_view.snapshot()["qa"]
        assert len(qa) == 1 and qa[0]["a"]
        release.set()
        await run_task
        # the engagement still ran to its own completion afterwards
        assert calls == ["authorized.example"]
        assert workspace.engagement_running is False
        # the answer was one plain chat: no tools attached, nothing to run
        assert len(chat_calls) == 1
        assert "tools" not in chat_calls[0]["kwargs"]
        assert len(chat_calls[0]["messages"]) == 2
        assert chat_calls[0]["messages"][0]["role"] == "system"
        assert chat_calls[0]["messages"][0]["content"] == QUESTION_SYSTEM_PROMPT
        snapshot_context = chat_calls[0]["messages"][1]["content"]
        assert "AUTHORIZED.EXAMPLE" in snapshot_context.upper()

    asyncio.run(scenario())


def test_answer_cannot_execute_tools(workspace, monkeypatch):
    """Belt and braces: even a hostile chat stub sees no tool channel."""
    seen: dict = {}

    def fake_chat(cfg, messages, model=None, **kwargs):
        seen["kwargs"] = kwargs
        seen["message_keys"] = [sorted(m.keys()) for m in messages]
        return "answered from the snapshot only"

    monkeypatch.setattr("kryonsec.llm.chat_local", fake_chat)
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("x.example"))
        await asyncio.to_thread(entered.wait, 5)
        await workspace.submit("run nmap for me")
        release.set()
        await run_task

    asyncio.run(scenario())
    # the chat call carries a model name and messages only — no tool
    # schema, no tool_choice, no execution hook of any kind
    assert "tools" not in seen["kwargs"]
    assert "tool_choice" not in seen["kwargs"]
    for keys in seen["message_keys"]:
        assert set(keys) <= {"role", "content"}


# ---- the approval contract and engagement controls -----------------------


def test_second_engagement_during_run_refused(workspace, monkeypatch):
    """/engage while an engagement runs is refused, not queued."""
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)
    _recorded_chat(monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("first.example"))
        await asyncio.to_thread(entered.wait, 5)
        await workspace.submit("/engage second.example")
        assert calls == ["first.example"], "a second engagement was started"
        assert "already running" in workspace.notice.lower()
        release.set()
        await run_task

    asyncio.run(scenario())


def test_mode_refused_during_running_engagement(workspace, monkeypatch):
    """`/mode` must not switch modes (or clear busy) while a worker runs."""
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("first.example"))
        await asyncio.to_thread(entered.wait, 5)
        await workspace.submit("/mode")
        assert workspace.mode == "purple", "mode was switched mid-engagement"
        assert workspace.engagement_running is True
        assert workspace.busy is False, "the /mode busy hack ran during an engagement"
        assert "still running" in workspace.notice.lower()
        release.set()
        await run_task
        # after the engagement finishes, /mode works again
        await workspace.submit("/mode")
        assert workspace.mode == "copilot"

    asyncio.run(scenario())


def test_busy_safe_commands_work_during_engagement(workspace, monkeypatch):
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch, outcome="completed")

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        await workspace.submit("/help")
        await workspace.submit("/sessions")
        assert "Loaded" in workspace.notice
        release.set()
        await run_task

    asyncio.run(scenario())


def test_question_after_engagement_completes(workspace, monkeypatch):
    """After the run: answers come from the final snapshot, honestly."""
    calls, entered, release = _start_fake_engagement(
        workspace, monkeypatch, outcome="completed"
    )
    _recorded_chat(monkeypatch, reply="The engagement completed.")

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        release.set()
        await run_task
        assert workspace.purple_view.snapshot()["outcome"] == "completed"
        await workspace.submit("how did it end?")
        qa = workspace.purple_view.snapshot()["qa"]
        assert len(qa) == 1
        assert qa[0]["a"] == "The engagement completed."

    asyncio.run(scenario())


# ---- fallback paths: the operator always gets a real answer ---------------


def test_llm_unavailable_falls_back_to_local_summary(workspace, monkeypatch):
    def broken_chat(cfg, messages, model=None, **kwargs):
        raise LlmUnavailable("offline in tests")

    monkeypatch.setattr("kryonsec.llm.chat_local", broken_chat)
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        await workspace.submit("what stage are you in?")
        release.set()
        await run_task

    asyncio.run(scenario())
    answer = workspace.purple_view.snapshot()["qa"][0]["a"]
    assert answer.startswith("(local summary —")
    assert "offline in tests" in answer
    # the deterministic summary is built from real snapshot facts
    assert "RECON_PASSIVE" in answer


def test_local_summary_covers_tool_failure(workspace):
    snapshot = {
        "target": "shop.example.com",
        "current_state": "EXPLOIT",
        "outcome": None,
        "completed_states": ["RECON_PASSIVE", "RECON_ACTIVE", "HYPOTHESIZE"],
        "failed_states": [],
        "counts": {"findings": 2, "errors": 1, "subdomains": 3, "endpoints": 4,
                   "hypotheses": 2, "evidence": 0},
        "findings": [("SQLi in /login", "possible / unverified", "high")],
        "tools": [
            {"name": "httpx", "status": "completed", "detail": "12 found"},
            {"name": "sqlmap", "status": "failed", "detail": "target re-embargoed"},
        ],
        "notices": ["tool sqlmap was rejected"],
        "sandbox_status": "ready",
        "sandbox_detail": "",
        "engagement_id": "abcd1234",
    }
    summary = engagement_plain_summary(snapshot)
    assert "EXPLOIT stage" in summary
    assert "2 finding(s)" in summary
    assert "sqlmap" in summary and "target re-embargoed" in summary
    assert "1 tool error(s)" in summary
    assert "RECON_PASSIVE, RECON_ACTIVE, HYPOTHESIZE" in summary


def test_local_summary_names_a_failed_stage(workspace):
    """The fallback answer must not hide a stage that did not finish."""
    snapshot = {
        "target": "shop.example.com",
        "current_state": "REPORT",
        "outcome": "failed",
        "completed_states": ["INIT", "RECON_PASSIVE", "RECON_ACTIVE", "REPORT"],
        "failed_states": ["HYPOTHESIZE"],
        "counts": {},
        "findings": [],
        "tools": [],
        "notices": [],
        "sandbox_status": "ready",
        "sandbox_detail": "",
        "engagement_id": "abcd1234",
    }
    summary = engagement_plain_summary(snapshot)
    assert "has finished: failed" in summary
    assert "did not finish: HYPOTHESIZE" in summary


def test_secret_shaped_question_is_redacted_before_any_model_call(
    workspace, monkeypatch
):
    """The raw secret never reaches the local model either.

    ``answer_question`` redacts the question before composing the prompt,
    so the model can only ever receive the placeholder.  ``_complete`` is
    the network boundary — stubbing it proves what would have been sent.
    """
    sent: list[list[dict]] = []
    sent_models: list[str] = []

    def fake_complete(cfg, model, messages, **kwargs):
        sent_models.append(model)
        sent.append([dict(message) for message in messages])
        return "I only see placeholders."

    monkeypatch.setattr("kryonsec.llm._complete", fake_complete)
    monkeypatch.setattr("kryonsec.llm._ollama_model_ok", lambda c, m: True)
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        await workspace.submit("is my key AKIAIOSFODNN7EXAMPLE exposed anywhere?")
        release.set()
        await run_task

    asyncio.run(scenario())
    assert sent, "the local model path was not exercised"
    assert sent_models and all(
        model.startswith("ollama/") for model in sent_models
    ), "an engagement question was routed to a hosted model"
    for messages in sent:
        blob = " ".join(str(message.get("content")) for message in messages)
        assert "AKIAIOSFODNN7EXAMPLE" not in blob, "a raw secret was sent to a model"
    # the answer is real either way (model reply or local summary)
    answer = workspace.purple_view.snapshot()["qa"][0]["a"]
    assert answer.strip()
    # and the stored question itself is redacted
    stored = workspace.purple_view.snapshot()["qa"][0]["q"]
    assert "AKIAIOSFODNN7EXAMPLE" not in stored


# ---- serialization: one answer at a time ----------------------------------


def test_second_question_refused_while_first_in_flight(workspace, monkeypatch):
    _recorded_chat(monkeypatch)
    gate = threading.Event()

    def slow_answer(cfg, snapshot, question):
        gate.wait(timeout=5)
        return "the slow but real answer"

    monkeypatch.setattr("kryonsec.ui.questions.answer_question", slow_answer)
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        first = asyncio.create_task(workspace.submit("what is running now?"))
        deadline = time.monotonic() + 5
        while not workspace._question_in_flight and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        assert workspace._question_in_flight
        await workspace.submit("and a second question?")
        gate.set()
        await first
        release.set()
        await run_task

    asyncio.run(scenario())
    snapshot = workspace.purple_view.snapshot()
    qa = snapshot["qa"]
    # only the first question was recorded; the second was refused
    assert len(qa) == 1
    assert qa[0]["a"] == "the slow but real answer"
    assert any("One question at a time" in n for n in snapshot["notices"])


def test_answer_matches_the_question_it_belongs_to(workspace, monkeypatch):
    replies = iter(["answer one", "answer two"])

    def fake_chat(cfg, messages, model=None, **kwargs):
        return next(replies)

    monkeypatch.setattr("kryonsec.llm.chat_local", fake_chat)
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        await workspace.submit("first question?")
        await workspace.submit("second question?")
        release.set()
        await run_task

    asyncio.run(scenario())
    qa = workspace.purple_view.snapshot()["qa"]
    assert [entry["a"] for entry in qa] == ["answer one", "answer two"]
    assert [entry["q"] for entry in qa] == ["first question?", "second question?"]


def test_engagement_receives_the_operator_stop_flag(workspace, monkeypatch):
    """Ctrl+C in the UI must reach the loop as a boundary stop, not a promise."""
    seen: dict[str, object] = {}
    entered = threading.Event()
    release = threading.Event()

    def fake_run_purple(cfg, target, *, ui=None, stop_requested=None, **kwargs):
        seen["stop"] = stop_requested
        entered.set()
        release.wait(timeout=10)
        return 0

    monkeypatch.setattr("kryonsec.cli._run_purple", fake_run_purple)

    async def scenario():
        task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        stop = seen["stop"]
        assert callable(stop)
        assert stop() is False
        workspace.stop_requested = True
        assert stop() is True
        release.set()
        await task

    asyncio.run(scenario())


# ---- reopened engagement views --------------------------------------------


def test_question_on_reopened_engagement(workspace, monkeypatch):
    """A recorded engagement replays from the audit chain and answers."""
    _recorded_chat(monkeypatch, reply="It was halted by the budget guard.")
    engagement_dir = workspace.cfg.home / "engagements" / "deadbeef"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "audit.jsonl").write_text(
        json.dumps({"event": "engagement_created", "target": "recorded.example"}) + "\n"
        + json.dumps({"event": "state_enter", "state": "RECON_PASSIVE"}) + "\n"
        + json.dumps(
            {
                "event": "engagement_finished",
                "outcome": "halted",
                "reason": "budget_exhausted",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    tab = EngagementTab(
        engagement_id="deadbeef", target="recorded.example", path=engagement_dir
    )
    workspace.mode_holder[0] = "purple"
    workspace.engagements = [tab]
    workspace.engagement_index = 0
    workspace.load_engagement_view(tab)
    assert workspace.purple_view.snapshot()["outcome"] == "halted"

    asyncio.run(workspace.submit("why did it stop?"))
    qa = workspace.purple_view.snapshot()["qa"]
    assert len(qa) == 1
    assert qa[0]["a"] == "It was halted by the budget guard."


def test_reopened_engagement_reports_its_real_duration(workspace):
    """A replay must not report "time since the operator opened the tab"."""
    engagement_dir = workspace.cfg.home / "engagements" / "cafe1234"
    engagement_dir.mkdir(parents=True)
    events = [
        {"event": "engagement_created", "target": "recorded.example",
         "ts": "2026-01-01T10:00:00+00:00"},
        {"event": "state_enter", "state": "RECON_PASSIVE",
         "ts": "2026-01-01T10:00:05+00:00"},
        {"event": "state_enter", "state": "RECON_ACTIVE",
         "ts": "2026-01-01T10:00:35+00:00"},
        {"event": "engagement_finished", "outcome": "completed",
         "ts": "2026-01-01T10:01:05+00:00"},
    ]
    (engagement_dir / "audit.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    tab = EngagementTab(
        engagement_id="cafe1234", target="recorded.example", path=engagement_dir
    )

    workspace.load_engagement_view(tab)
    snapshot = workspace.purple_view.snapshot()

    assert snapshot["recorded_duration"] == 65.0
    assert snapshot["state_duration"]["RECON_PASSIVE"] == 30.0
    assert snapshot["state_duration"]["RECON_ACTIVE"] == 30.0
    # The tab's sort key is the audit's real timestamp, not a field the
    # chain never wrote (it writes ``ts``, not ``timestamp``).
    tabs = workspace.engagement_store.list_tabs()
    assert tabs[0].started_at == "2026-01-01T10:00:00+00:00"


def test_reopened_failed_run_marks_the_recorded_stage(workspace):
    engagement_dir = workspace.cfg.home / "engagements" / "cafe5678"
    engagement_dir.mkdir(parents=True)
    events = [
        {"event": "engagement_created", "target": "recorded.example"},
        {"event": "state_enter", "state": "RECON_ACTIVE"},
        {"event": "engagement_finished", "outcome": "failed",
         "reason": "state_failed", "failed_states": ["RECON_ACTIVE"]},
    ]
    (engagement_dir / "audit.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    tab = EngagementTab(
        engagement_id="cafe5678", target="recorded.example", path=engagement_dir
    )

    workspace.load_engagement_view(tab)
    snapshot = workspace.purple_view.snapshot()

    assert snapshot["outcome"] == "failed"
    assert snapshot["failed_states"] == ["RECON_ACTIVE"]
    # A stage that failed is not also reported as completed.
    assert "RECON_ACTIVE" not in snapshot["completed_states"]


# ---- /report and report audit events (Phase 4) -----------------------------


def test_report_written_event_reaches_view(workspace, monkeypatch):
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    def fake_run_purple(cfg, target, *, ui=None, **kwargs):
        entered.set()
        release.wait(timeout=10)
        if ui is not None:
            ui.on_audit({"event": "report_written", "path": "/tmp/eng-1/report.md"})
            ui.finish("completed")

    monkeypatch.setattr("kryonsec.cli._run_purple", fake_run_purple)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        release.set()
        await run_task

    asyncio.run(scenario())
    snapshot = workspace.purple_view.snapshot()
    assert snapshot["report_path"] == "/tmp/eng-1/report.md"
    assert any("Report saved: /tmp/eng-1/report.md" in n for n in snapshot["notices"])


def test_report_failed_event_reaches_view(workspace, monkeypatch):
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        view = workspace.purple_view
        assert view is not None
        view.on_audit({"event": "report_failed", "reason": "template exploded"})
        snapshot = view.snapshot()
        assert any(
            "Report save failed — template exploded" in n for n in snapshot["notices"]
        )
        release.set()
        await run_task

    asyncio.run(scenario())


def test_report_command_shows_and_opens_path(workspace, monkeypatch, tmp_path):
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)
    report_file = tmp_path / "report.md"
    report_file.write_text("# report", encoding="utf-8")
    opened: list[str] = []
    monkeypatch.setattr("webbrowser.open", lambda uri: opened.append(uri) or True)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        view = workspace.purple_view
        assert view is not None
        view.report_path = str(report_file)
        await workspace.submit("/report")
        assert any("Report saved at:" in n for n in view.snapshot()["notices"])
        await workspace.submit("/report open")
        assert len(opened) == 1
        assert opened[0].endswith("report.md")
        release.set()
        await run_task

    asyncio.run(scenario())


def test_report_command_without_report_is_honest(workspace, monkeypatch):
    calls, entered, release = _start_fake_engagement(workspace, monkeypatch)

    async def scenario():
        run_task = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        await workspace.submit("/report")
        notices = workspace.purple_view.snapshot()["notices"]
        assert any("No report has been saved" in n for n in notices)
        release.set()
        await run_task

    asyncio.run(scenario())


# ---- /engage command: explicit starts only ---------------------------------


def test_engage_command_starts_explicit_engagement(workspace, monkeypatch):
    calls, entered, release = _start_fake_engagement(
        workspace, monkeypatch, outcome="completed"
    )

    async def scenario():
        first = asyncio.create_task(workspace.start_engagement("one.example"))
        await asyncio.to_thread(entered.wait, 5)
        release.set()
        await first
        await workspace.submit("/engage two.example")
        await asyncio.sleep(0.05)
        assert calls == ["one.example", "two.example"]

    asyncio.run(scenario())


def test_engage_without_target_gives_usage(workspace, monkeypatch):
    calls, entered, release = _start_fake_engagement(
        workspace, monkeypatch, outcome="completed"
    )

    async def scenario():
        first = asyncio.create_task(workspace.start_engagement("authorized.example"))
        await asyncio.to_thread(entered.wait, 5)
        release.set()
        await first
        await workspace.submit("/engage")
        notices = workspace.purple_view.snapshot()["notices"]
        assert any("/engage <authorized target>" in n for n in notices)

    asyncio.run(scenario())


# ---- answer_question unit behaviour ----------------------------------------


def test_answer_question_context_is_bounded_and_redacted():
    snapshot = {
        "target": "shop.example.com",
        "engagement_id": "abcd1234",
        "current_state": "EXPLOIT",
        "completed_states": ["RECON_PASSIVE"],
        "failed_states": [],
        "counts": {"subdomains": 2, "endpoints": 5, "hypotheses": 1,
                   "findings": 1, "evidence": 0, "errors": 0},
        "findings": [("Open admin panel", "possible / unverified", "medium")],
        "tools": [{"name": "httpx", "status": "running", "detail": "", "duration": None}],
        "notices": [],
        "sandbox_status": "ready",
        "sandbox_detail": "",
        "outcome": None,
        "halt_reason": None,
        "report_path": None,
    }
    from kryonsec.ui.questions import engagement_context_text

    context = engagement_context_text(snapshot)
    assert "shop.example.com" in context
    assert "EXPLOIT" in context
    assert "httpx — running" in context
    assert len(context) < 8000


# ---- privacy boundary: engagement questions are local-only ----------------


def _question_snapshot() -> dict:
    return {
        "target": "shop.example.com",
        "engagement_id": "abcd1234",
        "current_state": "EXPLOIT",
        "completed_states": ["RECON_PASSIVE"],
        "failed_states": [],
        "counts": {"subdomains": 2, "endpoints": 5, "hypotheses": 1,
                   "findings": 1, "evidence": 0, "errors": 0},
        "findings": [("Open admin panel", "possible / unverified", "medium")],
        "tools": [{"name": "httpx", "status": "running", "detail": "", "duration": None}],
        "notices": [],
        "sandbox_status": "ready",
        "sandbox_detail": "",
        "outcome": None,
        "halt_reason": None,
        "report_path": None,
    }


def test_answer_question_never_calls_the_hosted_router(tmp_path, monkeypatch):
    """The engagement snapshot must not reach a hosted provider, even when
    one is configured and healthy.  ``chat`` is the hosted router."""
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    cfg.ollama_host = "http://127.0.0.1:11434"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("engagement question reached the hosted router")

    seen: dict = {}

    def local(cfg_arg, messages, model=None, **kwargs):
        seen["model"] = model or cfg_arg.local_model
        return "local answer only"

    monkeypatch.setattr("kryonsec.llm.chat", forbidden)
    monkeypatch.setattr("kryonsec.llm.chat_local", local)

    answer = answer_question(cfg, _question_snapshot(), "what is happening?")

    assert answer == "local answer only"
    assert seen["model"].startswith("ollama/")


def test_chat_local_refuses_a_hosted_model_before_any_call(tmp_path, monkeypatch):
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    calls: list = []
    monkeypatch.setattr(
        "kryonsec.llm._complete",
        lambda *_args, **_kwargs: calls.append("called") or "unexpected",
    )

    with pytest.raises(LlmUnavailable, match="ollama/"):
        chat_local(cfg, [{"role": "user", "content": "hi"}], model="openai/gpt-4o")

    assert calls == []


def test_chat_local_refuses_a_non_loopback_endpoint_before_any_call(
    tmp_path, monkeypatch
):
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    cfg.ollama_host = "https://ollama.example.com"
    calls: list = []
    monkeypatch.setattr(
        "kryonsec.llm._complete",
        lambda *_args, **_kwargs: calls.append("called") or "unexpected",
    )

    with pytest.raises(LlmUnavailable, match="not loopback"):
        chat_local(cfg, [{"role": "user", "content": "hi"}])

    assert calls == []


def test_answer_question_falls_back_when_the_local_endpoint_is_remote(
    tmp_path, monkeypatch
):
    """A misconfigured OLLAMA_HOST must produce the deterministic summary,
    not a remote request and not an error in the engagement view."""
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    cfg.ollama_host = "https://ollama.example.com"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a non-loopback endpoint was contacted")

    monkeypatch.setattr("kryonsec.llm._complete", forbidden)

    answer = answer_question(cfg, _question_snapshot(), "what is happening?")

    assert answer.startswith("(local summary")
    assert "not loopback" in answer
    assert "shop.example.com" in answer


def test_is_loopback_endpoint_accepts_only_this_machine():
    assert is_loopback_endpoint("http://localhost:11434")
    assert is_loopback_endpoint("127.0.0.1:11434")
    assert is_loopback_endpoint("http://[::1]:11434")
    assert not is_loopback_endpoint("https://ollama.example.com")
    assert not is_loopback_endpoint("http://0.0.0.0:11434")
    assert not is_loopback_endpoint("http://10.0.0.5:11434")
    assert not is_loopback_endpoint("")
