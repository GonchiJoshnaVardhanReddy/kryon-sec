"""Real provider-usage capture + the KRYONSEC_DISABLE_LLM gate.

The Phase-5 engagement runs must measure tokens/cost as REAL
provider-reported numbers: _complete() captures each response's usage
object into a bounded module log, the LLM states accrue it with
estimate=False and audit llm_usage events, and the local token count
stays the clearly-labelled estimate fallback. The gate makes zero-LLM
baseline runs possible: the affected states fail audited, never silently.
"""

import builtins
import sys
from types import SimpleNamespace

import pytest

import kryonsec.llm as llm
from kryonsec.config import KryonsecConfig
from kryonsec.llm import LlmUnavailable
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.blue_team import (
    BlueTeamSubagent,
    RemediationSet,
    generate_remediations,
)
from kryonsec.purple.hypothesize import (
    Hypothesis,
    HypothesisSet,
    HypothesizeSubagent,
    propose_hypotheses_with_model,
)
from kryonsec.purple.orchestrator import BudgetTracker
from kryonsec.purple.recon_passive import EngagementGraph

HYP_REPLY = (
    '{"hypotheses": [{"id": "H1", "title": "t", '
    '"target_asset": "a", "rationale": "r"}]}'
)
REM_REPLY = (
    '{"remediations": [{"hypothesis_id": "H1", "title": "t", '
    '"fix": "f", "detection": "d", "severity": "medium"}]}'
)


@pytest.fixture(autouse=True)
def _clean_usage_log():
    """Each test starts from an empty capture log — attribution stays exact."""
    llm.clear_usage_log()
    yield
    llm.clear_usage_log()


@pytest.fixture
def cfg(tmp_path):
    """An openai-hosted config whose key is present, so chat() reaches
    litellm (faked below) instead of failing on the missing key."""
    c = KryonsecConfig(home=tmp_path)
    c.openai_api_key = "cfg-key-not-a-real-secret"
    return c


def _fake_completion(reply: str, usages: list[tuple[int, int, int]]):
    """A litellm.completion double that returns the reply with the given
    usage tuple(s), in order (so a repair-retry can differ)."""
    calls: list[dict] = []

    def fake_completion(**kwargs):
        calls.append(kwargs)
        usage = usages[min(len(calls) - 1, len(usages) - 1)]
        return SimpleNamespace(
            model=kwargs.get("model", "gpt-4o-mini"),
            choices=[SimpleNamespace(
                message=SimpleNamespace(content=reply))],
            usage=SimpleNamespace(
                prompt_tokens=usage[0],
                completion_tokens=usage[1],
                total_tokens=usage[2],
            ),
        )

    fake_completion.calls = calls
    return fake_completion


def _no_instructor(monkeypatch):
    """Force the JSON path to be the live one (instructor is optional)."""
    monkeypatch.setitem(sys.modules, "instructor", None)
    real_import = builtins.__import__

    def hook(name, *args, **kwargs):
        if name == "instructor":
            raise ImportError("forced for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", hook)


@pytest.fixture
def _no_pricing(monkeypatch):
    """completion_cost raises on every unpriced model; keep that the only
    behaviour in tests so cost determinism does not depend on the cost map
    that ships with litellm."""
    monkeypatch.setattr(
        "litellm.completion_cost",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("unpriced model")))


def _audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


def _events(audit, name):
    return [e for e in audit.entries() if e.get("event") == name]


def _graph():
    g = EngagementGraph(engagement_id="e-usage")
    g.add_node("target", "testcorp.example", {"source": "engagement_config"})
    g.add_node("subdomain", "www.testcorp.example", {"source": "crt.sh"})
    return g


# --- the capture layer ------------------------------------------------------

def test_chat_appends_a_real_usage_record(cfg, monkeypatch, _no_pricing):
    monkeypatch.setattr(
        "litellm.completion", _fake_completion("hello", [(11, 22, 33)]))
    text = llm.chat(cfg, [{"role": "user", "content": "hi"}], "gpt-4o-mini")
    assert text == "hello"
    records = llm.usage_log()
    assert len(records) == 1
    r = records[0]
    assert r["model"] == "gpt-4o-mini"
    assert r["prompt_tokens"] == 11
    assert r["completion_tokens"] == 22
    assert r["total_tokens"] == 33
    # unpriced model: cost is absent from the record, never invented
    assert r["cost_usd"] is None


def test_chat_with_usage_returns_this_calls_records(cfg, monkeypatch):
    monkeypatch.setattr(
        "litellm.completion", _fake_completion("hello", [(11, 22, 33)]))
    text, records = llm.chat_with_usage(
        cfg, [{"role": "user", "content": "hi"}], "gpt-4o-mini")
    assert text == "hello"
    assert [r["total_tokens"] for r in records] == [33]
    assert len(llm.usage_log()) == 1


def test_chat_with_usage_is_empty_when_the_call_fails(cfg, monkeypatch):
    def broken_completion(**kwargs):
        raise RuntimeError("provider down")

    monkeypatch.setattr("litellm.completion", broken_completion)
    with pytest.raises(LlmUnavailable):
        llm.chat_with_usage(
            cfg, [{"role": "user", "content": "hi"}], "gpt-4o-mini")
    assert llm.usage_log() == []


def test_a_response_without_a_usage_object_records_nothing(
        cfg, monkeypatch, _no_pricing):
    def no_usage_completion(**kwargs):
        return SimpleNamespace(
            model="gpt-4o-mini",
            choices=[SimpleNamespace(
                message=SimpleNamespace(content="hello"))],
            usage=None,
        )

    monkeypatch.setattr("litellm.completion", no_usage_completion)
    assert llm.chat(cfg, [{"role": "user", "content": "hi"}], "gpt-4o-mini") == "hello"
    assert llm.usage_log() == []


def test_usage_log_is_bounded():
    for i in range(llm._USAGE_LOG_LIMIT + 10):
        llm._append_usage_record({"total_tokens": i})
    log = llm.usage_log()
    assert len(log) == llm._USAGE_LOG_LIMIT
    # the OLDEST records are the ones dropped
    assert log[0]["total_tokens"] == 10
    assert log[-1]["total_tokens"] == llm._USAGE_LOG_LIMIT + 9


# --- the disable gate --------------------------------------------------------

def test_llm_disabled_parsing(monkeypatch):
    monkeypatch.delenv("KRYONSEC_DISABLE_LLM", raising=False)
    assert llm.llm_disabled() is False
    for on in ("1", "true", "TRUE", "yes"):
        monkeypatch.setenv("KRYONSEC_DISABLE_LLM", on)
        assert llm.llm_disabled() is True
    for off in ("0", "false", "no", ""):
        monkeypatch.setenv("KRYONSEC_DISABLE_LLM", off)
        assert llm.llm_disabled() is False


def test_the_gate_blocks_chat(cfg, monkeypatch):
    monkeypatch.setattr(
        "litellm.completion", _fake_completion("hello", [(11, 22, 33)]))
    monkeypatch.setenv("KRYONSEC_DISABLE_LLM", "1")
    with pytest.raises(LlmUnavailable, match="KRYONSEC_DISABLE_LLM"):
        llm.chat(cfg, [{"role": "user", "content": "hi"}], "gpt-4o-mini")
    assert llm.usage_log() == []


def test_the_gate_blocks_propose_and_generate(cfg, monkeypatch):
    monkeypatch.setattr(
        "litellm.completion", _fake_completion(HYP_REPLY, [(11, 22, 33)]))
    monkeypatch.setenv("KRYONSEC_DISABLE_LLM", "1")
    with pytest.raises(LlmUnavailable, match="KRYONSEC_DISABLE_LLM"):
        propose_hypotheses_with_model(cfg, "prompt text")
    with pytest.raises(LlmUnavailable, match="KRYONSEC_DISABLE_LLM"):
        generate_remediations(cfg, "prompt text")
    assert llm.usage_log() == []


# --- the LLM states accrue REAL usage and audit it --------------------------

def test_hypothesize_accrues_real_usage_and_audits_it(
        cfg, monkeypatch, tmp_path, _no_pricing):
    _no_instructor(monkeypatch)
    monkeypatch.setattr(
        "litellm.completion", _fake_completion(HYP_REPLY, [(11, 22, 33)]))
    audit = _audit(tmp_path)
    budget = BudgetTracker()

    sub = HypothesizeSubagent(cfg=cfg, graph=_graph(), audit=audit,
                              budget=budget)
    result = sub.run()

    assert result.status == "ok"
    # REAL provider-reported usage, and NOT counted as an estimate
    assert budget.used_tokens == 33
    assert budget.estimated_tokens == 0
    events = _events(audit, "llm_usage")
    assert len(events) == 1
    e = events[0]
    assert e["state"] == "HYPOTHESIZE"
    assert e["total_tokens"] == 33
    assert e["prompt_tokens"] == 11
    assert e["completion_tokens"] == 22
    assert "cost_usd" not in e  # unpriced: absent means unknown


def test_blue_team_accrues_real_usage_and_audits_it(
        cfg, monkeypatch, tmp_path, _no_pricing):
    _no_instructor(monkeypatch)
    monkeypatch.setattr(
        "litellm.completion", _fake_completion(REM_REPLY, [(7, 3, 10)]))
    audit = _audit(tmp_path)
    budget = BudgetTracker()

    sub = BlueTeamSubagent(cfg=cfg, graph=_graph(), audit=audit,
                           budget=budget)
    result = sub.run()

    assert result.status == "ok"
    assert budget.used_tokens == 10
    assert budget.estimated_tokens == 0
    events = _events(audit, "llm_usage")
    assert len(events) == 1
    assert events[0]["state"] == "BLUE_TEAM"
    assert events[0]["total_tokens"] == 10


def test_a_repair_retry_accrues_every_completed_call(
        cfg, monkeypatch, tmp_path, _no_pricing):
    """First reply is not valid JSON, the repair retry is — both calls are
    real spend and both are audited."""
    _no_instructor(monkeypatch)
    replies = iter(["not json at all", HYP_REPLY])

    def retry_completion(**kwargs):
        try:
            reply = next(replies)
        except StopIteration:  # a third call never happens
            reply = HYP_REPLY
        return SimpleNamespace(
            model="gpt-4o-mini",
            choices=[SimpleNamespace(message=SimpleNamespace(content=reply))],
            usage=SimpleNamespace(prompt_tokens=5, completion_tokens=5,
                                  total_tokens=10),
        )

    monkeypatch.setattr("litellm.completion", retry_completion)
    audit = _audit(tmp_path)
    budget = BudgetTracker()

    sub = HypothesizeSubagent(cfg=cfg, graph=_graph(), audit=audit,
                              budget=budget)
    assert sub.run().status == "ok"
    assert budget.used_tokens == 20  # both completed calls, summed
    assert budget.estimated_tokens == 0
    assert len(_events(audit, "llm_usage")) == 2


def test_estimate_fallback_when_the_provider_reports_nothing(
        cfg, monkeypatch, tmp_path, _no_pricing):
    """usage=None: the local token count takes over, visibly as an
    estimate (the pre-Phase-5 behaviour)."""
    _no_instructor(monkeypatch)

    def no_usage_completion(**kwargs):
        return SimpleNamespace(
            model="gpt-4o-mini",
            choices=[SimpleNamespace(
                message=SimpleNamespace(content=HYP_REPLY))],
            usage=None,
        )

    monkeypatch.setattr("litellm.completion", no_usage_completion)
    audit = _audit(tmp_path)
    budget = BudgetTracker(max_tokens=10)

    sub = HypothesizeSubagent(cfg=cfg, graph=_graph(), audit=audit,
                              budget=budget)
    assert sub.run().status == "ok"
    assert budget.used_tokens > 0
    assert budget.estimated_tokens == budget.used_tokens
    assert budget.exhausted()  # the tiny cap is enforced by the estimate
    assert _events(audit, "llm_usage") == []


def test_failed_state_still_accrues_the_attempts_real_usage(
        cfg, monkeypatch, tmp_path, _no_pricing):
    """The model answered twice with garbage (validation failed): the
    state fails audited, and the tokens it actually spent are accrued
    REAL — a failed state is not a free one."""
    _no_instructor(monkeypatch)
    monkeypatch.setattr(
        "litellm.completion", _fake_completion("still not json", [(9, 1, 10)]))
    audit = _audit(tmp_path)
    budget = BudgetTracker()

    sub = HypothesizeSubagent(cfg=cfg, graph=_graph(), audit=audit,
                              budget=budget)
    result = sub.run()

    assert result.status == "failed"
    assert _events(audit, "hypothesize_failed")  # audited reason
    assert budget.used_tokens == 20  # two completed calls, summed
    assert budget.estimated_tokens == 0
    assert len(_events(audit, "llm_usage")) == 2


# --- the baseline path: the gate makes the states fail AUDITED --------------

def test_the_gate_makes_hypothesize_fail_audited(
        cfg, monkeypatch, tmp_path):
    monkeypatch.setenv("KRYONSEC_DISABLE_LLM", "1")
    audit = _audit(tmp_path)
    budget = BudgetTracker()

    sub = HypothesizeSubagent(cfg=cfg, graph=_graph(), audit=audit,
                              budget=budget)
    result = sub.run()

    assert result.status == "failed"
    failed = _events(audit, "hypothesize_failed")
    assert failed and "KRYONSEC_DISABLE_LLM" in failed[0]["error"]
    assert _events(audit, "llm_usage") == []
    assert budget.used_tokens == 0  # zero LLM calls, zero spend
    assert not _events(audit, "hypothesis_proposed")  # nothing was proposed


def test_the_gate_makes_blue_team_fail_audited(cfg, monkeypatch, tmp_path):
    monkeypatch.setenv("KRYONSEC_DISABLE_LLM", "1")
    audit = _audit(tmp_path)
    budget = BudgetTracker()

    sub = BlueTeamSubagent(cfg=cfg, graph=_graph(), audit=audit,
                           budget=budget)
    result = sub.run()

    assert result.status == "failed"
    failed = _events(audit, "blue_team_failed")
    assert failed and "KRYONSEC_DISABLE_LLM" in failed[0]["error"]
    assert _events(audit, "llm_usage") == []
    assert budget.used_tokens == 0


def test_injected_llm_fn_still_works_with_the_new_drain(
        tmp_path):
    """llm_fn-injected states (tests, replay) accrue the local estimate
    exactly as before — no usage records exist to drain."""
    audit = _audit(tmp_path)
    budget = BudgetTracker(max_tokens=10)

    sub = HypothesizeSubagent(
        cfg=KryonsecConfig(home=tmp_path), graph=_graph(), audit=audit,
        llm_fn=lambda prompt: HypothesisSet(hypotheses=[
            Hypothesis(id="H1", title="t", target_asset="a",
                       rationale="r")]),
        budget=budget)
    assert sub.run().status == "ok"
    assert budget.used_tokens > 0
    assert budget.estimated_tokens == budget.used_tokens
    assert _events(audit, "llm_usage") == []


def test_remediation_set_shape_is_what_the_gate_sees():
    """Sanity on the JSON-path reply used above: it validates against the
    real schema, so the blue-team end-to-end tests exercise the real path."""
    import json

    assert isinstance(RemediationSet.model_validate(
        json.loads(REM_REPLY)), RemediationSet)
