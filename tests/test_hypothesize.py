"""Tests for the HYPOTHESIZE subagent (spec §4.2).

The LLM is injected — these tests verify the deterministic parts: prompt
rendering, schema validation, graph/audit writes, failure handling.
"""

import json

import pytest
from pydantic import ValidationError

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.hypothesize import (
    Hypothesis,
    HypothesisSet,
    HypothesizeSubagent,
    _extract_json,
    propose_hypotheses,
    render_hypothesize_prompt,
)
from kryonsec.purple.recon_passive import EngagementGraph


def _graph_with_findings():
    graph = EngagementGraph(engagement_id="e-h")
    graph.add_node("target", "testcorp.example", {"source": "engagement_config"})
    graph.add_node("subdomain", "www.testcorp.example", {"source": "crt.sh"})
    graph.add_node("subdomain", "api.testcorp.example", {"source": "crt.sh"})
    return graph


def _good_llm(prompt):
    assert "testcorp.example" in prompt  # recon findings are in the prompt
    return HypothesisSet(hypotheses=[
        Hypothesis(
            id="H1",
            title="Outdated framework on www host",
            target_asset="www.testcorp.example",
            rationale="Name suggests legacy stack",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            tools=["nmap", "nikto"],
            confidence=0.7,
        ),
    ])


# --- prompt rendering ---

def test_prompt_contains_findings():
    prompt = render_hypothesize_prompt(_graph_with_findings())
    assert "testcorp.example" in prompt
    assert "www.testcorp.example" in prompt
    assert "api.testcorp.example" in prompt
    assert "never" in prompt.lower() or "claim" in prompt.lower()
    # the tool allowlist is in the prompt
    assert "sqlmap" in prompt


def test_prompt_empty_graph():
    graph = EngagementGraph(engagement_id="e-h2")
    prompt = render_hypothesize_prompt(graph)
    assert "(none found)" in prompt


# --- schema ---

def test_hypothesis_set_caps_at_10():
    hyps = [Hypothesis(id=f"H{i}", title="t", target_asset="a", rationale="r")
            for i in range(11)]
    with pytest.raises(ValidationError):
        HypothesisSet(hypotheses=hyps)


def test_confidence_bounds():
    with pytest.raises(ValidationError):
        Hypothesis(id="H1", title="t", target_asset="a", rationale="r", confidence=1.5)


# --- JSON extraction (the no-instructor fallback) ---

def test_extract_json_plain():
    assert _extract_json('{"hypotheses": []}') == {"hypotheses": []}


def test_extract_json_fenced():
    text = 'Here you go:\n```json\n{"hypotheses": [{"id": "H1"}]}\n```\nbye'
    assert _extract_json(text)["hypotheses"][0]["id"] == "H1"


def test_extract_json_surrounding_text():
    text = 'Sure! {"hypotheses": []} hope that helps'
    assert _extract_json(text) == {"hypotheses": []}


def test_extract_json_garbage_raises():
    with pytest.raises(ValueError):
        _extract_json("no json here at all")


# --- subagent behavior ---

def test_hypothesize_success_writes_graph_and_audit(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_findings()

    sub = HypothesizeSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=_good_llm)
    result = sub.run()

    assert result.status == "ok"
    nodes = graph.by_type("hypothesis")
    assert [n["label"] for n in nodes] == ["H1"]
    assert nodes[0]["properties"]["tools"] == ["nmap", "nikto"]

    events = [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "state_enter" in events
    assert "hypothesis_proposed" in events
    assert "hypothesize_done" in events
    ok, reason = audit.verify()
    assert ok, reason


def test_hypothesize_llm_failure_is_failed_not_halt(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_findings()

    def dead_llm(prompt):
        raise RuntimeError("no provider available")

    sub = HypothesizeSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=dead_llm)
    result = sub.run()

    # LLM down => 'failed' (state machine walks on), never a silent halt
    assert result.status == "failed"
    events = [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "hypothesize_failed" in events
    assert graph.by_type("hypothesis") == []


def test_hypothesize_empty_set_ok(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph_with_findings()

    sub = HypothesizeSubagent(
        cfg=cfg, graph=graph, audit=audit, llm_fn=lambda p: HypothesisSet()
    )
    result = sub.run()
    assert result.status == "ok"
    assert graph.by_type("hypothesis") == []


# --- propose_hypotheses JSON path (llm.chat injected via monkeypatch) ---

def test_propose_hypotheses_json_fallback(monkeypatch, tmp_path):
    import sys

    cfg = KryonsecConfig(home=tmp_path)
    reply = '{"hypotheses": [{"id": "H1", "title": "t", "target_asset": "a", "rationale": "r"}]}'

    # force the JSON path: make "import instructor" raise ImportError
    monkeypatch.setitem(sys.modules, "instructor", None)
    import builtins

    real_import = builtins.__import__

    def no_instructor(name, *args, **kwargs):
        if name == "instructor":
            raise ImportError("forced for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_instructor)
    monkeypatch.setattr(
        "kryonsec.llm.chat", lambda cfg, messages, model, **kw: reply
    )

    result = propose_hypotheses(cfg, "prompt text")
    assert result.hypotheses[0].id == "H1"


def test_propose_hypotheses_json_repair_retry(monkeypatch, tmp_path):
    import sys

    cfg = KryonsecConfig(home=tmp_path)
    replies = iter([
        "oops not json",  # first attempt: invalid
        '{"hypotheses": [{"id": "H2", "title": "t", "target_asset": "a", "rationale": "r"}]}',  # retry
    ])

    monkeypatch.setitem(sys.modules, "instructor", None)
    import builtins

    real_import = builtins.__import__

    def no_instructor(name, *args, **kwargs):
        if name == "instructor":
            raise ImportError("forced for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_instructor)
    monkeypatch.setattr(
        "kryonsec.llm.chat", lambda cfg, messages, model, **kw: next(replies)
    )

    result = propose_hypotheses(cfg, "prompt text")
    assert result.hypotheses[0].id == "H2"
