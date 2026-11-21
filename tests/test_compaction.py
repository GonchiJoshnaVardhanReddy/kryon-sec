"""Tests for compaction behavior (spec §3.4, §6.4) using a mocked LLM."""

from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.session import GeneralSession
from kryonsec.llm import compaction_model_for


@pytest.fixture()
def cfg():
    return KryonsecConfig(max_session_tokens=100, compaction_trigger_ratio=0.8)


def _fill(session, n=20):
    for i in range(n):
        session.add("user", f"message number {i} about CVE-2020-{1000 + i}")


def test_compaction_triggers_and_summarizes(cfg):
    session = GeneralSession(cfg=cfg)
    _fill(session)

    captured = {}

    def fake_chat(cfg, messages, model, **kw):
        captured["model"] = model
        captured["content"] = messages[-1]["content"]
        return "SUMMARY: user discussed CVE-2020-1000 and more"

    with patch("kryonsec.copilot.session.chat", side_effect=fake_chat):
        import asyncio
        asyncio.run(session.maybe_compact())

    assert len(session.messages) < 20
    assert session.messages[0].content.startswith("[SESSION CHECKPOINT]")
    assert "SUMMARY" in session.messages[0].content


def test_compaction_redacts_secrets_before_llm(cfg):
    session = GeneralSession(cfg=cfg)
    session.add("user", "my password: supersecret99 " + "filler " * 50)
    session.add("user", "more filler " * 50)

    captured = {}

    def fake_chat(cfg, messages, model, **kw):
        captured["content"] = messages[-1]["content"]
        return "SUMMARY: placeholder «SECRET_1» preserved"

    with patch("kryonsec.copilot.session.chat", side_effect=fake_chat):
        import asyncio
        asyncio.run(session.maybe_compact())

    # the secret never reached the LLM
    assert "supersecret99" not in captured["content"]
    assert "«SECRET_1»" in captured["content"]
    # ...but the restored checkpoint keeps the real value for future turns
    assert "supersecret99" in session.messages[0].content


def test_compaction_model_for_secrets(cfg):
    assert compaction_model_for(cfg, secrets_present=True) == cfg.local_model
    assert compaction_model_for(cfg, secrets_present=False) == cfg.compaction_model


def test_no_compaction_below_threshold(cfg):
    session = GeneralSession(cfg=cfg)
    session.add("user", "short message")
    import asyncio
    asyncio.run(session.maybe_compact())
    assert len(session.messages) == 1


def test_message_cap_recounts_the_estimate():
    """The hard message cap drops messages; the token estimate must be
    recomputed from what remains — a stale-high estimate (counted before
    the drop) could trigger compaction on a session that no longer holds
    that many tokens."""
    from kryonsec.llm import count_tokens

    cfg = KryonsecConfig(max_messages=3, max_session_tokens=10_000)
    session = GeneralSession(cfg=cfg)
    for i in range(6):
        session.add("user", f"m{i} " + "x" * 400)
    assert len(session.messages) == 3
    expected = count_tokens("\n".join(m.content for m in session.messages))
    assert session.token_estimate == expected
