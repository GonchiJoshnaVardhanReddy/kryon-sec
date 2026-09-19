"""Tests for the litellm preload (latency fix: `import litellm` takes
seconds and used to hit the user's first message)."""

import sys
import threading
import time

import kryonsec.llm as llm


def test_preload_starts_a_thread_when_litellm_not_imported():
    was_imported = "litellm" in sys.modules
    if was_imported:  # another test/import already loaded it — sentinel path
        t = llm.preload_litellm()
        assert t is llm._PRELOAD_DONE  # no second thread, no double import
        return
    t = llm.preload_litellm()
    assert t is not None
    assert t.daemon
    t.join(timeout=30)
    assert not t.is_alive()
    # the import actually happened (or failed and was logged — never raised)
    assert "litellm" in sys.modules


def test_preload_is_idempotent():
    t1 = llm.preload_litellm()
    t2 = llm.preload_litellm()
    if "litellm" in sys.modules:
        assert t1 is t2 is llm._PRELOAD_DONE
    else:
        t1.join(timeout=30)
        assert llm.preload_litellm() is llm._PRELOAD_DONE


def test_preload_never_raises():
    # a broken litellm install must not crash the CLI at startup —
    # the lazy import later surfaces the real error with a traceback
    original = sys.modules.pop("litellm", None)
    try:
        t = llm.preload_litellm()
        if t is not llm._PRELOAD_DONE:
            t.join(timeout=30)
    finally:
        if original is not None:
            sys.modules["litellm"] = original


def test_quiet_litellm_lets_litellm_drop_unsupported_params(monkeypatch):
    """The fix for a hard 400 that arrives before any call is made.

    kryonsec asks for temperature=0.0 (deterministic answers), but a growing
    set of models are pinned at temperature=1 and reject anything else —
    litellm raises UnsupportedParamsError itself, from its own model map.
    `global.anthropic.claude-fable-5` on Bedrock did this, and the user saw
    it as "no AWS Bedrock model answered".
    """
    import litellm

    monkeypatch.setattr(litellm, "drop_params", False, raising=False)
    llm._quiet_litellm()
    assert litellm.drop_params is True


def test_quiet_litellm_still_silences_the_banner(monkeypatch):
    import litellm

    monkeypatch.setattr(litellm, "suppress_debug_info", False, raising=False)
    llm._quiet_litellm()
    assert litellm.suppress_debug_info is True


def test_quiet_litellm_never_raises():
    assert llm._quiet_litellm() is None
