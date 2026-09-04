"""Tests for the engagement runner (spec §4): two-tier gating.

On non-sandbox systems the engagement runs INIT + RECON_PASSIVE, then HALTs
at the first Zone B state with an audited reason — never runs un-sandboxed.
"""

from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.zonea import PassiveResult
from kryonsec.purple.runner import sandbox_available, start_engagement


def _fake_recon(domain):
    return PassiveResult(source="crt.sh", subdomains=["www." + domain])


@pytest.mark.parametrize(
    "runtimes,image_present,expected_reason",
    [
        (None, False, "docker CLI not found or daemon unreachable"),  # daemon down
        ("io.containerd.runc.v2,runc", False, "runsc"),  # no gVisor
        ("io.containerd.runc.v2,runc,runsc", False, "sandbox image not found"),  # no image
    ],
)
def test_sandbox_available_failure_paths(runtimes, image_present, expected_reason):
    with patch("kryonsec.purple.runner.platform.system", return_value="Linux"):
        with patch("kryonsec.purple.runner._docker_runtimes", return_value=runtimes):
            with patch("kryonsec.purple.runner._image_present", return_value=image_present):
                ok, reason = sandbox_available()
    assert not ok
    assert expected_reason in reason


def test_sandbox_available_ok_when_image_present():
    with patch("kryonsec.purple.runner.platform.system", return_value="Linux"):
        with patch(
            "kryonsec.purple.runner._docker_runtimes",
            return_value="io.containerd.runc.v2,runc,runsc",
        ):
            with patch("kryonsec.purple.runner._image_present", return_value=True):
                ok, reason = sandbox_available()
    assert ok, reason
    assert reason == "ok"


def test_sandbox_available_non_linux():
    with patch("kryonsec.purple.runner.platform.system", return_value="Windows"):
        ok, reason = sandbox_available()
    assert not ok
    assert "requires Linux" in reason


def test_engagement_halts_after_recon_without_sandbox(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    with patch("kryonsec.purple.runner.sandbox_available", return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.crt_sh_subdomains", side_effect=_fake_recon):
            orch, audit, graph = start_engagement(cfg, "e-run", target="target-corp.com")
            completed = orch.run()

    # INIT + RECON_PASSIVE ran; RECON_ACTIVE was blocked -> HALT
    assert completed[:3] == ["INIT", "RECON_PASSIVE", "RECON_ACTIVE"]
    assert orch.state == "HALT"
    assert "not Linux" in (orch.halt_reason or "")
    # Zone A results are present despite the halt
    assert [n["label"] for n in graph.by_type("subdomain")] == ["www.target-corp.com"]
    # the halt is audited
    import json
    with open(audit.path, encoding="utf-8") as f:
        events = [json.loads(line)["event"] for line in f if line.strip()]
    assert "zone_b_blocked" in events
    ok, reason = audit.verify()
    assert ok, reason


def test_engagement_runs_with_sandbox(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    with patch("kryonsec.purple.runner.sandbox_available", return_value=(True, "ok")):
        with patch("kryonsec.purple.recon_passive.crt_sh_subdomains", side_effect=_fake_recon):
            orch, audit, graph = start_engagement(cfg, "e-run2", target="target-corp.com")
            completed = orch.run()

    # Full loop: stubs report 'failed' but the state machine still walks on
    assert orch.state == "HALT"
    assert completed[0] == "INIT"
    assert "RECON_PASSIVE" in completed
    ok, reason = audit.verify()
    assert ok, reason


def test_full_loop_through_exploit(tmp_path):
    """Recon -> hypotheses -> approve H1 -> EXPLOIT spawns the tool ->
    report truthfully says testing happened."""
    from kryonsec.purple.hypothesize import Hypothesis, HypothesisSet

    cfg = KryonsecConfig(home=tmp_path)

    def fake_llm(prompt):
        assert "target-corp.com" in prompt
        return HypothesisSet(hypotheses=[
            Hypothesis(
                id="H1", title="SQLi on login", target_asset="/Login.asp",
                rationale="login form", cvss_vector="",
                tools=["sqlmap"], confidence=0.8,
            ),
        ])

    def approve_all(hypotheses):
        return {h["label"] for h in hypotheses}

    class FakeProc:
        returncode = 0
        stdout = ('{"exit_code": 0, "stdout": '
                  '"target is vulnerable to boolean-based blind"}')
        stderr = ""

    class FakeRun:
        def __init__(self):
            self.argv = None

        def __call__(self, argv, **kw):
            self.argv = argv
            return FakeProc()

    fake_run = FakeRun()

    # Inject fakes for the subagents the loop wires up. Direct monkeypatching
    # (not patch contexts) because each __init__ wraps the real one.
    import kryonsec.purple.hypothesize as hyp_mod
    import kryonsec.purple.human_review as hr_mod
    import kryonsec.purple.sandbox as sb_mod

    orig_hyp_init = hyp_mod.HypothesizeSubagent.__init__
    orig_hr_init = hr_mod.HumanReviewSubagent.__init__
    orig_sb_init = sb_mod.KaliSandbox.__init__

    def _init_hyp(self, cfg, graph, audit, llm_fn=None):
        orig_hyp_init(self, cfg, graph, audit, llm_fn=fake_llm)

    def _init_hr(self, graph, audit, reviewer=None):
        orig_hr_init(self, graph, audit, reviewer=approve_all)

    def _init_sb(self, cfg, **kw):
        self.cfg = cfg
        self.image = cfg.sandbox_image
        self.seccomp_profile = None
        self.timeout_s = 330
        self._run = fake_run

    hyp_mod.HypothesizeSubagent.__init__ = _init_hyp
    hr_mod.HumanReviewSubagent.__init__ = _init_hr
    sb_mod.KaliSandbox.__init__ = _init_sb
    try:
        with patch("kryonsec.purple.runner.sandbox_available", return_value=(True, "ok")):
            with patch("kryonsec.purple.recon_passive.crt_sh_subdomains", side_effect=_fake_recon):
                orch, audit, graph = start_engagement(
                    cfg, "e-x", target="target-corp.com")
                completed = orch.run()
    finally:
        hyp_mod.HypothesizeSubagent.__init__ = orig_hyp_init
        hr_mod.HumanReviewSubagent.__init__ = orig_hr_init
        sb_mod.KaliSandbox.__init__ = orig_sb_init

    assert "EXPLOIT" in completed
    assert fake_run.argv is not None
    assert fake_run.argv[0] == "docker"
    assert "sqlmap" in fake_run.argv

    attempts = graph.by_type("exploit_attempt")
    assert len(attempts) == 1
    assert attempts[0]["properties"]["confirmed"] is True
    assert len(graph.by_type("finding")) == 1

    report_path = cfg.home / "engagements" / "e-x" / "report.md"
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "Tools were run against the target" in content
    assert "No testing was done" not in content
    assert "H1:sqlmap" in content
    ok, reason = audit.verify()
    assert ok, reason
