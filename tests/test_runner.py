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
        with patch("kryonsec.purple.runtime_checks.docker_runtimes", return_value=runtimes):
            with patch("kryonsec.purple.runtime_checks.image_present", return_value=image_present):
                ok, reason = sandbox_available()
    assert not ok
    assert expected_reason in reason


def test_sandbox_available_ok_when_image_present():
    with patch("kryonsec.purple.runner.platform.system", return_value="Linux"):
        with patch(
            "kryonsec.purple.runtime_checks.docker_runtimes",
            return_value="io.containerd.runc.v2,runc,runsc",
        ):
            with patch("kryonsec.purple.runtime_checks.image_present", return_value=True):
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
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers", return_value=[_fake_recon]):
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
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers", return_value=[_fake_recon]):
            orch, audit, graph = start_engagement(cfg, "e-run2", target="target-corp.com")
            completed = orch.run()

    # Full loop: stubs report 'failed' but the state machine still walks on
    assert orch.state == "HALT"
    assert completed[0] == "INIT"
    assert "RECON_PASSIVE" in completed
    ok, reason = audit.verify()
    assert ok, reason


def test_engagement_status_factory_wraps_states(tmp_path):
    """The CLI passes status_factory: every non-interactive state runs
    inside it (spinner context), HUMAN_REVIEW never does."""
    from unittest.mock import patch

    cfg = KryonsecConfig(home=tmp_path)

    entered: list[str] = []
    released: list[str] = []

    class FakeCtx:
        def __init__(self, state):
            self.state = state

        def __enter__(self):
            entered.append(self.state)
            return self

        def __exit__(self, *exc):
            released.append(self.state)
            return False

    with patch("kryonsec.purple.runner.sandbox_available", return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers", return_value=[_fake_recon]):
            orch, audit, graph = start_engagement(
                cfg, "e-spin", target="target-corp.com",
                status_factory=FakeCtx,
            )
            orch.run()

    # loop states that actually ran, in order — no HUMAN_REVIEW
    assert "RECON_PASSIVE" in entered
    assert "HUMAN_REVIEW" not in entered
    assert "REPORT" not in entered  # halted before REPORT (no sandbox)
    assert entered == released      # every context was properly exited


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
            self.argvs = []

        def __call__(self, argv, **kw):
            self.argvs.append(argv)
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

    def _init_hyp(self, cfg, graph, audit, llm_fn=None, budget=None,
                  sandbox=None):
        # sandbox=None keeps the fake subagent offline (no searchsploit)
        orig_hyp_init(self, cfg, graph, audit, llm_fn=fake_llm, budget=budget,
                      sandbox=None)

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
            with patch("kryonsec.purple.recon_passive.zone_a_fetchers", return_value=[_fake_recon]):
                orch, audit, graph = start_engagement(
                    cfg, "e-x", target="target-corp.com")
                completed = orch.run()
    finally:
        hyp_mod.HypothesizeSubagent.__init__ = orig_hyp_init
        hr_mod.HumanReviewSubagent.__init__ = orig_hr_init
        sb_mod.KaliSandbox.__init__ = orig_sb_init

    assert "EXPLOIT" in completed
    assert fake_run.argvs  # sandbox spawns happened
    # EXPLOIT spawned sqlmap (VERIFY's probes may run after it, so check
    # every recorded argv, not just the last one)
    assert any("sqlmap" in argv for argv in fake_run.argvs)

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


# ---- code folder wiring (tool expansion Phase 5) --------------------------

def _audit_events(audit):
    import json
    with open(audit.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_engagement_code_folder_wiring(tmp_path):
    """--code folder: recorded in engagement_created, and only the
    BLUE_TEAM sandbox is built with the /code mount."""
    from kryonsec.purple.orchestrator import SubagentResult

    import kryonsec.purple.blue_team as bt_mod
    import kryonsec.purple.sandbox as sb_mod

    cfg = KryonsecConfig(home=tmp_path)
    code = tmp_path / "victim"
    code.mkdir()

    # (code_dir, evidence_dir) of every sandbox handed to a subagent —
    # the base construction AND every copy_with variant
    mounts: list = []
    bt_kwargs: dict = {}

    class FakeBlueTeam:
        def __init__(self, **kwargs):
            bt_kwargs.update(kwargs)

        def run(self):
            return SubagentResult(status="ok")

    class FakeProc:
        returncode = 0
        stdout = '{"exit_code": 0, "stdout": ""}'
        stderr = ""

    orig_sb_init = sb_mod.KaliSandbox.__init__
    orig_sb_copy = sb_mod.KaliSandbox.copy_with
    orig_bt = bt_mod.BlueTeamSubagent

    def _init_sb(self, cfg, code_dir=None, evidence_dir=None, **kw):
        orig_sb_init(self, cfg, code_dir=code_dir,
                     evidence_dir=evidence_dir, **kw)
        mounts.append((code_dir, evidence_dir))
        # every spawn "succeeds" with empty output — no docker needed
        self._run = lambda argv, **kw2: FakeProc()

    def _copy_sb(self, code_dir=None, evidence_dir=None):
        clone = orig_sb_copy(self, code_dir=code_dir, evidence_dir=evidence_dir)
        mounts.append((clone.code_dir, clone.evidence_dir))
        return clone

    bt_mod.BlueTeamSubagent = FakeBlueTeam
    sb_mod.KaliSandbox.__init__ = _init_sb
    sb_mod.KaliSandbox.copy_with = _copy_sb
    try:
        with patch("kryonsec.purple.runner.sandbox_available", return_value=(True, "ok")):
            with patch("kryonsec.purple.recon_passive.zone_a_fetchers", return_value=[_fake_recon]):
                orch, audit, graph = start_engagement(
                    cfg, "e-code", target="target-corp.com",
                    code_folder=str(code))
                completed = orch.run()
    finally:
        bt_mod.BlueTeamSubagent = orig_bt
        sb_mod.KaliSandbox.__init__ = orig_sb_init
        sb_mod.KaliSandbox.copy_with = orig_sb_copy

    assert "BLUE_TEAM" in completed
    # the subagent got the folder, and its sandbox got the /code mount
    assert bt_kwargs["code_folder"] == str(code)
    code_mounts = [cd for cd, _ in mounts if cd is not None]
    assert code_mounts == [str(code)]  # exactly one, and only blue team
    # the base sandbox (passive/hypothesize) is mount-free
    assert mounts[0] == (None, None)

    created = next(e for e in _audit_events(audit)
                   if e["event"] == "engagement_created")
    assert created["code_scan"] is True
    ok, reason = audit.verify()
    assert ok, reason


def test_engagement_without_code_folder_records_false(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    with patch("kryonsec.purple.runner.sandbox_available", return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers", return_value=[_fake_recon]):
            orch, audit, graph = start_engagement(cfg, "e-nc", target="target-corp.com")
            orch.run()

    created = next(e for e in _audit_events(audit)
                   if e["event"] == "engagement_created")
    assert created["code_scan"] is False


def test_run_purple_rejects_missing_code_folder(tmp_path):
    """A --code path that is not a folder is a hard error — never silently
    scan (or mount) the wrong thing."""
    from kryonsec.cli import _run_purple

    cfg = KryonsecConfig(home=tmp_path)
    rc = _run_purple(cfg, "target-corp.com",
                     code_folder=str(tmp_path / "does-not-exist"))
    assert rc == 2


@pytest.mark.parametrize("bad_id", [
    "../../../tmp/x",     # escapes cfg.home/engagements/
    "/etc",               # absolute — docker mount source
    "..",
    ".",
    "a/b",
    "a\\b",               # windows separator
    "..%2f..",
    "with space",
    "",                   # empty is falsy → auto-generated, but must not be ""-named
    "x" * 65,             # over the length bound
    "-leading-dash",
])
def test_run_purple_rejects_path_traversal_ids(tmp_path, bad_id):
    """--id is a path component and a docker bind-mount source.

    It was passed through unvalidated, so `--id ../../../tmp/x` wrote the
    audit chain, evidence and report outside the engagements tree, and
    `--id /etc` aimed the sandbox mount at the host's /etc.
    """
    from kryonsec.cli import _run_purple

    cfg = KryonsecConfig(home=tmp_path)
    rc = _run_purple(cfg, "target-corp.com", engagement_id=bad_id)
    assert rc == 2, f"{bad_id!r} should have been rejected"
    # and nothing was created outside/inside the tree for it
    assert not (tmp_path / "engagements").exists() or not any(
        (tmp_path / "engagements").iterdir()
    )


@pytest.mark.parametrize("good_id", [
    "e-1", "abc123", "Engagement_2026-09-18", "a.b", "x" * 64,
])
def test_run_purple_accepts_reasonable_ids(tmp_path, good_id):
    """The validation must not reject ordinary ids — it stops traversal, not
    naming choices. (These never reach the state machine: sandbox is absent,
    so the run stops after passive recon.)"""
    from kryonsec.cli import _run_purple

    cfg = KryonsecConfig(home=tmp_path)
    with patch("kryonsec.purple.runner.sandbox_available",
               return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.zone_a_fetchers",
                   return_value=[_fake_recon]):
            rc = _run_purple(cfg, "target-corp.com", engagement_id=good_id)
    assert rc == 0, f"{good_id!r} should have been accepted"
    assert (cfg.home / "engagements" / good_id).is_dir()


def test_engagement_evidence_dir_wiring(tmp_path):
    """Phase 8: every evidence-PRODUCING state (active recon, exploit,
    post-exploit, verify) builds its sandbox with the rw /evidence mount
    pointing into the engagement folder; passive/hypothesize sandboxes
    stay mount-free."""
    from kryonsec.purple.hypothesize import Hypothesis, HypothesisSet

    import kryonsec.purple.hypothesize as hyp_mod
    import kryonsec.purple.human_review as hr_mod
    import kryonsec.purple.sandbox as sb_mod

    cfg = KryonsecConfig(home=tmp_path)

    # (code_dir, evidence_dir) of every sandbox handed to a subagent
    mounts: list = []

    def fake_llm(prompt):
        return HypothesisSet(hypotheses=[
            Hypothesis(
                id="H1", title="SQLi on login", target_asset="/Login.asp",
                rationale="login form", cvss_vector="", tools=["sqlmap"],
                confidence=0.8,
            ),
        ])

    def approve_all(hypotheses):
        return {h["label"] for h in hypotheses}

    class FakeProc:
        returncode = 0
        stdout = '{"exit_code": 0, "stdout": "vulnerable"}'
        stderr = ""

    orig_hyp_init = hyp_mod.HypothesizeSubagent.__init__
    orig_hr_init = hr_mod.HumanReviewSubagent.__init__
    orig_sb_init = sb_mod.KaliSandbox.__init__
    orig_sb_copy = sb_mod.KaliSandbox.copy_with

    def _init_hyp(self, cfg, graph, audit, llm_fn=None, budget=None,
                  sandbox=None):
        orig_hyp_init(self, cfg, graph, audit, llm_fn=fake_llm, budget=budget,
                      sandbox=None)

    def _init_hr(self, graph, audit, reviewer=None):
        orig_hr_init(self, graph, audit, reviewer=approve_all)

    def _init_sb(self, cfg, code_dir=None, evidence_dir=None, **kw):
        orig_sb_init(self, cfg, code_dir=code_dir,
                     evidence_dir=evidence_dir, **kw)
        mounts.append((code_dir, evidence_dir))
        self._run = lambda argv, **kw2: FakeProc()

    def _copy_sb(self, code_dir=None, evidence_dir=None):
        clone = orig_sb_copy(self, code_dir=code_dir, evidence_dir=evidence_dir)
        mounts.append((clone.code_dir, clone.evidence_dir))
        return clone

    hyp_mod.HypothesizeSubagent.__init__ = _init_hyp
    hr_mod.HumanReviewSubagent.__init__ = _init_hr
    sb_mod.KaliSandbox.__init__ = _init_sb
    sb_mod.KaliSandbox.copy_with = _copy_sb
    try:
        with patch("kryonsec.purple.runner.sandbox_available", return_value=(True, "ok")):
            with patch("kryonsec.purple.recon_passive.zone_a_fetchers", return_value=[_fake_recon]):
                orch, audit, graph = start_engagement(
                    cfg, "e-ev", target="target-corp.com")
                completed = orch.run()
    finally:
        hyp_mod.HypothesizeSubagent.__init__ = orig_hyp_init
        hr_mod.HumanReviewSubagent.__init__ = orig_hr_init
        sb_mod.KaliSandbox.__init__ = orig_sb_init
        sb_mod.KaliSandbox.copy_with = orig_sb_copy

    assert "RECON_ACTIVE" in completed
    # POST_EXPLOIT is dormant (no tool yields a shell, so shell_obtained
    # never fires) — the three evidence-producing states that actually run
    # are active recon, exploit, verify. Passive/hypothesize get no mount.
    expected = str(cfg.home / "engagements" / "e-ev" / "evidence")
    producers = [ed for _, ed in mounts if ed is not None]
    assert producers == [expected] * 3
    assert mounts[0] == (None, None)  # the base sandbox needs no evidence mount
    # the folder was actually created on disk
    assert (cfg.home / "engagements" / "e-ev" / "evidence").is_dir()
    ok, reason = audit.verify()
    assert ok, reason
