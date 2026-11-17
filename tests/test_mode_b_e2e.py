"""Phase 2C.1 — Mode B end-to-end scenario suite, OFFLINE tier.

Drives the REAL engine — the real orchestrator loop inside
``start_engagement``, the real subagents for every state, the real
KaliSandbox argv composition and its fail-closed invariants, the real
audit chain, the real graph persistence and the real report builder —
through complete engagements, one test per Phase 2C.1 scenario (A–H).

What is a fixture here, and what that means:

- ``run_fn``: the container launch goes through the sandbox's injectable
  docker-CLI seam (``KaliSandbox._run``), bound to the deterministic
  :class:`LabRunner`. Tool outputs it emits are FIXTURES: findings derived
  from them prove the engine's derivation/mechanism (confirmation markers,
  outcome words, verification mechanics) — NOT that a real tool confirmed
  a real vulnerability. Only the real-container tier
  (``test_mode_b_e2e_lab_it.py``, ``KRYONSEC_MODE_B_E2E=1``) may claim
  "a real runsc container executed".
- HYPOTHESIZE / BLUE_TEAM consultants: deterministic in-process objects
  injected at the subagents' declared ``llm_fn`` seams. Zone-A fetchers
  are an empty fixture and enrichment is stubbed, so NO network call —
  target or third-party — leaves the host in this suite.
- Gate 2 / Gate 3 decisions: scripted callables at the same choke points
  the UI and terminal paths use (scenario H drives the real controller
  ``ApprovalGate`` cross-thread handoff).

The sandbox-adversarial paths this tier exercises through REAL code: the
fail-closed Zone-B halt when the sandbox is unavailable (Scenario D), the
per-tool scope refusal (Scenario C), the timeout/kill path (Scenario E),
conservative confirmation and independent verification (Scenario F), and
the audit chain invariants throughout.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.blue_team import Remediation, RemediationSet
from kryonsec.purple.hypothesize import Hypothesis, HypothesisSet
from kryonsec.purple.runner import (
    persist_graph,
    record_engagement_ending,
    start_engagement,
)

# Digest-pinned FAKE image: the same shape production composes into every
# docker argv (and the mutable-tag warning stays silent).
LAB_IMAGE = "kryonsec-lab/sandbox@sha256:" + "f" * 64
# TEST-NET-3: never routed on the public internet. Matches the conftest
# egress fixture's allowed network, so the (fake) boundary accepts it.
LAB_TARGET = "203.0.113.7"

# Deterministic lab pages. The verifier's boolean probe needs the TRUE and
# baseline responses to be identical and the FALSE one to differ.
PAGE_TRUE = "LAB-FIXTURE-PAGE-A: deterministic lab page for id=7 (fixture body)"
PAGE_FALSE = "LAB-FIXTURE-PAGE-B: false branch, 0 rows (fixture body)"
# sqlmap confirmation fixture: contains the engine's real markers
# ("is vulnerable", "back-end dbms") — derives a finding via the REAL
# marker logic, from fixture bytes.
SQLMAP_CONFIRMED = (
    "Parameter 'id' is vulnerable. back-end dbms: SQLite "
    "(deterministic fixture output — no real tool ran)")
# A claim from a tool the engine NEVER lets confirm (nikto is in
# _NEVER_CONFIRMS): "is vulnerable" must stay unconfirmed.
NIKTO_UNTRUSTED_CLAIM = (
    "is vulnerable, uncheck this — deterministic fixture claiming more "
    "than nikto is ever allowed to confirm")
# A secret planted in tool output: the chain, graph and report must all
# carry the redaction, never the key (real detector, real redaction).
# Built by concatenation so the repo source itself never contains an
# AWS-key-shaped literal (nothing to find — it is not a real key).
PLANTED_SECRET = "AKIA" + "IOSFODNN7EXAMPLE"

ISOLATION_FLAGS = ("--runtime", "runsc", "--user", "kryonsec-runner",
                   "--read-only")


# ------------------------------------------------------------ lab harness


class LabRunner:
    """Deterministic docker-CLI bridge bound to ``KaliSandbox._run``.

    Records every docker argv the REAL sandbox composition produces and
    routes by tool name (first argv element after the image). Scripted
    payloads are the tool's stdout; ``(timeout,)`` raises a real
    ``subprocess.TimeoutExpired`` so the sandbox's kill path runs; an int
    is an exit code with empty stdout. Tool docker-management calls
    (container kill) carry no image and return success.
    """

    def __init__(self) -> None:
        self.docker_argv: list[list[str]] = []
        self.executed: list[str] = []
        self.tool_argvs: dict[str, list[list[str]]] = {}
        self.scripts: dict[str, list] = {}
        self.same_curl = False  # True -> verifier's boolean probe can't tell

    def script(self, tool: str, *payloads: object) -> "LabRunner":
        self.scripts[tool] = list(payloads)
        return self

    def spawns(self, tool: str) -> list[list[str]]:
        return self.tool_argvs.get(tool, [])

    def __call__(self, argv: list[str], **kwargs):
        self.docker_argv.append(argv)
        assert argv[:1] == ["docker"], (
            f"non-docker process reached the lab bridge: {argv[:3]}")
        if LAB_IMAGE not in argv:  # docker management (rm/kill), not a spawn
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        tool_argv = argv[argv.index(LAB_IMAGE) + 1:]
        tool = tool_argv[0] if tool_argv else ""
        self.executed.append(tool)
        self.tool_argvs.setdefault(tool, []).append(tool_argv)

        payload = self.scripts.get(tool) or []
        if payload and payload[0] == ("timeout",):
            raise subprocess.TimeoutExpired(cmd="docker", timeout=330)
        if payload and isinstance(payload[0], int):
            body, exit_code = "", int(payload[0])
        elif payload:
            body, exit_code = str(payload[0]), 0
        else:
            body, exit_code = "", 0

        if tool == "curl" and tool not in self.scripts:
            blob = " ".join(tool_argv)
            hit_false = "1%3D2" in blob or "1=2" in blob
            body = PAGE_FALSE if (hit_false and not self.same_curl) else PAGE_TRUE

        stdout = json.dumps({"exit_code": exit_code, "stdout": body})
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")


# Original __init__s, captured ONCE: installing a second wrapper inside
# one test must not chain wrappers (a chained consultant init would let
# an earlier run's payload win — exactly the bug this avoids).
_ORIGINAL_INITS: dict[type, object] = {}


def _original_init(cls) -> object:
    if cls not in _ORIGINAL_INITS:
        _ORIGINAL_INITS[cls] = cls.__init__
    return _ORIGINAL_INITS[cls]


def _wire_lab_sandbox(monkeypatch, runner: LabRunner) -> None:
    """Build a REAL KaliSandbox, then bind the lab bridge as its ``_run``.

    ``copy_with`` clones ``__dict__``, so per-state variants (evidence dir,
    code mount) keep the lab bridge; the argv each spawn records is exactly
    what the real composition produced.
    """
    import kryonsec.purple.sandbox as sandbox_mod

    real_init = _original_init(sandbox_mod.KaliSandbox)

    def lab_init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        self._run = runner

    monkeypatch.setattr(sandbox_mod.KaliSandbox, "__init__", lab_init)


def _consultant_init(real_cls, payload):
    """Deterministic consultant at the subagent's declared ``llm_fn`` seam."""
    real_init = _original_init(real_cls)

    def init(self, *args, **kwargs):
        kwargs.pop("llm_fn", None)
        real_init(self, *args, llm_fn=lambda _prompt: payload, **kwargs)

    return init


def _patch_engine(monkeypatch, runner: LabRunner, *, sandbox_ok=True,
                  sandbox_reason="ok", hypotheses=None, remediations=None):
    """Fixture seams, all at their defining modules (the runner's loader
    imports the subagent classes inside its function body)."""
    import kryonsec.purple.enrichment as enrichment
    import kryonsec.purple.recon_passive as recon_passive
    import kryonsec.purple.runner as runner_mod

    monkeypatch.setattr(
        runner_mod, "sandbox_available",
        lambda image=None: (sandbox_ok, sandbox_reason))
    # Zero third-party egress: no Zone-A sources at all, and enrichment
    # (NVD/KEV/EPSS — host-side HTTP) stubbed out. Their real behaviour is
    # the subject of test_zonea/test_enrichment suites.
    monkeypatch.setattr(recon_passive, "zone_a_fetchers", lambda cfg: [])
    monkeypatch.setattr(enrichment, "enrich_hypotheses", lambda *a, **k: None)
    _wire_lab_sandbox(monkeypatch, runner)
    if hypotheses is not None:
        from kryonsec.purple import hypothesize

        monkeypatch.setattr(
            hypothesize.HypothesizeSubagent, "__init__",
            _consultant_init(hypothesize.HypothesizeSubagent, hypotheses))
    if remediations is not None:
        from kryonsec.purple import blue_team

        monkeypatch.setattr(
            blue_team.BlueTeamSubagent, "__init__",
            _consultant_init(blue_team.BlueTeamSubagent, remediations))


def _cfg(tmp_path: Path) -> KryonsecConfig:
    cfg = KryonsecConfig(home=tmp_path)
    cfg.database_url = f"sqlite:///{tmp_path / 'purple.db'}"
    cfg.sandbox_image = LAB_IMAGE
    return cfg


def _sqli_hypotheses(asset="/product?id=7",
                     tools=("sqlmap", "curl")) -> HypothesisSet:
    return HypothesisSet(hypotheses=[Hypothesis(
        id="H1", title="numeric id boolean SQLi",
        target_asset=asset,
        rationale="deterministic lab fixture: the page echoes a numeric id",
        tools=list(tools), confidence=0.6,
    )])


def _out_of_scope_hypotheses() -> HypothesisSet:
    # An absolute URL on a host that is NOT the engagement target: exactly
    # the shape a compromised/hallucinating model might propose.
    return HypothesisSet(hypotheses=[Hypothesis(
        id="H9", title="metadata service SSRF",
        target_asset="http://169.254.169.254/latest/meta-data/",
        rationale="deterministic fixture: hostile out-of-scope proposal",
        tools=["curl"], confidence=0.9,
    )])


def _remediation_set() -> RemediationSet:
    return RemediationSet(remediations=[Remediation(
        hypothesis_id="H1", title="parameterize the numeric query",
        fix="use bound parameters instead of string interpolation",
        detection="boolean-difference alerts on the id parameter",
        severity="high",
    )])


def _read_chain(home: Path, engagement_id: str) -> list[dict]:
    path = home / "engagements" / engagement_id / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_engagement(tmp_path, monkeypatch, *, engagement_id="e2e",
                   target=LAB_TARGET, scripts=None, reviewer=None,
                   post_exploit_approver=None, sandbox_ok=True,
                   sandbox_reason="ok", same_curl=False,
                   hypotheses=None, remediations=None):
    """Run one REAL engagement start-to-HALT with the lab fixtures.

    Mirrors the CLI boundary: start_engagement -> orch.run() ->
    persist_graph -> record_engagement_ending. Returns the artifacts.
    """
    runner = LabRunner()
    runner.same_curl = same_curl
    for tool, payloads in (scripts or {}).items():
        runner.script(tool, *payloads)
    _patch_engine(
        monkeypatch, runner, sandbox_ok=sandbox_ok,
        sandbox_reason=sandbox_reason,
        hypotheses=_sqli_hypotheses() if hypotheses is None else hypotheses,
        remediations=_remediation_set() if remediations is None
        else remediations)
    cfg = _cfg(tmp_path)
    # The storage engine is cached process-wide (one DATABASE_URL per
    # process is the production shape); a controller built earlier in this
    # test would otherwise own the cache with its own SQLite file. Reset so
    # every engagement binds its own engagement storage.
    from kryonsec.storage import reset_engine as _reset_storage

    _reset_storage()

    observed: list[str] = []
    reviewer = reviewer or (lambda hyps: {h["label"] for h in hyps})
    approver_calls: list[str] = []
    post_exploit_approver = post_exploit_approver or (
        lambda claim: approver_calls.append(claim) or False)

    orch, audit, graph = start_engagement(
        cfg, engagement_id, target=target,
        progress=observed.append,
        human_reviewer=reviewer,
        post_exploit_approver=post_exploit_approver,
    )
    # Wrap, don't replace: the engine's own checkpoint hook must keep
    # running exactly as production wired it.
    checkpoint = orch.on_state_complete
    completed_states: list[str] = []

    def on_state_complete(state: str) -> None:
        completed_states.append(state)
        checkpoint(state)

    orch.on_state_complete = on_state_complete
    audit_events: list[dict] = []
    audit.add_observer(audit_events.append)

    completed = orch.run()
    # The CLI's post-run duties, so the artifacts match a real command run.
    persist_graph(cfg, engagement_id, graph, audit)
    record_engagement_ending(
        cfg, engagement_id,
        outcome="halted" if orch.halt_reason else "completed",
        reason=orch.halt_reason,
        last_state=completed[-1] if completed else None,
        states_entered=len(completed),
    )
    engagement_dir = cfg.home / "engagements" / engagement_id
    events = _read_chain(cfg.home, engagement_id)
    return SimpleNamespace(
        orch=orch, audit=audit, graph=graph, runner=runner, cfg=cfg,
        completed=completed, halt_reason=orch.halt_reason,
        events=events, audit_events=audit_events, observed=observed,
        dir=engagement_dir, approver_calls=approver_calls,
        chain=engagement_dir / "audit.jsonl",
        report_md=engagement_dir / "report.md",
        report_json=engagement_dir / "report.json",
    )


def _named(events: list[dict], name: str) -> list[dict]:
    return [e for e in events if e.get("event") == name]


def _one(events: list[dict], name: str) -> dict:
    found = _named(events, name)
    assert found, f"expected at least one {name!r} event, got none"
    return found[-1]


def _by_type(run, ntype: str) -> list[dict]:
    return run.graph.by_type(ntype)


def _assert_docker_invariants(run) -> None:
    """Every recorded spawn argv carries the full production isolation set."""
    assert run.runner.docker_argv, "no docker spawns recorded"
    for argv in run.runner.docker_argv:
        if LAB_IMAGE not in argv:
            continue  # docker management (container kill), not a spawn
        for flag in ISOLATION_FLAGS:
            assert flag in argv, f"missing isolation flag {flag!r} in {argv}"


def _assert_chain_integrity(run) -> None:
    ok, _error = run.audit.verify()
    assert ok is True
    endings = _named(run.events, "engagement_finished")
    assert len(endings) == 1, "expected exactly one terminal event"
    assert _named(run.events, "engagement_created"), "no creation event"


# --------------------------------------------------------------- scenarios


def test_scenario_a_full_authorized_workflow_end_to_end(tmp_path, monkeypatch):
    """A: accept -> scope ok -> recon -> hypotheses -> Gate 2 approve ->
    exploit -> evidence -> independent verify -> blue team -> report ->
    audit chain intact."""
    run = run_engagement(
        tmp_path, monkeypatch,
        scripts={"sqlmap": [SQLMAP_CONFIRMED]},
        engagement_id="e2e-a")

    # The full loop ran, in order; POST_EXPLOIT is correctly skipped
    # (no shell was obtained) but everything else reached REPORT.
    assert run.completed == [
        "INIT", "RECON_PASSIVE", "RECON_ACTIVE", "HYPOTHESIZE",
        "HUMAN_REVIEW", "EXPLOIT", "VERIFY", "BLUE_TEAM", "REPORT"]
    assert run.halt_reason is None
    assert run.orch.state == "HALT"

    # Gate 2: the decision is audited per hypothesis, approved here.
    reviewed = _named(run.events, "hypothesis_reviewed")
    assert reviewed and all(e["approved"] for e in reviewed)
    _one(run.events, "human_review_done")

    # Exploit: real argv composition, real confirmation logic over fixture
    # output — a finding is derived ONLY through the marker table.
    assert run.runner.spawns("sqlmap"), "sqlmap never reached the sandbox"
    _assert_docker_invariants(run)
    _one(run.events, "finding_confirmed")
    findings = _by_type(run, "finding")
    assert [f["label"] for f in findings] == ["H1"]
    attempts = _by_type(run, "exploit_attempt")
    assert any(a["label"] == "H1:sqlmap" and a["properties"].get("confirmed")
               for a in attempts)

    # Independent verification: three curl probes (baseline/true/false) ran,
    # and the verifier's agreement — not sqlmap's word — marks verified.
    assert len(run.runner.spawns("curl")) >= 3
    _one(run.events, "finding_verified")
    attempts_v = _by_type(run, "verify_attempt")
    assert any(v["properties"].get("verified") is True for v in attempts_v)

    # Blue team produced the deterministic remediation.
    assert _by_type(run, "remediation"), "no remediation node"
    _one(run.events, "remediation_proposed")

    # Report exists on disk and records the finding.
    assert run.report_md.exists() and run.report_json.exists()
    report_text = run.report_json.read_text(encoding="utf-8")
    assert "H1" in report_text

    # Audit chain: SHA-chained, intact, exactly one terminal event.
    _assert_chain_integrity(run)
    assert _named(run.events, "graph_persisted"), "graph not persisted"
    assert run.observed, "progress callback never fired"


def test_scenario_b_gate2_denial_routes_to_blue_team(tmp_path, monkeypatch):
    """B: Gate 2 denies -> no exploit runs -> defensive analysis still
    happens -> denial is in the chain."""
    run = run_engagement(
        tmp_path, monkeypatch,
        scripts={"sqlmap": [SQLMAP_CONFIRMED]},
        reviewer=lambda hyps: set(),
        engagement_id="e2e-b")

    assert run.halt_reason is None
    assert "EXPLOIT" not in run.completed
    assert "POST_EXPLOIT" not in run.completed
    assert "BLUE_TEAM" in run.completed and "REPORT" in run.completed

    # Every hypothesis was audited as rejected.
    reviewed = _named(run.events, "hypothesis_reviewed")
    assert reviewed and all(not e["approved"] for e in reviewed)
    assert _one(run.events, "human_review_done")["approved"] == 0

    # Nothing ran toward the target after the denial: recon ran before
    # Gate 2 (legitimately), but no exploit-phase tool may ever fire.
    assert "sqlmap" not in run.runner.executed
    assert "curl" not in run.runner.executed
    assert not _by_type(run, "finding")
    assert not _by_type(run, "exploit_attempt")

    # v2.1.1 fix: rejection still produces defensive recommendations.
    assert _by_type(run, "remediation")
    assert run.report_json.exists()
    _assert_chain_integrity(run)


def test_scenario_c_out_of_scope_target_refused(tmp_path, monkeypatch):
    """C: (1) the CLI preflight refuses a non-domain/IP target outright;
    (2) in-engine, an absolute out-of-scope asset proposed by the model is
    refused before any spawn — nothing is sent to the other host."""
    from kryonsec.purple.zonea import validate_target

    # (1) real preflight: bare IPs and TEST-NET addresses are not domains —
    # the command never starts for them.
    with pytest.raises(ValueError):
        validate_target("203.0.113.7")
    with pytest.raises(ValueError):
        validate_target("http://10.0.0.5/admin")
    # control: a real domain-shaped target passes the same gate
    assert validate_target("http://lab.example.com") == "lab.example.com"

    # (2) the model proposes an absolute out-of-scope asset; the operator
    # approves; the ENGINE still refuses to touch the other host.
    run = run_engagement(
        tmp_path, monkeypatch,
        hypotheses=_out_of_scope_hypotheses(),
        engagement_id="e2e-c")

    assert "EXPLOIT" in run.completed and run.halt_reason is None
    # No process was ever aimed at the out-of-scope host.
    for argv in run.runner.docker_argv:
        assert "169.254.169.254" not in " ".join(argv)
    assert not _by_type(run, "finding")
    assert not _named(run.events, "finding_confirmed")
    # The refusal is on the record, and the engagement still completes.
    assert run.report_json.exists()
    _assert_chain_integrity(run)


def test_scenario_d_sandbox_unavailable_fails_closed(tmp_path, monkeypatch):
    """D: no sandbox -> Zone B halts fail-closed, NOTHING executes on the
    host, and the halt is audited."""
    run = run_engagement(
        tmp_path, monkeypatch,
        sandbox_ok=False, sandbox_reason="lab fixture: sandbox unavailable",
        engagement_id="e2e-d")

    # The loop halts at the first Zone B state; sandbox-free states still ran.
    assert run.halt_reason == "lab fixture: sandbox unavailable"
    assert run.completed == ["INIT", "RECON_PASSIVE", "RECON_ACTIVE"]
    assert "EXPLOIT" not in run.completed

    # Fail-closed, in the chain: sandbox_check + zone_b_blocked.
    check = _one(run.events, "sandbox_check")
    assert check["available"] is False
    blocked = _named(run.events, "zone_b_blocked")
    assert {e["state"] for e in blocked} >= {"RECON_ACTIVE"}
    assert all("sandbox unavailable" in e["reason"] for e in blocked)

    # Zero host fallback: the lab bridge saw no process at all.
    assert run.runner.docker_argv == []
    assert run.runner.executed == []

    # No report: the engagement never reached REPORT, and the terminal
    # event records the halt.
    assert not run.report_md.exists()
    _assert_chain_integrity(run)
    assert _one(run.events, "engagement_finished")["outcome"] == "halted"


def test_scenario_e_tool_timeout_is_not_a_finding(tmp_path, monkeypatch):
    """E: a tool that hangs is killed by the sandbox's real timeout path;
    its failure produces no finding, and the run reports honestly."""
    run = run_engagement(
        tmp_path, monkeypatch,
        scripts={"sqlmap": [("timeout",)]},
        engagement_id="e2e-e1")

    assert run.halt_reason is None
    assert run.runner.spawns("sqlmap"), "sqlmap never reached the sandbox"
    _assert_docker_invariants(run)

    # No finding may be derived from a timed-out run.
    assert not _by_type(run, "finding")
    assert not _named(run.events, "finding_confirmed")
    # The attempt is on the record as a failure, not a success.
    attempts = _by_type(run, "exploit_attempt")
    assert any(a["label"] == "H1:sqlmap" and not a["properties"].get("ok")
               for a in attempts)

    # VERIFY planned around zero findings; the loop still completed and the
    # report does not claim a confirmed SQLi.
    assert _one(run.events, "verify_plan")["findings_to_verify"] == 0
    assert run.completed[-1] == "REPORT"
    assert run.report_json.exists()
    assert "is vulnerable" not in run.report_json.read_text(encoding="utf-8")
    _assert_chain_integrity(run)


def test_scenario_f_unverified_claims_stay_unverified(tmp_path, monkeypatch):
    """F: (1) a tool whose words CLAIM success but whose class never
    confirms is not a finding; (2) a confirmed claim that the INDEPENDENT
    verifier cannot reproduce stays unverified — no post-exploit arises."""
    # (1) nikto output claiming "is vulnerable": nikto is in _NEVER_CONFIRMS.
    run1 = run_engagement(
        tmp_path, monkeypatch,
        hypotheses=_sqli_hypotheses(tools=("nikto",)),
        scripts={"nikto": [NIKTO_UNTRUSTED_CLAIM]},
        engagement_id="e2e-f1")
    assert run1.runner.spawns("nikto")
    assert not _by_type(run1, "finding")
    assert not _named(run1.events, "finding_confirmed")
    assert "POST_EXPLOIT" not in run1.completed

    # (2) sqlmap's marker-derived finding, but the independent boolean
    # probe sees identical responses (same_curl): the verifier must NOT
    # agree just because the producer was loud.
    run2 = run_engagement(
        tmp_path, monkeypatch,
        scripts={"sqlmap": [SQLMAP_CONFIRMED]},
        same_curl=True,
        post_exploit_approver=lambda claim: True,
        engagement_id="e2e-f2")
    assert _named(run2.events, "finding_confirmed"), "producer finding missing"
    verifications = _by_type(run2, "verify_attempt")
    assert verifications and all(
        v["properties"].get("verified") is not True for v in verifications)
    # No post-exploit privilege arises from an unverified claim.
    assert "POST_EXPLOIT" not in run2.completed
    assert run2.approver_calls == [], "Gate 3 approver was consulted"
    assert run2.report_json.exists()
    _assert_chain_integrity(run2)


def test_scenario_g_gate3_post_exploit_dormant(tmp_path, monkeypatch):
    """G: Gate 3 cannot be bypassed — even an always-yes approver is never
    consulted without a verified shell; POST_EXPLOIT and its capability
    contracts remain dormant."""
    run = run_engagement(
        tmp_path, monkeypatch,
        scripts={"sqlmap": [SQLMAP_CONFIRMED]},
        post_exploit_approver=lambda claim: True,
        engagement_id="e2e-g")

    assert "POST_EXPLOIT" not in run.completed
    assert run.approver_calls == [], "Gate 3 approver was consulted"
    # Phase 3 (2026-11-17): the dormancy skip is itself audited now —
    # the ONE post_exploit event allowed here, precisely because it
    # records that the gate never ran. Any gate/claim/decision event
    # would be a bypass.
    post_exploit_events = [e for e in run.events
                           if "post_exploit" in str(e.get("event"))]
    assert [e["event"] for e in post_exploit_events] == \
        ["post_exploit_skipped_dormant"]

    # The transition table itself: only shell_obtained AND approved moves
    # to POST_EXPLOIT; either missing goes to VERIFY.
    from kryonsec.purple.orchestrator import SubagentResult, next_state

    assert next_state("EXPLOIT", SubagentResult(
        shell_obtained=True, post_exploit_approved=False)) == "VERIFY"
    assert next_state("EXPLOIT", SubagentResult(
        shell_obtained=False, post_exploit_approved=True)) == "VERIFY"
    assert next_state("EXPLOIT", SubagentResult(
        shell_obtained=True, post_exploit_approved=True)) == "POST_EXPLOIT"

    # Post-exploit capability verification ships DORMANT: the contract
    # registry is empty by design until producers are vetted.
    from kryonsec.purple.capability_verify import (
        CAPABILITY_VERIFICATION_CONTRACTS)

    assert CAPABILITY_VERIFICATION_CONTRACTS == {}


def test_scenario_h_ui_gate_and_report_redaction(tmp_path, monkeypatch):
    """H: the REAL controller approval gate (cross-thread handoff, the same
    choke point the Textual app uses) drives Gate 2 — approve and deny —
    and a secret planted in tool output is redacted in the report."""
    from kryonsec.storage import reset_engine
    from kryonsec.ui.session_store import EngagementStore, SessionStore
    from kryonsec.ui.workspace import WorkspaceController

    def make_controller():
        cfg = KryonsecConfig(home=tmp_path / "ui-home",
                             workspace=tmp_path / "ui-workspace")
        cfg.database_url = f"sqlite:///{tmp_path / 'ui.db'}"
        store = SessionStore(cfg)
        store.ensure_schema()
        controller = WorkspaceController(
            cfg, session_store=store,
            engagement_store=EngagementStore(cfg),
            system_prompt="test prompt")
        return controller

    def decide_later(controller, approved, deadline=20.0):
        def worker():
            end = time.monotonic() + deadline
            while time.monotonic() < end:
                if controller.approval is not None:
                    controller.decide_approval(approved)
                    return
                time.sleep(0.02)
            raise AssertionError("UI approval gate never appeared")

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        return thread

    # Approve through the real gate: the engine proceeds through EXPLOIT.
    controller = make_controller()
    try:
        approver_thread = decide_later(controller, approved=True)
        run_ok = run_engagement(
            tmp_path, monkeypatch,
            scripts={"sqlmap": [SQLMAP_CONFIRMED]},
            reviewer=controller.request_human_review,
            engagement_id="e2e-h1")
        approver_thread.join(timeout=30)
        assert not approver_thread.is_alive()
        assert "EXPLOIT" in run_ok.completed
        assert all(e["approved"] for e in _named(
            run_ok.events, "hypothesis_reviewed"))
        assert controller.approval is None  # gate handed back after decision
    finally:
        controller.close()
    reset_engine()

    # Deny through the same gate: the engine skips EXPLOIT — the UI path
    # cannot grant what the human refused.
    controller = make_controller()
    try:
        deny_thread = decide_later(controller, approved=False)
        run_deny = run_engagement(
            tmp_path, monkeypatch,
            scripts={"sqlmap": [SQLMAP_CONFIRMED]},
            reviewer=controller.request_human_review,
            engagement_id="e2e-h2")
        deny_thread.join(timeout=30)
        assert not deny_thread.is_alive()
        assert "EXPLOIT" not in run_deny.completed
        assert "sqlmap" not in run_deny.runner.executed
        assert "curl" not in run_deny.runner.executed
        assert all(not e["approved"] for e in _named(
            run_deny.events, "hypothesis_reviewed"))
    finally:
        controller.close()
    reset_engine()

    # Redaction: a secret planted in tool output reaches neither the graph,
    # the chain nor the report in recognizable form.
    run_red = run_engagement(
        tmp_path, monkeypatch,
        scripts={"sqlmap": [SQLMAP_CONFIRMED + f" leak={PLANTED_SECRET}"]},
        engagement_id="e2e-h3")
    finding = _by_type(run_red, "finding")[0]
    excerpt = finding["properties"].get("excerpt", "")
    assert PLANTED_SECRET not in excerpt
    # The redaction placeholder proves the value was actually detected and
    # replaced (not merely dropped) — and that it stayed replaced all the
    # way into the report.
    assert "«SECRET_" in excerpt
    chain_text = run_red.chain.read_text(encoding="utf-8")
    assert PLANTED_SECRET not in chain_text
    report_text = run_red.report_json.read_text(encoding="utf-8")
    assert PLANTED_SECRET not in report_text
    _assert_chain_integrity(run_red)
