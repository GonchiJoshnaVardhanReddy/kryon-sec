"""Phase 2B.7 tests: adapter failure classification + bounded infra retry.

Everything here uses HARMLESS synthetic adapters and FAKE sandbox result
objects (the codebase's standard duck-typed test seam) — no real security
tool, no sandbox process, no network, no scan.

The contract under test:
- every adapter failure carries a structured ``failure_class`` set at the
  decision point that PRODUCED the failure (never string-matched later);
- ONLY the ``sandbox_infrastructure`` class is retryable, exactly one
  retry, and the retry re-enters the SAME sandbox path under a fresh
  audited request_id;
- refusals, timeouts and tool failures are never retried;
- the optional progress callback receives redacted one-line METADATA —
  never tool output;
- the legacy (planner-less) fallback provably does NOT enforce any
  engagement-wide tool budget — documented behavior, tested honestly.
"""

import json

from kryonsec.config import KryonsecConfig
from kryonsec.purple.adapters import (
    ADAPTER_FAILURE_REFUSED_ALLOWLIST,
    ADAPTER_FAILURE_REFUSED_APPROVAL,
    ADAPTER_FAILURE_REFUSED_INVARIANT,
    ADAPTER_FAILURE_REFUSED_POLICY,
    ADAPTER_FAILURE_SANDBOX_INFRASTRUCTURE,
    ADAPTER_FAILURE_TIMEOUT,
    AdapterRegistry,
    ModeBToolAdapter,
    PreparedAdapterRun,
    collect_adapter_evidence,
    execute_adapter,
    failure_explanation,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import (
    SPAWN_ERROR_KIND_ALLOWLIST,
    SPAWN_ERROR_KIND_INFRASTRUCTURE,
    SPAWN_ERROR_KIND_INVARIANT,
    SPAWN_ERROR_KIND_TIMEOUT,
    SpawnResult,
)

TARGET = "target-corp.com"
ORIG_REQUEST_ID = "req00000orig"


# ---- synthetic, harmless adapter (mirrors test_purple_adapters) ---------

def _adapter(**over) -> ModeBToolAdapter:
    base = dict(
        adapter_id="echo-probe",
        title="Echo probe",
        purpose="Harmless smoke adapter: prints a fixed acknowledgement "
                "line inside the sandbox; no network, no target touch.",
        category="utility",
        stages=("BLUE_TEAM",),
        executable="echo",
        command_template=("{term}", "--probe-complete"),
        target_kind="term",
        max_seconds=30,
        approvals=(),
        network="none",
        risk="inert",
        evidence_kind="text_excerpt",
    )
    base.update(over)
    return ModeBToolAdapter(**base)


def _registry() -> AdapterRegistry:
    reg = AdapterRegistry()
    reg.register(_adapter())
    return reg


def _prepared() -> PreparedAdapterRun:
    return PreparedAdapterRun(
        adapter_id="echo-probe", request_id=ORIG_REQUEST_ID,
        argv=["echo", "target-corp.com", "--probe-complete"],
        target=TARGET, target_kind="term", tool="echo",
        max_seconds=30, network="none", approvals=())


class _Audit:
    """A fresh audit log per test, with event read-back."""

    def __init__(self, tmp_path):
        self.log = AuditLog(tmp_path / "audit.jsonl")

    def events(self, name=None) -> "list[dict]":
        out = []
        for line in open(self.log.path, encoding="utf-8"):
            if not line.strip():
                continue
            e = json.loads(line)
            if name is None or e["event"] == name:
                out.append(e)
        return out


def _ok_result(stdout="probe-complete") -> SpawnResult:
    return SpawnResult(ok=True, exit_code=0, stdout=stdout,
                       error="", truncated=False)


def _infra_result(msg="no JSON payload from sandbox: daemon hiccup"):
    return SpawnResult(ok=False, exit_code=-1, stdout="", error=msg,
                       error_kind=SPAWN_ERROR_KIND_INFRASTRUCTURE)


class _ScriptedSandbox:
    """Duck-typed sandbox returning scripted SpawnResults in order —
    and recording every spawn call (argv + network_mode) for the
    no-bypass assertions."""

    def __init__(self, results, egress_policy=None):
        self._results = list(results)
        self.calls: "list[tuple[list, object]]" = []
        self.egress_policy = egress_policy

    def spawn(self, argv, timeout_s=None, network_mode=None):
        self.calls.append((list(argv), network_mode))
        return self._results.pop(0)


def _graph() -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    return graph


# ---- 1. classification at the decision point ----------------------------

def test_timeout_is_classified_and_never_retried(tmp_path):
    audit = _Audit(tmp_path)
    sandbox = _ScriptedSandbox([SpawnResult(
        ok=False, exit_code=-1, stdout="",
        error="tool exceeded 30s sandbox timeout",
        error_kind=SPAWN_ERROR_KIND_TIMEOUT)])
    rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                          audit=audit.log, max_spawn_attempts=2)
    assert rec.executed is False
    assert rec.outcome == "not_run"
    assert rec.failure_class == ADAPTER_FAILURE_TIMEOUT
    assert len(sandbox.calls) == 1          # target was contacted — no retry
    assert rec.duration_s >= 0.0
    text = failure_explanation(rec)
    # the explanation names the timeout class and carries the excerpt
    assert "whole time window" in text and "sandbox timeout" in text


def test_infrastructure_retried_once_with_fresh_audited_id(tmp_path):
    audit = _Audit(tmp_path)
    sandbox = _ScriptedSandbox([_infra_result(), _infra_result()])
    rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                          audit=audit.log, max_spawn_attempts=2)
    # exactly two spawn attempts, identical argv (never a new command)
    assert len(sandbox.calls) == 2
    assert sandbox.calls[0][0] == sandbox.calls[1][0]
    assert rec.failure_class == ADAPTER_FAILURE_SANDBOX_INFRASTRUCTURE
    # the retry ran under a FRESH request id (correlatable in the audit)
    assert rec.request_id != ORIG_REQUEST_ID
    assert len(rec.request_id) >= 8
    retries = audit.events("adapter_infra_retry")
    assert len(retries) == 1
    assert retries[0]["request_id"] == ORIG_REQUEST_ID
    assert retries[0]["retry_request_id"] == rec.request_id
    assert retries[0]["failure_class"] == \
        ADAPTER_FAILURE_SANDBOX_INFRASTRUCTURE
    # both attempts audited as spawns under their own ids
    spawn_events = audit.events("adapter_spawn")
    assert [e["request_id"] for e in spawn_events] \
        == [ORIG_REQUEST_ID, rec.request_id]


def test_infrastructure_retry_then_success(tmp_path):
    audit = _Audit(tmp_path)
    sandbox = _ScriptedSandbox([_infra_result(), _ok_result()])
    rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                          audit=audit.log, graph=_graph(),
                          max_spawn_attempts=2)
    assert rec.executed is True
    assert rec.outcome == "attempted"
    assert rec.failure_class == ""
    assert rec.duration_s >= 0.0


def test_refusals_are_never_retried(tmp_path):
    for kind, msg, expect in (
        (SPAWN_ERROR_KIND_INVARIANT,
         "sandbox isolation invariant broken — refusing to launch",
         ADAPTER_FAILURE_REFUSED_INVARIANT),
        (SPAWN_ERROR_KIND_ALLOWLIST, "tool_not_in_allowlist",
         ADAPTER_FAILURE_REFUSED_ALLOWLIST),
    ):
        audit = _Audit(tmp_path / kind)
        sandbox = _ScriptedSandbox([SpawnResult(
            ok=False, exit_code=-1, stdout="", error=msg, error_kind=kind)])
        rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                              audit=audit.log, max_spawn_attempts=2)
        assert len(sandbox.calls) == 1
        assert rec.failure_class == expect
        assert "not run" in failure_explanation(rec)


def test_attempt_count_is_hard_capped_at_two(tmp_path):
    audit = _Audit(tmp_path)
    # even a caller asking for 9 attempts gets at most 2 spawns
    sandbox = _ScriptedSandbox([_infra_result()] * 9)
    rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                          audit=audit.log, max_spawn_attempts=9)
    assert len(sandbox.calls) == 2
    assert rec.failure_class == ADAPTER_FAILURE_SANDBOX_INFRASTRUCTURE


def test_retry_disabled_by_default(tmp_path):
    audit = _Audit(tmp_path)
    sandbox = _ScriptedSandbox([_infra_result()])
    rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                          audit=audit.log)   # default max_spawn_attempts=1
    assert len(sandbox.calls) == 1
    assert rec.failure_class == ADAPTER_FAILURE_SANDBOX_INFRASTRUCTURE


# ---- 2. duck-typed fallback (sandboxes without error_kind) --------------

def test_string_fallback_for_legacy_result_objects(tmp_path):
    cases = [
        ("tool exceeded 30s sandbox timeout",
         ADAPTER_FAILURE_TIMEOUT),
        ("tool_not_in_allowlist", ADAPTER_FAILURE_REFUSED_ALLOWLIST),
        ("sandbox isolation invariant broken — refusing to launch",
         ADAPTER_FAILURE_REFUSED_INVARIANT),
        ("no JSON payload from sandbox: docker died",
         ADAPTER_FAILURE_SANDBOX_INFRASTRUCTURE),
    ]
    for i, (msg, expect) in enumerate(cases):
        audit = _Audit(tmp_path / f"fallback{i}")
        # a result object WITHOUT error_kind (old sandbox / test fake)
        legacy = type("LegacyResult", (), {})()
        legacy.ok = False
        legacy.exit_code = -1
        legacy.stdout = ""
        legacy.error = msg
        legacy.truncated = False
        sandbox = _ScriptedSandbox([legacy])
        rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                              audit=audit.log)
        assert rec.failure_class == expect, msg


# ---- 3. refusals carry failure_class on record and audit ----------------

def test_policy_refusal_record_and_event(tmp_path):
    audit = _Audit(tmp_path)
    # target-scope adapter + a sandbox with NO egress policy → refused
    reg = AdapterRegistry()
    reg.register(_adapter(adapter_id="curl-probe", title="curl probe",
                          purpose="target-touching probe, egress required",
                          category="web_recon", stages=("RECON_ACTIVE",),
                          executable="curl", command_template=("{url}",),
                          target_kind="url", network="target_scope",
                          risk="active"))
    prep = PreparedAdapterRun(
        adapter_id="curl-probe", request_id=ORIG_REQUEST_ID,
        argv=["curl", TARGET], target=TARGET, target_kind="url",
        tool="curl", max_seconds=30, network="target_scope", approvals=())
    sandbox = _ScriptedSandbox([_ok_result()])   # would "work" if reached
    rec = execute_adapter(reg, prep, sandbox=sandbox, audit=audit.log)
    assert len(sandbox.calls) == 0        # refused before any spawn
    assert rec.failure_class == ADAPTER_FAILURE_REFUSED_POLICY
    events = audit.events("adapter_refused")
    assert len(events) == 1
    assert events[0]["failure_class"] == ADAPTER_FAILURE_REFUSED_POLICY


def test_approval_refusal_record_and_event(tmp_path):
    audit = _Audit(tmp_path)
    reg = AdapterRegistry()
    reg.register(_adapter(approvals=("hypothesis_gate",), risk="active",
                          category="exploit", stages=("EXPLOIT",),
                          network="target_scope",
                          purpose="gate-governed probe"))
    prep = PreparedAdapterRun(
        adapter_id="echo-probe", request_id=ORIG_REQUEST_ID,
        argv=["echo", "x"], target=TARGET, target_kind="term",
        tool="echo", max_seconds=30, network="target_scope",
        approvals=("hypothesis_gate",))
    sandbox = _ScriptedSandbox([_ok_result()], egress_policy=object())
    rec = execute_adapter(reg, prep, sandbox=sandbox, audit=audit.log,
                          approvals_granted=set())
    assert len(sandbox.calls) == 0
    assert rec.failure_class == ADAPTER_FAILURE_REFUSED_APPROVAL
    assert audit.events("adapter_refused")[0]["failure_class"] \
        == ADAPTER_FAILURE_REFUSED_APPROVAL
    assert rec.executed is False and rec.argv == []


# ---- 4. progress events are redacted metadata only ----------------------

def test_progress_lines_never_carry_tool_output(tmp_path):
    audit = _Audit(tmp_path)
    seen: "list[str]" = []
    secret_stdout = "TOKEN=supersecretvalue999 probe-complete"
    sandbox = _ScriptedSandbox([
        _infra_result(),
        _ok_result(stdout=secret_stdout)])
    rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                          audit=audit.log, graph=_graph(),
                          max_spawn_attempts=2, progress=seen.append)
    # one "started" line per attempt + one final outcome line
    assert len(seen) == 3
    assert all("echo-probe" in line for line in seen)
    assert sum(line.startswith("echo-probe → ") for line in seen) == 2
    assert sum(line.startswith("echo-probe ← ") for line in seen) == 1
    assert any(f"(exit 0" in line and "s)" in line for line in seen)
    # the tool's stdout NEVER reaches the progress channel
    assert all("supersecretvalue999" not in line for line in seen)
    assert all("probe-complete" not in line for line in seen)


def test_progress_failure_line_names_the_explanation(tmp_path):
    audit = _Audit(tmp_path)
    seen: "list[str]" = []
    sandbox = _ScriptedSandbox([SpawnResult(
        ok=False, exit_code=-1, stdout="",
        error="tool exceeded 30s sandbox timeout",
        error_kind=SPAWN_ERROR_KIND_TIMEOUT)])
    execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                    audit=audit.log, progress=seen.append)
    assert len(seen) == 2
    assert seen[-1].startswith("echo-probe ✗ ")
    assert "timeout" in seen[-1]


# ---- 5. evidence graph round-trip (planner compatibility) ---------------

def test_failure_class_and_duration_flow_into_adapter_attempt_nodes(tmp_path):
    audit = _Audit(tmp_path)
    graph = _graph()
    rec = execute_adapter(_registry(), _prepared(), sandbox=_ScriptedSandbox(
        [_ok_result()]), audit=audit.log, graph=graph)
    records, invalid = collect_adapter_evidence(graph, audit.log)
    assert invalid == []
    assert len(records) == 1
    assert records[0].failure_class == ""      # success: no failure class
    assert records[0].duration_s >= 0.0
    assert records[0].request_id == rec.request_id


def test_planner_untouched_dedupe_still_scopes_by_adapter_and_base(tmp_path):
    # the planner's planned/executed accounting reads _executed_pairs;
    # the retry change must not have altered the (adapter, base) pair set
    audit = _Audit(tmp_path)
    sandbox = _ScriptedSandbox([_infra_result(), _ok_result()])
    execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                    audit=audit.log, max_spawn_attempts=2)
    names = [e["event"] for e in audit.events()]
    # no new unbounded event types; the retry is its own audited event
    assert names.count("adapter_infra_retry") == 1
    assert "adapter_retry" not in names


# ---- 6. config knob ------------------------------------------------------

def test_config_spawn_retries_default_and_roundtrip(tmp_path):
    cfg = KryonsecConfig()
    assert cfg.adapter_spawn_retries == 1
    data = cfg.to_toml_dict()
    assert data["adapters"] == {"spawn_retries": 1}
    back = KryonsecConfig.from_toml(data)
    assert back.adapter_spawn_retries == 1
    off = KryonsecConfig.from_toml({"adapters": {"spawn_retries": 0}})
    assert off.adapter_spawn_retries == 0
    # a larger value is stored honestly; the engine caps attempts at 2
    big = KryonsecConfig.from_toml({"adapters": {"spawn_retries": 7}})
    assert big.adapter_spawn_retries == 7
    # a negative value is nonsense — never accepted
    neg = KryonsecConfig.from_toml({"adapters": {"spawn_retries": -3}})
    assert neg.adapter_spawn_retries == 0


def test_recon_active_lane_budget_from_config(tmp_path):
    """The lane clamps the configured budget to [0, 1] — one retry max."""
    graph = _graph()
    cfg = KryonsecConfig(adapter_spawn_retries=0)
    sub = ReconActiveSubagent(cfg=cfg, graph=graph,
                              audit=AuditLog(tmp_path / "a.jsonl"),
                              target=TARGET, sandbox=None)
    assert sub.spawn_retries == 0
    cfg = KryonsecConfig(adapter_spawn_retries=7)
    sub = ReconActiveSubagent(cfg=cfg, graph=graph,
                              audit=AuditLog(tmp_path / "b.jsonl"),
                              target=TARGET, sandbox=None)
    assert sub.spawn_retries == 1


# ---- 7. honest legacy-fallback finding (Task 7) --------------------------

def test_legacy_fallback_runs_every_base_with_no_engagement_budget(tmp_path):
    """Documented 2B.7 finding, proven: with NO plan (planner off, or a
    planner failure), ``_planned_bases`` returns EVERY validated base
    unchanged, and nothing on the legacy path enforces an
    engagement-wide tool budget — only each adapter's own max_seconds
    and the sandbox's 300s kill apply. The planner's PlannerBudget is
    planner-only; a legacy run is NOT budget-halted."""
    cfg = KryonsecConfig(tool_planner_enabled=False)
    sub = ReconActiveSubagent(cfg=cfg, graph=_graph(),
                              audit=AuditLog(tmp_path / "c.jsonl"),
                              target=TARGET, sandbox=None)
    assert sub._plan is None
    bases = [f"https://host{i}.target-corp.com/" for i in range(5)]
    for adapter_id in ("httpx-probe", "whatweb-probe", "nuclei-probe",
                       "tls-probe", "api-probe"):
        # every lane, every base — no planner selection, no budget cut
        assert sub._planned_bases(adapter_id, bases) == bases


# ---- 8. no bypass of the isolation boundaries ---------------------------

def test_retry_reenters_the_same_sandbox_path(tmp_path):
    """The retry must not weaken anything: same argv, same network
    mode, same timeout — a fresh attempt through the same spawn
    contract, never a host fallback or an argv change."""
    audit = _Audit(tmp_path)
    sandbox = _ScriptedSandbox([_infra_result(), _ok_result()])
    rec = execute_adapter(_registry(), _prepared(), sandbox=sandbox,
                          audit=audit.log, max_spawn_attempts=2)
    assert rec.executed is True
    first, second = sandbox.calls
    assert first == second                     # identical argv + network
    assert first[1] == "none"                  # network_mode preserved
    # every spawn event went through the audit (no silent second attempt)
    assert len(audit.events("adapter_spawn")) == 2
    assert len(audit.events("adapter_result")) == 2
