"""Phase 2B.2 tests: the vetted Mode B tool-adapter foundation.

Everything here uses HARMLESS synthetic adapters (an ``echo`` probe and
a ``curl``-shaped URL adapter driven by a FAKE sandbox result object) —
no real security tool, no sandbox process, no network, no scan. The
tests exercise the real contract: explicit registration, layered
validation, scope refusal, approval gates, sandbox-only execution,
audit events, and evidence records that can never claim verification.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapters import (
    ADAPTER_CATEGORIES,
    AdapterError,
    AdapterNotRegistered,
    AdapterRunRecord,
    AdapterScopeRefused,
    AdapterRegistry,
    DuplicateAdapterError,
    PreparedAdapterRun,
    ModeBToolAdapter,
    collect_adapter_evidence,
    execute_adapter,
    prepare_adapter_run,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult

SUBDOMAINS = ["mail.target-corp.com"]
TARGET = "target-corp.com"


# ---- synthetic, harmless adapters -------------------------------------------

def _echo_adapter(**over) -> ModeBToolAdapter:
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


def _curl_adapter(**over) -> ModeBToolAdapter:
    """A curl-shaped TARGET-TOUCHING adapter — never executed for real
    in these tests: every execution goes through a fake sandbox result."""
    base = dict(
        adapter_id="curl-probe",
        title="curl probe",
        purpose="Single GET against the in-scope target URL; light "
                "banner check for future web-recon plans.",
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable="curl",
        command_template=("-sS", "--max-time", "{rate}", "{url}"),
        target_kind="url",
        max_seconds=60,
        approvals=(),
        network="target_scope",
        risk="active",
        evidence_kind="text_excerpt",
    )
    base.update(over)
    return ModeBToolAdapter(**base)


def _exploit_adapter(**over) -> ModeBToolAdapter:
    """An adapter wired to the stages that REQUIRE gates (Gate 2)."""
    return _curl_adapter(
        adapter_id="curl-exploit",
        title="curl exploit-stage probe",
        purpose="Gate-2-governed web probe for approved hypotheses.",
        category="exploit",
        stages=("EXPLOIT",),
        approvals=("hypothesis_gate",),
        risk="active",
    )


def _curl_probe_impactful() -> ModeBToolAdapter:
    return _curl_adapter(
        adapter_id="shell-followup",
        title="post-exploit follow-up probe",
        purpose="Impactful post-exploit-stage probe; Gate 3 governs it.",
        category="post_exploit",
        stages=("POST_EXPLOIT",),
        approvals=("post_exploit_gate",),
        risk="impactful",
    )


class _StubEgressPolicy:
    """The duck-typed egress-policy stub (the executor only needs it
    present; the REAL boundary lives inside the sandbox's own spawn)."""

    dns_resolvers = ("192.0.2.53",)  # TEST-NET-1 fixture for the dnsx lane's -r


class FakeSandbox:
    """Duck-typed sandbox double (the codebase's standard test seam)."""

    def __init__(self, result, *, egress_policy=None, timeout_s=330,
                 image="kryonsec/sandbox@sha256:" + "a" * 12):
        self._result = result
        self.spawned = []
        self.egress_policy = egress_policy
        self.timeout_s = timeout_s
        self.image = image

    def spawn(self, argv, timeout_s=None, network_mode=None):
        self.spawned.append((argv, timeout_s))
        self.network_modes = getattr(self, "network_modes", [])
        self.network_modes.append(network_mode)
        return self._result


def _events(audit) -> "list[dict]":
    return [json.loads(line) for line in open(audit.path, encoding="utf-8")
            if line.strip()]


def _event_names(audit) -> "list[str]":
    return [e["event"] for e in _events(audit)]


def _graph() -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    graph.add_node("hypothesis", "H1", {
        "title": "curl-worthy probe",
        "target_asset": "/index.php?id=1",
        "rationale": "synthetic",
        "cvss_vector": "",
        "tools": ["curl-probe"],
        "confidence": 0.8,
        "approved": True,
    })
    graph.add_node("hypothesis", "H2", {
        "title": "not approved",
        "target_asset": "/x",
        "rationale": "",
        "cvss_vector": "",
        "tools": ["curl-probe"],
        "confidence": 0.5,
        "approved": False,
    })
    return graph


# ---- 1. unknown adapter rejection --------------------------------------------

def test_unknown_adapter_is_rejected_everywhere(tmp_path):
    reg = AdapterRegistry()
    assert reg.adapter_ids() == ()      # starts EMPTY — nothing ships on
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(AdapterNotRegistered):
        reg.get("ghost-tool")
    with pytest.raises(AdapterNotRegistered):
        reg.describe("ghost-tool")
    with pytest.raises(AdapterNotRegistered):
        prepare_adapter_run(reg, "ghost-tool", params={"term": "x"})
    # execution against a never-registered id: audited refusal, then raise
    ghost = PreparedAdapterRun(
        adapter_id="ghost-tool", request_id="abcdefgh1234", argv=["x"],
        target="", target_kind="none", tool="ghost-tool", max_seconds=30,
        network="none", approvals=())
    with pytest.raises(AdapterNotRegistered):
        execute_adapter(reg, ghost, sandbox=FakeSandbox(
            SpawnResult(ok=True, exit_code=0, stdout="")), audit=audit)
    assert _event_names(audit).count("adapter_refused") == 1
    assert "is not registered" in _events(audit)[0]["reason"]


# ---- 2. explicit registration (and its failure rules) ------------------------

def test_explicit_registration_and_constrained_construction():
    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    reg.register(_curl_adapter())
    assert reg.adapter_ids() == ("curl-probe", "echo-probe")  # sorted, opt-in
    # construction itself refuses invalid definitions
    with pytest.raises(ValidationError):
        _echo_adapter(category="not-a-category")
    with pytest.raises(ValidationError):
        _echo_adapter(stages=("NO_SUCH_STATE",))
    with pytest.raises(ValidationError):
        _curl_adapter(network="none")      # target-touch claims no-egress
    with pytest.raises(ValidationError):
        _curl_adapter(risk="inert")        # target-touch must be active+
    with pytest.raises(ValidationError):
        _curl_adapter(stages=("POST_EXPLOIT",), risk="impactful",
                      approvals=())        # post-exploit needs Gate 3
    with pytest.raises(ValidationError):
        _curl_adapter(stages=("EXPLOIT",), approvals=())   # Gate 2 needed
    with pytest.raises(ValidationError):
        _echo_adapter(executable="/tmp/evil.sh")   # LLM-chosen path
    with pytest.raises(ValidationError):
        _echo_adapter(executable="../../overpass") # traversal executable
    with pytest.raises(ValidationError):
        _echo_adapter(max_seconds=400)     # above the sandbox ceiling


# ---- 3. safe discovery --------------------------------------------------------

def test_discovery_lists_but_never_authorizes(tmp_path):
    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    reg.register(_curl_adapter())
    # search by category / stage / query
    assert [a.adapter_id for a in reg.search(category="utility")] \
        == ["echo-probe"]
    assert [a.adapter_id for a in reg.search(stage="RECON_ACTIVE")] \
        == ["curl-probe"]
    assert [a.adapter_id for a in reg.search(query="smoke")] \
        == ["echo-probe"]
    assert reg.search(category="exploit") == ()   # nothing yet: honest
    # describe is informative only — and says so
    described = json.loads(reg.describe("echo-probe"))
    assert described["command_template"] == \
        list(_echo_adapter().command_template)
    assert "NOT authorization" in described["note"]
    # availability is a planning API, not a license
    unegressed = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""))
    ok, reasons = reg.check_available("curl-probe", unegressed)
    assert not ok and any("egress policy" in r for r in reasons)
    ok, reasons = reg.check_available("echo-probe", unegressed)
    assert ok and reasons == []


# ---- 4. input and schema validation -------------------------------------------

def test_parameter_validation(tmp_path):
    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    with pytest.raises(AdapterError):   # missing the template placeholder
        prepare_adapter_run(reg, "echo-probe", target=TARGET)
    with pytest.raises(AdapterError):   # unexpected extra inputs
        prepare_adapter_run(reg, "echo-probe", target=TARGET,
                            params={"term": "x", "bogus": "y"})
    with pytest.raises(AdapterError):   # command-injection-shaped term
        prepare_adapter_run(reg, "echo-probe", target=TARGET,
                            params={"term": "x; rm -rf /tmp"})


# ---- 5. command-template restrictions ------------------------------------------

def test_rendered_argv_must_match_the_fixed_template(tmp_path):
    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    prep = prepare_adapter_run(reg, "echo-probe", target=TARGET,
                               params={"term": "probe-a"})
    assert prep.argv == ["echo", "probe-a", "--probe-complete"]
    # an unchanged core argv: template literals are constant, only the
    # placeholder slot carries caller data (which Layer 2 validated)
    audit = AuditLog(tmp_path / "a.jsonl")
    record = execute_adapter(reg, prep, sandbox=FakeSandbox(
        SpawnResult(ok=True, exit_code=0, stdout="ack")), audit=audit)
    assert record.executed is True
    assert record.verification == "not_verified"
    assert record.untrusted is True


# ---- 6. target scope validation -------------------------------------------------

def test_out_of_scope_targets_are_refused_at_preparation(tmp_path):
    reg = AdapterRegistry()
    reg.register(_curl_adapter())
    # an absolute URL aimed OUTSIDE the engagement host
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, "curl-probe", target=TARGET,
            target_asset="https://elsewhere.example.com/scan",
            subdomains=SUBDOMAINS)
    # an in-scope absolute URL is fine
    prep = prepare_adapter_run(
        reg, "curl-probe", target=TARGET,
        target_asset=f"http://{TARGET}/index.php",
        subdomains=SUBDOMAINS, params={"rate": "10"})
    assert "target-corp.com" in prep.target
    # a subdomain-alias asset composes inside scope too
    prep = prepare_adapter_run(
        reg, "curl-probe", target=TARGET,
        target_asset="https://mail.target-corp.com/",
        subdomains=SUBDOMAINS, params={"rate": "10"})
    assert "mail.target-corp.com" in prep.target


# ---- 7. approval enforcement -----------------------------------------------------

def test_hypothesis_gate_requires_a_real_approved_hypothesis(tmp_path):
    reg = AdapterRegistry()
    reg.register(_exploit_adapter())
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    h1 = [n for n in graph.by_type("hypothesis")
          if n["label"] == "H1"][0]
    prep = prepare_adapter_run(
        reg, "curl-exploit", target=TARGET,
        target_asset=f"http://{TARGET}/index.php",
        subdomains=SUBDOMAINS, params={"rate": "10"})
    fake = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout="ack"),
                       egress_policy=_StubEgressPolicy())
    # no grants at all -> refused, nothing spawned
    rec = execute_adapter(reg, prep, sandbox=fake, audit=audit,
                          graph=graph, hypothesis_id=h1["id"])
    assert rec.executed is False and rec.outcome == "refused"
    assert fake.spawned == []
    assert "approval gate" in rec.error_excerpt
    # granted but WITHOUT a real approved hypothesis -> still refused
    h2 = [n for n in graph.by_type("hypothesis") if n["label"] == "H2"][0]
    rec = execute_adapter(reg, prep, sandbox=fake, audit=audit,
                          graph=graph, hypothesis_id=h2["id"],
                          approvals_granted={"hypothesis_gate"})
    assert rec.executed is False
    assert "no approved hypothesis" in rec.error_excerpt
    assert fake.spawned == []
    # granted WITH the approved hypothesis -> the sandbox runs
    rec = execute_adapter(reg, prep, sandbox=fake, audit=audit,
                          graph=graph, hypothesis_id=h1["id"],
                          approvals_granted={"hypothesis_gate"},
                          )
    assert rec.executed is True
    assert fake.spawned and fake.spawned[0][0][0] == "curl"
    names = _event_names(audit)
    assert names.count("adapter_refused") == 2
    assert "adapter_spawn" in names and "adapter_result" in names


def test_post_exploit_gate_is_required_for_post_exploit_stage(tmp_path):
    reg = AdapterRegistry()
    reg.register(_curl_adapter(
        adapter_id="shell-followup",
        title="post-exploit follow-up probe",
        purpose="Impactful post-exploit-stage probe; Gate 3 governs it.",
        category="post_exploit",
        stages=("POST_EXPLOIT",),
        approvals=("post_exploit_gate",),
        risk="impactful",
    ))
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, "shell-followup", target=TARGET,
                               target_asset=f"http://{TARGET}/",
                               params={"rate": "10"})
    fake = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout="ack"),
                       egress_policy=_StubEgressPolicy())
    rec = execute_adapter(reg, prep, sandbox=fake, audit=audit)
    assert rec.executed is False and "post_exploit_gate" in \
        rec.error_excerpt
    assert fake.spawned == []
    rec = execute_adapter(reg, prep, sandbox=fake, audit=audit,
                          approvals_granted={"post_exploit_gate"})
    assert rec.executed is True


# ---- 8. sandbox unavailable ------------------------------------------------------

def test_missing_sandbox_refuses_without_host_fallback(tmp_path):
    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, "echo-probe", target=TARGET,
                               params={"term": "probe"})
    for bad_sandbox in (None, object()):   # none, and no-spawn blob
        rec = execute_adapter(reg, prep, sandbox=bad_sandbox, audit=audit)
        assert rec.executed is False and rec.outcome == "refused"
        assert "no sandbox" in rec.error_excerpt
    assert _event_names(audit).count("adapter_refused") == 2


# ---- 9. network-egress unavailable -------------------------------------------------

def test_target_touching_adapter_needs_the_egress_policy(tmp_path):
    reg = AdapterRegistry()
    reg.register(_curl_adapter())
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, "curl-probe", target=TARGET,
                               target_asset=f"http://{TARGET}/",
                               params={"rate": "10"})
    fake = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout="ack"))
    # sandbox WITHOUT the engagement egress boundary: refused with a
    # clear reason, before the (would-be-failing) spawn
    rec = execute_adapter(reg, prep, sandbox=fake, audit=audit)
    assert rec.executed is False and rec.outcome == "refused"
    assert "egress policy" in rec.error_excerpt
    assert fake.spawned == []
    assert _event_names(audit).count("adapter_refused") == 1


# ---- 10. no host execution fallback --------------------------------------------------

def test_no_host_execution_or_mcp_paths_in_the_adapter_module():
    """The adapter layer contains NO subprocess use and NO host-side MCP
    imports — the only spawn it can express is the sandbox's."""
    source = Path("src/kryonsec/purple/adapters.py").read_text(
        encoding="utf-8")
    assert "subprocess" not in source
    assert "mcp_registry" not in source
    assert "mcp_tools" not in source
    assert "import mcp" not in source


# ---- 11. timeout and output bounds -----------------------------------------------------

def test_per_call_timeout_is_requested_and_capped_by_the_sandbox(tmp_path):
    """The real KaliSandbox must never run a call LONGER than its own
    ceiling — an adapter's tighter bound is capped down (min semantics)."""
    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.sandbox import KaliSandbox

    captured = {}

    def fake_run(argv, capture_output, text, timeout):
        captured["timeout"] = timeout
        return FakeCompleted()

    class FakeCompleted:
        returncode = 0
        stdout = json.dumps(
            {"exit_code": 0, "stdout": ("x" * 4000)})
        stderr = ""

    cfg = KryonsecConfig(home=tmp_path)
    sbx = KaliSandbox(cfg, run_fn=fake_run, timeout_s=60)
    # adapter asks 45s (inside the 60s ceiling) — honored exactly
    sbx.spawn(["echo", "hi"], timeout_s=45)
    assert captured["timeout"] == 45
    # adapter asks 120s (above it) — capped to the sandbox's own bound
    sbx.spawn(["echo", "hi"], timeout_s=120)
    assert captured["timeout"] == 60


def test_timeout_failure_and_output_bounds_in_the_record(tmp_path):
    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, "echo-probe", target=TARGET,
                               params={"term": "probe"})
    fake = FakeSandbox(SpawnResult(
        ok=False, exit_code=-1, stdout="",
        error="tool exceeded 30s sandbox timeout"))
    rec = execute_adapter(reg, prep, sandbox=fake, audit=audit)
    assert rec.executed is False and rec.exit_code == -1
    assert "30s" in rec.error_excerpt and rec.truncated is False
    # a huge, secret-shaped output is bounded, redacted and untrusted
    # (the bearer-token fixture is locally generated placeholder
    # material — GitGuardian-safe — that still matches kryonsec's own
    # redactor patterns, so this redaction stays a real check)
    fake2 = FakeSandbox(SpawnResult(
        ok=True, exit_code=0, truncated=True,
        stdout="bearer KRYONFAKE0000000aaaaaaaaaaaaaaaaaaa "
              + "y" * 10000))
    rec = execute_adapter(reg, prep, sandbox=fake2, audit=audit)
    assert rec.executed is True
    assert len(rec.output_excerpt) <= 500
    fake_secret = "bearer KRYONFAKE0000000aaaaaaaaaaaaaaaaaaa"
    assert fake_secret not in rec.output_excerpt
    assert rec.truncated is True
    # the audit itself never carries raw tool output
    raw = open(audit.path, encoding="utf-8").read()
    assert "bearer KRYONFAKE0000000aaaaaaaaaaaaaaaaaaa" not in raw
    assert '"argv":' in raw              # argv is on the record by design


# ---- 12. malformed evidence --------------------------------------------------------------

def test_malformed_evidence_is_excluded_and_audited(tmp_path):
    graph = EngagementGraph(engagement_id="e-x")
    audit = AuditLog(tmp_path / "a.jsonl")
    graph.add_node("adapter_attempt", "junk-1", {
        "adapter_id": "echo-probe",
        # a node with missing RUN fields (no request_id/executed/argv)
        # is not schema-valid evidence
        "outcome": "attempted",
    })
    records, invalid = collect_adapter_evidence(graph, audit)
    assert records == [] and len(invalid) == 1
    assert "adapter_evidence_malformed" in _event_names(audit)


# ---- 13. duplicate registration ------------------------------------------------------------

def test_duplicate_registration_is_refused():
    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    with pytest.raises(DuplicateAdapterError):
        reg.register(_echo_adapter())
    # even a DIFFERENT adapter with the same id is refused (identity is
    # stable; silent re-pointing is never acceptable)
    with pytest.raises(DuplicateAdapterError):
        reg.register(_echo_adapter(title="A different echo probe"))


# ---- 14. isolation from host-side MCP servers ------------------------------------------------

def test_registry_cannot_reach_mode_a_or_the_global_allowlist():
    """Registering an adapter must not widen the Mode B global
    allowlist or touch the Mode A MCP stack."""
    from kryonsec.purple.allowlist import EXPLOIT_ALLOWLIST_TEMPLATES

    before = json.dumps(EXPLOIT_ALLOWLIST_TEMPLATES, sort_keys=True)
    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    reg.register(_curl_adapter())
    after = json.dumps(EXPLOIT_ALLOWLIST_TEMPLATES, sort_keys=True)
    assert before == after
    # the adapter's executable is absent from the DEFAULT allowlist
    assert "echo" not in EXPLOIT_ALLOWLIST_TEMPLATES
    # per-adapter allowlists are scoped to their own adapter only
    assert reg._allowlist("echo-probe")._compiled.keys() == {"echo"}


# ---- 15. compatibility with Exploit / Post-Exploit agents -------------------------------

def test_shipped_agents_are_unchanged_and_adapter_free(tmp_path):
    """The engine keeps its own deterministic path: a default
    ExploitSubagent run is untouched by an adapter registry."""
    import sys
    del sys

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.exploit import ExploitSubagent

    reg = AdapterRegistry()
    reg.register(_echo_adapter())
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    fake = FakeSandbox(SpawnResult(
        ok=True, exit_code=0, stdout="clean"))
    result = ExploitSubagent(cfg, graph, audit, TARGET, fake).run()
    assert result.status == "ok"
    result = ExploitSubagent(cfg, graph, audit, TARGET, fake).run()
    assert result.status == "ok"
    # the engine's route produced no adapter node in the engagement graph
    assert graph.by_type("adapter_attempt") == []
    # the subagent's DEFAULT allowlist knows no adapter tool
    from kryonsec.purple.allowlist import ToolAllowlist
    assert "echo-probe" not in ToolAllowlist()._compiled
    assert "echo" not in ToolAllowlist()._compiled


def test_e2e_registered_adapter_run_produces_linked_evidence(tmp_path):
    """End to end (with fakes): register -> prepare -> gated execution ->
    evidence node + lineage edge + audit chain, all schema-valid."""
    reg = AdapterRegistry()
    reg.register(_exploit_adapter())
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    h1 = [n for n in graph.by_type("hypothesis")
          if n["properties"].get("approved")][0]
    prep = prepare_adapter_run(
        reg, "curl-exploit", target=TARGET,
        target_asset=f"http://{TARGET}/index.php",
        subdomains=SUBDOMAINS, params={"rate": "10"})
    fake = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout="ack"),
                       egress_policy=_StubEgressPolicy())
    rec = execute_adapter(reg, prep, sandbox=fake, audit=audit,
                          graph=graph, hypothesis_id=h1["id"],
                          approvals_granted={"hypothesis_gate"})
    assert rec.executed is True
    nodes = graph.by_type("adapter_attempt")
    assert len(nodes) == 1
    props = nodes[0]["properties"]
    # the node's own record validates (schema-valid evidence only)
    restored = AdapterRunRecord.model_validate(props)
    assert restored.adapter_id == "curl-exploit"
    assert restored.verification == "not_verified"
    assert props["untrusted_note"].startswith("untrusted tool output")
    # lineage: hypothesis --tested_by--> adapter_attempt
    hyp_to_attempt = [e for e in graph.edges
                      if e.get("source_node_id") == h1["id"]
                      and e.get("relationship") == "tested_by"]
    assert hyp_to_attempt, "attempt must be linked to its hypothesis"
    # read-back with the collector: exactly one valid record
    records, invalid = collect_adapter_evidence(graph, audit)
    assert len(records) == 1 and invalid == []
    audit_ok, reason = audit.verify()
    assert audit_ok, reason
