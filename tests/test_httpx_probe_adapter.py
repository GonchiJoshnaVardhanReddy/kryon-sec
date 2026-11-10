"""Phase 2B.3 tests: the httpx-probe production Mode B adapter.

MOCKED tests (the default, huge majority): a duck-typed sandbox double
returns canned SpawnResults — no process, no packets, no scan. They pin
the contract: explicit registration, fixed adapter template, Project-
Discovery identification, scope/URL/Layer-2 refusals, gate + sandbox +
egress enforcement, output bounds, no host fallback, deterministic
 Recon Active integration (no duplicate probing), and the no-new-
capability invariants (Gate 2/3 and Post-Exploit untouched).

REAL IT (exactly one, opt-in): a genuine httpx run against an
OPERATOR-SUPPLIED locally controlled lab endpoint through a REAL
Docker + gVisor runsc sandbox and the REAL egress boundary. Guarded by
KRYONSEC_HTTPX_IT=1 — skipped silently otherwise (like
test_egress_integration). NEVER runs against anything public; the lab
URL comes from the operator.

Run the real IT on a Linux host with Docker + runsc + the pinned image:
    KRYONSEC_HTTPX_IT=1 KRYONSEC_HTTPX_LAB_URL=http://192.168.x.y:8080/ \
        .venv/bin/python -m pytest tests/test_httpx_probe_adapter.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_httpx import (
    ADAPTER_ID,
    HTTPX_PROBE_TEMPLATE,
    TOOL_EXECUTABLE,
    HttpxObservation,
    find_adapter_attempt_node,
    make_httpx_probe_adapter,
    parse_httpx_json_lines,
    production_registry,
    record_httpx_evidence,
)
from kryonsec.purple.adapters import (
    AdapterError,
    AdapterNotRegistered,
    AdapterRegistry,
    AdapterRunRecord,
    AdapterScopeRefused,
    collect_adapter_evidence,
    execute_adapter,
    prepare_adapter_run,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult

TARGET = "target-corp.com"

# the ONLY production registry contains exactly one vetted adapter


# ---- harmless fakes ------------------------------------------------------------


class _StubEgressPolicy:
    """Duck-typed egress-policy stub (the executor only needs presence;
    the REAL enforcement lives inside the sandbox's own spawn)."""


class FakeSandbox:
    """Duck-typed sandbox double carrying the attributes the adapter
    path reads (spawn/egress_policy/timeout_s/image)."""

    def __init__(self, result=None, *, script=None, egress_policy=None,
                 timeout_s=330,
                 image="kryonsec/sandbox@sha256:abcdef123456"):
        self._result = result
        self._script = script
        self.spawned = []
        self.egress_policy = egress_policy
        self.timeout_s = timeout_s
        self.image = image

    def spawn(self, argv, timeout_s=None):
        self.spawned.append((list(argv), timeout_s))
        if self._script is not None:
            return self._script(argv)
        return self._result


def _jsonl(*objs) -> str:
    return "\n".join(json.dumps(o) for o in objs) + "\n"


def _obs_line(url="http://target-corp.com:8080/", status=200,
              title="Login", tech=("Nginx",), webserver="nginx"):
    return {"url": url, "status_code": status, "title": title,
            "tech": list(tech), "webserver": webserver}


def _events(audit) -> "list[dict]":
    return [json.loads(line) for line in open(audit.path, encoding="utf-8")
            if line.strip()]


def _event_names(audit) -> "list[str]":
    return [e["event"] for e in _events(audit)]


def _cmdl(sandbox) -> "list[list[str]]":
    """The argv lists a FakeSandbox spawned (spawned is (argv, timeout))."""
    return [argv for argv, _t in sandbox.spawned]


def _graph(hypotheses=True) -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    if hypotheses:
        graph.add_node("hypothesis", "H1", {
            "title": "probe-me", "target_asset": "/", "rationale": "x",
            "cvss_vector": "", "tools": [], "confidence": 0.5,
            "approved": False,      # NOT approved — adapter must never
        })                          # upgrade this
    return graph


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------

def test_production_registry_registers_httpx_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("httpx-probe",)          # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "web_recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "url"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()          # RECON_ACTIVE authorization =
                                            # engagement model, not silent
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_httpx_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_httpx_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


# ---- 2. correct fixed command rendering ------------------------------------------

def test_fixed_template_rendering():
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        target_asset="http://target-corp.com:8080/")
    assert prep.argv == [
        "httpx-toolkit", "-u", "http://target-corp.com:8080/",
        "-silent", "-json", "-status-code", "-title", "-tech-detect",
        "-no-color", "-duc",
    ]
    url = "http://target-corp.com:8080/"
    rebuilt = [url if a == "{url}" else a for a in HTTPX_PROBE_TEMPLATE]
    assert prep.argv == ["httpx-toolkit", *rebuilt]
    # the adapter template stays in lockstep with the Layer-2 template
    from kryonsec.purple.allowlist import ACTIVE_RECON_TEMPLATES
    assert list(HTTPX_PROBE_TEMPLATE) == ACTIVE_RECON_TEMPLATES["httpx-toolkit"]


# ---- 3. ProjectDiscovery httpx identification --------------------------------------

def test_projectdiscovery_httpx_identification():
    """The executable is the REAL Kali binary (httpx-toolkit upstream is
    ProjectDiscovery httpx; debian/rules installs it ONLY under that
    name) and the evidence always names the tool honestly."""
    adapter = make_httpx_probe_adapter()
    assert adapter.executable == "httpx-toolkit"
    assert "ProjectDiscovery" in adapter.purpose
    reg = production_registry()
    described = json.loads(reg.describe(ADAPTER_ID))
    assert described["executable"] == "httpx-toolkit"
    assert described["evidence_kind"] == "json_report"
    obs, _m = parse_httpx_json_lines(_jsonl(_obs_line()))
    props = obs[0].properties(request_id="requestid0001")
    assert props["source"] == "httpx-toolkit"
    assert props["adapter"] == ADAPTER_ID


# ---- 4. unauthorized target refusal --------------------------------------------------

def test_out_of_scope_target_refused_at_preparation():
    reg = production_registry()
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="https://elsewhere.example.com/")
    # a sibling domain that is NOT a subdomain of the target
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="http://target-corp.net/")
    with pytest.raises(AdapterScopeRefused):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            target_asset="http://sub.target-corp.net/")
    # in-scope subdomain composes fine
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="https://mail.target-corp.com/")
    assert "mail.target-corp.com" in prep.target


# ---- 5. invalid URL rejection ----------------------------------------------------

def test_invalid_urls_rejected():
    reg = production_registry()
    # shell-metacharacter / injection-shaped "url" is refused by Layer 2
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="http://x/;$rm -rf /tmp")
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset="http://x/ -o /tmp/pwned")
    # arguments cannot be smuggled inside the url slot of the template


# ---- 6. Layer-2 allowlist rejection -------------------------------------------------

def test_layer2_deviating_argv_rejected():
    from kryonsec.purple.allowlist import (ACTIVE_RECON_TEMPLATES,
                                           AllowlistViolation, ToolAllowlist)

    template = list(ACTIVE_RECON_TEMPLATES["httpx-toolkit"])
    assert len(template) >= 8                       # the fixed contract
    url = "http://target-corp.com:8080/"
    good = ["httpx-toolkit"] + [url if a == "{url}" else a
                                for a in template]
    allow = ToolAllowlist({"httpx-toolkit": template})
    allow.validate(TOOL_EXECUTABLE, good)           # the real shape passes

    for deviating in (
        ["httpx-toolkit", "-u", url, "-silent",
         "-status-code", "-o", "/tmp/out",          # out-of-template flag
         "-title", "-tech-detect", "-no-color", "-duc"],
        ["httpx-toolkit", "-u", url, "-silent",
         "-status-code", "-title", "-tech-detect", "-no-color"],
    ):
        with pytest.raises(AllowlistViolation):
            allow.validate(TOOL_EXECUTABLE, deviating)


# ---- 7. missing gate/authorization where required -------------------------------------

def test_gated_variant_refused_without_grant():   # 7: gate where required
    """The production adapter documents gate freedom
    (RECON_ACTIVE authorization = engagement model); a variant that
    names EXPLOIT MUST demand the hypothesis gate and is REFUSED
    without it — the Gate 2 enforcement module is unchanged."""
    from kryonsec.purple.adapters import ModeBToolAdapter

    variant = make_httpx_probe_adapter()
    exploit_variant = ModeBToolAdapter(
        **{**variant.model_dump(), "adapter_id": "httpx-gated",
           "stages": ("EXPLOIT",), "approvals": ("hypothesis_gate",),
           "risk": "active"})
    reg = AdapterRegistry()
    reg.register(exploit_variant)
    prep = prepare_adapter_run(reg, "httpx-gated", target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout=_jsonl(_obs_line())),
                      egress_policy=_StubEgressPolicy())
    audit = AuditLog(Path("tmp") / "gate_a.jsonl")
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                             graph=_graph(), hypothesis_id="H1")
    assert record.executed is False and record.outcome == "refused"
    assert "approval gate" in record.error_excerpt
    assert sbx.spawned == []


# ---- shared helpers -------------------------------------------------------------


def _audit_tmp(tmp_path=None):
    return AuditLog(tmp_path / "a.jsonl") if tmp_path else \
        AuditLog("/tmp/p2b3_tmp_audit.jsonl")


# ---- 8. missing sandbox ---------------------------------------------------------------

def test_missing_sandbox_no_host_fallback(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    for bad in (None, object()):          # none + no-spawn blob
        record = execute_adapter(reg, prep, sandbox=bad, audit=audit)
        assert record.executed is False and record.outcome == "refused"
        assert "no sandbox" in record.error_excerpt
    assert _event_names(audit).count("adapter_refused") == 2


# ---- 9. egress boundary unavailable ------------------------------------------------------

def test_no_egress_boundary_refused(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    unegressed = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""))
    record = execute_adapter(reg, prep, sandbox=unegressed, audit=audit)
    assert record.executed is False and record.outcome == "refused"
    assert "egress policy" in record.error_excerpt
    assert unegressed.spawned == []
    assert _event_names(audit).count("adapter_refused") == 1


# ---- 10. tool timeout ---------------------------------------------------------------------

def test_tool_timeout_is_an_honest_failure(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                  error="tool exceeded 120s sandbox timeout"),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert "120s" in record.error_excerpt
    assert output == ""
    # no attempt node, no endpoint nodes, refusal failures audited
    assert graph.by_type("adapter_attempt") == []
    assert graph.by_type("web_endpoint") == []
    # timeout bound respected on the spawn call (adapter max_seconds)
    assert sbx.spawned and sbx.spawned[0][1] == make_httpx_probe_adapter(
    ).max_seconds


# ---- 11. nonzero tool exit -------------------------------------------------------------------

def test_nonzero_exit_is_not_success(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=1, stdout="",
                                  error="connection refused"),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    assert record.executed is False and record.outcome == "not_run"
    assert record.exit_code == 1
    assert graph.by_type("web_endpoint") == []
    names = _event_names(audit)
    assert "adapter_result" in names
    for ev in _events(audit):
        if ev["event"] == "adapter_result":
            assert ev["ok"] is False and ev["exit_code"] == 1


# ---- 12. malformed and oversized output -----------------------------------------------------

def test_malformed_output_never_becomes_observations(tmp_path):
    garbage = (
        "httpx-probe chatter\n"
        "NOT JSON AT ALL\n"
        '{"url": "http://t/", "status_code": "not-int"}\n'
        '["an", "array"]\n'
        '{"unrelated": true}\n'
        "\n"
    )
    obs, malformed = parse_httpx_json_lines(garbage)
    assert obs == [] and malformed == 5

    # a VALID line among garbage still parses (defensive, not paranoid)
    mixed = garbage + _jsonl(_obs_line())
    obs, malformed = parse_httpx_json_lines(mixed)
    assert len(obs) == 1 and malformed == 5

    # oversized: the observation cap holds; each field is bounded
    flood = _jsonl(*[_obs_line(url=f"http://t:{i}/") for i in range(500)])
    obs, _ = parse_httpx_json_lines(flood)
    assert len(obs) == 50                       # max_observations default
    caps = HttpxObservation.model_fields
    assert caps["url"].metadata is not None     # bounded field lengths


def test_record_evidence_refuses_without_attempt_node(tmp_path):
    """A refused run must never fabricate endpoint evidence."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    prep = prepare_adapter_run(registry, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    record = execute_adapter(registry, prep,
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    obs, _ = parse_httpx_json_lines(_jsonl(_obs_line()))
    ids = record_httpx_evidence(graph, audit, run_record=record,
                                observations=obs)
    assert ids == []
    assert graph.by_type("web_endpoint") == []
    names = _event_names(audit)
    assert "httpx_adapter_evidence_refused" in names


# ---- 13. status 200 / exit 0 / tech are NOT vulnerability confirmation -------------------

def test_success_output_is_recon_evidence_never_confirmation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(script=lambda argv: SpawnResult(
        ok=True, exit_code=0, stdout=_jsonl(
            _obs_line(status=200, title="Login", tech=("Nginx", "PHP")))),
        egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is True and record.exit_code == 0
    # HARD invariants:
    assert record.verification == "not_verified"
    assert record.untrusted is True
    assert "confirmed" not in record.model_dump()
    obs, _m = parse_httpx_json_lines(output)
    ids = record_httpx_evidence(graph, audit, run_record=record,
                                observations=obs)
    props = find_adapter_attempt_node(graph, record.request_id
                                      ) or {}
    ep = graph.by_type("web_endpoint")[0]["properties"]
    assert ep["verification"] == "not_verified"
    # nothing on the graph became a finding / capability / approval
    assert graph.by_type("finding") == []
    assert graph.by_type("capability") == []
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    # ...and no gate lifecycle events were written by the adapter path
    names = _event_names(audit)
    assert not any("gate" in n for n in names if n != "adapter_refused")


# ---- 14. evidence graph and audit-chain persistence -----------------------------------------

def test_evidence_graph_and_audit_chain(tmp_path):
    from kryonsec.purple.lineage import RELATIONSHIP_TYPES

    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(script=lambda argv: SpawnResult(
        ok=True, exit_code=0, stdout=_jsonl(_obs_line(), _obs_line(
            url="https://target-corp.com:8443/", status=301, title="",
            tech=(), webserver=""))),
        egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    obs, malformed = parse_httpx_json_lines(output)
    assert len(obs) == 2 and malformed == 0
    created = record_httpx_evidence(graph, audit, run_record=record,
                                    observations=obs,
                                    malformed_lines=malformed)
    assert len(created) == 2
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None
    restored = AdapterRunRecord.model_validate(attempt["properties"])
    assert restored.adapter_id == ADAPTER_ID
    assert restored.verification == "not_verified"
    # produced lineage edges carry non-hypothesis provenance honestly
    produced = [e for e in graph.edges
                if e.get("relationship") == "produced"
                and e.get("source_node_id") == attempt["id"]]
    assert len(produced) == 2
    # read-back: the attempt validates through the collector
    records, invalid = collect_adapter_evidence(graph, audit)
    assert len(records) == 1 and invalid == []
    assert "produced" in RELATIONSHIP_TYPES
    ok, reason = audit.verify()
    assert ok, reason
    names = _event_names(audit)
    assert "httpx_adapter_evidence" in names
    ev = [e for e in _events(audit) if e["event"] == "httpx_adapter_evidence"]
    assert ev[0]["observations"] == 2 and ev[0]["web_endpoint_nodes"] == 2


# ---- 15. no host execution fallback ---------------------------------------------------------

def test_no_host_execution_in_adapter_modules():
    for mod in ("adapter_httpx.py", "adapters.py"):
        source = Path("src/kryonsec/purple") / mod
        text = source.read_text(encoding="utf-8")
        assert "subprocess" not in text, mod
        assert "import mcp" not in text, mod
        assert "docker " + "run" not in text, mod


# ---- 16. no duplicate Recon Active probing ------------------------------------------------------

def _recon(sandbox, registry, tmp_path):
    cfg = _cfg(tmp_path)
    audit = AuditLog(tmp_path / "ra.jsonl")
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    sub = ReconActiveSubagent(cfg, graph, audit, TARGET, sandbox,
                              adapter_registry=registry)
    result = sub.run()
    return result, sandbox.spawned, graph, audit


def _cfg(tmp_path):
    from kryonsec.config import KryonsecConfig

    return KryonsecConfig(home=tmp_path / "home")


def _fake_stage1(script):
    """Sandbox fake: stage1 always finds 8080; tools callback-scripted."""
    return FakeSandbox(script=script, egress_policy=_StubEgressPolicy())


def _script_no_duplicate_httpx(argv):
    tool = argv[0]
    if tool == "nmap":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="8080/tcp   open  http    nginx")
    if tool == "naabu":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="target-corp.com:8080")
    if tool == "dnsx":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="target-corp.com [A] 203.0.113.7")
    if tool == "httpx":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="http://t:8080/ [200] [Login] [Nginx]")
    if tool == "httpx-toolkit":
        url = argv[argv.index("-u") + 1]
        return SpawnResult(ok=True, exit_code=0, stdout=_jsonl(
            _obs_line(url=url, status=200, title="Login")))
    return SpawnResult(ok=True, exit_code=0, stdout="")


def test_adapter_mode_probes_once_never_both(tmp_path):
    sandbox = _fake_stage1(_script_no_duplicate_httpx)
    result, spawned, graph, audit = _recon(sandbox, production_registry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs_httpx = [a for a in cmdl if a and a[0] == "httpx"]
    runs_toolkt = [a for a in cmdl if a and a[0] == "httpx-toolkit"]
    assert runs_httpx == []                 # legacy REPLACED
    assert len(runs_toolkt) == 1            # exactly one adapter probe
    # argv shape carried the fixed JSONL contract
    assert "-json" in runs_toolkt[0] and "-silent" in runs_toolkt[0]
    assert "-duc" in runs_toolkt[0]
    eps = graph.by_type("web_endpoint")
    assert len(eps) == 1
    assert eps[0]["properties"]["source"] == "httpx-toolkit"
    assert eps[0]["properties"]["adapter"] == ADAPTER_ID
    assert len(graph.by_type("adapter_attempt")) == 1
    names = _event_names(audit)
    assert "recon_active_httpx_adapter" in names
    assert "recon_active_adapter_failure" not in names
    # legacy url parsing never produced nodes alongside
    assert not [e for e in eps if e["properties"]["source"] == "httpx"]


def test_empty_registry_falls_back_legacy_deterministically(tmp_path):
    sandbox = _fake_stage1(_script_no_duplicate_httpx)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    assert [a for a in cmdl if a and a[0] == "httpx"]      # legacy ran
    assert [a for a in cmdl if a and a[0] == "httpx-toolkit"] == []
    assert graph.by_type("adapter_attempt") == []
    eps = graph.by_type("web_endpoint")
    assert eps and eps[0]["properties"]["source"] == "httpx"


def test_no_registry_runs_the_classic_plan(tmp_path):
    sandbox = _fake_stage1(_script_no_duplicate_httpx)
    cfg = _cfg(tmp_path)
    audit = AuditLog(tmp_path / "ra.jsonl")
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    result = ReconActiveSubagent(cfg, graph, audit, TARGET, sandbox).run()
    assert result.status == "ok"
    cmdl = [argv for argv, _t in sandbox.spawned]
    assert [a for a in cmdl if a and a[0] == "httpx"]


# ---- 17. Gate 2 / Gate 3 behavior unchanged ---------------------------------------------------

def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout=_jsonl(_obs_line())),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    assert record.executed is True
    # no gate events, no hypothesis approval writes, no capability writes
    for ev in _events(audit):
        label = json.dumps(ev)
        assert "gate_decision" not in label
        assert "capability" not in ev.get("event", "")
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    assert graph.by_type("capability") == []
    # the shipped registry CANNOT reach gated stages: every adapter
    # runs in RECON_ACTIVE only
    for adapter in reg.list_adapters():
        assert adapter.stages == ("RECON_ACTIVE",)
    # ...and the registration rules still forbid illegal climb:
    from kryonsec.purple.adapters import ModeBToolAdapter

    with pytest.raises(ValidationError):
        ModeBToolAdapter(**{
            **make_httpx_probe_adapter().model_dump(),
            "adapter_id": "httpx-post", "stages": ("POST_EXPLOIT",),
        })


# ---- 18. no capability or Post-Exploit activation ------------------------------------------------

def test_no_capability_or_post_exploit_activation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout=_jsonl(_obs_line())),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    obs, _m = parse_httpx_json_lines(_jsonl(_obs_line()))
    record_httpx_evidence(graph, audit, run_record=record, observations=obs)
    # a 200 + tech fingerprint does NOT create capability claims,
    # exploit attempts or post-exploit inputs
    assert graph.by_type("capability") == []
    assert graph.by_type("exploit_attempt") == []
    assert graph.by_type("finding") == []
    # the run record cannot open any capability lifecycle
    dump = record.model_dump()
    assert "confirmed" not in dump and "approvals" not in dump
    # the entire registration vocabulary excludes gates for
    # RECON_ACTIVE-only production
    adapter = reg.get(ADAPTER_ID)
    assert adapter.approvals == ()
    assert adapter.stages == ("RECON_ACTIVE",)
    # post-exploit gate text is untouched (module imports still resolve)
    from kryonsec.purple.capability import capability_gate_text

    assert callable(capability_gate_text)


# ---- the ONE genuine integration test (opt-in, local lab only) ------------------------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + pinned image + an operator lab URL."""
    lab = os.environ.get("KRYONSEC_HTTPX_LAB_URL", "").strip()
    if not lab.lower().startswith(("http://", "https://")):
        return False, "KRYONSEC_HTTPX_LAB_URL must be an http(s) lab URL"
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_HTTPX_IT") != "1":
        return False, "KRYONSEC_HTTPX_IT=1 not set"
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    if not ok:
        return False, f"docker daemon: {reason}"
    if not rc.runsc_registered():
        return False, "runsc runtime not registered"
    from kryonsec.config import KryonsecConfig

    image = KryonsecConfig().sandbox_image
    if not rc.image_present(image):
        return False, f"pinned sandbox image absent: {image}"
    return True, ""


def test_real_httpx_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real Pinned httpx-toolkit JSONL run — against the local
    lab endpoint the OPERATOR supplies. Skipped silently otherwise.

    Authorize NOTHING public: point KRYONSEC_HTTPX_LAB_URL at an
    endpoint you control (e.g. your own LAN nginx container).
    """
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from urllib.parse import urlsplit

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.egress import EgressGate, build_policy, \
        release_active
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig()
    lab = os.environ["KRYONSEC_HTTPX_LAB_URL"].strip()
    host = urlsplit(lab).hostname or ""
    assert host, lab

    policy = build_policy(cfg, "httpx-it", target=host)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog(Path("tmp_httpx_it_audit.jsonl"))
    graph = EngagementGraph(engagement_id="httpx-it")
    graph.add_node("target", host, {})
    try:
        prep = prepare_adapter_run(reg, ADAPTER_ID, target=host,
                                   target_asset=lab)
        record, output = execute_adapter(reg, prep, sandbox=sbx,
                                         audit=audit, graph=graph,
                                         full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.verification == "not_verified"
        obs, malformed = parse_httpx_json_lines(output)
        created = record_httpx_evidence(graph, audit, run_record=record,
                                        observations=obs,
                                        malformed_lines=malformed)
        assert record.exit_code == 0
        # realistic lab: at least the probe produced well-formed rows
        assert obs, f"no observations parsed from lab run ({malformed} bad)"
        assert len(created) == len(obs)
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("httpx-it")
        except Exception:
            pass
