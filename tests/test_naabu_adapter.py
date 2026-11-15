"""Tool Expansion Batch 1 tests: the naabu-probe production Mode B
adapter.

MOCKED tests (the default, huge majority): a duck-typed sandbox double
returns canned SpawnResults — no process, no packets, no scan. They pin
the contract: explicit registration (single + combined RECON_ACTIVE
registry), the byte-identical fixed template with the LANE-PINNED port
list and rate (no full-range scan, no rate escalation — spec §9.1),
preparation refusals, gate + sandbox + egress enforcement, output
bounds, honest failure classification, no host fallback, deterministic
Recon Active integration (the adapter REPLACES the legacy naabu
discovery entry; exactly one scan per state; ports merge into the
shared open_ports set with NO graph nodes of its own — legacy parity),
planner integration (covered post-hoc), and the no-new-capability
invariants (Gate 2/3 and Post-Exploit untouched).

REAL IT (exactly one, opt-in): a genuine naabu run against an
OPERATOR-SUPPLIED locally controlled lab target through a REAL Docker +
gVisor runsc sandbox and the REAL egress boundary. Guarded by
KRYONSEC_NAABU_IT=1 — skipped silently otherwise. NEVER runs against
anything public; the lab target comes from the operator. An empty port
list is an honest INCONCLUSIVE, never a failure mask.

Run the real IT on a Linux host with Docker + runsc + the pinned image:
    KRYONSEC_NAABU_IT=1 KRYONSEC_NAABU_LAB_TARGET=lab-host.example \
        KRYONSEC_SANDBOX_IMAGE='<digest-pinned-image>' \
        .venv/bin/python -m pytest tests/test_naabu_adapter.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_naabu import (
    ADAPTER_ID,
    NAABU_PROBE_TEMPLATE,
    NAABU_ADAPTER_ID,
    TOOL_EXECUTABLE,
    NaabuObservation,
    find_adapter_attempt_node,
    make_naabu_probe_adapter,
    parse_naabu_lines,
    production_registry,
    record_naabu_evidence,
)
from kryonsec.purple.adapter_whatweb import recon_active_registry
from kryonsec.purple.adapters import (
    AdapterError,
    AdapterNotRegistered,
    AdapterRegistry,
    AdapterRunRecord,
    execute_adapter,
    prepare_adapter_run,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import RECON_PORTS, ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.tool_planner import ToolCapabilityCatalog, \
    ToolPlanner

TARGET = "target-corp.com"


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


def _events(audit) -> "list[dict]":
    return [json.loads(line) for line in open(audit.path, encoding="utf-8")
            if line.strip()]


def _event_names(audit) -> "list[str]":
    return [e["event"] for e in _events(audit)]


def _graph() -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    graph.add_node("hypothesis", "H1", {
        "title": "probe-me", "target_asset": "/", "rationale": "x",
        "cvss_vector": "", "tools": [], "confidence": 0.5,
        "approved": False,          # NOT approved — adapter must never
    })                              # upgrade this
    return graph


def _cfg(tmp_path):
    from kryonsec.config import KryonsecConfig

    return KryonsecConfig(home=tmp_path / "home")


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------

def test_production_registry_registers_naabu_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("naabu-probe",)          # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "domain"
    assert adapter.executable == "naabu"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()          # RECON_ACTIVE authorization =
                                            # engagement model, not silent
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_naabu_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_naabu_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_naabu_probe():
    reg = recon_active_registry()
    assert "naabu-probe" in reg.adapter_ids()
    adapter = reg.get(NAABU_ADAPTER_ID)
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.approvals == ()
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"


# ---- 2. correct fixed command rendering + byte-identical lockstep ---------------

def test_fixed_template_rendering():
    """The lane pins ports/rate to the SAME constants the legacy
    discovery entry uses; the rendered argv is byte-identical to it."""
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    assert prep.argv == ["naabu", "-host", TARGET, "-p", RECON_PORTS,
                         "-rate", "100", "-silent"]
    assert prep.target == TARGET
    assert prep.target_kind == "domain"


def test_template_is_byte_identical_to_the_shipped_layer2_template():
    """The adapter adds NO flag the legacy naabu entry does not carry:
    the argv it renders validates against the SHIPPED Layer-2 template
    unchanged, and no extra switches can ever appear."""
    from kryonsec.purple.allowlist import (ACTIVE_RECON_TEMPLATES,
                                           ToolAllowlist)

    assert list(NAABU_PROBE_TEMPLATE) == \
        list(ACTIVE_RECON_TEMPLATES["naabu"])
    shipped = ToolAllowlist(dict(ACTIVE_RECON_TEMPLATES))
    shipped.validate(TOOL_EXECUTABLE,
                     ["naabu", "-host", TARGET, "-p", RECON_PORTS,
                      "-rate", "100", "-silent"])
    # the template carries EXACTLY the legacy flag set — nothing extra
    flags = [a for a in NAABU_PROBE_TEMPLATE if a.startswith("-")]
    assert flags == ["-host", "-p", "-rate", "-silent"]


# ---- 3. identification ------------------------------------------------------------

def test_naabu_identification():
    """The executable is the REAL bundled binary (entrypoint-allowlisted
    in the pinned sandbox image) and the evidence names the tool."""
    adapter = make_naabu_probe_adapter()
    assert adapter.executable == "naabu"
    assert "naabu" in adapter.purpose
    reg = production_registry()
    described = json.loads(reg.describe(ADAPTER_ID))
    assert described["executable"] == "naabu"
    assert described["evidence_kind"] == "text_excerpt"


# ---- 4. preparation refusals --------------------------------------------------------

def test_placeholders_and_option_shaped_values_refused():
    reg = production_registry()
    # a domain adapter without the engagement target is refused
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target="   ",
                            params={"ports": RECON_PORTS, "rate": "100"})
    # the template's placeholders REQUIRE explicit params (the lane
    # pins them) — all-or-nothing, never defaults
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET)
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            params={"ports": RECON_PORTS})
    # unexpected params are refused
    with pytest.raises(AdapterError):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            params={"ports": RECON_PORTS, "rate": "100", "extra": "x"})
    # option-shaped caller input is refused (option injection): no
    # value may begin with '-'
    with pytest.raises(AdapterError):
        prepare_adapter_run(
            reg, ADAPTER_ID, target="-host",
            params={"ports": RECON_PORTS, "rate": "100"})
    with pytest.raises(AdapterError):
        prepare_adapter_run(
            reg, ADAPTER_ID, target=TARGET,
            params={"ports": "-p", "rate": "100"})


# ---- 5. missing gate/authorization where required -------------------------------------

def test_gated_variant_refused_without_grant(tmp_path):
    """A variant that names EXPLOIT MUST demand the hypothesis gate and
    is REFUSED without it — the Gate 2 enforcement module is unchanged."""
    from kryonsec.purple.adapters import ModeBToolAdapter

    variant = make_naabu_probe_adapter()
    exploit_variant = ModeBToolAdapter(
        **{**variant.model_dump(), "adapter_id": "naabu-gated",
           "stages": ("EXPLOIT",), "approvals": ("hypothesis_gate",),
           "risk": "active"})
    reg = AdapterRegistry()
    reg.register(exploit_variant)
    prep = prepare_adapter_run(
        reg, "naabu-gated", target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    audit = AuditLog(Path("tmp") / "gate_a.jsonl")
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                             graph=_graph(), hypothesis_id="H1")
    assert record.executed is False and record.outcome == "refused"
    assert "approval gate" in record.error_excerpt
    assert sbx.spawned == []


# ---- 6. missing sandbox ---------------------------------------------------------------

def test_missing_sandbox_no_host_fallback(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    for bad in (None, object()):          # none + no-spawn blob
        record = execute_adapter(reg, prep, sandbox=bad, audit=audit)
        assert record.executed is False and record.outcome == "refused"
        assert "no sandbox" in record.error_excerpt
    assert _event_names(audit).count("adapter_refused") == 2


# ---- 7. egress boundary unavailable ------------------------------------------------------

def test_no_egress_boundary_refused(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    unegressed = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""))
    record = execute_adapter(reg, prep, sandbox=unegressed, audit=audit)
    assert record.executed is False and record.outcome == "refused"
    assert "egress policy" in record.error_excerpt
    assert unegressed.spawned == []
    assert _event_names(audit).count("adapter_refused") == 1


# ---- 8. tool timeout / nonzero exit — honest failures --------------------------------------

def test_tool_timeout_is_an_honest_failure(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                  error="tool exceeded 120s sandbox timeout"),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert record.failure_class == "timeout"
    assert output == ""
    # no attempt node (and the adapter never creates any node of its own)
    assert graph.by_type("adapter_attempt") == []
    # timeout bound respected on the spawn call (adapter max_seconds)
    assert sbx.spawned and sbx.spawned[0][1] == \
        make_naabu_probe_adapter().max_seconds


def test_nonzero_exit_is_not_success(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=1, stdout="",
                                  error="host unreachable"),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    assert record.executed is False and record.outcome == "not_run"
    assert record.exit_code == 1
    assert record.verification == "not_verified"
    names = _event_names(audit)
    assert "adapter_result" in names
    for ev in _events(audit):
        if ev["event"] == "adapter_result":
            assert ev["ok"] is False and ev["exit_code"] == 1


# ---- 9. malformed and oversized output -----------------------------------------------------

def test_malformed_output_never_becomes_observations():
    garbage = (
        # banner/noise lines — not results
        "naabu 2.3.1\n"
        "NOT A HOST:PORT LINE\n"
        # a scan error that slipped through -silent
        "naabu error: sendto: permission denied\n"
        # an out-of-range port
        "target-corp.com:99999\n"
        "\n"
    )
    obs, malformed = parse_naabu_lines(garbage)
    assert obs == [] and malformed == 4

    # a VALID line among garbage still parses (defensive, not paranoid)
    obs, malformed = parse_naabu_lines(garbage + "target-corp.com:8080\n")
    assert [o.port for o in obs] == [8080] and malformed == 4

    # duplicate ports collapse to the first observation
    obs, _m = parse_naabu_lines("t:80\nt:80\n")
    assert [o.port for o in obs] == [80]

    # oversized: the observation cap holds; fields are bounded
    flood = "\n".join(f"t:{p}" for p in range(1, 300))
    obs, _ = parse_naabu_lines(flood)
    assert len(obs) == 100                     # max_observations default
    caps = NaabuObservation.model_fields
    assert caps["port"].metadata is not None   # bounded field lengths


# ---- 10. evidence recording: legacy parity (no nodes of its own) ---------------

def test_record_evidence_refuses_without_attempt_node(tmp_path):
    """A refused run must never leave fabricated port evidence behind —
    audited, then nothing (there are no nodes)."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    prep = prepare_adapter_run(
        registry, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    record = execute_adapter(registry, prep,
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    obs, _ = parse_naabu_lines("target-corp.com:8080\n")
    ids = record_naabu_evidence(graph, audit, run_record=record,
                                observations=obs)
    assert ids == []
    assert graph.by_type("adapter_attempt") == []
    names = _event_names(audit)
    assert "naabu_adapter_evidence_refused" in names


def test_evidence_is_legacy_parity_no_graph_nodes(tmp_path):
    """The run's adapter_attempt node (created by execute_adapter) is
    the graph evidence; the parse adds NO node of its own — the ports
    flow back to the caller's port set (legacy parity)."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    prep = prepare_adapter_run(
        registry, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    stdout = "target-corp.com:8080\ntarget-corp.com:443\n"
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=stdout),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(
        registry, prep, sandbox=sbx, audit=audit, graph=graph,
        full_output=True)
    obs, malformed = parse_naabu_lines(output)
    assert [o.port for o in obs] == [443, 8080]
    assert malformed == 0
    created = record_naabu_evidence(graph, audit, run_record=record,
                                    observations=obs,
                                    malformed_lines=malformed)
    assert created == []                        # ALWAYS — parity
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None
    restored = AdapterRunRecord.model_validate(attempt["properties"])
    assert restored.adapter_id == ADAPTER_ID
    assert restored.verification == "not_verified"
    # exactly ONE new node on the graph: the attempt itself
    assert len(graph.by_type("adapter_attempt")) == 1
    ev = [e for e in _events(audit)
          if e["event"] == "naabu_adapter_evidence"]
    assert ev[0]["ports"] == [443, 8080]
    assert ev[0]["graph_nodes"] == 0
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_port_run_is_an_honest_inconclusive(tmp_path):
    """A clean scan that found NOTHING is audited with zero ports —
    never a negative 'no open ports' claim."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    prep = prepare_adapter_run(
        registry, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(
        registry, prep, sandbox=sbx, audit=audit, graph=graph,
        full_output=True)
    obs, _m = parse_naabu_lines(output)
    record_naabu_evidence(graph, audit, run_record=record,
                          observations=obs)
    ev = [e for e in _events(audit)
          if e["event"] == "naabu_adapter_evidence"]
    assert ev[0]["ports"] == []
    assert ev[0]["graph_nodes"] == 0


# ---- 11. status/exit is NOT vulnerability confirmation -----------------------

def test_open_port_is_recon_evidence_never_confirmation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout="target-corp.com:8080"),
                      egress_policy=_StubEgressPolicy())
    record, _output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                      graph=graph, full_output=True)
    assert record.executed is True and record.exit_code == 0
    # HARD invariants:
    assert record.verification == "not_verified"
    assert record.untrusted is True
    assert "confirmed" not in record.model_dump()
    obs, _m = parse_naabu_lines("target-corp.com:8080")
    record_naabu_evidence(graph, audit, run_record=record, observations=obs)
    # nothing on the graph became a finding / capability / approval
    assert graph.by_type("finding") == []
    assert graph.by_type("capability") == []
    assert graph.by_type("service") == []       # nmap's node type: untouched
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    # ...and no gate lifecycle events were written by the adapter path
    names = _event_names(audit)
    assert not any("gate" in n for n in names if n != "adapter_refused")


# ---- 12. no host execution fallback ---------------------------------------------------------

def test_no_host_execution_in_adapter_module():
    source = Path("src/kryonsec/purple") / "adapter_naabu.py"
    text = source.read_text(encoding="utf-8")
    assert "subprocess" not in text
    assert "import mcp" not in text
    assert "docker " + "run" not in text


# ---- 13. no duplicate Recon Active scan (deterministic either/or) ----------------------

def _recon(sandbox, registry, tmp_path, *, planner=None):
    cfg = _cfg(tmp_path)
    audit = AuditLog(tmp_path / "ra.jsonl")
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    sub = ReconActiveSubagent(cfg, graph, audit, TARGET, sandbox,
                              adapter_registry=registry, planner=planner)
    result = sub.run()
    return result, sandbox.spawned, graph, audit


def _script_discovery_and_web(argv):
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
    if tool == "httpx-toolkit":
        url = argv[argv.index("-u") + 1]
        return SpawnResult(ok=True, exit_code=0, stdout=(
            json.dumps({"url": url, "status_code": 200,
                        "title": "Login", "tech": ["Nginx"],
                        "webserver": "nginx"}) + "\n"))
    return SpawnResult(ok=True, exit_code=0, stdout="")


def _fake_stage1(script):
    return FakeSandbox(script=script, egress_policy=_StubEgressPolicy())


def test_adapter_mode_scans_naabu_once_never_both(tmp_path):
    """DETERMINISTIC either/or: the legacy naabu discovery entry is
    REPLACED by the adapter run — exactly ONE naabu spawn per state,
    and its ports flow into the SAME shared set the web bases derive
    from (the 8080 base gets probed)."""
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(sandbox, recon_active_registry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs = [a for a in cmdl if a and a[0] == "naabu"]
    assert len(runs) == 1
    assert runs[0] == ["naabu", "-host", TARGET, "-p", RECON_PORTS,
                       "-rate", "100", "-silent"]
    # the port the adapter found drove the stage-2 base: one web probe
    # against http://target-corp.com:8080/
    web = [a for a in cmdl if a and a[0] == "httpx-toolkit"]
    assert len(web) == 1
    assert web[0][web[0].index("-u") + 1] == "http://target-corp.com:8080/"
    # legacy parity: the naabu lane adds NO service/port graph nodes —
    # the ONLY service node is the one nmap's authoritative parse
    # created (source: "nmap"); its label pins port/proto
    services = graph.by_type("service")
    assert [s["label"] for s in services] == \
        [f"{TARGET}:8080/tcp"]
    assert all(s["properties"].get("source") == "nmap"
               for s in services)
    names = _event_names(audit)
    assert "recon_active_naabu_adapter" in names
    assert "recon_active_naabu" not in names   # the legacy parse event
    assert "recon_active_adapter_failure" not in names
    ev = [e for e in _events(audit)
          if e["event"] == "recon_active_naabu_adapter"]
    assert ev[0]["open_ports"] == [8080]


def test_empty_registry_falls_back_legacy_deterministically(tmp_path):
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    assert [a for a in cmdl if a and a[0] == "naabu"] != []
    assert graph.by_type("adapter_attempt") == []
    assert "recon_active_naabu_adapter" not in _event_names(audit)


# ---- 14. planner integration (covered post-hoc) ----------------------------------------------

def _plan_triples(decided_event):
    """Parse the planning_decided summary lines into (status, adapter,
    target) triples."""
    out = []
    for line in decided_event.get("entries", []):
        parts = line.split()
        if len(parts) >= 3:
            out.append((parts[0].strip(), parts[1].strip(),
                        parts[2].strip()))
    return out


def test_planner_reports_the_scan_covered_post_hoc(tmp_path):
    """The naabu lane runs BEFORE the plan (it needs the observed
    ports); a plan built afterwards reports the fresh successful run as
    covered — targeting the ENGAGEMENT DOMAIN, never a URL base."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()))
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, _spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    events = _events(audit)
    decided = next(e for e in events if e["event"] == "planning_decided")
    triples = _plan_triples(decided)
    assert any(a == "naabu-probe" and t == TARGET
               for _s, a, t in triples)
    assert not any(t.startswith("http")
                   for _s, a, t in triples if a == "naabu-probe")
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert not any("naabu-probe" in ln
                   for ln in done["planned_not_executed"])
    ok, reason = audit.verify()
    assert ok, reason


def test_failed_scan_is_not_coverage(tmp_path):
    """A FAILED scan is never reported as covered: its plan entry stays
    eligible and the done event honestly lists it as planned-but-not-
    executed (the check did not complete)."""
    def script(argv):
        r = _script_discovery_and_web(argv)
        if argv[0] == "naabu":
            return SpawnResult(ok=False, exit_code=1, stdout="",
                               error="sendto: permission denied")
        return r

    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()))
    sandbox = _fake_stage1(script)
    result, _spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    events = _events(audit)
    names = [e["event"] for e in events]
    assert "recon_active_adapter_failure" in names
    decided = next(e for e in events if e["event"] == "planning_decided")
    triples = _plan_triples(decided)
    assert any(a == "naabu-probe" and t == TARGET
               for _s, a, t in triples)      # eligible, not covered
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert any("naabu-probe" in ln
               for ln in done["planned_not_executed"])


# ---- 15. Gate 2 / Gate 3 behavior unchanged ---------------------------------------------------

def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        params={"ports": RECON_PORTS, "rate": "100"})
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout="target-corp.com:8080"),
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
            **make_naabu_probe_adapter().model_dump(),
            "adapter_id": "naabu-post", "stages": ("POST_EXPLOIT",),
        })


# ---- the ONE genuine integration test (opt-in, local lab only) ------------------------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab
    target."""
    lab = os.environ.get("KRYONSEC_NAABU_LAB_TARGET", "").strip()
    if not lab or lab.startswith("-"):
        return False, ("KRYONSEC_NAABU_LAB_TARGET must be a lab host "
                       "you control")
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_NAABU_IT") != "1":
        return False, "KRYONSEC_NAABU_IT=1 not set"
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    if not ok:
        return False, f"docker daemon: {reason}"
    if not rc.runsc_registered():
        return False, "runsc runtime not registered"
    from kryonsec.config import KryonsecConfig

    image = KryonsecConfig().sandbox_image
    if "@sha256:" not in image:
        return False, ("sandbox image is not digest-pinned in this "
                       "environment (rule 7) — set KRYONSEC_SANDBOX_IMAGE")
    if not rc.image_present(image):
        return False, f"pinned sandbox image absent: {image}"
    return True, ""


def test_real_naabu_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real naabu port scan — against the lab host the OPERATOR
    supplies. Skipped silently otherwise.

    Authorize NOTHING public: point KRYONSEC_NAABU_LAB_TARGET at a host
    you control (e.g. a lab container on your own Docker bridge). An
    empty port list from a clean run is an honest INCONCLUSIVE (the
    assertion below allows it) — never a failure mask.
    """
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.egress import EgressGate, build_policy, \
        release_active
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig()
    lab = os.environ["KRYONSEC_NAABU_LAB_TARGET"].strip()

    policy = build_policy(cfg, "naabu-it", target=lab)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_naabu_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="naabu-it")
    graph.add_node("target", lab, {})
    try:
        prep = prepare_adapter_run(
            reg, ADAPTER_ID, target=lab,
            params={"ports": RECON_PORTS, "rate": "100"})
        record, output = execute_adapter(reg, prep, sandbox=sbx,
                                         audit=audit, graph=graph,
                                         full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.exit_code == 0
        assert record.verification == "not_verified"
        obs, malformed = parse_naabu_lines(output)
        record_naabu_evidence(graph, audit, run_record=record,
                              observations=obs,
                              malformed_lines=malformed)
        # honest either way: ports found or an inconclusive scan — the
        # graph carries exactly the run's attempt node, nothing more
        assert len(graph.by_type("adapter_attempt")) == 1
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("naabu-it")
        except Exception:
            pass
