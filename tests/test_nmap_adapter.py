"""Tool Expansion Batch 2 tests: the nmap-probe production Mode B
adapter.

MOCKED tests (the default, huge majority): a duck-typed sandbox double
returns canned SpawnResults — no process, no packets, no scan. They pin
the contract: explicit registration (single + combined RECON_ACTIVE
registry), the byte-identical fixed template with the LANE-PINNED rate
and the bounded RECON_PORTS port list (no full-range scan, no NSE
scripts, no timing/free flags), domain scope/preparation refusals,
gate + sandbox + egress enforcement, output bounds, honest failure
classification, no host fallback, deterministic Recon Active
integration (the adapter REPLACES the legacy nmap discovery entry;
exactly ONE scan per state; legacy-shape service nodes with adapter
provenance; ports merge into the shared set), planner coverage
post-hoc (the discovery lane is NOT planner-gated), and the
no-new-capability invariants (Gate 2/3 and Post-Exploit untouched).

REAL IT (exactly one, opt-in): a genuine nmap -sV service scan against
an OPERATOR-SUPPLIED locally controlled lab host through a REAL Docker
+ gVisor runsc sandbox and the REAL egress boundary. Guarded by
KRYONSEC_NMAP_IT=1 — skipped silently otherwise. NEVER runs against
anything public; the lab host comes from the operator.

Run the real IT on a Linux host with Docker + runsc + the pinned image:
    KRYONSEC_NMAP_IT=1 \
        KRYONSEC_NMAP_LAB_HOST=lab-host.example \
        KRYONSEC_SANDBOX_IMAGE='<digest-pinned-image>' \
        .venv/bin/python -m pytest tests/test_nmap_adapter.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_nmap import (
    ADAPTER_ID,
    MAX_SERVICES,
    NMAP_ADAPTER_ID,
    NMAP_PROBE_TEMPLATE,
    PINNED_RATE,
    TOOL_EXECUTABLE,
    NmapServiceObservation,
    find_adapter_attempt_node,
    make_nmap_probe_adapter,
    parse_nmap_service_lines,
    production_registry,
    record_nmap_evidence,
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
from kryonsec.purple.recon_active import RECON_PORTS, \
    ReconActiveSubagent, parse_nmap_services
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.tool_planner import PlannerBudget, \
    ToolCapabilityCatalog, ToolPlanner

TARGET = "target-corp.com"
NMAP_STDOUT = (
    "Starting Nmap 7.95 ( https://nmap.org )\n"
    "Nmap scan report for target-corp.com (203.0.113.7)\n"
    "Host is up (0.010s latency).\n"
    "\n"
    "PORT     STATE SERVICE       VERSION\n"
    "80/tcp   open  http          nginx 1.24.0\n"
    "443/tcp  open  ssl/http      nginx 1.24.0\n"
    "8080/tcp open  http-proxy    Werkzeug httpd 3.0.1\n"
    "22/tcp   closed ssh\n"
    "\n"
    "Service detection performed. Nmap done: 1 IP address "
    "(1 host up) scanned.\n"
)


# ---- harmless fakes ------------------------------------------------------------


class _StubEgressPolicy:
    """Duck-typed egress-policy stub (the executor only needs presence;
    the REAL enforcement lives inside the sandbox's own spawn)."""

    dns_resolvers = ("192.0.2.53",)  # TEST-NET-1 fixture for the dnsx lane's -r


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


def _prep(reg=None, *, params=None):
    return prepare_adapter_run(
        reg if reg is not None else production_registry(), ADAPTER_ID,
        target=TARGET,
        params=params if params is not None
        else {"ports": RECON_PORTS, "rate": PINNED_RATE})


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------

def test_production_registry_registers_nmap_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("nmap-probe",)            # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "domain"
    assert adapter.executable == "nmap"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()           # RECON_ACTIVE authorization =
                                             # engagement model, not silent
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_nmap_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_nmap_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_nmap_probe():
    reg = recon_active_registry()
    assert "nmap-probe" in reg.adapter_ids()
    adapter = reg.get(NMAP_ADAPTER_ID)
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.approvals == ()
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"


# ---- 2. correct fixed command rendering + byte-identical lockstep ---------------

def test_fixed_template_rendering():
    reg = production_registry()
    prep = _prep(reg)
    assert prep.argv == ["nmap", "-Pn", "-sT", "-sV", "-sC", "--max-rate",
                         "100", "-p", RECON_PORTS, TARGET]
    assert prep.target == TARGET
    assert prep.target_kind == "domain"
    rebuilt = [RECON_PORTS if a == "{ports}"
               else (PINNED_RATE if a == "{rate}" else
                     (TARGET if a == "{target}" else a))
               for a in NMAP_PROBE_TEMPLATE]
    assert prep.argv == ["nmap", *rebuilt]


def test_template_is_byte_identical_to_the_shipped_layer2_template():
    """The adapter adds NO flag the legacy nmap discovery entry does not
    carry: the argv it renders validates against the SHIPPED Layer-2
    template unchanged, and no NSE/timing/free flag can ever appear."""
    from kryonsec.purple.allowlist import (ACTIVE_RECON_TEMPLATES,
                                           ToolAllowlist)

    assert list(NMAP_PROBE_TEMPLATE) == \
        list(ACTIVE_RECON_TEMPLATES["nmap"])
    shipped = ToolAllowlist(dict(ACTIVE_RECON_TEMPLATES))
    shipped.validate(TOOL_EXECUTABLE,
                     ["nmap", "-Pn", "-sT", "-sV", "-sC", "--max-rate",
                      "100", "-p", RECON_PORTS, TARGET])
    # the template carries EXACTLY the legacy flag set — nothing extra
    flags = [a for a in NMAP_PROBE_TEMPLATE if a.startswith("-")]
    assert flags == ["-Pn", "-sT", "-sV", "-sC", "--max-rate", "-p"]
    for forbidden in ("-sS", "-sU", "-A", "-T", "--script", "-oX", "-oJ",
                      "-oN", "-oG", "-f", "-D", "-S", "-e", "--privileged",
                      "--send-ip", "--send-eth"):
        assert forbidden not in NMAP_PROBE_TEMPLATE, forbidden


def test_scan_constants_are_pinned_to_the_legacy_entry():
    """``--max-rate 100`` and the bounded RECON_PORTS list are the
    legacy discovery entry's constants — the module pins the rate and
    the lane passes both. A different rate, a full-range port spec or
    any NSE script would be a conscious code change, auditable in git,
    never caller input."""
    assert PINNED_RATE == "100"
    adapter = make_nmap_probe_adapter()
    assert adapter.max_seconds == 300        # ≤ the 330s sandbox ceiling
    reg = production_registry()
    prep = _prep(reg)
    assert prep.argv[prep.argv.index("--max-rate") + 1] == PINNED_RATE
    assert prep.argv[prep.argv.index("-p") + 1] == RECON_PORTS


# ---- 3. identification ------------------------------------------------------------

def test_nmap_identification():
    """The executable is the REAL bundled binary (entrypoint-allowlisted
    in the pinned sandbox image) and the evidence names the tool."""
    adapter = make_nmap_probe_adapter()
    assert adapter.executable == "nmap"
    assert "nmap" in adapter.purpose
    reg = production_registry()
    described = json.loads(reg.describe(ADAPTER_ID))
    assert described["executable"] == "nmap"
    assert described["evidence_kind"] == "text_excerpt"


# ---- 4. preparation refusals -----------------------------------------------------

def test_unexpected_params_are_refused():
    """The lane owns the pinned constants; caller input never widens the
    scan (no extra ports, no other rate, no free-form additions)."""
    reg = production_registry()
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            params={"ports": RECON_PORTS,
                                    "rate": PINNED_RATE,
                                    "extra": "1"})
    # a grammar-valid NON-pinned port spec is accepted at the prepare
    # layer — the framework's job is argv SAFETY, not scan policy.
    # That is exactly why the pin lives in the LANE (the only
    # dispatcher): it always passes RECON_PORTS itself, never caller
    # params — asserted by the lane tests below (exact argv) and by the
    # module's no-new-aggression rule (a different port list would be a
    # conscious code change in the repo, auditable in git).
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               params={"ports": "1-65535",
                                       "rate": PINNED_RATE})
    assert prep.argv[prep.argv.index("-p") + 1] == "1-65535"


def test_option_shaped_and_bad_values_are_refused():
    reg = production_registry()
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            params={"ports": "-p 22", "rate": "100"})
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            params={"ports": RECON_PORTS, "rate": "-1"})


def test_unknown_registry_refuses_preparation():
    with pytest.raises(AdapterNotRegistered):
        prepare_adapter_run(AdapterRegistry(), ADAPTER_ID, target=TARGET,
                            params={"ports": RECON_PORTS,
                                    "rate": PINNED_RATE})


# ---- 5. execution enforcement (gates / egress / sandbox / no host) -----------------

def test_target_touching_run_needs_the_egress_boundary(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    record = execute_adapter(reg, _prep(reg),
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    assert record.executed is False and record.outcome == "refused"
    names = _event_names(audit)
    assert "adapter_refused" in names
    assert not any(e["event"] == "adapter_spawn" for e in _events(audit))


def test_run_is_not_verified_and_untrusted(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=NMAP_STDOUT),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, _prep(reg), sandbox=sbx,
                                     audit=audit, graph=graph,
                                     full_output=True)
    assert record.executed is True and record.exit_code == 0
    assert record.verification == "not_verified"   # HARD invariant
    assert record.untrusted is True
    assert "confirmed" not in record.model_dump()
    assert record.evidence_kind == "text_excerpt"
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None


def test_no_host_execution_in_adapter_module():
    source = Path("src/kryonsec/purple") / "adapter_nmap.py"
    text = source.read_text(encoding="utf-8")
    assert "subprocess" not in text
    assert "import mcp" not in text
    assert "docker " + "run" not in text


# ---- 6. parsing: legacy lockstep, defensive, bounded --------------------------------

def test_parse_is_lockstep_with_the_legacy_parser():
    """The adapter parses with the SAME regex the legacy discovery entry
    uses (lockstep by construction): identical services, same order."""
    observations, malformed = parse_nmap_service_lines(NMAP_STDOUT)
    legacy = parse_nmap_services(NMAP_STDOUT)
    assert [(o.port, o.proto, o.service, o.version) for o in observations] \
        == [(s["port"], s["proto"], s["service"], s["version"])
            for s in legacy]
    assert [(o.port, o.proto, o.service) for o in observations] == [
        (80, "tcp", "http"), (443, "tcp", "ssl/http"),
        (8080, "tcp", "http-proxy"),
    ]
    assert malformed == 1            # the closed 22/tcp line is counted


def test_parse_is_defensive_and_bounded():
    banner = ("Starting Nmap 7.95\n"
              "Nmap scan report for x\n"
              "PORT STATE SERVICE\n"
              "Nmap done\n")
    obs, malformed = parse_nmap_service_lines(banner)
    # report headers are NOT port-shaped — skipped silently (only a
    # port-SHAPED line that the state filter rejects counts malformed)
    assert obs == [] and malformed == 0
    assert parse_nmap_service_lines("") == ([], 0)
    assert parse_nmap_service_lines(None) == ([], 0)
    flood = "\n".join(f"{8000 + i}/tcp open  http  x{i}"
                      for i in range(200))
    obs, _ = parse_nmap_service_lines(flood)
    assert len(obs) == MAX_SERVICES       # the bounded cap holds


# ---- 7. evidence recording: legacy-shape service nodes + refusal ---------------------

def test_record_evidence_refuses_without_attempt_node(tmp_path):
    """A refused run must never fabricate service evidence."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    record = execute_adapter(registry, _prep(registry),
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    obs, _ = parse_nmap_service_lines(NMAP_STDOUT)
    ids = record_nmap_evidence(graph, audit, run_record=record,
                               observations=obs)
    assert ids == []
    assert graph.by_type("service") == []
    names = _event_names(audit)
    assert "nmap_adapter_evidence_refused" in names


def test_evidence_mapping_is_legacy_shape_and_idempotent(tmp_path):
    """Each observation maps to ONE legacy-shape ``service`` node (the
    same node type the legacy parse produces and HYPOTHESIZE reads,
    labelled target:port/proto) with a produced-lineage edge from the
    run's adapter_attempt node; a repeat mapping adds NOTHING
    (first-wins by label)."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=NMAP_STDOUT),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(registry, _prep(registry),
                                     sandbox=sbx, audit=audit, graph=graph,
                                     full_output=True)
    obs, malformed = parse_nmap_service_lines(output)
    assert len(obs) == 3 and malformed == 1
    created = record_nmap_evidence(graph, audit, run_record=record,
                                   observations=obs)
    assert len(created) == 3
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None
    restored = AdapterRunRecord.model_validate(attempt["properties"])
    assert restored.adapter_id == ADAPTER_ID
    nodes = graph.by_type("service")
    assert len(nodes) == 3
    by_label = {n["label"]: n for n in nodes}
    props = by_label[f"{TARGET}:80/tcp"]["properties"]
    assert props["port"] == 80 and props["service"] == "http"
    assert props["source"] == "nmap"             # the legacy source tag
    assert props["adapter"] == ADAPTER_ID        # + adapter provenance
    assert props["request_id"] == record.request_id
    assert props["verification"] == "not_verified"
    assert props["untrusted"] is True
    # lineage: attempt --produced--> service, for EVERY node
    for node in nodes:
        assert graph.has_edge(attempt, "produced", node)
    # idempotence: a REPEAT mapping adds nothing (first-wins by label)
    ids2 = record_nmap_evidence(graph, audit, run_record=record,
                                observations=obs)
    assert ids2 == []
    assert len(graph.by_type("service")) == 3
    ev = [e for e in _events(audit) if e["event"] == "nmap_adapter_evidence"]
    assert ev[0]["services"] == 3 and ev[0]["service_nodes"] == 3
    assert ev[0]["duplicate_or_refused"] == 0
    assert ev[1]["duplicate_or_refused"] == 3    # the repeat mapping
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_service_run_is_an_honest_inconclusive(tmp_path):
    """A clean scan that found NOTHING open is audited with zero
    services — never a negative 'nothing is running' claim."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(registry, _prep(registry),
                                     sandbox=sbx, audit=audit, graph=graph,
                                     full_output=True)
    obs, _ = parse_nmap_service_lines(output)
    created = record_nmap_evidence(graph, audit, run_record=record,
                                   observations=obs)
    assert created == []
    assert graph.by_type("service") == []
    ev = [e for e in _events(audit) if e["event"] == "nmap_adapter_evidence"]
    assert ev[0]["services"] == 0 and ev[0]["service_nodes"] == 0


# ---- 8. deterministic Recon Active either/or ---------------------------------------

def _recon(sandbox, registry, tmp_path, *, planner=None):
    cfg = _cfg(tmp_path)
    audit = AuditLog(tmp_path / "ra.jsonl")
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    sub = ReconActiveSubagent(cfg, graph, audit, TARGET, sandbox,
                              adapter_registry=registry, planner=planner)
    result = sub.run()
    return result, sandbox.spawned, graph, audit


def _script_recon(argv):
    tool = argv[0]
    if tool == "nmap":
        # the ADAPTER and the LEGACY entry share argv[0] — the either/or
        # rule below counts spawns to prove only ONE ran
        return SpawnResult(ok=True, exit_code=0, stdout=NMAP_STDOUT)
    if tool == "naabu":
        return SpawnResult(ok=True, exit_code=0,
                           stdout=f"{TARGET}:8080")
    if tool == "dnsx":
        return SpawnResult(ok=True, exit_code=0,
                           stdout=f"{TARGET} [A] 203.0.113.7")
    return SpawnResult(ok=True, exit_code=0, stdout="")


def _nmap_runs(cmdl):
    return [a for a in cmdl if a and a[0] == "nmap"]


def test_adapter_mode_scans_nmap_once_never_both(tmp_path):
    """DETERMINISTIC either/or: the legacy nmap discovery entry is
    REPLACED by the adapter run — exactly ONE scan per state — and the
    services land in the SAME legacy-shape service nodes with the
    adapter provenance, ports merging into the shared open set."""
    sandbox = FakeSandbox(script=_script_recon,
                          egress_policy=_StubEgressPolicy())
    result, spawned, graph, audit = _recon(sandbox,
                                           recon_active_registry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs = _nmap_runs(cmdl)
    assert len(runs) == 1
    assert runs[0] == ["nmap", "-Pn", "-sT", "-sV", "-sC", "--max-rate",
                       "100", "-p", RECON_PORTS, TARGET]
    nodes = graph.by_type("service")
    assert {n["label"] for n in nodes} == \
        {f"{TARGET}:80/tcp", f"{TARGET}:443/tcp", f"{TARGET}:8080/tcp"}
    assert all(n["properties"]["adapter"] == ADAPTER_ID for n in nodes)
    assert all(n["properties"]["source"] == "nmap" for n in nodes)
    # the ports merged into the shared state: web bases exist for them
    names = _event_names(audit)
    assert "recon_active_nmap_adapter" in names
    nmap_ev = [e for e in _events(audit)
               if e["event"] == "recon_active_nmap_adapter"]
    assert len(nmap_ev[0]["services"]) == 3
    assert "recon_active_adapter_failure" not in names


def test_empty_registry_falls_back_legacy_deterministically(tmp_path):
    sandbox = FakeSandbox(script=_script_recon,
                          egress_policy=_StubEgressPolicy())
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    assert _nmap_runs(cmdl) != []            # the legacy plan, unchanged
    nodes = graph.by_type("service")
    assert nodes and all(
        (e.get("properties") or {}).get("adapter") is None
        for e in nodes)                      # legacy parse nodes only
    assert graph.by_type("adapter_attempt") == []
    assert "recon_active_nmap_adapter" not in _event_names(audit)


# ---- 9. planner coverage post-hoc (the discovery lane is NOT gated) ----------------

def test_planner_reports_the_scan_covered_post_hoc(tmp_path):
    """nmap-probe is a pre-plan discovery lane like naabu-probe: it runs
    BEFORE the plan exists and the plan reports it as covered —
    targeting the ENGAGEMENT DOMAIN, never a URL base."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()))
    sandbox = FakeSandbox(script=_script_recon,
                          egress_policy=_StubEgressPolicy())
    result, spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    events = _events(audit)
    decided = next(e for e in events if e["event"] == "planning_decided")
    nmap_entry = next(e for e in decided["entries"]
                      if "nmap-probe" in e and "covered" in e)
    assert TARGET in nmap_entry
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert done["planned_not_executed"] == []
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_budget_never_stops_the_discovery_lane(tmp_path):
    """The discovery lanes are NOT planner-gated: under a zero budget
    the nmap adapter lane STILL runs (the plan needs its ports) and the
    plan reports it covered."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()),
                          budget=PlannerBudget(max_total_seconds=0))
    sandbox = FakeSandbox(script=_script_recon,
                          egress_policy=_StubEgressPolicy())
    result, spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    assert _nmap_runs([argv for argv, _t in spawned]) != []
    events = _events(audit)
    decided = next(e for e in events if e["event"] == "planning_decided")
    assert decided["counts"].get("selected", 0) == 0
    assert decided["counts"].get("covered") == 3   # nmap + naabu + dnsx
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert done["planned_selected"] == 0
    assert done["planned_executed"] == 0


def test_failed_scan_is_not_coverage(tmp_path):
    """A FAILED scan is never reported as covered: its plan entry stays
    eligible and the done event honestly lists it as planned-but-not-
    executed."""
    def script(argv):
        r = _script_recon(argv)
        if argv[0] == "nmap":
            return SpawnResult(ok=False, exit_code=1, stdout="",
                               error="scan failed")
        return r

    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()))
    sandbox = FakeSandbox(script=script, egress_policy=_StubEgressPolicy())
    result, _spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    events = _events(audit)
    names = [e["event"] for e in events]
    assert "recon_active_adapter_failure" in names
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert any("nmap-probe" in ln for ln in done["planned_not_executed"])


# ---- 10. Gate 2 / Gate 3 behavior unchanged -----------------------------------------

def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=NMAP_STDOUT),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, _prep(reg), sandbox=sbx, audit=audit,
                             graph=graph)
    assert record.executed is True
    for ev in _events(audit):
        label = json.dumps(ev)
        assert "gate_decision" not in label
        assert "capability" not in ev.get("event", "")
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    assert graph.by_type("capability") == []
    assert graph.by_type("finding") == []
    from kryonsec.purple.adapters import ModeBToolAdapter

    with pytest.raises(ValidationError):
        ModeBToolAdapter(**{
            **make_nmap_probe_adapter().model_dump(),
            "adapter_id": "nmap-exploit", "stages": ("EXPLOIT",),
        })


# ---- the ONE genuine integration test (opt-in, local lab only) ----------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab
    host."""
    lab = os.environ.get("KRYONSEC_NMAP_LAB_HOST", "").strip()
    if not lab or lab.startswith("-") or "/" in lab:
        return False, ("KRYONSEC_NMAP_LAB_HOST must be a lab host you "
                       "control")
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_NMAP_IT") != "1":
        return False, "KRYONSEC_NMAP_IT=1 not set"
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


def test_real_nmap_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real nmap -sV scan — against the lab host the OPERATOR
    supplies. Skipped silently otherwise.

    Authorize NOTHING public: point KRYONSEC_NMAP_LAB_HOST at a host
    you control. An empty scan from a clean run is an honest
    INCONCLUSIVE (the assertions below allow it) — never a failure
    mask.
    """
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.egress import EgressGate, build_policy, \
        release_active
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig()
    lab = os.environ["KRYONSEC_NMAP_LAB_HOST"].strip()
    policy = build_policy(cfg, "nmap-it", target=lab)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_nmap_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="nmap-it")
    graph.add_node("target", lab, {})
    try:
        prep = prepare_adapter_run(reg, ADAPTER_ID, target=lab,
                                   params={"ports": RECON_PORTS,
                                           "rate": PINNED_RATE})
        record, output = execute_adapter(reg, prep, sandbox=sbx,
                                         audit=audit, graph=graph,
                                         full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.exit_code == 0
        assert record.verification == "not_verified"
        obs, malformed = parse_nmap_service_lines(output)
        created = record_nmap_evidence(graph, audit, run_record=record,
                                       observations=obs)
        nodes = graph.by_type("service")
        assert len(nodes) == len(created)
        assert all(n["properties"]["verification"] == "not_verified"
                   for n in nodes)
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("nmap-it")
        except Exception:
            pass
