"""Tool Expansion Batch 2 tests: the gowitness-probe production Mode B
adapter.

MOCKED tests (the default, huge majority): a duck-typed sandbox double
returns canned SpawnResults — no process, no packets, no screenshots.
They pin the contract: explicit registration (single + combined
RECON_ACTIVE registry), the byte-identical fixed template (the rw
``/evidence`` mount pinned, console silenced with ``-q``, the browser
pinned to the image's own chromium — no delay/no header knobs),
URL scope/preparation refusals,
gate + sandbox + egress enforcement, honest failure classification,
no host fallback, the NO-TEXT-CONTRACT rule (the exit code is the
truth — gowitness console chatter is never interpreted), deterministic
Recon Active integration (the adapter REPLACES the legacy gowitness
web-plan entry; exactly ONE screenshot per base; ONE legacy-shape
``screenshot`` node with adapter provenance; a refused/failed run
records NO node), planner gating (like every other web lane: zero
budget → no spawn), and the no-new-capability invariants (Gate 2/3 and
Post-Exploit untouched).

REAL IT (exactly one, opt-in): a genuine gowitness screenshot against
an OPERATOR-SUPPLIED locally controlled lab URL through a REAL Docker
+ gVisor runsc sandbox and the REAL egress boundary. Guarded by
KRYONSEC_GOWITNESS_IT=1 — skipped silently otherwise. NEVER runs
against anything public; the lab URL comes from the operator.

Run the real IT on a Linux host with Docker + runsc + the pinned image:
    KRYONSEC_GOWITNESS_IT=1 \\
        KRYONSEC_GOWITNESS_LAB_URL=http://127.0.0.1:8080/ \\
        KRYONSEC_SANDBOX_IMAGE='<digest-pinned-image>' \\
        .venv/bin/python -m pytest tests/test_gowitness_adapter.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_gowitness import (
    ADAPTER_ID,
    GOWITNESS_ADAPTER_ID,
    GOWITNESS_PROBE_TEMPLATE,
    SCREENSHOT_DIR,
    TOOL_EXECUTABLE,
    find_adapter_attempt_node,
    make_gowitness_probe_adapter,
    production_registry,
    record_gowitness_evidence,
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
from kryonsec.purple.recon_active import ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.tool_planner import PlannerBudget, \
    ToolCapabilityCatalog, ToolPlanner

TARGET = "target-corp.com"
BASE = "http://target-corp.com:8080/"


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


def _prep(reg=None, *, base=BASE):
    """Prepared run — NO params: the template's only placeholder ({url})
    is composed by the framework from the base."""
    return prepare_adapter_run(
        reg if reg is not None else production_registry(), ADAPTER_ID,
        target=TARGET, target_asset=base)


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------

def test_production_registry_registers_gowitness_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("gowitness-probe",)       # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "web_recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "url"
    assert adapter.executable == "gowitness"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()           # RECON_ACTIVE authorization =
                                             # engagement model, not silent
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_gowitness_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_gowitness_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_gowitness_probe():
    reg = recon_active_registry()
    assert "gowitness-probe" in reg.adapter_ids()
    adapter = reg.get(GOWITNESS_ADAPTER_ID)
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.approvals == ()
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"


# ---- 2. the fixed command — byte-identical to the shipped entry ------------------

def test_fixed_template_rendering():
    """The adapter argv is EXACTLY the legacy plan entry's argv: same
    subcommand, same scope-validated base, same pinned rw evidence
    mount, console silenced, browser pinned to the image's chromium."""
    reg = production_registry()
    prep = _prep(reg)
    assert prep.argv == ["gowitness", "scan", "single", "-u", BASE,
                         "--screenshot-path", SCREENSHOT_DIR,
                         "--chrome-path", "/usr/bin/chromium", "-q"]
    assert prep.target == BASE
    assert prep.target_kind == "url"


def test_template_is_byte_identical_to_the_shipped_layer2_template():
    """The adapter adds NO flag the shipped gowitness entry does not
    carry: the argv it renders validates against the SHIPPED Layer-2
    template unchanged, and no delay/header/scalarize knob can ever
    appear. (gowitness 3.2.2 removed ``scan website`` and the
    ``--no-console``/``--disable-db`` flags — the shipped template
    follows the real binary, verified live; ``--chrome-path`` pins the
    image's OWN chromium so no runtime browser download can happen.)"""
    from kryonsec.purple.allowlist import (ACTIVE_RECON_TEMPLATES,
                                           ToolAllowlist)

    assert list(GOWITNESS_PROBE_TEMPLATE) == \
        list(ACTIVE_RECON_TEMPLATES["gowitness"])
    shipped = ToolAllowlist(dict(ACTIVE_RECON_TEMPLATES))
    shipped.validate(TOOL_EXECUTABLE,
                     ["gowitness", "scan", "single", "-u", BASE,
                      "--screenshot-path", SCREENSHOT_DIR,
                      "--chrome-path", "/usr/bin/chromium", "-q"])
    # the screenshot directory is the FIXED rw evidence mount — never
    # caller input
    assert SCREENSHOT_DIR == "/evidence"
    flags = [a for a in GOWITNESS_PROBE_TEMPLATE if a.startswith("-")]
    assert flags == ["-u", "--screenshot-path", "--chrome-path", "-q"]
    # the ONLY chrome-path value is the image's own binary — the
    # template can never be pointed elsewhere
    i = GOWITNESS_PROBE_TEMPLATE.index("--chrome-path")
    assert GOWITNESS_PROBE_TEMPLATE[i + 1] == "/usr/bin/chromium"
    for forbidden in ("--delay", "--chrome-wss", "--viewport",
                      "--disable-javascript",
                      "--user-agent", "--header"):
        assert forbidden not in GOWITNESS_PROBE_TEMPLATE, forbidden


def test_screenshot_budget_is_pinned():
    adapter = make_gowitness_probe_adapter()
    assert adapter.max_seconds == 120
    assert adapter.evidence_kind == "screenshot_file"


# ---- 3. identification ------------------------------------------------------------

def test_gowitness_identification():
    """The executable is the REAL bundled binary (entrypoint-allowlisted
    in the pinned sandbox image) and the evidence names the tool."""
    adapter = make_gowitness_probe_adapter()
    assert adapter.executable == "gowitness"
    assert "gowitness" in adapter.purpose
    reg = production_registry()
    described = json.loads(reg.describe(ADAPTER_ID))
    assert described["executable"] == "gowitness"
    assert described["evidence_kind"] == "screenshot_file"


# ---- 4. preparation refusals -------------------------------------------------------

def test_out_of_scope_assets_refused_at_preparation():
    reg = production_registry()
    # absolute assets whose host is not the target / a subdomain:
    # the caller cannot aim the browser at an arbitrary host
    for out in ("https://elsewhere.example.com/",
                "http://target-corp.net/",
                "http://sub.target-corp.net/"):
        with pytest.raises(AdapterError):
            prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                                target_asset=out)
    # an in-scope subdomain composes fine (the standard scope rule)
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="https://mail.target-corp.com/")
    assert prep.target == "https://mail.target-corp.com/"


def test_injection_shaped_urls_rejected():
    """Shell-metacharacter / injection-shaped 'url' values deviate
    EXACTLY like any other out-of-template argument: refused at
    preparation, never rendered, never spawned."""
    reg = production_registry()
    for bad in ("http://x/;$rm -rf /tmp", "http://x/ -o /tmp/pwned",
                "http://x/ && cat /etc/passwd"):
        with pytest.raises(AdapterError):
            prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                                target_asset=bad)


def test_no_caller_params_the_template_has_no_placeholders_to_fill():
    """The lane supplies NOTHING: no params dict is needed ({url} is
    framework-composed) and ANY params dict is refused — a caller
    screenshot-path, extra flag or even a pre-composed 'url' can never
    reach the template."""
    reg = production_registry()
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE,
                            params={"screenshot_path": "/tmp/evil"})
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE, params={"delay": "5"})
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE, params={"url": BASE})
    # option-shaped caller input is refused (option injection): no
    # value may begin with '-'
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE,
                            params={"screenshot_path": "--no-sandbox"})


def test_unknown_registry_refuses_preparation():
    with pytest.raises(AdapterNotRegistered):
        prepare_adapter_run(AdapterRegistry(), ADAPTER_ID, target=TARGET,
                            target_asset=BASE)


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


def test_gated_variant_refused_without_grant(tmp_path):
    """A variant that names EXPLOIT MUST demand the hypothesis gate and
    is REFUSED without it — the Gate 2 enforcement module is unchanged."""
    from kryonsec.purple.adapters import ModeBToolAdapter

    variant = make_gowitness_probe_adapter()
    exploit_variant = ModeBToolAdapter(
        **{**variant.model_dump(), "adapter_id": "gowitness-gated",
           "stages": ("EXPLOIT",), "approvals": ("hypothesis_gate",),
           "risk": "active"})
    reg = AdapterRegistry()
    reg.register(exploit_variant)
    prep = prepare_adapter_run(reg, "gowitness-gated", target=TARGET,
                               target_asset=BASE)
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    audit = AuditLog(Path("tmp") / "gate_a.jsonl")
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                             graph=_graph(), hypothesis_id="H1")
    assert record.executed is False and record.outcome == "refused"
    assert "approval gate" in record.error_excerpt
    assert sbx.spawned == []


def test_missing_sandbox_no_host_fallback(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = _prep(reg)
    for bad in (None, object()):          # none + no-spawn blob
        record = execute_adapter(reg, prep, sandbox=bad, audit=audit)
        assert record.executed is False and record.outcome == "refused"
        assert "no sandbox" in record.error_excerpt
    assert _event_names(audit).count("adapter_refused") == 2


def test_no_egress_boundary_refused(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    prep = _prep(reg)
    unegressed = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""))
    record = execute_adapter(reg, prep, sandbox=unegressed, audit=audit)
    assert record.executed is False and record.outcome == "refused"
    assert "egress policy" in record.error_excerpt
    assert unegressed.spawned == []
    assert _event_names(audit).count("adapter_refused") == 1


# ---- 6. tool timeout / nonzero exit — honest failures, NO node -----------------------

def test_tool_timeout_is_an_honest_failure(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = _prep(reg)
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                  error="tool exceeded 120s sandbox timeout"),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert record.failure_class == "timeout"
    assert output == ""
    # no attempt node, no screenshot node
    assert graph.by_type("adapter_attempt") == []
    assert graph.by_type("screenshot") == []
    # timeout bound respected on the spawn call (adapter max_seconds)
    assert sbx.spawned and sbx.spawned[0][1] == \
        make_gowitness_probe_adapter().max_seconds


def test_nonzero_exit_is_not_success_and_leaves_no_node(tmp_path):
    """The exit code is the truth: a failed run is NOT a screenshot —
    no node, no fabricated evidence, an honest audited failure."""
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = _prep(reg)
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=1, stdout="",
                                  error="chrome crashed"),
                      egress_policy=_StubEgressPolicy())
    record, _output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                      graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert record.exit_code == 1
    assert record.verification == "not_verified"
    created = record_gowitness_evidence(graph, audit, run_record=record)
    assert created == []
    assert graph.by_type("screenshot") == []
    names = _event_names(audit)
    assert "adapter_result" in names
    for ev in _events(audit):
        if ev["event"] == "adapter_result":
            assert ev["ok"] is False and ev["exit_code"] == 1


# ---- 7. evidence recording: ONE legacy-shape screenshot node + refusal ---------------

def test_record_evidence_refuses_without_attempt_node(tmp_path):
    """A refused run must never fabricate screenshot evidence."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    record = execute_adapter(registry, _prep(registry),
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    ids = record_gowitness_evidence(graph, audit, run_record=record)
    assert ids == []
    assert graph.by_type("screenshot") == []
    names = _event_names(audit)
    assert "gowitness_adapter_evidence_refused" in names


def test_one_screenshot_node_per_run_with_adapter_provenance(tmp_path):
    """A successful run records ONE legacy-shape ``screenshot`` node
    (the same node type the legacy gowitness parse produces, labelled
    by the screenshotted base URL) with a produced-lineage edge from
    the run's adapter_attempt node; the node records WHERE the PNG
    lives (the rw /evidence mount), never the image content."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    record, _output = execute_adapter(registry, _prep(registry),
                                      sandbox=sbx, audit=audit, graph=graph,
                                      full_output=True)
    assert record.executed is True and record.exit_code == 0
    created = record_gowitness_evidence(graph, audit, run_record=record)
    assert len(created) == 1
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None
    restored = AdapterRunRecord.model_validate(attempt["properties"])
    assert restored.adapter_id == ADAPTER_ID
    nodes = graph.by_type("screenshot")
    assert len(nodes) == 1
    node = nodes[0]
    assert node["label"] == BASE              # the legacy label: the base
    props = node["properties"]
    assert props["source"] == "gowitness"     # the legacy source tag
    assert props["dir"] == "/evidence"        # the legacy dir tag
    assert props["adapter"] == ADAPTER_ID     # + adapter provenance
    assert props["request_id"] == record.request_id
    assert props["verification"] == "not_verified"
    assert props["untrusted"] is True
    # lineage: attempt --produced--> screenshot
    assert graph.has_edge(attempt, "produced", node)
    ev = [e for e in _events(audit)
          if e["event"] == "gowitness_adapter_evidence"]
    assert ev[0]["screenshot_nodes"] == 1
    assert ev[0]["duplicate_or_refused"] == 0
    ok, reason = audit.verify()
    assert ok, reason


def test_repeat_screenshot_of_the_same_base_is_skipped_first_wins(tmp_path):
    """Duplicate labels (the same base already screenshotted) are
    SKIPPED — first-wins — and the skip is AUDITED, never silent."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    first, _ = execute_adapter(registry, _prep(registry), sandbox=sbx,
                               audit=audit, graph=graph, full_output=True)
    created1 = record_gowitness_evidence(graph, audit, run_record=first)
    assert len(created1) == 1
    # a SECOND run of the same base (fresh request id) — the label
    # exists, so nothing new is created
    second, _ = execute_adapter(registry, _prep(registry), sandbox=sbx,
                                audit=audit, graph=graph, full_output=True)
    assert second.request_id != first.request_id
    created2 = record_gowitness_evidence(graph, audit, run_record=second)
    assert created2 == []
    assert len(graph.by_type("screenshot")) == 1
    ev = [e for e in _events(audit)
          if e["event"] == "gowitness_adapter_evidence"]
    assert ev[1]["screenshot_nodes"] == 0
    assert ev[1]["duplicate_or_refused"] == 1
    ok, reason = audit.verify()
    assert ok, reason


# ---- 8. the screenshot is recon evidence, never a vulnerability claim ----------------

def test_screenshot_is_recon_evidence_never_confirmation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    record, _output = execute_adapter(reg, _prep(reg), sandbox=sbx,
                                      audit=audit, graph=graph,
                                      full_output=True)
    assert record.executed is True and record.exit_code == 0
    # HARD invariants:
    assert record.verification == "not_verified"
    assert record.untrusted is True
    assert "confirmed" not in record.model_dump()
    record_gowitness_evidence(graph, audit, run_record=record)
    props = graph.by_type("screenshot")[0]["properties"]
    assert props["verification"] == "not_verified"
    # nothing on the graph became a finding / capability / approval
    assert graph.by_type("finding") == []
    assert graph.by_type("capability") == []
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    # ...and no gate lifecycle events were written by the adapter path
    names = _event_names(audit)
    assert not any("gate" in n for n in names if n != "adapter_refused")


# ---- 9. no host execution fallback ---------------------------------------------------------

def test_no_host_execution_in_adapter_module():
    source = Path("src/kryonsec/purple") / "adapter_gowitness.py"
    text = source.read_text(encoding="utf-8")
    assert "subprocess" not in text
    assert "import mcp" not in text
    assert "docker " + "run" not in text


# ---- 10. no duplicate Recon Active screenshot (deterministic either/or) ----------------

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
    if tool == "gowitness":
        # the ADAPTER and the LEGACY entry share argv[0] — the either/or
        # rule below counts spawns to prove only ONE ran; gowitness's
        # console chatter is NOT a parseable contract (exit code rules)
        return SpawnResult(ok=True, exit_code=0, stdout="")
    return SpawnResult(ok=True, exit_code=0, stdout="")


def _fake_stage1(script):
    return FakeSandbox(script=script, egress_policy=_StubEgressPolicy())


def _gowitness_runs(cmdl):
    return [a for a in cmdl if a and a[0] == "gowitness"]


def test_adapter_mode_screenshots_once_never_both(tmp_path):
    """DETERMINISTIC either/or: the legacy gowitness web-plan entry is
    REPLACED by the adapter run — exactly ONE screenshot per base — and
    the node lands in the SAME legacy shape with the adapter
    provenance the legacy argv-based node cannot carry."""
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(sandbox, recon_active_registry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs = _gowitness_runs(cmdl)
    assert len(runs) == 1
    assert runs[0] == ["gowitness", "scan", "single", "-u", BASE,
                       "--screenshot-path", "/evidence",
                       "--chrome-path", "/usr/bin/chromium", "-q"]
    nodes = graph.by_type("screenshot")
    assert len(nodes) == 1
    node = nodes[0]
    assert node["label"] == BASE
    assert node["properties"]["source"] == "gowitness"
    assert node["properties"]["dir"] == "/evidence"
    assert node["properties"]["adapter"] == ADAPTER_ID
    names = _event_names(audit)
    assert "recon_active_gowitness_adapter" in names
    gowitness_ev = [e for e in _events(audit)
                    if e["event"] == "recon_active_gowitness_adapter"]
    assert gowitness_ev[0]["base"] == BASE
    assert "recon_active_adapter_failure" not in names


def test_empty_registry_falls_back_legacy_deterministically(tmp_path):
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    assert _gowitness_runs(cmdl) != []       # the legacy plan, unchanged
    nodes = graph.by_type("screenshot")
    assert nodes and all(
        (e.get("properties") or {}).get("adapter") is None
        for e in nodes)                      # legacy argv-based nodes only
    assert graph.by_type("adapter_attempt") == []
    assert "recon_active_gowitness_adapter" not in _event_names(audit)


# ---- 11. planner gating (the web lanes are planner-gated, 2B.6) ------------------------------

def test_planner_selected_screenshot_runs_with_the_pinned_argv(tmp_path):
    """gowitness-probe is planner-gated like every other web lane: with
    the default budget its base is SELECTED, the lane runs it ONCE with
    the pinned argv, and the run links back to the plan id."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()))
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    runs = _gowitness_runs([argv for argv, _t in spawned])
    assert len(runs) == 1
    assert runs[0] == ["gowitness", "scan", "single", "-u", BASE,
                       "--screenshot-path", "/evidence",
                       "--chrome-path", "/usr/bin/chromium", "-q"]
    events = _events(audit)
    decided = next(e for e in events if e["event"] == "planning_decided")
    # one plain-http base: 7 eligible checks selected (httpx, whatweb,
    # api, katana, gowitness, nuclei, feroxbuster), tls rejected, and
    # the three discovery probes (nmap, naabu, dnsx) covered post-hoc
    # (pre-plan lanes)
    assert decided["counts"] == {"selected": 7, "rejected": 1,
                                 "covered": 3}
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert done["planned_selected"] == 7
    assert done["planned_executed"] == 7
    assert done["planned_not_executed"] == []
    # the lane's own event links to the plan id
    gowitness_ev = [e for e in events
                    if e["event"] == "recon_active_gowitness_adapter"]
    assert gowitness_ev[0]["plan_id"] == decided["plan_id"]
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_budget_defers_the_screenshot_never_spawns_gowitness(tmp_path):
    """A zero budget defers EVERY planner-gated adapter check: the
    gowitness lane dispatches no base, so NO screenshot spawn, no
    screenshot node, no failure event — an honest unrun check, never a
    silent skip."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()),
                          budget=PlannerBudget(max_total_seconds=0))
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    assert _gowitness_runs([argv for argv, _t in spawned]) == []
    assert graph.by_type("screenshot") == []
    names = _event_names(audit)
    assert "recon_active_gowitness_adapter" not in names
    assert "recon_active_adapter_failure" not in names
    events = _events(audit)
    decided = next(e for e in events if e["event"] == "planning_decided")
    assert decided["counts"].get("selected", 0) == 0
    assert decided["counts"].get("covered") == 3   # the discovery lanes
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert done["planned_selected"] == 0
    assert done["planned_executed"] == 0


def test_failed_screenshot_is_not_coverage(tmp_path):
    """A FAILED screenshot is never reported as covered: the done event
    honestly lists it as planned-but-not-executed (the check did not
    complete)."""
    def script(argv):
        r = _script_discovery_and_web(argv)
        if argv[0] == "gowitness":
            return SpawnResult(ok=False, exit_code=1, stdout="",
                               error="chrome crashed")
        return r

    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()))
    sandbox = _fake_stage1(script)
    result, _spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    events = _events(audit)
    names = [e["event"] for e in events]
    assert "recon_active_adapter_failure" in names
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert any("gowitness-probe" in ln
               for ln in done["planned_not_executed"])


# ---- 12. Gate 2 / Gate 3 behavior unchanged ---------------------------------------------------

def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
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
            **make_gowitness_probe_adapter().model_dump(),
            "adapter_id": "gowitness-post", "stages": ("POST_EXPLOIT",),
        })


# ---- the ONE genuine integration test (opt-in, local lab only) ----------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab
    URL."""
    lab = os.environ.get("KRYONSEC_GOWITNESS_LAB_URL", "").strip()
    if not lab or not lab.startswith(("http://", "https://")):
        return False, ("KRYONSEC_GOWITNESS_LAB_URL must be a lab URL "
                       "you control")
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_GOWITNESS_IT") != "1":
        return False, "KRYONSEC_GOWITNESS_IT=1 not set"
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


def test_real_gowitness_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real gowitness screenshot — against the lab URL the
    OPERATOR supplies. Skipped silently otherwise.

    Authorize NOTHING public: point KRYONSEC_GOWITNESS_LAB_URL at a web
    server you control. The run must exit 0 and leave ONE screenshot
    node; the PNG itself lands in the rw /evidence mount (the
    engagement folder) — the node records THAT, never the content.
    """
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.egress import EgressGate, build_policy, \
        release_active
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig()
    lab = os.environ["KRYONSEC_GOWITNESS_LAB_URL"].strip()
    # the egress boundary authorizes HOSTS, not URLs — the lab host is
    # derived from the operator's URL (scope: that host only)
    import urllib.parse

    lab_host = urllib.parse.urlparse(lab).hostname or ""
    assert lab_host, f"KRYONSEC_GOWITNESS_LAB_URL has no host: {lab!r}"

    policy = build_policy(cfg, "gowitness-it", target=lab_host)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_gowitness_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="gowitness-it")
    graph.add_node("target", lab_host, {})
    try:
        prep = prepare_adapter_run(reg, ADAPTER_ID, target=lab,
                                   target_asset=lab)
        record, _output = execute_adapter(reg, prep, sandbox=sbx,
                                          audit=audit, graph=graph,
                                          full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.exit_code == 0
        assert record.verification == "not_verified"
        created = record_gowitness_evidence(graph, audit, run_record=record)
        nodes = graph.by_type("screenshot")
        assert len(nodes) == len(created)
        assert all(n["properties"]["verification"] == "not_verified"
                   for n in nodes)
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("gowitness-it")
        except Exception:
            pass
