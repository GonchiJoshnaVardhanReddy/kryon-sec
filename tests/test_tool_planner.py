"""Tests for the deterministic Mode B tool planner (Phase 2B.6).

Everything here runs against harmless fakes and the REAL production
adapter registry — the planner is host-side pure Python: no subprocess,
no network, no sandbox, no LLM. The one integration group drives a full
ReconActiveSubagent with the same FakeSandbox pattern the adapter tests
use, to prove the plan actually filters the execution lanes.

Structure follows the phase test plan:
  1. capability catalog
  2. capability selection
  3. planning / priorities / budget
  4. security boundaries
  5. evidence + audit integration (full subagent run)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_whatweb import recon_active_registry
from kryonsec.purple.adapters import (
    AdapterRegistry,
    AdapterRunRecord,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.tool_planner import (
    CatalogEntry,
    ExecutionPlan,
    PlannerBudget,
    PlanEntry,
    ToolCapabilityCatalog,
    ToolPlanner,
    ToolSuggestion,
    normalize_target,
)

TARGET = "target-corp.com"
HTTPS_BASE = f"https://{TARGET}:8443/"
HTTP_BASE = f"http://{TARGET}:8080/"

STATUS_PATTERNS = {"selected", "covered", "deferred", "rejected",
                   "out_of_stage"}


# ---- fakes ---------------------------------------------------------------------


class RecordingAudit:
    """Duck-typed audit double: records every event in order."""

    def __init__(self):
        self.events: "list[dict]" = []

    def write(self, entry: dict) -> str:
        self.events.append(dict(entry))
        return ""


def _graph() -> EngagementGraph:
    return EngagementGraph(engagement_id="e-plan")


def _catalog(registry=None) -> ToolCapabilityCatalog:
    return ToolCapabilityCatalog(registry or recon_active_registry())


def _planner(catalog=None, **kw) -> ToolPlanner:
    return ToolPlanner(catalog or _catalog(), **kw)


def _plan(**kw) -> ExecutionPlan:
    bases = kw.pop("bases", [HTTPS_BASE])
    audit = kw.pop("audit", None) or RecordingAudit()
    graph = kw.pop("graph", None) or _graph()
    state = kw.pop("state", "RECON_ACTIVE")
    target = kw.pop("target", TARGET)
    # every remaining kwarg is a ToolPlanner constructor kwarg
    return _planner(**kw).plan(
        state=state, target=target, bases=bases, graph=graph, audit=audit)


def _status_map(plan: ExecutionPlan) -> "dict[tuple[str, str], str]":
    """(adapter_id, normalized target) -> status, for easy assertions."""
    return {(e.adapter_id, normalize_target(e.target)): e.status
            for e in plan.entries}


def _attempt_node(graph, adapter_id, target, *, executed=True,
                  exit_code=0, outcome="attempted", truncated=False,
                  created_at=None) -> dict:
    """A realistic adapter_attempt node (the shape the executor writes)."""
    record = AdapterRunRecord(
        adapter_id=adapter_id,
        request_id="req-123",
        tool="tool",
        argv=["tool", target],
        target=target,
        executed=executed,
        exit_code=exit_code,
        outcome=outcome,
        truncated=truncated,
        evidence_kind="json_report",
    )
    props = record.model_dump()
    if created_at:
        props["__created_at"] = created_at
    node = graph.add_node(
        node_type="adapter_attempt",
        label=f"adapter_attempt:{adapter_id}:req123",
        properties=props,
        provenance={"agent": "ADAPTER", "source_type": "tool"},
    )
    if created_at:
        # created_at lives on the node, not in the properties — set it
        # the way a persisted (loaded) node would carry it
        node["created_at"] = created_at
    return node


# ===========================================================================
# 1. the capability catalog
# ===========================================================================


def test_catalog_refuses_non_registry_input():
    """The catalog is a VIEW over a real AdapterRegistry — anything
    else (raw adapters, dicts, None) is a TypeError, never a catalog."""
    with pytest.raises(TypeError):
        ToolCapabilityCatalog(None)          # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ToolCapabilityCatalog([])            # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ToolCapabilityCatalog("registry")    # type: ignore[arg-type]


def test_catalog_describes_exactly_the_registered_adapters():
    rows = _catalog().describe()
    ids = [r["adapter_id"] for r in rows]
    # stable, priority-ordered (discovery probes first, then basic
    # identification, then the long checks)
    assert ids == ["naabu-probe", "dnsx-probe", "httpx-probe",
                   "whatweb-probe", "api-probe", "katana-probe",
                   "tls-probe", "nuclei-probe"]
    row = next(r for r in rows if r["adapter_id"] == "tls-probe")
    assert row["executable"] == "/opt/kryonsec/tls_probe.py"
    assert row["stages"] == ["RECON_ACTIVE"]
    assert row["max_seconds"] == 300
    assert row["verification"] == "not_verified (hard-wired)"
    assert row["registration_source"] == "AdapterRegistry (frozen)"


def test_catalog_presence_never_makes_a_tool_executable():
    """A tool that is NOT registered does not exist in the catalog: an
    unregistered id has no entry, no executable, no plan path."""
    catalog = _catalog()
    assert catalog.entry("searchsploit-term") is None
    assert catalog.entry("nmap") is None
    assert catalog.entry("made-up-tool") is None
    # the unregistered-but-known id is only ever reported, never enabled
    assert "searchsploit-term" in catalog.known_but_unregistered(
        {"searchsploit-term": 99})


def test_catalog_metadata_defaults_are_consistent():
    catalog = _catalog()
    for entry in catalog.entries():
        assert entry.priority > 0
        assert entry.cost_category in ("low", "medium", "high")
        assert entry.adapter.max_seconds >= 10
        # every check names its inputs — EXCEPT the two Batch 1
        # discovery probes, which run pre-discovery by design: their
        # input is the engagement target itself, not graph evidence
        if entry.adapter_id in ("naabu-probe", "dnsx-probe"):
            assert entry.requires_evidence == ()
        else:
            assert entry.requires_evidence


# ===========================================================================
# 2. capability selection
# ===========================================================================


def test_https_website_selects_the_full_web_surface():
    plan = _plan(bases=[HTTPS_BASE])
    sm = _status_map(plan)
    for adapter in ("httpx-probe", "whatweb-probe", "api-probe",
                    "katana-probe", "tls-probe", "nuclei-probe"):
        assert sm[(adapter, normalize_target(HTTPS_BASE))] == "selected"
    assert plan.counts() == {"selected": 6}
    # the domain-kind discovery probes are NOT paired with URL bases:
    # without domain_targets they get no entries at all (never
    # mis-dispatched against a target kind they cannot prepare)
    assert ("naabu-probe", normalize_target(HTTPS_BASE)) not in sm
    assert ("dnsx-probe", normalize_target(HTTPS_BASE)) not in sm


def test_http_only_website_never_gets_a_tls_check():
    plan = _plan(bases=[HTTP_BASE])
    sm = _status_map(plan)
    assert sm[("tls-probe", normalize_target(HTTP_BASE))] == "rejected"
    entry = next(e for e in plan.entries if e.adapter_id == "tls-probe")
    assert "TLS" in entry.reason or "tls" in entry.reason
    for adapter in ("httpx-probe", "whatweb-probe", "api-probe",
                    "katana-probe", "nuclei-probe"):
        assert sm[(adapter, normalize_target(HTTP_BASE))] == "selected"


def test_explicit_api_endpoint_selects_httpx_and_api_probe():
    api_base = f"https://api.{TARGET}:8443/"
    plan = _plan(bases=[api_base])
    sm = _status_map(plan)
    assert sm[("api-probe", normalize_target(api_base))] == "selected"
    assert sm[("httpx-probe", normalize_target(api_base))] == "selected"


def test_no_available_evidence_produces_an_empty_plan():
    """No open web ports -> no bases -> an explicit empty plan, audited
    — never an unrestricted fallback."""
    audit = RecordingAudit()
    plan = _plan(bases=[], audit=audit)
    assert plan.entries == ()
    assert plan.counts() == {}
    decided = audit.events[-1]
    assert decided["event"] == "planning_decided"
    assert decided["counts"] == {}


def test_unregistered_adapter_never_appears_in_a_plan():
    """A registry without tls-probe -> the planner cannot select it and
    cannot even describe it. Suggestions naming it are recorded and
    dropped — never executed."""
    reg = recon_active_registry()
    # build a reduced registry: everything except tls-probe
    reduced = AdapterRegistry()
    for a in reg.list_adapters():
        if a.adapter_id != "tls-probe":
            reduced.register(a)
    audit = RecordingAudit()
    planner = _planner(
        ToolCapabilityCatalog(reduced),
        suggestions=(ToolSuggestion(
            adapter_id="tls-probe", target_asset=HTTPS_BASE,
            rationale="please scan tls"),))
    plan = planner.plan(
        state="RECON_ACTIVE", target=TARGET, bases=[HTTPS_BASE],
        graph=_graph(), audit=audit)
    assert all(e.adapter_id != "tls-probe" for e in plan.entries)
    assert any("tls-probe" in r for r in planner.suggestion_rejections)
    names = [e["event"] for e in audit.events]
    assert "planning_decided" in names


def test_plan_entries_carry_the_registry_executable_only():
    """Every plan entry's executable comes from the registered adapter —
    the planner never invents, renames or wraps an executable."""
    plan = _plan(bases=[HTTPS_BASE])
    reg = recon_active_registry()
    executables = {a.adapter_id: a.executable
                   for a in reg.list_adapters()}
    for e in plan.entries:
        assert e.executable == executables[e.adapter_id]


def test_planner_has_no_execution_surface():
    """The planner never executes: no sandbox, no spawn, no argv
    builder — planning is a pure function over validated inputs."""
    planner = _planner()
    for attr in ("sandbox", "spawn", "execute", "run_command",
                 "dispatch", "build_argv"):
        assert not hasattr(planner, attr), attr
    assert not hasattr(_plan(), "argv")


# ===========================================================================
# 3. planning, priorities, budget
# ===========================================================================


def test_dependency_order_basic_identification_first():
    """Entries for one base run in explicit priority order: service
    identification (httpx) before fingerprints (whatweb) before the
    read-only API baseline, before the long checks."""
    plan = _plan(bases=[HTTPS_BASE])
    order = [e.adapter_id for e in plan.entries
             if e.target == HTTPS_BASE]
    assert order == ["httpx-probe", "whatweb-probe", "api-probe",
                     "katana-probe", "tls-probe", "nuclei-probe"]


def test_duplicate_work_avoided_on_complete_prior_run():
    graph = _graph()
    _attempt_node(graph, "httpx-probe", HTTP_BASE)
    audit = RecordingAudit()
    plan = _plan(bases=[HTTP_BASE], graph=graph, audit=audit)
    sm = _status_map(plan)
    assert sm[("httpx-probe", normalize_target(HTTP_BASE))] == "covered"
    # every other check stays selected — dedupe is per (adapter, base)
    assert sm[("whatweb-probe", normalize_target(HTTP_BASE))] == "selected"
    covered = next(e for e in plan.entries if e.status == "covered")
    assert covered.estimated_seconds == 0
    assert covered.evidence_refs  # the prior run is referenced
    assert plan.planned_seconds == sum(
        e.estimated_seconds for e in plan.entries if e.status == "selected")


def test_dedupe_requires_executed_exit_zero_not_truncated():
    """A prior run that did not happen, failed, was truncated, or was
    mis-recorded is NEVER coverage — the check stays eligible."""
    cases = [
        dict(executed=False),
        dict(exit_code=1),
        dict(outcome="not_run"),
        dict(truncated=True),
    ]
    for kw in cases:
        graph = _graph()
        _attempt_node(graph, "httpx-probe", HTTP_BASE, **kw)
        plan = _plan(bases=[HTTP_BASE], graph=graph)
        assert _status_map(plan)[
            ("httpx-probe", normalize_target(HTTP_BASE))] == "selected", kw


def test_stale_prior_run_is_not_coverage():
    """Evidence older than the freshness window is re-eligible."""
    graph = _graph()
    _attempt_node(graph, "httpx-probe", HTTP_BASE,
                  created_at="2020-01-01T00:00:00Z")
    plan = _plan(bases=[HTTP_BASE], graph=graph, max_evidence_age_s=3600)
    assert _status_map(plan)[
        ("httpx-probe", normalize_target(HTTP_BASE))] == "selected"


def test_fresh_prior_run_is_coverage():
    graph = _graph()
    node = _attempt_node(graph, "httpx-probe", HTTP_BASE)
    fresh = (datetime.now(timezone.utc) - timedelta(seconds=60)
             ).strftime("%Y-%m-%dT%H:%M:%SZ")
    node["created_at"] = fresh
    plan = _plan(bases=[HTTP_BASE], graph=graph, max_evidence_age_s=3600)
    assert _status_map(plan)[
        ("httpx-probe", normalize_target(HTTP_BASE))] == "covered"


def test_partial_tls_run_is_not_coverage():
    """The honest-partial rule: the tls wrapper exits 0 even when it was
    killed early — coverage requires the summary node's status to read
    ``complete``. A partial summary keeps the check eligible."""
    graph = _graph()
    _attempt_node(graph, "tls-probe", HTTPS_BASE)
    graph.add_node(
        node_type="tls_observation",
        label=f"testssl {TARGET}:8443",
        properties={"node": f"{TARGET}:8443", "status": "partial",
                    "classification": "tool_reported_observation"},
    )
    plan = _plan(bases=[HTTPS_BASE], graph=graph)
    assert _status_map(plan)[
        ("tls-probe", normalize_target(HTTPS_BASE))] == "selected"


def test_complete_tls_run_is_coverage():
    graph = _graph()
    _attempt_node(graph, "tls-probe", HTTPS_BASE)
    graph.add_node(
        node_type="tls_observation",
        label=f"testssl {TARGET}:8443",
        properties={"node": f"{TARGET}:8443", "status": "complete"},
    )
    plan = _plan(bases=[HTTPS_BASE], graph=graph)
    assert _status_map(plan)[
        ("tls-probe", normalize_target(HTTPS_BASE))] == "covered"


def test_malformed_attempt_node_is_audited_and_never_coverage():
    graph = _graph()
    graph.add_node(
        node_type="adapter_attempt",
        label="adapter_attempt:httpx-probe:bad",
        properties={"adapter_id": "httpx-probe", "garbage": True},
    )
    audit = RecordingAudit()
    plan = _plan(bases=[HTTP_BASE], graph=graph, audit=audit)
    assert _status_map(plan)[
        ("httpx-probe", normalize_target(HTTP_BASE))] == "selected"
    assert any(e["event"] == "planner_malformed_attempt_node"
               for e in audit.events)


def test_budget_exhaustion_defers_with_an_explainable_reason():
    """A tight budget fills in priority order; entries that no longer
    fit are DEFERRED with the exact seconds in the reason — never
    dropped silently, never overriding eligibility."""
    audit = RecordingAudit()
    plan = _plan(bases=[HTTP_BASE],
                 budget=PlannerBudget(max_total_seconds=500), audit=audit)
    sm = _status_map(plan)
    assert sm[("httpx-probe", normalize_target(HTTP_BASE))] == "selected"
    assert sm[("whatweb-probe", normalize_target(HTTP_BASE))] == "selected"
    assert sm[("api-probe", normalize_target(HTTP_BASE))] == "selected"
    # priority packing: 120+120+120 = 360s committed; the crawl (180s)
    # and nuclei (300s) no longer fit in 500s. The TLS check is
    # REJECTED outright (plain-http scheme gate) — eligibility always
    # beats the budget.
    assert sm[("katana-probe", normalize_target(HTTP_BASE))] == "deferred"
    assert sm[("tls-probe", normalize_target(HTTP_BASE))] == "rejected"
    assert sm[("nuclei-probe", normalize_target(HTTP_BASE))] == "deferred"
    assert plan.planned_seconds <= 500
    deferred = [e for e in plan.entries if e.status == "deferred"]
    for e in deferred:
        assert "budget" in e.reason
        # the reason carries the entry's own seconds honestly
        assert str(e.estimated_seconds) in e.reason
    decided = audit.events[-1]
    assert decided["counts"]["deferred"] == 2
    lines = decided["entries"]
    assert any("deferred" in ln for ln in lines)


def test_budget_never_overrides_eligibility():
    """Even with a huge budget, plain-HTTP TLS checks stay rejected and
    out-of-stage adapters stay out of the stage."""
    plan = _plan(bases=[HTTP_BASE], budget=PlannerBudget(max_total_seconds=100_000))
    assert _status_map(plan)[
        ("tls-probe", normalize_target(HTTP_BASE))] == "rejected"


def test_timeout_budgeting_reflects_adapter_max_seconds():
    plan = _plan(bases=[HTTPS_BASE])
    for e in plan.entries:
        reg_max = recon_active_registry().get(e.adapter_id).max_seconds
        assert e.estimated_seconds == reg_max
    assert plan.planned_seconds == sum(
        e.estimated_seconds for e in plan.entries)
    assert plan.planned_seconds <= plan.budget_seconds


def test_zero_budget_defers_everything_eligible():
    plan = _plan(bases=[HTTP_BASE], budget=PlannerBudget(max_total_seconds=0))
    statuses = {e.status for e in plan.entries if e.status != "rejected"}
    assert statuses == {"deferred"}


# ===========================================================================
# 4. advisory LLM suggestions (never required, never authorizing)
# ===========================================================================


def test_planner_works_with_no_llm():
    """No LLM, no suggestions — the deterministic planner functions
    identically and records no suggestion rejections."""
    planner = _planner()
    plan = planner.plan(state="RECON_ACTIVE", target=TARGET,
                        bases=[HTTPS_BASE], graph=_graph(),
                        audit=RecordingAudit())
    assert plan.counts() == {"selected": 6}
    assert planner.suggestion_rejections == []
    assert not any(e.suggested for e in plan.entries)


def test_suggestion_cannot_supply_executable_or_argv_or_template():
    """The suggestion schema physically has no executable/argv/target-
    invention/template fields — extra fields are FORBIDDEN, not
    ignored."""
    for bad in ({"adapter_id": "httpx-probe", "target_asset": HTTP_BASE,
                 "executable": "/bin/sh"},
                {"adapter_id": "httpx-probe", "target_asset": HTTP_BASE,
                 "argv": ["-oG", "/tmp/x"]},
                {"adapter_id": "httpx-probe", "target_asset": HTTP_BASE,
                 "template": "cves/2021/CVE-2021-44228"},
                {"adapter_id": "httpx-probe", "target_asset": HTTP_BASE,
                 "target": "https://evil.example.com/"}):
        with pytest.raises(ValidationError):
            ToolSuggestion(**bad)


def test_malformed_suggestion_recorded_never_policy_weakening():
    """An unregistered-adapter suggestion is recorded and dropped; the
    plan is identical to the no-suggestion plan."""
    planner = _planner(suggestions=(ToolSuggestion(
        adapter_id="unknown-adapter", target_asset=HTTPS_BASE,
        rationale="x"),))
    plan = planner.plan(state="RECON_ACTIVE", target=TARGET,
                        bases=[HTTPS_BASE], graph=_graph(),
                        audit=RecordingAudit())
    assert plan.counts() == {"selected": 6}
    assert planner.suggestion_rejections and \
        "not registered" in planner.suggestion_rejections[0]


def test_conflicting_suggestions_first_one_wins():
    planner = _planner(suggestions=(
        ToolSuggestion(adapter_id="whatweb-probe", target_asset=HTTP_BASE,
                       rationale="first"),
        ToolSuggestion(adapter_id="whatweb-probe", target_asset=HTTP_BASE,
                       rationale="second"),
    ))
    plan = planner.plan(state="RECON_ACTIVE", target=TARGET,
                        bases=[HTTP_BASE], graph=_graph(),
                        audit=RecordingAudit())
    entry = next(e for e in plan.entries
                 if e.adapter_id == "whatweb-probe")
    assert entry.suggested and "first" in entry.reason
    assert any("conflicting" in r
               for r in planner.suggestion_rejections)


def test_suggestion_target_outside_base_set_rejected():
    """A suggestion naming an out-of-scope / not-in-plan target is
    recorded as rejected — never executed, never added to the plan."""
    planner = _planner(suggestions=(ToolSuggestion(
        adapter_id="httpx-probe",
        target_asset="https://unauthorized.example.com/",
        rationale="scan this too"),))
    plan = planner.plan(state="RECON_ACTIVE", target=TARGET,
                        bases=[HTTP_BASE], graph=_graph(),
                        audit=RecordingAudit())
    targets = {e.target for e in plan.entries}
    assert "https://unauthorized.example.com/" not in targets
    assert any("not in the plan's evidence-backed base set" in r
               for r in planner.suggestion_rejections)


def test_accepted_suggestion_is_only_an_annotation():
    """A valid suggestion marks its entry suggested and explains itself
    — it does not change eligibility, ordering or the budget."""
    planner = _planner(suggestions=(ToolSuggestion(
        adapter_id="tls-probe", target_asset=HTTP_BASE,
        rationale="operator asked for a TLS baseline"),))
    plan = planner.plan(state="RECON_ACTIVE", target=TARGET,
                        bases=[HTTP_BASE], graph=_graph(),
                        audit=RecordingAudit())
    entry = next(e for e in plan.entries if e.adapter_id == "tls-probe")
    # still rejected on the plain-http base — a suggestion is NOT
    # execution authorization
    assert entry.status == "rejected" and entry.suggested


# ===========================================================================
# 5. security boundaries
# ===========================================================================


def test_planner_never_widens_the_base_set():
    """Bases come from observed open ports only; the plan contains
    exactly the pairs it was given — nothing discovered, nothing
    invented."""
    plan = _plan(bases=[HTTPS_BASE])
    assert {e.target for e in plan.entries} == {HTTPS_BASE}


def test_out_of_stage_adapter_is_reported_not_run():
    """A registered adapter whose stage is not this one gets an explicit
    ``out_of_stage`` entry — e.g. the HYPOTHESIZE searchsploit term
    lookup never enters RECON_ACTIVE plans."""
    from kryonsec.purple.adapter_searchsploit import (
        make_searchsploit_term_adapter,
    )
    reg = recon_active_registry()
    reg.register(make_searchsploit_term_adapter())
    audit = RecordingAudit()
    plan = ToolPlanner(ToolCapabilityCatalog(reg)).plan(
        state="RECON_ACTIVE", target=TARGET, bases=[HTTPS_BASE],
        graph=_graph(), audit=audit)
    entry = next(e for e in plan.entries
                 if e.adapter_id == "searchsploit-term")
    assert entry.status == "out_of_stage"
    assert plan.counts().get("out_of_stage") == 1


def test_no_arbitrary_argv_construction():
    """Plan entries carry NO argv — argv stays frozen in the registry
    and is composed only by the existing dispatch path."""
    mod = (Path(__file__).resolve().parents[1] / "src" / "kryonsec" /
           "purple" / "tool_planner.py").read_text(encoding="utf-8")
    assert "command_template" in mod  # the catalog READS the template
    assert 'plan.append' not in mod
    with pytest.raises(ValidationError):
        PlanEntry(adapter_id="httpx-probe", executable="httpx",
                  target=HTTP_BASE, stage="RECON_ACTIVE", priority=10,
                  estimated_seconds=120, status="selected",
                  argv=["-oG", "/tmp/x"])  # extra fields are FORBIDDEN


def test_no_host_execution_and_no_mcp_in_the_planner_module():
    mod = (Path(__file__).resolve().parents[1] / "src" / "kryonsec" /
           "purple" / "tool_planner.py").read_text(encoding="utf-8")
    assert "subprocess" not in mod
    assert "os.system" not in mod
    assert "docker" not in mod.lower().replace("docker-only", "")
    assert "copilot" not in mod
    assert "mcp" not in mod


def test_post_exploit_stays_dormant_and_planner_free():
    post = (Path(__file__).resolve().parents[1] / "src" / "kryonsec" /
            "purple" / "post_exploit.py").read_text(encoding="utf-8")
    assert "tool_planner" not in post


def test_gates_are_untouched_by_the_planner():
    """The planner does not read, write or decide approvals: approvals
    come only from the registered adapters' own gate definitions."""
    reg = recon_active_registry()
    for a in reg.list_adapters():
        # whatever the adapter declares, the planner merely reports it
        entry = _catalog().entry(a.adapter_id)
        assert entry is not None
    assert not hasattr(ToolPlanner, "approve")
    assert not hasattr(ToolPlanner, "bypass")


def test_planner_fail_closed_on_bad_input():
    """Malformed inputs fail CLOSED with an exception the caller must
    treat as a planner failure — never silently degraded plans."""
    planner = _planner()
    with pytest.raises(Exception):
        planner.plan(state="RECON_ACTIVE", target=TARGET,
                     bases=[None], graph=_graph(),
                     audit=RecordingAudit())  # type: ignore[list-item]


# ===========================================================================
# 6. evidence + audit integration (full subagent run)
# ===========================================================================


def _tool(argv0: str):
    return argv0


def _stage_script(argv):
    """Stage 1 finds one HTTP port; adapter tools answer honest payloads;
    everything else answers empty. Same fake shape as the adapter ITs."""
    tool = argv[0]
    if tool == "nmap":
        return SpawnResult(ok=True, exit_code=0,
                           stdout="8080/tcp   open  http    nginx")
    if tool == "naabu":
        return SpawnResult(ok=True, exit_code=0,
                           stdout=f"{TARGET}:8080")
    if tool == "dnsx":
        return SpawnResult(ok=True, exit_code=0,
                           stdout=f"{TARGET} [A] 203.0.113.7")
    if tool == "httpx":
        return SpawnResult(ok=True, exit_code=0, stdout="")
    return SpawnResult(ok=True, exit_code=0, stdout="")


class _FakeSandbox:
    def __init__(self, script):
        self._script = script
        self.spawned = []
        self.egress_policy = object()
        self.timeout_s = 330
        self.image = "kryonsec/sandbox@sha256:" + "ab" * 32

    def spawn(self, argv, timeout_s=None):
        self.spawned.append((list(argv), timeout_s))
        return self._script(argv)


def _events(audit) -> "list[dict]":
    return [json.loads(line) for line in open(audit.path,
                                              encoding="utf-8")
            if line.strip()]


def _subagent_run(tmp_path, *, planner=None, script=None,
                  registry=None):
    from kryonsec.config import KryonsecConfig

    sandbox = _FakeSandbox(script or _stage_script)
    audit = AuditLog(tmp_path / "ra.jsonl")
    graph = EngagementGraph(engagement_id="e-run")
    graph.add_node("target", TARGET, {})
    sub = ReconActiveSubagent(
        KryonsecConfig(home=tmp_path / "home"), graph, audit, TARGET,
        sandbox,  # type: ignore[arg-type]
        adapter_registry=registry if registry is not None
        else recon_active_registry(),
        planner=planner,
    )
    result = sub.run()
    return result, sandbox, audit, graph


def test_plan_filters_lanes_and_links_audit_events(tmp_path):
    """A zero budget defers every planner-gated adapter check: NOTHING
    planner-gated spawns, the discovery lanes still run (they are NOT
    planner-gated — the plan needs their observed ports and reports
    them as covered post-hoc), the legacy crawl tools still run
    (unchanged), and the audit carries the planned-vs-executed truth."""
    planner = _planner(budget=PlannerBudget(max_total_seconds=0))
    result, sandbox, audit, graph = _subagent_run(
        tmp_path, planner=planner)
    assert result.status == "ok"
    tools_spawned = [argv[0] for argv, _t in sandbox.spawned]
    # discovery + legacy web tools ran exactly as before. katana is NO
    # longer among them: its legacy entry is omitted (the katana-probe
    # adapter is registered) and the adapter lane itself is deferred by
    # the zero budget — the same rule the other web lanes always had.
    for tool in ("nmap", "naabu", "dnsx", "feroxbuster", "gowitness"):
        assert tool in tools_spawned, tool
    assert "katana" not in tools_spawned
    # the PLANNER-GATED web adapters spawned nothing at all; the two
    # discovery probes (naabu-probe / dnsx-probe) are the documented
    # exception — their lanes run pre-discovery, so their executables
    # DID spawn (as the naabu/dnsx entries above show)
    reg = recon_active_registry()
    un_gated = {"naabu-probe", "dnsx-probe"}
    for adapter in reg.list_adapters():
        if adapter.adapter_id in un_gated:
            continue
        assert adapter.executable not in tools_spawned, adapter.adapter_id
    events = _events(audit)
    names = [e["event"] for e in events]
    assert "planning_decided" in names
    assert "planner_plan_applied" in names
    decided = next(e for e in events if e["event"] == "planning_decided")
    # the two discovery lanes ran BEFORE the plan and show up post-hoc
    # as covered (fresh successful adapter_attempt nodes) — never as
    # fabricated selections
    assert decided["counts"].get("covered") == 2
    assert decided["counts"].get("selected", 0) == 0
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert done["planned_selected"] == 0
    assert done["planned_executed"] == 0
    ok, reason = audit.verify()
    assert ok, reason


def test_planned_and_executed_agree_on_a_full_run(tmp_path):
    """Default budget -> every eligible check selected and actually
    executed; recon_active_done records the agreement; per-run adapter
    events link back to the plan id."""
    planner = _planner()
    result, sandbox, audit, graph = _subagent_run(
        tmp_path, planner=planner)
    assert result.status == "ok"
    events = _events(audit)
    decided = next(e for e in events
                   if e["event"] == "planning_decided")
    # one plain-http base: 5 eligible checks selected (httpx, whatweb,
    # api, katana, nuclei), tls rejected, and the two discovery probes
    # covered post-hoc (their lanes ran before the plan)
    assert decided["counts"] == {"selected": 5, "rejected": 1,
                                 "covered": 2}
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert done["planned_selected"] == 5
    assert done["planned_executed"] == 5
    assert done["planned_not_executed"] == []
    # the tls check was rejected for the plain-http base — recorded
    assert decided["counts"].get("rejected", 0) == 1
    plan_id = decided["plan_id"]
    linked = [e for e in events
              if e.get("plan_id") == plan_id
              and e["event"].startswith("recon_active_")]
    assert linked, "adapter runs must link back to the plan"
    ok, reason = audit.verify()
    assert ok, reason


def _expect_web_adapters_spawned(registry, tools_spawned, *, https=False):
    """Every registered adapter whose scheme matches the discovered
    bases must have spawned (the tls-probe adapter only ever spawns for
    https bases — the deterministic scheme rule, planner or not)."""
    for adapter in registry.list_adapters():
        if adapter.adapter_id == "tls-probe" and not https:
            continue
        assert adapter.executable in tools_spawned, adapter.adapter_id


def test_planner_failure_falls_back_to_legacy_path(tmp_path):
    """A planner crash is audited (planner_failed) and RECON_ACTIVE
    falls back to the exact pre-2B.6 path — adapter lanes run
    unfiltered, nothing new, nothing widened."""
    class _BrokenPlanner:
        def plan(self, **kw):
            raise RuntimeError("planner exploded")

    result, sandbox, audit, graph = _subagent_run(
        tmp_path, planner=_BrokenPlanner())
    assert result.status == "ok"
    events = _events(audit)
    names = [e["event"] for e in events]
    assert "planner_failed" in names
    assert "planning_decided" not in names
    # the pre-2B.6 path ran: every scheme-eligible adapter spawned
    tools_spawned = {argv[0] for argv, _t in sandbox.spawned}
    _expect_web_adapters_spawned(recon_active_registry(), tools_spawned)
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert "plan_id" not in done  # no plan to compare against
    ok, reason = audit.verify()
    assert ok, reason


def test_no_planner_is_bit_identical_legacy_behavior(tmp_path):
    """planner=None (the default): no planning events at all, and the
    adapter lanes run exactly as in 2B.5."""
    result, sandbox, audit, graph = _subagent_run(tmp_path)
    assert result.status == "ok"
    names = [e["event"] for e in _events(audit)]
    assert "planning_decided" not in names
    assert "planner_plan_applied" not in names
    assert "planner_failed" not in names
    tools_spawned = {argv[0] for argv, _t in sandbox.spawned}
    _expect_web_adapters_spawned(recon_active_registry(), tools_spawned)


def test_audit_chain_integrity_with_planning_events(tmp_path):
    planner = _planner(budget=PlannerBudget(max_total_seconds=0))
    _result, _sandbox, audit, _graph = _subagent_run(
        tmp_path, planner=planner)
    ok, reason = audit.verify()
    assert ok, reason
