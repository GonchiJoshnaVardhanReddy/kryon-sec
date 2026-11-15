"""Tool Expansion Batch 1 tests: the katana-probe production Mode B
adapter.

MOCKED tests (the default, huge majority): a duck-typed sandbox double
returns canned SpawnResults — no process, no packets, no crawl. They pin
the contract: explicit registration (single + combined RECON_ACTIVE
registry), the byte-identical fixed template with the LANE-PINNED depth
2 (no deeper crawl, no forms, no JSON stream), URL scope/preparation
refusals, gate + sandbox + egress enforcement, output bounds, honest
failure classification, no host fallback, deterministic Recon Active
integration (the adapter REPLACES the legacy katana web-plan entry;
exactly ONE crawl per base; legacy-shape path nodes with adapter
provenance, first-wins dedupe), planner gating (like every other web
lane: zero budget → no spawn), and the no-new-capability invariants
(Gate 2/3 and Post-Exploit untouched).

REAL IT (exactly one, opt-in): a genuine katana crawl against an
OPERATOR-SUPPLIED locally controlled lab URL through a REAL Docker +
gVisor runsc sandbox and the REAL egress boundary. Guarded by
KRYONSEC_KATANA_IT=1 — skipped silently otherwise. NEVER runs against
anything public; the lab URL comes from the operator. An empty crawl
result is an honest INCONCLUSIVE, never a failure mask.

Run the real IT on a Linux host with Docker + runsc + the pinned image:
    KRYONSEC_KATANA_IT=1 \
        KRYONSEC_KATANA_LAB_URL=http://lab-host.example:8080/ \
        KRYONSEC_SANDBOX_IMAGE='<digest-pinned-image>' \
        .venv/bin/python -m pytest tests/test_katana_adapter.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_katana import (
    ADAPTER_ID,
    KATANA_ADAPTER_ID,
    KATANA_PROBE_TEMPLATE,
    PINNED_DEPTH,
    TOOL_EXECUTABLE,
    KatanaObservation,
    derive_crawled_path,
    find_adapter_attempt_node,
    make_katana_probe_adapter,
    parse_katana_lines,
    production_registry,
    record_katana_evidence,
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


def _prep(reg=None, *, target_asset=BASE):
    return prepare_adapter_run(
        reg if reg is not None else production_registry(), ADAPTER_ID,
        target=TARGET, target_asset=target_asset,
        params={"depth": PINNED_DEPTH})


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------

def test_production_registry_registers_katana_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("katana-probe",)          # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "web_recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "url"
    assert adapter.executable == "katana"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()           # RECON_ACTIVE authorization =
                                             # engagement model, not silent
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_katana_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_katana_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_katana_probe():
    reg = recon_active_registry()
    assert "katana-probe" in reg.adapter_ids()
    adapter = reg.get(KATANA_ADAPTER_ID)
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.approvals == ()
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"


# ---- 2. correct fixed command rendering + byte-identical lockstep ---------------

def test_fixed_template_rendering():
    reg = production_registry()
    prep = _prep(reg)
    assert prep.argv == ["katana", "-u", BASE, "-d", "2", "-silent"]
    assert prep.target == BASE
    assert prep.target_kind == "url"
    rebuilt = [BASE if a == "{url}"
               else (PINNED_DEPTH if a == "{depth}" else a)
               for a in KATANA_PROBE_TEMPLATE]
    assert prep.argv == ["katana", *rebuilt]


def test_template_is_byte_identical_to_the_shipped_layer2_template():
    """The adapter adds NO flag the legacy katana entry does not carry:
    the argv it renders validates against the SHIPPED Layer-2 template
    unchanged, and no JSON stream / form / header / wordlist switch can
    ever appear."""
    from kryonsec.purple.allowlist import (ACTIVE_RECON_TEMPLATES,
                                           ToolAllowlist)

    assert list(KATANA_PROBE_TEMPLATE) == \
        list(ACTIVE_RECON_TEMPLATES["katana"])
    shipped = ToolAllowlist(dict(ACTIVE_RECON_TEMPLATES))
    shipped.validate(TOOL_EXECUTABLE,
                     ["katana", "-u", BASE, "-d", "2", "-silent"])
    # the template carries EXACTLY the legacy flag set — nothing extra
    flags = [a for a in KATANA_PROBE_TEMPLATE if a.startswith("-")]
    assert flags == ["-u", "-d", "-silent"]
    for forbidden in ("-json", "-jc", "-kf", "-proxy", "-headers",
                      "-header", "-body", "-form", "-c", "-rl", "-w",
                      "-H", "-o"):
        assert forbidden not in KATANA_PROBE_TEMPLATE, forbidden


def test_crawl_depth_is_pinned_to_the_legacy_two():
    """``-d 2`` is the legacy plan entry's depth — the module pins it as
    a constant and the lane passes exactly that. A deeper crawl would
    be a conscious code change, auditable in git, never caller input."""
    assert PINNED_DEPTH == "2"
    adapter = make_katana_probe_adapter()
    assert adapter.max_seconds == 180        # ≤ the 330s sandbox ceiling
    reg = production_registry()
    prep = _prep(reg)
    assert prep.argv[prep.argv.index("-d") + 1] == PINNED_DEPTH
    # the SHIPPED template carries the same depth placeholder — the
    # legacy entry and the adapter entry are byte-identical once filled
    assert KATANA_PROBE_TEMPLATE[KATANA_PROBE_TEMPLATE.index("-d")
                                 + 1] == "{depth}"


# ---- 3. identification ------------------------------------------------------------

def test_katana_identification():
    """The executable is the REAL bundled binary (entrypoint-allowlisted
    in the pinned sandbox image) and the evidence names the tool."""
    adapter = make_katana_probe_adapter()
    assert adapter.executable == "katana"
    assert "katana" in adapter.purpose
    reg = production_registry()
    described = json.loads(reg.describe(ADAPTER_ID))
    assert described["executable"] == "katana"
    assert described["evidence_kind"] == "text_excerpt"


# ---- 4. preparation refusals (URL scope + option injection) --------------------------

def test_out_of_scope_assets_refused_at_preparation():
    reg = production_registry()
    # absolute assets whose host is not the target / a subdomain:
    # the caller cannot aim the crawler at an arbitrary host
    for out in ("https://elsewhere.example.com/", "http://target-corp.net/",
                "http://sub.target-corp.net/"):
        with pytest.raises(AdapterError):
            prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                                target_asset=out,
                                params={"depth": PINNED_DEPTH})
    # an in-scope subdomain composes fine (the standard scope rule)
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="https://mail.target-corp.com/",
                               params={"depth": PINNED_DEPTH})
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
                                target_asset=bad,
                                params={"depth": PINNED_DEPTH})


def test_depth_param_is_all_or_nothing_and_option_shaped_refused():
    reg = production_registry()
    # the template's placeholder REQUIRES an explicit param (the lane
    # pins it) — all-or-nothing, never a default depth
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE)
    # unexpected params are refused
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE,
                            params={"depth": "2", "extra": "x"})
    # option-shaped caller input is refused (option injection): no
    # value may begin with '-'
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE, params={"depth": "-d"})


# ---- 5. missing gate/authorization where required -------------------------------------

def test_gated_variant_refused_without_grant(tmp_path):
    """A variant that names EXPLOIT MUST demand the hypothesis gate and
    is REFUSED without it — the Gate 2 enforcement module is unchanged."""
    from kryonsec.purple.adapters import ModeBToolAdapter

    variant = make_katana_probe_adapter()
    exploit_variant = ModeBToolAdapter(
        **{**variant.model_dump(), "adapter_id": "katana-gated",
           "stages": ("EXPLOIT",), "approvals": ("hypothesis_gate",),
           "risk": "active"})
    reg = AdapterRegistry()
    reg.register(exploit_variant)
    prep = prepare_adapter_run(reg, "katana-gated", target=TARGET,
                               target_asset=BASE,
                               params={"depth": PINNED_DEPTH})
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
    prep = _prep(reg)
    for bad in (None, object()):          # none + no-spawn blob
        record = execute_adapter(reg, prep, sandbox=bad, audit=audit)
        assert record.executed is False and record.outcome == "refused"
        assert "no sandbox" in record.error_excerpt
    assert _event_names(audit).count("adapter_refused") == 2


# ---- 7. egress boundary unavailable ------------------------------------------------------

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


# ---- 8. tool timeout / nonzero exit — honest failures --------------------------------------

def test_tool_timeout_is_an_honest_failure(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = _prep(reg)
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                  error="tool exceeded 180s sandbox timeout"),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is False and record.outcome == "not_run"
    assert record.failure_class == "timeout"
    assert output == ""
    # no attempt node, no path nodes
    assert graph.by_type("adapter_attempt") == []
    assert graph.by_type("path") == []
    # timeout bound respected on the spawn call (adapter max_seconds)
    assert sbx.spawned and sbx.spawned[0][1] == \
        make_katana_probe_adapter().max_seconds


def test_nonzero_exit_is_not_success(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = _prep(reg)
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=1, stdout="",
                                  error="connection refused"),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    assert record.executed is False and record.outcome == "not_run"
    assert record.exit_code == 1
    assert record.verification == "not_verified"
    assert graph.by_type("path") == []
    names = _event_names(audit)
    assert "adapter_result" in names
    for ev in _events(audit):
        if ev["event"] == "adapter_result":
            assert ev["ok"] is False and ev["exit_code"] == 1


# ---- 9. malformed and oversized output -----------------------------------------------------

def test_malformed_output_never_becomes_observations():
    garbage = (
        # banner/noise lines — not results
        "katana 9.x\n"
        "[INF] crawler started\n"
        # a crawl error that slipped through -silent
        "[ERR] could not connect: connection refused\n"
        "not a url line\n"
        "\n"
    )
    obs, malformed = parse_katana_lines(garbage, target=TARGET)
    assert obs == [] and malformed == 4

    # a VALID line among garbage still parses (defensive, not paranoid)
    obs, malformed = parse_katana_lines(
        garbage + "http://target-corp.com:8080/admin\n", target=TARGET)
    assert [o.url for o in obs] == \
        ["http://target-corp.com:8080/admin"] and malformed == 4

    # query strings are KEPT (the legacy parse keeps them too)
    obs, _m = parse_katana_lines(
        "http://target-corp.com:8080/search?q=1", target=TARGET)
    assert obs[0].path == ":8080/search?q=1"

    # the path derivation is the LEGACY one: split on the engagement
    # target, query kept, never empty
    assert derive_crawled_path(
        "http://target-corp.com:8080/", TARGET) == ":8080/"
    assert derive_crawled_path(
        "https://mail.target-corp.com/x", TARGET) == "/x"
    assert derive_crawled_path("http://elsewhere.example.com/z", TARGET) \
        == "http://elsewhere.example.com/z"       # no target: whole URL

    # oversized: the observation cap holds; fields are bounded
    flood = "\n".join(f"http://target-corp.com:8080/p{i}"
                      for i in range(1, 300))
    obs, _ = parse_katana_lines(flood, target=TARGET)
    assert len(obs) == 100                     # max_observations default
    caps = KatanaObservation.model_fields
    assert caps["url"].metadata is not None    # bounded field lengths


# ---- 10. evidence recording: legacy-shape path nodes + refusal ------------------------

def test_record_evidence_refuses_without_attempt_node(tmp_path):
    """A refused run must never fabricate path evidence."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    record = execute_adapter(registry, _prep(registry),
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    obs, _ = parse_katana_lines("http://target-corp.com:8080/admin\n",
                                target=TARGET)
    ids = record_katana_evidence(graph, audit, run_record=record,
                                 observations=obs)
    assert ids == []
    assert graph.by_type("path") == []
    names = _event_names(audit)
    assert "katana_adapter_evidence_refused" in names


def test_evidence_mapping_is_legacy_shape_and_idempotent(tmp_path):
    """Each observation maps to ONE legacy-shape ``path`` node (the same
    node type the legacy parse produces and HYPOTHESIZE reads, labelled
    by the derived path) with a produced-lineage edge from the run's
    adapter_attempt node; a repeat mapping adds NOTHING (first-wins by
    label), and paths another source already placed are SKIPPED."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    stdout = ("http://target-corp.com:8080/admin?page=1\n"
              "http://target-corp.com:8080/login\n")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=stdout),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(registry, _prep(registry),
                                     sandbox=sbx, audit=audit, graph=graph,
                                     full_output=True)
    obs, malformed = parse_katana_lines(output, target=TARGET)
    assert [o.path for o in obs] == [":8080/admin?page=1", ":8080/login"]
    assert malformed == 0
    created = record_katana_evidence(graph, audit, run_record=record,
                                     observations=obs,
                                     malformed_lines=malformed)
    assert len(created) == 2
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None
    restored = AdapterRunRecord.model_validate(attempt["properties"])
    assert restored.adapter_id == ADAPTER_ID
    nodes = graph.by_type("path")
    assert len(nodes) == 2
    by_label = {n["label"]: n for n in nodes}
    props = by_label[":8080/login"]["properties"]
    assert props["url"] == "http://target-corp.com:8080/login"
    assert props["source"] == "katana"           # the legacy source tag
    assert props["adapter"] == ADAPTER_ID        # + adapter provenance
    assert props["request_id"] == record.request_id
    assert props["verification"] == "not_verified"
    assert props["untrusted"] is True
    # lineage: attempt --produced--> path, for BOTH nodes
    assert graph.has_edge(attempt, "produced", by_label[":8080/login"])
    assert graph.has_edge(attempt, "produced",
                          by_label[":8080/admin?page=1"])
    # idempotence: a REPEAT mapping adds nothing (first-wins by label)
    ids2 = record_katana_evidence(graph, audit, run_record=record,
                                  observations=obs)
    assert ids2 == []
    assert len(graph.by_type("path")) == 2
    # cross-source: a path ANOTHER source placed first is skipped too
    graph.add_node("path", ":8080/admin", {"source": "feroxbuster",
                                           "status": 200})
    obs3 = [KatanaObservation(url="http://target-corp.com:8080/admin",
                              path=":8080/admin")]
    ids3 = record_katana_evidence(graph, audit, run_record=record,
                                  observations=obs3)
    assert ids3 == []
    admins = [n for n in graph.by_type("path") if n["label"] == ":8080/admin"]
    assert len(admins) == 1                      # the feroxbuster one
    assert admins[0]["properties"]["source"] == "feroxbuster"
    ev = [e for e in _events(audit) if e["event"] == "katana_adapter_evidence"]
    assert ev[0]["observations"] == 2 and ev[0]["path_nodes"] == 2
    assert ev[0]["duplicate_or_refused"] == 0
    assert ev[1]["duplicate_or_refused"] == 2    # the repeat mapping
    assert ev[2]["path_nodes"] == 0 and ev[2]["duplicate_or_refused"] == 1
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_observation_run_is_an_honest_inconclusive(tmp_path):
    """A clean crawl that found NOTHING is audited with zero paths —
    never a negative 'nothing exists' claim."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(registry, _prep(registry),
                                     sandbox=sbx, audit=audit, graph=graph,
                                     full_output=True)
    obs, _m = parse_katana_lines(output, target=TARGET)
    created = record_katana_evidence(graph, audit, run_record=record,
                                     observations=obs)
    assert created == []
    assert graph.by_type("path") == []
    ev = [e for e in _events(audit) if e["event"] == "katana_adapter_evidence"]
    assert ev[0]["observations"] == 0 and ev[0]["path_nodes"] == 0


# ---- 11. status/exit is NOT vulnerability confirmation -----------------------

def test_crawled_path_is_recon_evidence_never_confirmation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout="http://target-corp.com:8080/admin"),
                      egress_policy=_StubEgressPolicy())
    record, _output = execute_adapter(reg, _prep(reg), sandbox=sbx,
                                      audit=audit, graph=graph,
                                      full_output=True)
    assert record.executed is True and record.exit_code == 0
    # HARD invariants:
    assert record.verification == "not_verified"
    assert record.untrusted is True
    assert "confirmed" not in record.model_dump()
    obs, _m = parse_katana_lines("http://target-corp.com:8080/admin",
                                 target=TARGET)
    record_katana_evidence(graph, audit, run_record=record, observations=obs)
    props = graph.by_type("path")[0]["properties"]
    assert props["verification"] == "not_verified"
    # nothing on the graph became a finding / capability / approval
    assert graph.by_type("finding") == []
    assert graph.by_type("capability") == []
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    # ...and no gate lifecycle events were written by the adapter path
    names = _event_names(audit)
    assert not any("gate" in n for n in names if n != "adapter_refused")


# ---- 12. no host execution fallback ---------------------------------------------------------

def test_no_host_execution_in_adapter_module():
    source = Path("src/kryonsec/purple") / "adapter_katana.py"
    text = source.read_text(encoding="utf-8")
    assert "subprocess" not in text
    assert "import mcp" not in text
    assert "docker " + "run" not in text


# ---- 13. no duplicate Recon Active crawl (deterministic either/or) ----------------------

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
    if tool == "katana":
        # the ADAPTER and the LEGACY entry share argv[0] — the either/or
        # rule below counts spawns to prove only ONE ran
        return SpawnResult(ok=True, exit_code=0, stdout=(
            "http://target-corp.com:8080/admin?page=1\n"
            "http://target-corp.com:8080/login\n"))
    return SpawnResult(ok=True, exit_code=0, stdout="")


def _fake_stage1(script):
    return FakeSandbox(script=script, egress_policy=_StubEgressPolicy())


def _katana_runs(cmdl):
    return [a for a in cmdl if a and a[0] == "katana"]


def test_adapter_mode_crawls_katana_once_never_both(tmp_path):
    """DETERMINISTIC either/or: the legacy katana web-plan entry is
    REPLACED by the adapter run — exactly ONE crawl per base (the legacy
    entry and the adapter share argv[0], so two spawns would show), and
    the crawled paths land in the SAME legacy-shape path nodes with the
    adapter provenance."""
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(sandbox, recon_active_registry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs = _katana_runs(cmdl)
    assert len(runs) == 1
    assert runs[0] == ["katana", "-u", BASE, "-d", "2", "-silent"]
    nodes = graph.by_type("path")
    assert {n["label"] for n in nodes} == \
        {":8080/admin?page=1", ":8080/login"}
    assert all(n["properties"]["adapter"] == ADAPTER_ID for n in nodes)
    assert all(n["properties"]["source"] == "katana" for n in nodes)
    names = _event_names(audit)
    assert "recon_active_katana_adapter" in names
    # the legacy text-parse never ran (its entry was omitted): every
    # path node carries the adapter provenance the legacy parse lacks
    katana_ev = [e for e in _events(audit)
                 if e["event"] == "recon_active_katana_adapter"]
    assert katana_ev[0]["base"] == BASE
    assert katana_ev[0]["observations"] == 2
    assert "recon_active_adapter_failure" not in names


def test_empty_registry_falls_back_legacy_deterministically(tmp_path):
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    assert _katana_runs(cmdl) != []          # the legacy plan, unchanged
    nodes = graph.by_type("path")
    assert nodes and all(
        (e.get("properties") or {}).get("adapter") is None
        for e in nodes)                      # legacy excerpt nodes only
    assert graph.by_type("adapter_attempt") == []
    assert "recon_active_katana_adapter" not in _event_names(audit)


# ---- 14. planner gating (the web lanes are planner-gated, 2B.6) ------------------------------

def test_planner_selected_crawl_runs_with_the_pinned_argv(tmp_path):
    """katana-probe is planner-gated like every other web lane: with the
    default budget its base is SELECTED, the lane runs it ONCE with the
    pinned argv, and the run links back to the plan id."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()))
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    runs = _katana_runs([argv for argv, _t in spawned])
    assert len(runs) == 1
    assert runs[0] == ["katana", "-u", BASE, "-d", "2", "-silent"]
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
    katana_ev = [e for e in events
                 if e["event"] == "recon_active_katana_adapter"]
    assert katana_ev[0]["plan_id"] == decided["plan_id"]
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_budget_defers_the_crawl_never_spawns_katana(tmp_path):
    """A zero budget defers EVERY planner-gated adapter check: the
    katana lane dispatches no base, so NO crawl spawn, no path nodes,
    no failure event — an honest unrun check, never a silent skip."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()),
                          budget=PlannerBudget(max_total_seconds=0))
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    assert _katana_runs([argv for argv, _t in spawned]) == []
    assert graph.by_type("path") == []
    names = _event_names(audit)
    assert "recon_active_katana_adapter" not in names
    assert "recon_active_adapter_failure" not in names
    events = _events(audit)
    decided = next(e for e in events if e["event"] == "planning_decided")
    assert decided["counts"].get("selected", 0) == 0
    assert decided["counts"].get("covered") == 3   # the discovery lanes
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert done["planned_selected"] == 0
    assert done["planned_executed"] == 0


def test_failed_crawl_is_not_coverage(tmp_path):
    """A FAILED crawl is never reported as covered: the done event
    honestly lists it as planned-but-not-executed (the check did not
    complete)."""
    def script(argv):
        r = _script_discovery_and_web(argv)
        if argv[0] == "katana":
            return SpawnResult(ok=False, exit_code=1, stdout="",
                               error="connection refused")
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
    assert any("katana-probe" in ln for ln in done["planned_not_executed"])


# ---- 15. Gate 2 / Gate 3 behavior unchanged ---------------------------------------------------

def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                  stdout="http://target-corp.com:8080/admin"),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, _prep(reg), sandbox=sbx, audit=audit,
                             graph=graph)
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
            **make_katana_probe_adapter().model_dump(),
            "adapter_id": "katana-post", "stages": ("POST_EXPLOIT",),
        })


# ---- the ONE genuine integration test (opt-in, local lab only) ------------------------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab
    URL."""
    lab = os.environ.get("KRYONSEC_KATANA_LAB_URL", "").strip()
    if not lab or lab.startswith("-"):
        return False, ("KRYONSEC_KATANA_LAB_URL must be a lab URL "
                       "you control")
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_KATANA_IT") != "1":
        return False, "KRYONSEC_KATANA_IT=1 not set"
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


def test_real_katana_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real katana crawl — against the lab URL the OPERATOR
    supplies. Skipped silently otherwise.

    Authorize NOTHING public: point KRYONSEC_KATANA_LAB_URL at a web
    server you control (e.g. a lab container on your own Docker
    bridge). An empty crawl from a clean run is an honest INCONCLUSIVE
    (the assertion below allows it) — never a failure mask.
    """
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.egress import EgressGate, build_policy, \
        release_active
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig()
    lab = os.environ["KRYONSEC_KATANA_LAB_URL"].strip()
    # the egress boundary authorizes HOSTS, not URLs — the lab host is
    # derived from the operator's URL (scope: that host only)
    import urllib.parse

    lab_host = urllib.parse.urlparse(lab).hostname or ""
    assert lab_host, f"KRYONSEC_KATANA_LAB_URL has no host: {lab!r}"

    policy = build_policy(cfg, "katana-it", target=lab_host)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_katana_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="katana-it")
    graph.add_node("target", lab_host, {})
    try:
        prep = prepare_adapter_run(reg, ADAPTER_ID, target=lab,
                                   target_asset=lab,
                                   params={"depth": PINNED_DEPTH})
        record, output = execute_adapter(reg, prep, sandbox=sbx,
                                         audit=audit, graph=graph,
                                         full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.exit_code == 0
        assert record.verification == "not_verified"
        obs, malformed = parse_katana_lines(output, target=lab)
        created = record_katana_evidence(graph, audit, run_record=record,
                                         observations=obs,
                                         malformed_lines=malformed)
        # honest either way: paths found or an inconclusive crawl —
        # every created node stays not_verified, and the audit chain
        # holds
        nodes = graph.by_type("path")
        assert len(nodes) == len(created)
        assert all(n["properties"]["verification"] == "not_verified"
                   for n in nodes)
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("katana-it")
        except Exception:
            pass
