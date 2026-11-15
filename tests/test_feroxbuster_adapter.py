"""Tool Expansion Batch 2 tests: the feroxbuster-probe production Mode B
adapter.

MOCKED tests (the default, huge majority): a duck-typed sandbox double
returns canned SpawnResults — no process, no packets, no directory
busting. They pin the contract: explicit registration (single + combined
RECON_ACTIVE registry), the byte-identical fixed template (the baked
seclists wordlist, 5 threads, 30s per-request timeout — no recursion,
no extensions, no caller wordlist/threads knobs), the FRAMEWORK-COMPOSED
FUZZ-marker URL (the lane can never point the fuzzing at a different
origin than the scope-validated base), URL scope/preparation refusals,
gate + sandbox + egress enforcement, output bounds, honest failure
classification, no host fallback, deterministic Recon Active
integration (the adapter REPLACES the legacy feroxbuster web-plan entry;
exactly ONE bust per base; legacy-shape path nodes with adapter
provenance, first-wins dedupe across sources), planner gating (like
every other web lane: zero budget → no spawn), and the
no-new-capability invariants (Gate 2/3 and Post-Exploit untouched).

REAL IT (exactly one, opt-in): a genuine feroxbuster run against an
OPERATOR-SUPPLIED locally controlled lab URL through a REAL Docker +
gVisor runsc sandbox and the REAL egress boundary. Guarded by
KRYONSEC_FEROX_IT=1 — skipped silently otherwise. NEVER runs against
anything public; the lab URL comes from the operator.

Run the real IT on a Linux host with Docker + runsc + the pinned image:
    KRYONSEC_FEROX_IT=1 \\
        KRYONSEC_FEROX_LAB_URL=http://127.0.0.1:8080/ \\
        KRYONSEC_SANDBOX_IMAGE='<digest-pinned-image>' \\
        .venv/bin/python -m pytest tests/test_feroxbuster_adapter.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_feroxbuster import (
    ADAPTER_ID,
    FEROXBUSTER_ADAPTER_ID,
    FEROXBUSTER_PROBE_TEMPLATE,
    MAX_OBSERVATIONS,
    TOOL_EXECUTABLE,
    FeroxBusterObservation,
    find_adapter_attempt_node,
    make_feroxbuster_probe_adapter,
    parse_feroxbuster_lines,
    production_registry,
    record_feroxbuster_evidence,
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
from kryonsec.purple.allowlist import SECLISTS_WEB
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import (
    ReconActiveSubagent,
    parse_feroxbuster,
)
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.tool_planner import PlannerBudget, \
    ToolCapabilityCatalog, ToolPlanner

TARGET = "target-corp.com"
BASE = "http://target-corp.com:8080/"
FUZZ_BASE = "http://target-corp.com:8080/FUZZ"
FEROX_STDOUT = (
    " 🚀 feroxbuster 2.10.0\n"
    "-----------------------------------------\n"
    "200      GET       15l       34w      345c "
    "http://target-corp.com:8080/admin\n"
    "301      GET        9l       28w      317c "
    "http://target-corp.com:8080/old => "
    "http://target-corp.com:8080/old/\n"
    "403      GET        9l       10w      200c "
    "http://target-corp.com:8080/secret\n"
    "404      GET        1l        3w       20c "
    "http://target-corp.com:8080/missing\n"
    "[=] Press [Ctrl+C] to cancel\n"
    "\n"
)


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


def _prep(reg=None, *, base=BASE):
    """Prepared run — NO params: the template's only placeholder
    ({urlfuzz}) is composed by the framework from the base."""
    return prepare_adapter_run(
        reg if reg is not None else production_registry(), ADAPTER_ID,
        target=TARGET, target_asset=base)


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------

def test_production_registry_registers_feroxbuster_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("feroxbuster-probe",)     # EXACTLY the vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "web_recon"
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.target_kind == "url"
    assert adapter.executable == "feroxbuster"
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"
    assert adapter.approvals == ()           # RECON_ACTIVE authorization =
                                             # engagement model, not silent
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_feroxbuster_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_feroxbuster_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_feroxbuster_probe():
    reg = recon_active_registry()
    assert "feroxbuster-probe" in reg.adapter_ids()
    adapter = reg.get(FEROXBUSTER_ADAPTER_ID)
    assert adapter.stages == ("RECON_ACTIVE",)
    assert adapter.approvals == ()
    assert adapter.network == "target_scope"
    assert adapter.risk == "active"


# ---- 2. the fixed command + the FRAMEWORK-COMPOSED FUZZ URL ---------------------

def test_fixed_template_rendering_with_the_composed_fuzz_url():
    """The FUZZ-marker URL is composed DETERMINISTICALLY by the adapter
    framework from the scope-validated base — the lane never passes it
    and can never point the busting at a different origin."""
    reg = production_registry()
    prep = _prep(reg)
    assert prep.argv == ["feroxbuster", "-u", FUZZ_BASE, "-w",
                         SECLISTS_WEB, "-t", "5", "--timeout", "30"]
    assert prep.target == BASE
    assert prep.target_kind == "url"
    # a base WITHOUT the trailing slash composes identically (the SAME
    # rule the legacy entry applies: rstrip("/") + "/FUZZ")
    prep2 = _prep(reg, base="http://target-corp.com:8080")
    assert prep2.argv[prep2.argv.index("-u") + 1] == FUZZ_BASE
    # the legacy composition parity — byte for byte
    for legacy_base in ("http://target-corp.com:8080/",
                        "http://target-corp.com:8080"):
        legacy = legacy_base.rstrip("/") + "/FUZZ"
        prep3 = _prep(reg, base=legacy_base)
        assert prep3.argv[prep3.argv.index("-u") + 1] == legacy


def test_template_is_byte_identical_to_the_shipped_layer2_template():
    """The adapter adds NO flag the shipped feroxbuster entry does not
    carry: the argv it renders validates against the SHIPPED Layer-2
    template unchanged, and no recursion/extension/output/free flag can
    ever appear."""
    from kryonsec.purple.allowlist import (ACTIVE_RECON_TEMPLATES,
                                           ToolAllowlist)

    assert list(FEROXBUSTER_PROBE_TEMPLATE) == \
        list(ACTIVE_RECON_TEMPLATES["feroxbuster"])
    shipped = ToolAllowlist(dict(ACTIVE_RECON_TEMPLATES))
    shipped.validate(TOOL_EXECUTABLE,
                     ["feroxbuster", "-u", FUZZ_BASE, "-w",
                      SECLISTS_WEB, "-t", "5", "--timeout", "30"])
    # the wordlist is the baked seclists path — never caller input
    assert SECLISTS_WEB in FEROXBUSTER_PROBE_TEMPLATE
    flags = [a for a in FEROXBUSTER_PROBE_TEMPLATE if a.startswith("-")]
    assert flags == ["-u", "-w", "-t", "--timeout"]
    for forbidden in ("-r", "-x", "-o", "--json", "--no-state",
                      "--threads", "--wordlist", "--extensions",
                      "-d", "--depth", "--smart"):
        assert forbidden not in FEROXBUSTER_PROBE_TEMPLATE, forbidden


def test_burst_constants_are_pinned():
    adapter = make_feroxbuster_probe_adapter()
    assert adapter.max_seconds == 300        # <= the 330s sandbox ceiling
    reg = production_registry()
    prep = _prep(reg)
    assert prep.argv[prep.argv.index("-t") + 1] == "5"
    assert prep.argv[prep.argv.index("--timeout") + 1] == "30"
    assert prep.argv[prep.argv.index("-w") + 1] == SECLISTS_WEB


# ---- 3. identification ------------------------------------------------------------

def test_feroxbuster_identification():
    """The executable is the REAL bundled binary (entrypoint-allowlisted
    in the pinned sandbox image) and the evidence names the tool."""
    adapter = make_feroxbuster_probe_adapter()
    assert adapter.executable == "feroxbuster"
    assert "feroxbuster" in adapter.purpose
    reg = production_registry()
    described = json.loads(reg.describe(ADAPTER_ID))
    assert described["executable"] == "feroxbuster"
    assert described["evidence_kind"] == "text_excerpt"


# ---- 4. preparation refusals -------------------------------------------------------

def test_out_of_scope_assets_refused_at_preparation():
    reg = production_registry()
    # absolute assets whose host is not the target / a subdomain:
    # the caller cannot aim the fuzzer at an arbitrary host
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
    assert prep.argv[prep.argv.index("-u") + 1] == \
        "https://mail.target-corp.com/FUZZ"


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
    """The lane supplies NOTHING: no params dict is needed (the fuzz URL
    is framework-composed) and ANY params dict is refused — a caller
    wordlist, thread count or even a pre-composed 'urlfuzz' can never
    reach the template."""
    reg = production_registry()
    # all-or-nothing: unexpected params are refused
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE,
                            params={"wordlist": "/tmp/evil.txt"})
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE, params={"threads": "50"})
    # the FUZZ marker URL itself is NEVER caller input: a params dict
    # carrying it is refused as unexpected (the framework composes it)
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE,
                            params={"urlfuzz": "http://evil.example/FUZZ"})
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE, params={"url": BASE})
    # option-shaped caller input is refused (option injection): no
    # value may begin with '-'
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                            target_asset=BASE, params={"w": "-oG"})


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

    variant = make_feroxbuster_probe_adapter()
    exploit_variant = ModeBToolAdapter(
        **{**variant.model_dump(), "adapter_id": "ferox-gated",
           "stages": ("EXPLOIT",), "approvals": ("hypothesis_gate",),
           "risk": "active"})
    reg = AdapterRegistry()
    reg.register(exploit_variant)
    prep = prepare_adapter_run(reg, "ferox-gated", target=TARGET,
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


# ---- 6. tool timeout / nonzero exit — honest failures -------------------------------

def test_tool_timeout_is_an_honest_failure(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = _prep(reg)
    sbx = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                  error="tool exceeded 300s sandbox timeout"),
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
        make_feroxbuster_probe_adapter().max_seconds


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


# ---- 7. parsing: legacy lockstep, defensive, bounded ---------------------------------

def test_parse_is_lockstep_with_the_legacy_parser():
    """The adapter parses with the SAME regex objects the legacy web
    entry uses (lockstep by construction): identical paths, same order,
    same status filter."""
    observations, malformed = parse_feroxbuster_lines(FEROX_STDOUT)
    legacy = parse_feroxbuster(FEROX_STDOUT)
    assert [(o.path, o.status) for o in observations] == \
        [(p["path"], p["status"]) for p in legacy]
    assert [(o.path, o.status) for o in observations] == [
        ("/admin", 200), ("/old", 301), ("/secret", 403),
    ]
    # the 404 line and the banner/progress junk are counted malformed
    # — never interpreted, never dropped silently
    assert malformed == 4


def test_parse_handles_the_redirect_and_bare_path_variants():
    # the redirect variant: url group stops before " =>"
    obs, _ = parse_feroxbuster_lines(
        "301      GET        9l       28w      317c "
        "http://target-corp.com:8080/a => http://target-corp.com:8080/a/")
    assert obs == [FeroxBusterObservation(path="/a", status=301)]
    # a bare-path build (legacy parity): the path stays as printed
    obs, _ = parse_feroxbuster_lines(
        "200      GET       15l       34w      345c /admin")
    assert obs == [FeroxBusterObservation(path="/admin", status=200)]
    # query strings are KEPT (the legacy parse keeps them too)
    obs, _ = parse_feroxbuster_lines(
        "200      GET       15l       34w      345c "
        "http://target-corp.com:8080/search?q=1")
    assert obs[0].path == "/search?q=1"


def test_parse_is_defensive_and_bounded():
    banner = (
        "feroxbuster v2.10.0\n"
        "-----------------------------------------\n"
        "[=] Scan started\n"
        "[> ] 5 requests sent\n"
        "\n"
    )
    obs, malformed = parse_feroxbuster_lines(banner)
    assert obs == [] and malformed == 4
    assert parse_feroxbuster_lines("") == ([], 0)
    assert parse_feroxbuster_lines(None) == ([], 0)
    flood = "\n".join(
        f"200      GET       15l       34w      345c "
        f"http://target-corp.com:8080/p{i}" for i in range(300))
    obs, _ = parse_feroxbuster_lines(flood)
    assert len(obs) == MAX_OBSERVATIONS       # the bounded cap holds
    caps = FeroxBusterObservation.model_fields
    assert caps["path"].metadata is not None  # bounded field lengths


# ---- 8. evidence recording: legacy-shape path nodes + refusal ------------------------

def test_record_evidence_refuses_without_attempt_node(tmp_path):
    """A refused run must never fabricate path evidence."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    record = execute_adapter(registry, _prep(registry),
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    obs, _ = parse_feroxbuster_lines(
        "200      GET       15l       34w      345c "
        "http://target-corp.com:8080/admin")
    ids = record_feroxbuster_evidence(graph, audit, run_record=record,
                                      observations=obs)
    assert ids == []
    assert graph.by_type("path") == []
    names = _event_names(audit)
    assert "feroxbuster_adapter_evidence_refused" in names


def test_evidence_mapping_is_legacy_shape_and_idempotent(tmp_path):
    """Each observation maps to ONE legacy-shape ``path`` node (the same
    node type the legacy parse produces and HYPOTHESIZE reads, labelled
    by the discovered path) with a produced-lineage edge from the run's
    adapter_attempt node; a repeat mapping adds NOTHING (first-wins by
    label), and paths another source already placed are SKIPPED."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=FEROX_STDOUT),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(registry, _prep(registry),
                                     sandbox=sbx, audit=audit, graph=graph,
                                     full_output=True)
    obs, malformed = parse_feroxbuster_lines(output)
    assert [o.path for o in obs] == ["/admin", "/old", "/secret"]
    assert malformed == 4
    created = record_feroxbuster_evidence(graph, audit, run_record=record,
                                          observations=obs,
                                          malformed_lines=malformed)
    assert len(created) == 3
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None
    restored = AdapterRunRecord.model_validate(attempt["properties"])
    assert restored.adapter_id == ADAPTER_ID
    nodes = graph.by_type("path")
    assert len(nodes) == 3
    by_label = {n["label"]: n for n in nodes}
    props = by_label["/admin"]["properties"]
    assert props["status"] == 200
    assert props["source"] == "feroxbuster"      # the legacy source tag
    assert props["adapter"] == ADAPTER_ID        # + adapter provenance
    assert props["request_id"] == record.request_id
    assert props["verification"] == "not_verified"
    assert props["untrusted"] is True
    # lineage: attempt --produced--> path, for EVERY node
    for node in nodes:
        assert graph.has_edge(attempt, "produced", node)
    # idempotence: a REPEAT mapping adds nothing (first-wins by label)
    ids2 = record_feroxbuster_evidence(graph, audit, run_record=record,
                                       observations=obs)
    assert ids2 == []
    assert len(graph.by_type("path")) == 3
    # cross-source: a path ANOTHER source placed first is skipped too
    graph.add_node("path", "/admin2", {"source": "katana",
                                       "url": BASE + "admin2"})
    obs3 = [FeroxBusterObservation(path="/admin2", status=200)]
    ids3 = record_feroxbuster_evidence(graph, audit, run_record=record,
                                       observations=obs3)
    assert ids3 == []
    admins = [n for n in graph.by_type("path") if n["label"] == "/admin2"]
    assert len(admins) == 1                      # the katana one
    assert admins[0]["properties"]["source"] == "katana"
    ev = [e for e in _events(audit)
          if e["event"] == "feroxbuster_adapter_evidence"]
    assert ev[0]["observations"] == 3 and ev[0]["path_nodes"] == 3
    assert ev[0]["malformed_lines"] == 4
    assert ev[0]["duplicate_or_refused"] == 0
    assert ev[1]["duplicate_or_refused"] == 3    # the repeat mapping
    assert ev[2]["path_nodes"] == 0 and ev[2]["duplicate_or_refused"] == 1
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_observation_run_is_an_honest_inconclusive(tmp_path):
    """A clean bust that found NOTHING is audited with zero paths —
    never a negative 'nothing exists' claim."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=""),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(registry, _prep(registry),
                                     sandbox=sbx, audit=audit, graph=graph,
                                     full_output=True)
    obs, _m = parse_feroxbuster_lines(output)
    created = record_feroxbuster_evidence(graph, audit, run_record=record,
                                          observations=obs)
    assert created == []
    assert graph.by_type("path") == []
    ev = [e for e in _events(audit)
          if e["event"] == "feroxbuster_adapter_evidence"]
    assert ev[0]["observations"] == 0 and ev[0]["path_nodes"] == 0


# ---- 9. status/exit is NOT vulnerability confirmation -----------------------

def test_discovered_path_is_recon_evidence_never_confirmation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=FEROX_STDOUT),
                      egress_policy=_StubEgressPolicy())
    record, _output = execute_adapter(reg, _prep(reg), sandbox=sbx,
                                      audit=audit, graph=graph,
                                      full_output=True)
    assert record.executed is True and record.exit_code == 0
    # HARD invariants:
    assert record.verification == "not_verified"
    assert record.untrusted is True
    assert "confirmed" not in record.model_dump()
    obs, _m = parse_feroxbuster_lines(FEROX_STDOUT)
    record_feroxbuster_evidence(graph, audit, run_record=record,
                                observations=obs)
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


# ---- 10. no host execution fallback ---------------------------------------------------------

def test_no_host_execution_in_adapter_module():
    source = Path("src/kryonsec/purple") / "adapter_feroxbuster.py"
    text = source.read_text(encoding="utf-8")
    assert "subprocess" not in text
    assert "import mcp" not in text
    assert "docker " + "run" not in text


# ---- 11. no duplicate Recon Active bust (deterministic either/or) ----------------------

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
    if tool == "feroxbuster":
        # the ADAPTER and the LEGACY entry share argv[0] — the either/or
        # rule below counts spawns to prove only ONE ran
        return SpawnResult(ok=True, exit_code=0, stdout=FEROX_STDOUT)
    return SpawnResult(ok=True, exit_code=0, stdout="")


def _fake_stage1(script):
    return FakeSandbox(script=script, egress_policy=_StubEgressPolicy())


def _ferox_runs(cmdl):
    return [a for a in cmdl if a and a[0] == "feroxbuster"]


def test_adapter_mode_busts_feroxbuster_once_never_both(tmp_path):
    """DETERMINISTIC either/or: the legacy feroxbuster web-plan entry is
    REPLACED by the adapter run — exactly ONE bust per base (the legacy
    entry and the adapter share argv[0], so two spawns would show) —
    and the discovered paths land in the SAME legacy-shape path nodes
    with the adapter provenance."""
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(sandbox, recon_active_registry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs = _ferox_runs(cmdl)
    assert len(runs) == 1
    assert runs[0] == ["feroxbuster", "-u", FUZZ_BASE, "-w", SECLISTS_WEB,
                       "-t", "5", "--timeout", "30"]
    nodes = graph.by_type("path")
    assert {n["label"] for n in nodes} == {"/admin", "/old", "/secret"}
    assert all(n["properties"]["adapter"] == ADAPTER_ID for n in nodes)
    assert all(n["properties"]["source"] == "feroxbuster" for n in nodes)
    names = _event_names(audit)
    assert "recon_active_feroxbuster_adapter" in names
    ferox_ev = [e for e in _events(audit)
                if e["event"] == "recon_active_feroxbuster_adapter"]
    assert ferox_ev[0]["base"] == BASE
    assert ferox_ev[0]["observations"] == 3
    assert ferox_ev[0]["malformed_lines"] == 4
    assert "recon_active_adapter_failure" not in names


def test_empty_registry_falls_back_legacy_deterministically(tmp_path):
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    assert _ferox_runs(cmdl) != []           # the legacy plan, unchanged
    nodes = graph.by_type("path")
    assert nodes and all(
        (e.get("properties") or {}).get("adapter") is None
        for e in nodes)                      # legacy excerpt nodes only
    assert graph.by_type("adapter_attempt") == []
    assert "recon_active_feroxbuster_adapter" not in _event_names(audit)


# ---- 12. planner gating (the web lanes are planner-gated, 2B.6) ------------------------------

def test_planner_selected_bust_runs_with_the_pinned_argv(tmp_path):
    """feroxbuster-probe is planner-gated like every other web lane:
    with the default budget its base is SELECTED, the lane runs it ONCE
    with the pinned argv, and the run links back to the plan id."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()))
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    runs = _ferox_runs([argv for argv, _t in spawned])
    assert len(runs) == 1
    assert runs[0] == ["feroxbuster", "-u", FUZZ_BASE, "-w", SECLISTS_WEB,
                       "-t", "5", "--timeout", "30"]
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
    ferox_ev = [e for e in events
                if e["event"] == "recon_active_feroxbuster_adapter"]
    assert ferox_ev[0]["plan_id"] == decided["plan_id"]
    ok, reason = audit.verify()
    assert ok, reason


def test_zero_budget_defers_the_bust_never_spawns_feroxbuster(tmp_path):
    """A zero budget defers EVERY planner-gated adapter check: the
    feroxbuster lane dispatches no base, so NO bust spawn, no path
    nodes, no failure event — an honest unrun check, never a silent
    skip."""
    planner = ToolPlanner(ToolCapabilityCatalog(recon_active_registry()),
                          budget=PlannerBudget(max_total_seconds=0))
    sandbox = _fake_stage1(_script_discovery_and_web)
    result, spawned, graph, audit = _recon(
        sandbox, recon_active_registry(), tmp_path, planner=planner)
    assert result.status == "ok"
    assert _ferox_runs([argv for argv, _t in spawned]) == []
    assert graph.by_type("path") == []
    names = _event_names(audit)
    assert "recon_active_feroxbuster_adapter" not in names
    assert "recon_active_adapter_failure" not in names
    events = _events(audit)
    decided = next(e for e in events if e["event"] == "planning_decided")
    assert decided["counts"].get("selected", 0) == 0
    assert decided["counts"].get("covered") == 3   # the discovery lanes
    done = next(e for e in events if e["event"] == "recon_active_done")
    assert done["planned_selected"] == 0
    assert done["planned_executed"] == 0


def test_failed_bust_is_not_coverage(tmp_path):
    """A FAILED bust is never reported as covered: the done event
    honestly lists it as planned-but-not-executed (the check did not
    complete)."""
    def script(argv):
        r = _script_discovery_and_web(argv)
        if argv[0] == "feroxbuster":
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
    assert any("feroxbuster-probe" in ln
               for ln in done["planned_not_executed"])


# ---- 13. Gate 2 / Gate 3 behavior unchanged ---------------------------------------------------

def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=FEROX_STDOUT),
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
            **make_feroxbuster_probe_adapter().model_dump(),
            "adapter_id": "feroxbuster-exploit", "stages": ("EXPLOIT",),
        })


# ---- the ONE genuine integration test (opt-in, local lab only) ----------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab
    URL."""
    lab = os.environ.get("KRYONSEC_FEROX_LAB_URL", "").strip()
    if not lab or not lab.startswith(("http://", "https://")):
        return False, ("KRYONSEC_FEROX_LAB_URL must be a lab URL you "
                       "control")
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_FEROX_IT") != "1":
        return False, "KRYONSEC_FEROX_IT=1 not set"
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


def test_real_feroxbuster_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real feroxbuster run — against the lab URL the OPERATOR
    supplies. Skipped silently otherwise.

    Authorize NOTHING public: point KRYONSEC_FEROX_LAB_URL at a server
    you control. An empty result set from a clean run is an honest
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
    lab = os.environ["KRYONSEC_FEROX_LAB_URL"].strip()
    # the egress boundary authorizes HOSTS, not URLs — the lab host is
    # derived from the operator's URL (scope: that host only)
    import urllib.parse

    lab_host = urllib.parse.urlparse(lab).hostname or ""
    assert lab_host, f"KRYONSEC_FEROX_LAB_URL has no host: {lab!r}"

    policy = build_policy(cfg, "ferox-it", target=lab_host)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_ferox_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="ferox-it")
    graph.add_node("target", lab_host, {})
    try:
        prep = prepare_adapter_run(reg, ADAPTER_ID, target=lab,
                                   target_asset=lab)
        record, output = execute_adapter(reg, prep, sandbox=sbx,
                                         audit=audit, graph=graph,
                                         full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.exit_code == 0
        assert record.verification == "not_verified"
        obs, malformed = parse_feroxbuster_lines(output)
        created = record_feroxbuster_evidence(graph, audit,
                                              run_record=record,
                                              observations=obs,
                                              malformed_lines=malformed)
        nodes = graph.by_type("path")
        assert len(nodes) == len(created)
        assert all(n["properties"]["verification"] == "not_verified"
                   for n in nodes)
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("ferox-it")
        except Exception:
            pass
