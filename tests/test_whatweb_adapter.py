"""Phase 2B.5 tests: the whatweb-probe production Mode B adapter.

MOCKED tests (the default, huge majority): a duck-typed sandbox double
returns canned SpawnResults — no process, no packets, no scan. They pin
the contract: explicit registration (single + combined RECON_ACTIVE
registry), fixed adapter template with NO aggression (level 1 only),
WhatWeb identification, scope/URL/Layer-2 refusals, gate + sandbox +
egress enforcement, output bounds, no host fallback, deterministic
Recon Active integration (the adapter REPLACES the legacy whatweb plan
entry; never both; never duplicating the httpx-probe evidence), and
the no-new-capability invariants (Gate 2/3 and Post-Exploit untouched).

REAL IT (exactly one, opt-in): a genuine whatweb run against an
OPERATOR-SUPPLIED locally controlled lab endpoint through a REAL
Docker + gVisor runsc sandbox and the REAL egress boundary. Guarded by
KRYONSEC_WHATWEB_IT=1 — skipped silently otherwise (like
test_egress_integration). NEVER runs against anything public; the lab
URL comes from the operator.

Run the real IT on a Linux host with Docker + runsc + the pinned image:
    KRYONSEC_WHATWEB_IT=1 KRYONSEC_WHATWEB_LAB_URL=http://192.168.x.y:8080/ \
        KRYONSEC_SANDBOX_IMAGE='<digest-pinned-image>' \
        .venv/bin/python -m pytest tests/test_whatweb_adapter.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kryonsec.purple.adapter_whatweb import (
    ADAPTER_ID,
    TOOL_EXECUTABLE,
    WHATWEB_PROBE_TEMPLATE,
    WhatwebObservation,
    find_adapter_attempt_node,
    make_whatweb_probe_adapter,
    parse_whatweb_lines,
    production_registry,
    record_whatweb_evidence,
    recon_active_registry,
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


def _brief(url="http://target-corp.com:8080/", status=200, text="OK",
           rest=None) -> str:
    """The REAL brief-format line shape (captured live from WhatWeb
    0.6.4 in the pinned sandbox image against a local lab)."""
    if rest is None:
        rest = ("Country[RESERVED][ZZ], HTML5, "
                "HTTPServer[SimpleHTTP/0.6 Python/3.14.7], "
                "IP[172.17.0.3], Python[3.14.7], Title[Directory list]")
    return f"{url} [{status} {text}] {rest}"


def _events(audit) -> "list[dict]":
    return [json.loads(line) for line in open(audit.path, encoding="utf-8")
            if line.strip()]


def _event_names(audit) -> "list[str]":
    return [e["event"] for e in _events(audit)]


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


def _cfg(tmp_path):
    from kryonsec.config import KryonsecConfig

    return KryonsecConfig(home=tmp_path / "home")


# ---- 1. registration and discovery (explicit; unknown stays disabled) ----------

def test_production_registry_registers_whatweb_probe_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == ("whatweb-probe",)        # EXACTLY the vetted adapter
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
    assert reg.get(ADAPTER_ID) == make_whatweb_probe_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_whatweb_probe_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


def test_combined_recon_active_registry_carries_both_web_adapters():
    reg = recon_active_registry()
    assert reg.adapter_ids() == (
        "httpx-probe", "nuclei-probe", "whatweb-probe")
    # all three stay RECON_ACTIVE-only; none mounted a gate
    for adapter in reg.list_adapters():
        assert adapter.stages == ("RECON_ACTIVE",)
        assert adapter.approvals == ()
        assert adapter.network == "target_scope"
        assert adapter.risk == "active"


# ---- 2. correct fixed command rendering + NO-aggression -------------------------

def test_fixed_template_rendering():
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=TARGET,
        target_asset="http://target-corp.com:8080/")
    assert prep.argv == [
        "whatweb", "-a", "1", "--no-errors", "--color=never",
        "http://target-corp.com:8080/",
    ]
    url = "http://target-corp.com:8080/"
    rebuilt = [url if a == "{url}" else a for a in WHATWEB_PROBE_TEMPLATE]
    assert prep.argv == ["whatweb", *rebuilt]


def test_aggression_is_never_raised_by_the_adapter():
    """-a 1 is PINNED in the registry-compiled Layer-2 template: the
    level the alternation template would also permit (3 = the
    aggressive mode the adapter must never run) deviates EXACTLY like
    any other out-of-template argument."""
    from kryonsec.purple.allowlist import (ACTIVE_RECON_TEMPLATES,
                                           AllowlistViolation, ToolAllowlist)

    url = "http://target-corp.com:8080/"
    # the adapter run shape validates against the SHIPPED template
    shipped = ToolAllowlist_shipped()
    good = ["whatweb", "-a", "1", "--no-errors", "--color=never", url]
    shipped.validate(TOOL_EXECUTABLE, good)
    # the FIXED adapter allowlist (registration-compiled) rejects
    # every other level — the aggressive mode can never sneak through
    reg_allow = ToolAllowlist({
        "whatweb": list(WHATWEB_PROBE_TEMPLATE)})
    for level in ("3", "2", "{1|2|3}", "4"):
        with pytest.raises(AllowlistViolation):
            reg_allow.validate(
                TOOL_EXECUTABLE,
                ["whatweb", "-a", level, "--no-errors",
                 "--color=never", url])
    # and the template contains no aggressive/introspective switches
    assert WHATWEB_PROBE_TEMPLATE[WHATWEB_PROBE_TEMPLATE.index("-a")
                                  + 1] == "1"
    assert "--log-json" not in WHATWEB_PROBE_TEMPLATE
    assert "--log-verbose" not in WHATWEB_PROBE_TEMPLATE


def ToolAllowlist_shipped():
    from kryonsec.purple.allowlist import (ACTIVE_RECON_TEMPLATES,
                                           ToolAllowlist)

    return ToolAllowlist(dict(ACTIVE_RECON_TEMPLATES))


# ---- 3. WhatWeb identification ----------------------------------------------------

def test_whatweb_identification():
    """The executable is the REAL bundled binary (WhatWeb 0.6.4 in the
    pinned sandbox image, entrypoint-allowlisted) and the evidence
    always names the tool honestly."""
    adapter = make_whatweb_probe_adapter()
    assert adapter.executable == "whatweb"
    assert "WhatWeb" in adapter.purpose
    reg = production_registry()
    described = json.loads(reg.describe(ADAPTER_ID))
    assert described["executable"] == "whatweb"
    assert described["evidence_kind"] == "text_excerpt"
    obs, _m = parse_whatweb_lines(_brief())
    props = obs[0].properties(request_id="requestid0001")
    assert props["source"] == "whatweb"
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

    template = list(ACTIVE_RECON_TEMPLATES["whatweb"])
    assert len(template) == 5                        # the fixed contract
    url = "http://target-corp.com:8080/"
    good = ["whatweb"] + [
        url if a == "{url}"
        else ("1" if a == "{1|2|3}" else a)
        for a in template]
    allow = ToolAllowlist({"whatweb": template})
    allow.validate(TOOL_EXECUTABLE, good)            # the real shape passes

    for deviating in (
        ["whatweb", "-a", "1", "--no-errors",            # out-of-template
         "-q", "--log-json=-", url],                     # switches even if
        ["whatweb", "-a", "1", "--no-errors", url],      # honestly nicer
    ):
        with pytest.raises(AllowlistViolation):
            allow.validate(TOOL_EXECUTABLE, deviating)


# ---- 7. missing gate/authorization where required -------------------------------------

def test_gated_variant_refused_without_grant():
    """The production adapter documents gate freedom
    (RECON_ACTIVE authorization = engagement model); a variant that
    names EXPLOIT MUST demand the hypothesis gate and is REFUSED
    without it — the Gate 2 enforcement module is unchanged."""
    from kryonsec.purple.adapters import ModeBToolAdapter

    variant = make_whatweb_probe_adapter()
    exploit_variant = ModeBToolAdapter(
        **{**variant.model_dump(), "adapter_id": "whatweb-gated",
           "stages": ("EXPLOIT",), "approvals": ("hypothesis_gate",),
           "risk": "active"})
    reg = AdapterRegistry()
    reg.register(exploit_variant)
    prep = prepare_adapter_run(reg, "whatweb-gated", target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=_brief()),
                      egress_policy=_StubEgressPolicy())
    audit = AuditLog(Path("tmp") / "gate_a.jsonl")
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                             graph=_graph(), hypothesis_id="H1")
    assert record.executed is False and record.outcome == "refused"
    assert "approval gate" in record.error_excerpt
    assert sbx.spawned == []


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
    # no attempt node, no fingerprint nodes, refusal failures audited
    assert graph.by_type("adapter_attempt") == []
    assert graph.by_type("tech_fingerprint") == [] or not [
        n for n in graph.by_type("tech_fingerprint")
        if (n.get("properties") or {}).get("adapter") == ADAPTER_ID]
    # timeout bound respected on the spawn call (adapter max_seconds)
    assert sbx.spawned and sbx.spawned[0][1] == make_whatweb_probe_adapter(
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
    assert not [n for n in graph.by_type("tech_fingerprint")
                if (n.get("properties") or {}).get("adapter") == ADAPTER_ID]
    names = _event_names(audit)
    assert "adapter_result" in names
    for ev in _events(audit):
        if ev["event"] == "adapter_result":
            assert ev["ok"] is False and ev["exit_code"] == 1


# ---- 12. malformed and oversized output -----------------------------------------------------

def test_malformed_output_never_becomes_observations():
    garbage = (
        # the banner/version line — not a result
        "WhatWeb - Next generation web scanner version 0.6.4.\n"
        "NOT A BRIEF LINE\n"
        # an error line that slipped through --no-errors
        'ERROR Opening: http://127.0.0.1:1/ - Connection refused'
        ' - connect(2) for "127.0.0.1" port 1\n'
        # a status code that is not 3 digits + a URL-less plugin smear
        "target-corp.com [OK] Python[3.14.7]\n"
        "\n"
    )
    obs, malformed = parse_whatweb_lines(garbage)
    assert obs == [] and malformed == 4

    # a VALID line among garbage still parses (defensive, not paranoid)
    obs, malformed = parse_whatweb_lines(garbage + _brief())
    assert len(obs) == 1 and malformed == 4

    # commas INSIDE bracketed values stay one plugin token
    obs, _m = parse_whatweb_lines(
        _brief(rest="Title[Dependency, & Version], HTML5"))
    assert obs[0].plugins == (
        "Title[Dependency, & Version]", "HTML5")

    # plugin tokens that do not parse are dropped, never invented
    obs, _m = parse_whatweb_lines(_brief(rest="HTML5,, ,Python[3.14.7]"))
    assert obs[0].plugins == ("HTML5", "Python[3.14.7]")

    # oversized: the observation cap holds; each field is bounded
    flood = "\n".join(_brief(url=f"http://t:{i}/") for i in range(500))
    obs, _ = parse_whatweb_lines(flood)
    assert len(obs) == 20                       # max_observations default
    caps = WhatwebObservation.model_fields
    assert caps["url"].metadata is not None     # bounded field lengths


# ---- 13. evidence recording: full mapping + refusal without attempt node ---------------

def test_record_evidence_refuses_without_attempt_node(tmp_path):
    """A refused run must never fabricate fingerprint evidence."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    prep = prepare_adapter_run(registry, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    record = execute_adapter(registry, prep,
                             sandbox=FakeSandbox(egress_policy=None),
                             audit=audit)
    obs, _ = parse_whatweb_lines(_brief())
    ids = record_whatweb_evidence(graph, audit, run_record=record,
                                  observations=obs)
    assert ids == []
    assert not [n for n in graph.by_type("tech_fingerprint")
                if (n.get("properties") or {}).get("adapter") == ADAPTER_ID]
    names = _event_names(audit)
    assert "whatweb_adapter_evidence_refused" in names


def test_evidence_mapping_and_idempotence(tmp_path):
    """The run maps to tech_fingerprint nodes — same node type the
    legacy whatweb path produces, keyed by the probed base; a repeat
    run against the same base adds NOTHING (first wins)."""
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    registry = production_registry()
    prep = prepare_adapter_run(registry, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=_brief()),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(
        registry, prep, sandbox=sbx, audit=audit, graph=graph,
        full_output=True)
    obs, malformed = parse_whatweb_lines(output)
    assert len(obs) == 1 and malformed == 0
    created = record_whatweb_evidence(graph, audit, run_record=record,
                                      observations=obs,
                                      malformed_lines=malformed)
    assert len(created) == 1
    attempt = find_adapter_attempt_node(graph, record.request_id)
    assert attempt is not None
    restored = AdapterRunRecord.model_validate(attempt["properties"])
    assert restored.adapter_id == ADAPTER_ID
    # the node carries the parsed fingerprint + context-renderable
    # excerpt + adapter provenance; a REPEAT mapping is idempotent
    node = graph.by_type("tech_fingerprint")[0]
    props = node["properties"]
    assert props["source"] == "whatweb"
    assert props["adapter"] == ADAPTER_ID
    assert props["verification"] == "not_verified"
    assert props["status"] == 200
    assert props["excerpt"].startswith("http://target-corp.com:8080/")
    ids2 = record_whatweb_evidence(graph, audit, run_record=record,
                                   observations=obs)
    assert ids2 == []
    assert len(graph.by_type("tech_fingerprint")) == 1
    # the httpx-probe node type stays untouched — no cross-evidence
    assert graph.by_type("web_endpoint") == []
    ev = [e for e in _events(audit)
          if e["event"] == "whatweb_adapter_evidence"]
    assert ev[0]["observations"] == 1
    assert ev[0]["tech_fingerprint_nodes"] == 1
    assert ev[0]["duplicate_or_refused"] == 0
    ok, reason = audit.verify()
    assert ok, reason


# ---- 14. status/exit/fingerprint is NOT vulnerability confirmation -----------------------

def test_fingerprint_is_recon_evidence_never_confirmation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=_brief()),
                      egress_policy=_StubEgressPolicy())
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is True and record.exit_code == 0
    # HARD invariants:
    assert record.verification == "not_verified"
    assert record.untrusted is True
    assert "confirmed" not in record.model_dump()
    obs, _m = parse_whatweb_lines(output)
    record_whatweb_evidence(graph, audit, run_record=record,
                            observations=obs)
    ep = graph.by_type("tech_fingerprint")[0]["properties"]
    assert ep["verification"] == "not_verified"
    # nothing on the graph became a finding / capability / approval
    assert graph.by_type("finding") == []
    assert graph.by_type("capability") == []
    hyp = graph.by_type("hypothesis")[0]
    assert hyp["properties"]["approved"] is False
    # ...and no gate lifecycle events were written by the adapter path
    names = _event_names(audit)
    assert not any("gate" in n for n in names if n != "adapter_refused")


# ---- 15. no host execution fallback ---------------------------------------------------------

def test_no_host_execution_in_adapter_modules():
    for mod in ("adapter_httpx.py", "adapter_whatweb.py",
                "adapter_nuclei.py", "adapters.py"):
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


def _fake_stage1(script):
    """Sandbox fake: stage1 always finds 8080; tools callback-scripted."""
    return FakeSandbox(script=script, egress_policy=_StubEgressPolicy())


def _script_both_adapters(argv):
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
    if tool == "whatweb":
        # the ADAPTER (level 1) and the LEGACY (level 3) share argv[0];
        # both get an honest brief line for their level's URL
        url = argv[-1]
        return SpawnResult(ok=True, exit_code=0, stdout=_brief(url=url))
    if tool == "httpx-toolkit":
        url = argv[argv.index("-u") + 1]
        return SpawnResult(ok=True, exit_code=0, stdout=(
            json.dumps({"url": url, "status_code": 200,
                        "title": "Login", "tech": ["Nginx"],
                        "webserver": "nginx"}) + "\n"))
    return SpawnResult(ok=True, exit_code=0, stdout="")


def _whatweb_runs(cmdl):
    runs = [a for a in cmdl if a and a[0] == "whatweb"]
    return {run[run.index("-a") + 1]: run for run in runs}


def test_adapter_mode_probes_whatweb_once_never_both(tmp_path):
    sandbox = _fake_stage1(_script_both_adapters)
    result, spawned, graph, audit = _recon(sandbox, recon_active_registry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs = _whatweb_runs(cmdl)
    # DETERMINISTIC either/or: the legacy -a 3 entry is REPLACED by the
    # level-1 adapter run — never both probing the same base
    assert list(runs) == ["1"]
    assert "--no-errors" in runs["1"] and "--color=never" in runs["1"]
    fps = graph.by_type("tech_fingerprint")
    assert len(fps) == 1
    assert fps[0]["properties"]["source"] == "whatweb"
    assert fps[0]["properties"]["adapter"] == ADAPTER_ID
    # the httpx adapter side of the combined registry still runs its
    # lane — and its web_endpoint evidence is SEPARATE from the
    # whatweb tech_fingerprint evidence (the nuclei-probe adapter, the
    # third member, runs its vuln-check lane separately too)
    runs_toolkt = [a for a in cmdl if a and a[0] == "httpx-toolkit"]
    runs_legacy_httpx = [a for a in cmdl if a and a[0] == "httpx"]
    assert runs_legacy_httpx == []
    assert len(runs_toolkt) == 1
    assert len(graph.by_type("web_endpoint")) == 1
    assert len(graph.by_type("adapter_attempt")) == 3
    names = _event_names(audit)
    assert "recon_active_whatweb_adapter" in names
    assert "recon_active_adapter_failure" not in names
    # no whatweb tech_fingerprint from a legacy text parse (only the
    # adapter's, provenance-tagged); no duplicate node for the base
    assert len([e for e in graph.by_type("tech_fingerprint")
                if e["label"] == "http://target-corp.com:8080/"]) == 1


def test_empty_registry_falls_back_legacy_deterministically(tmp_path):
    sandbox = _fake_stage1(_script_both_adapters)
    result, spawned, graph, audit = _recon(sandbox, AdapterRegistry(),
                                           tmp_path)
    assert result.status == "ok"
    cmdl = [argv for argv, _t in spawned]
    runs = _whatweb_runs(cmdl)
    assert list(runs) == ["3"]              # the legacy plan, unchanged
    fps = graph.by_type("tech_fingerprint")
    assert fps and all(
        (e.get("properties") or {}).get("adapter") is None
        for e in fps)                       # legacy excerpt nodes only
    assert graph.by_type("adapter_attempt") == []
    assert "recon_active_whatweb_adapter" not in _event_names(audit)


def test_no_registry_runs_the_classic_plan(tmp_path):
    sandbox = _fake_stage1(_script_both_adapters)
    cfg = _cfg(tmp_path)
    audit = AuditLog(tmp_path / "ra.jsonl")
    graph = EngagementGraph(engagement_id="e-x")
    graph.add_node("target", TARGET, {})
    result = ReconActiveSubagent(cfg, graph, audit, TARGET, sandbox).run()
    assert result.status == "ok"
    cmdl = [argv for argv, _t in sandbox.spawned]
    runs = _whatweb_runs(cmdl)
    assert list(runs) == ["3"]
    # unknown-adapter rule: an injected registry WITHOUT the id behaves
    # like no registry (deterministic legacy, never a.failed stab)
    from kryonsec.purple.adapter_httpx import make_httpx_probe_adapter

    reg = AdapterRegistry()
    reg.register(make_httpx_probe_adapter())
    sandbox2 = _fake_stage1(_script_both_adapters)
    res2 = _recon(sandbox2, reg, tmp_path / "u2")
    assert _whatweb_runs([a for a, _t in sandbox2.spawned]) \
        .keys() == {"3"}
    assert res2[0].status == "ok"


def test_registry_load_does_not_break_httpx_probe_lanes(tmp_path):
    """The 2B.3 rule holds under the combined registry: exactly one
    httpx adapter probe, zero legacy httpx."""
    sandbox = _fake_stage1(_script_both_adapters)
    result, _spawned, graph, audit = _recon(sandbox,
                                            recon_active_registry(),
                                            tmp_path)
    assert result.status == "ok"
    eps = graph.by_type("web_endpoint")
    assert len(eps) == 1
    assert eps[0]["properties"]["adapter"] == "httpx-probe"
    # both attempt nodes recorded; both adapters' evidence events wrote
    names = _event_names(audit)
    assert names.count("recon_active_httpx_adapter") == 1
    assert names.count("recon_active_whatweb_adapter") == 1
    ok, reason = audit.verify()
    assert ok, reason


# ---- 17. Gate 2 / Gate 3 behavior unchanged ---------------------------------------------------

def test_gates_untouched_by_adapter_path(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=_brief()),
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
            **make_whatweb_probe_adapter().model_dump(),
            "adapter_id": "whatweb-post", "stages": ("POST_EXPLOIT",),
        })


# ---- 18. no capability or Post-Exploit activation ------------------------------------------------

def test_no_capability_or_post_exploit_activation(tmp_path):
    reg = production_registry()
    audit = AuditLog(tmp_path / "a.jsonl")
    graph = _graph()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target=TARGET,
                               target_asset="http://target-corp.com:8080/")
    sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=_brief()),
                      egress_policy=_StubEgressPolicy())
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit, graph=graph)
    obs, _m = parse_whatweb_lines(_brief())
    record_whatweb_evidence(graph, audit, run_record=record, observations=obs)
    # a fingerprint does NOT create capability claims, exploit attempts
    # or post-exploit inputs
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
    """Real Docker + runsc + DIGEST-PINNED image + an operator lab URL."""
    lab = os.environ.get("KRYONSEC_WHATWEB_LAB_URL", "").strip()
    if not lab.lower().startswith(("http://", "https://")):
        return False, "KRYONSEC_WHATWEB_LAB_URL must be an http(s) lab URL"
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_WHATWEB_IT") != "1":
        return False, "KRYONSEC_WHATWEB_IT=1 not set"
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


def test_real_whatweb_probe_lab_it():
    """GENUINE adapter IT: real Docker+gVisor runsc sandbox, real egress
    boundary, real WhatWeb brief-format fingerprint run — against the
    local lab endpoint the OPERATOR supplies. Skipped silently
    otherwise.

    Authorize NOTHING public: point KRYONSEC_WHATWEB_LAB_URL at an
    endpoint you control (e.g. a lab container on your own Docker
    bridge).
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
    lab = os.environ["KRYONSEC_WHATWEB_LAB_URL"].strip()
    host = urlsplit(lab).hostname or ""
    assert host, lab

    policy = build_policy(cfg, "whatweb-it", target=host)
    gate = EgressGate()
    established, est_reason = gate.establish(policy)
    assert established, f"egress establish: {est_reason}"
    sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
    reg = production_registry()
    audit = AuditLog("tmp_whatweb_it_audit.jsonl")
    graph = EngagementGraph(engagement_id="whatweb-it")
    graph.add_node("target", host, {})
    try:
        prep = prepare_adapter_run(reg, ADAPTER_ID, target=host,
                                   target_asset=lab)
        record, output = execute_adapter(reg, prep, sandbox=sbx,
                                         audit=audit, graph=graph,
                                         full_output=True)
        assert record.executed is True, record.error_excerpt
        assert record.verification == "not_verified"
        obs, malformed = parse_whatweb_lines(output)
        created = record_whatweb_evidence(graph, audit, run_record=record,
                                          observations=obs,
                                          malformed_lines=malformed)
        assert record.exit_code == 0
        # realistic lab: at least the probe produced well-formed rows.
        # An EMPTY output with a clean exit means the sandbox could not
        # reach the lab (connection refused is silent under --no-errors
        # in WhatWeb's brief mode) — operator: check the lab URL is
        # still serving before blaming the adapter.
        assert obs, (f"no observations parsed from lab run "
                     f"({malformed} bad) — empty output from a "
                     f"zero-exit run usually means the lab endpoint "
                     f"was not reachable; verify it with curl first")
        assert len(created) == len(obs)
        # the observed data says what the fingerprint SHOULD be: the
        # lab is a plain HTTP file server — expect at least a server
        # fingerprint, and NEVER an upgrade of verification
        finger = obs[0]
        assert finger.status_code == 200
        assert any(p.startswith("HTTPServer[") for p in finger.plugins)
        graph_fp = graph.by_type("tech_fingerprint")
        assert graph_fp and graph_fp[0]["properties"][
            "verification"] == "not_verified"
        ok2, reason2 = audit.verify()
        assert ok2, reason2
    finally:
        try:
            release_active("whatweb-it")
        except Exception:
            pass
