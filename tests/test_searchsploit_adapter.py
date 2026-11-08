"""Phase 2B.4 tests: the searchsploit-term production Mode B adapter.

MOCKED tests (the default, huge majority): a duck-typed sandbox double
returns canned SpawnResults — no process, no packets, no scan. They pin
the contract: explicit registration, fixed options-first template (-j
-t {term}), read-only/no-network standing, strict query validation
(option-shaped and malformed terms refuse), the parsed JSON evidence
schema (potential references ONLY — never vulnerability confirmation),
malformed/empty/oversized handling, disposition of the legacy
searchsploit table lookup (deterministic either/or, never both), audit
chain + evidence lineage, no host fallback, and the no-new-capability
invariants (Gate 2/3 and Post-Exploit untouched).

REAL IT (exactly one, opt-in): a genuine `searchsploit -j -t <term>`
run against the LOCAL ExploitDB copy inside the REAL Docker + gVisor
runsc sandbox. Guarded by KRYONSEC_SEARCHSPLOIT_IT=1 — skipped
silently otherwise (like test_egress_integration). Zero egress is
needed: the query is a local database read, and the adapter network
standing is "none".

Run the real IT on a Linux host with Docker + runsc + the pinned image:
    KRYONSEC_SEARCHSPLOIT_IT=1 \
        .venv/bin/python -m pytest tests/test_searchsploit_adapter.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from kryonsec.purple.adapter_searchsploit import (
    ADAPTER_ID,
    SEARCHSPLOIT_TERM_TEMPLATE,
    TOOL_EXECUTABLE,
    find_adapter_attempt_node,
    make_searchsploit_term_adapter,
    parse_searchsploit_json,
    production_registry,
    record_exploitdb_evidence,
    secure_term,
)
from kryonsec.purple.adapters import (
    AdapterError,
    AdapterNotRegistered,
    AdapterRegistry,
    collect_adapter_evidence,
    execute_adapter,
    prepare_adapter_run,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult

TERM_CVE = "CVE-2017-5638"

#: one real-shape ExploitDB response (verified live in the pinned image,
#: keys and value shapes mirrored exactly)
SAMPLE_JSON = json.dumps({
    "SEARCH": TERM_CVE,
    "DB_PATH_EXPLOIT": "/usr/share/exploitdb",
    "RESULTS_EXPLOIT": [
        {
            "Title": "Apache Struts 2.3.2 - 'Include' Parameters "
                     "File Upload Code Execution",
            "EDB-ID": "31615",
            "Date_Published": "2014-02-14",
            "Author": "metasploit",
            "Type": "webapps",
            "Platform": "java",
            "Port": "",
            "Verified": "0",
            "Codes": "",
            "Tags": "",
            "Aliases": "",
            "Screenshot": "",
            "Application": "",
            "Source": "",
            "Path": "/usr/share/exploitdb/exploits/java/remote/31615.rb",
        },
        {
            "Title": "Apache mod_ssl < 2.8.7 OpenSSL - OpenFuck",
            "EDB-ID": "21671",
            "Date_Published": "2002-07-30",
            "Author": "spabam",
            "Type": "remote",
            "Platform": "unix",
            "Port": "80",
            "Verified": "1",
            "Codes": "CVE-2002-0082;OSVDB-857",
            "Tags": "",
            "Aliases": "OpenFuck;OpenFuck.c",
            "Screenshot": "",
            "Application": "",
            "Source": "https://www.securityfocus.com/bid/5363/info",
            "Path": "/usr/share/exploitdb/exploits/unix/remote/21671.c",
        },
    ],
    "RESULTS_SHELLCODE": [
        {
            "Title": "Linux/x86 - Add Root User (shellcode)",
            "EDB-ID": "55555",
            "Codes": "",
        }
    ],
})


def _empty_json() -> str:
    return json.dumps({
        "SEARCH": TERM_CVE,
        "DB_PATH_EXPLOIT": "/usr/share/exploitdb",
        "RESULTS_EXPLOIT": [],
        "RESULTS_SHELLCODE": [],
    })


# ---- harmless fakes ------------------------------------------------------------


def _events(audit) -> "list[dict]":
    return [json.loads(line) for line in open(audit.path, encoding="utf-8")
            if line.strip()]


def _event_names(audit) -> "list[str]":
    return [e["event"] for e in _events(audit)]


def _graph(cve=TERM_CVE) -> EngagementGraph:
    graph = EngagementGraph(engagement_id="e-ss")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "struts include",
        "target_asset": "/showthread?id=1",
        "rationale": "stack mentions struts",
        "cve": cve,
        "tools": ["nuclei"],
        "confidence": 0.5,
        "approved": False,          # NOT approved — the adapter must
                                    # never upgrade this
    })
    return graph


def _h_node(graph) -> dict:
    return [n for n in graph.by_type("hypothesis")][0]


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


def _searchsploit_sandbox(stdout=SAMPLE_JSON, ok=True, exit_code=0,
                          error="") -> FakeSandbox:
    """A sandbox double that answers ONLY the searchsploit adapter
    argv; nuclei_meta (a separate enrichment lookup) gets a clean empty
    match so the counts stay honest."""
    def script(argv):
        if argv[0] == TOOL_EXECUTABLE:
            return SpawnResult(ok=ok, exit_code=exit_code, stdout=stdout,
                               error=error)
        return SpawnResult(ok=True, exit_code=0, stdout='{"matches": []}')

    return FakeSandbox(script=script)


def _prepared(reg=None, term=TERM_CVE):
    return prepare_adapter_run(
        reg or production_registry(),
        ADAPTER_ID,
        target="target-corp.com",
        params={"term": term},
        request_id="requestid0001",
    )


# ---- enrichment integration (enrich_hypotheses with the registry) ---------------

def _patch_apis(monkeypatch):
    """Third-party API envelopes off; the adapter path must be exactly
    as sandbox-local as the legacy one."""
    monkeypatch.setattr("kryonsec.copilot.cve.lookup_cve",
                        lambda cfg, cve: None)
    monkeypatch.setattr("kryonsec.purple.enrichment.kev_cves",
                        lambda cfg: set())
    monkeypatch.setattr("kryonsec.purple.enrichment.epss_for",
                        lambda cfg, cve: None)
    monkeypatch.setattr("kryonsec.purple.enrichment.osv_record",
                        lambda cfg, cve: None)
    monkeypatch.setattr("kryonsec.purple.enrichment.ghsa_record",
                        lambda cfg, cve: None)


def _enrich(monkeypatch, tmp_path, sandbox, registry=None):
    from kryonsec.purple.enrichment import enrich_hypotheses

    from kryonsec.config import KryonsecConfig
    from kryonsec.storage import init_db, reset_engine

    reset_engine()
    cfg = KryonsecConfig(home=tmp_path / "home")
    cfg.database_url = f"sqlite:///{tmp_path / 'ss.db'}"
    init_db(cfg)
    try:
        _patch_apis(monkeypatch)
        audit = AuditLog(tmp_path / "audit.jsonl")
        graph = _graph()
        counts = enrich_hypotheses(cfg, graph, audit, sandbox=sandbox,
                                   adapter_registry=registry)
        return graph, audit, counts
    finally:
        reset_engine()


# ---- 1. registration and discovery ----------------------------------------------

def test_production_registry_registers_searchsploit_term_explicitly():
    reg = production_registry()
    ids = reg.adapter_ids()
    assert ids == (ADAPTER_ID,)           # EXACTLY the one vetted adapter
    adapter = reg.get(ADAPTER_ID)
    assert adapter.category == "recon"
    assert adapter.stages == ("HYPOTHESIZE",)
    assert adapter.target_kind == "term"
    assert adapter.network == "none"
    assert adapter.risk == "informational"
    assert adapter.approvals == ()
    assert adapter.evidence_kind == "json_report"
    # registration NEVER creates a general-purpose interface: the
    # factory is deterministic and registry duplicates refuse
    assert reg.get(ADAPTER_ID) == make_searchsploit_term_adapter()
    with pytest.raises(AdapterError):
        reg.register(make_searchsploit_term_adapter())
    empty = AdapterRegistry()
    with pytest.raises(AdapterNotRegistered):
        empty.get(ADAPTER_ID)


# ---- 2. strict query and argv validation -----------------------------------------

def test_secure_term_validation_matrix():
    assert secure_term("OpenSSL 1.1.1 <bad;|&> x") == "OpenSSL 1.1.1 bad x"
    assert secure_term("windows-kernel") == "windows-kernel"
    assert secure_term("???zip ") == "zip"
    with pytest.raises(ValueError):
        secure_term("")                       # empty query refused
    with pytest.raises(ValueError):
        secure_term("???")                    # no usable query characters
    with pytest.raises(ValueError):
        secure_term(",,,,,,,,,,,,===")        # punctuation-only
    with pytest.raises(ValueError):
        secure_term("-u 1234")                # option-shaped: could be
                                              # read as a CLI option
    assert len(secure_term("x" * 500)) <= 60  # bounded


def test_preparation_refuses_option_shaped_terms_and_extra_params():
    """The term slot is a VALUE, never an option: a term like '-u 1234'
    would be parsed by the tool's own getopts as its UPDATE command.
    The shared _fill_template guard refuses any dash-leading value (the
    enrichment helper additionally refuses at term-cleaning time)."""
    reg = production_registry()
    with pytest.raises(AdapterError):
        _prepared(reg, term="-u 1234")
    with pytest.raises(AdapterError):
        prepare_adapter_run(reg, ADAPTER_ID, target="t",
                            params={"term": TERM_CVE, "junk": "x"})


def test_fixed_template_rendering_options_first_term_last():
    prep = _prepared()
    assert SEARCHSPLOIT_TERM_TEMPLATE == ("-j", "-t", "{term}")
    assert prep.argv == ["searchsploit", "-j", "-t", TERM_CVE]
    assert prep.target_kind == "term"
    assert prep.network == "none"
    # Layer 2, adapter scope: a deviating rendered argv is rejected
    from kryonsec.purple.allowlist import AllowlistViolation, ToolAllowlist

    allow = ToolAllowlist(make_searchsploit_term_adapter().templates_map())
    assert allow.validate(
        TOOL_EXECUTABLE, [TOOL_EXECUTABLE, "-j", "-t", TERM_CVE]) is None
    with pytest.raises(AllowlistViolation):
        allow.validate(TOOL_EXECUTABLE,
                       [TOOL_EXECUTABLE, "-j", "-t", TERM_CVE, "-m"])


# ---- 3. valid JSON parsing --------------------------------------------------------

def test_parse_real_shape_verified_rows_and_shellcode():
    refs, malformed = parse_searchsploit_json(SAMPLE_JSON)
    assert malformed == 0
    assert len(refs) == 3
    first, second, shell = refs
    assert first.edb_id == "31615"
    assert "Include" in first.title
    assert first.verified is False and first.codes == ()
    assert second.edb_id == "21671"
    assert second.verified is True
    assert second.codes == ("CVE-2002-0082", "OSVDB-857")
    assert shell.exploit_type == ""    # minimal row parses with empty
                                       # metadata, never dropped silently
    props = second.properties(request_id="requestid0001", term=TERM_CVE,
                              hypothesis_id="H1")
    assert props["source_tool"] == "searchsploit"
    assert props["adapter"] == ADAPTER_ID
    assert props["reference_only"] is True
    assert props["untrusted"] is True
    assert props["verification"] == "not_verified"
    line = second.display_line()
    assert line.startswith("EDB-21671")
    assert len(line) <= 300


# ---- 4. malformed and oversized JSON ----------------------------------------------

def test_malformed_payloads_fail_closed():
    for bad in (
        "banner text\nE     Exploit DB Search\n",
        '{"SEARCH": "x"',                          # truncated
        json.dumps(["not", "an", "object"]),       # top-level list
        json.dumps({"SEARCH": "x", "OTHER": []}),  # no results arrays
        "",                                        # empty stdout
    ):
        refs, malformed = parse_searchsploit_json(bad)
        assert refs == [] and malformed == 1, bad
    # mixed: non-dict rows dropped, bad rows counted, good row kept
    mixed = json.dumps({
        "RESULTS_EXPLOIT": [
            "garbage",
            {"Title": "no id row"},
            {"EDB-ID": "not-digits", "Title": "x"},
            {"EDB-ID": "40142", "Title": "ok row"},
        ],
        "RESULTS_SHELLCODE": [],
    })
    refs, malformed = parse_searchsploit_json(mixed)
    assert [r.edb_id for r in refs] == ["40142"]
    assert malformed == 2


def test_oversized_output_is_bounded_and_then_fails_closed():
    """The adapter's own output bound truncates oversized stdout; a
    truncated JSON tail is parsed as ONE malformed payload — no
    reference is ever invented from a cut."""
    with tempfile.TemporaryDirectory() as td:
        sbx = FakeSandbox(SpawnResult(ok=True, exit_code=0,
                                      stdout="x" * 40_000
                                      + json.dumps({
                                          "RESULTS_EXPLOIT": [],
                                          "RESULTS_SHELLCODE": []})))
        record, output = execute_adapter(
            production_registry(), _prepared(), sandbox=sbx,
            audit=AuditLog(Path(td) / "a.jsonl"), full_output=True)
        assert record.executed is True
        assert len(output) <= 20_000
        refs, malformed = parse_searchsploit_json(output)
        assert refs == [] and malformed == 1


# ---- 5. empty database results -----------------------------------------------------

def test_empty_results_yield_no_references_and_no_true_flag(monkeypatch,
                                                            tmp_path):
    sbx = _searchsploit_sandbox(stdout=_empty_json())
    graph, audit, counts = _enrich(monkeypatch, Path(tmp_path), sbx,
                                   registry=production_registry())
    enrich = _h_node(graph)["properties"]["enrichment"]
    assert enrich["exploit_available"] is False
    assert enrich["exploit_references"] == []
    assert enrich["exploits"] == []
    assert graph.by_type("exploit_reference") == []
    # the search DID run — exactly one audited adapter lookup
    assert _event_names(audit).count("hypothesize_searchsploit_adapter") == 1
    assert counts["lookups"] >= 1


# ---- 6. read-only restrictions ------------------------------------------------------

def test_template_is_read_only_no_prohibited_flags():
    forbidden = (
        "-u", "--update", "-m", "--mirror", "-x", "--examine",
        "-p", "--path", "-w", "--www", "--nmap", "--exclude",
        "--cve",
    )
    for token in forbidden:
        assert token not in SEARCHSPLOIT_TERM_TEMPLATE, token
    prep = _prepared()
    for token in forbidden:
        assert token not in prep.argv, token
    adapter = make_searchsploit_term_adapter()
    assert adapter.executable == "searchsploit"
    assert adapter.max_seconds == 120
    assert adapter.output_bound_chars == 20_000


# ---- 7. no database update or exploit execution --------------------------------------

def test_nothing_executes_but_local_queries(monkeypatch, tmp_path):
    """Every spawned argv is the fixed local query (or the separate
    bounded nuclei_meta lookup): no update, no shell, no exploit-file
    execution — reference paths are recorded as STRINGS only."""
    sbx = _searchsploit_sandbox()
    graph, audit, _ = _enrich(monkeypatch, Path(tmp_path), sbx,
                              registry=production_registry())
    spawners = set()
    for argv, _t in sbx.spawned:
        spawners.add(argv[0])
        if argv[0] == TOOL_EXECUTABLE:
            assert argv == [TOOL_EXECUTABLE, "-j", "-t", TERM_CVE]
        else:
            assert argv[0].endswith("/nuclei_meta.py")
            assert argv[1] == TERM_CVE
    assert spawners <= {TOOL_EXECUTABLE, "/opt/kryonsec/nuclei_meta.py"}
    refs = graph.by_type("exploit_reference")
    assert refs, "the sample search must produce reference nodes"
    assert all(
        n["properties"]["path"].startswith("/usr/share/exploitdb/")
        for n in refs if n["properties"]["path"])


# ---- 8. no network permission --------------------------------------------------------

def test_no_network_none_standing_and_no_egress(monkeypatch, tmp_path):
    """network='none' and the run succeeds on a sandbox WITHOUT an
    egress policy (the local database read needs no network at all)."""
    adapter = make_searchsploit_term_adapter()
    assert adapter.network == "none"
    assert adapter.risk == "informational"
    sbx = _searchsploit_sandbox()
    assert sbx.egress_policy is None
    _graph, audit, _counts = _enrich(monkeypatch, Path(tmp_path), sbx,
                                     registry=production_registry())
    assert _event_names(audit).count("hypothesize_searchsploit_adapter") == 1


# ---- 9. missing sandbox and runtime failure -------------------------------------------

def test_missing_sandbox_is_an_audited_skip(monkeypatch, tmp_path):
    graph, audit, _counts = _enrich(monkeypatch, Path(tmp_path), None,
                                    registry=production_registry())
    events = _events(audit)
    skip = [e for e in events if e["event"] == "enrichment_lookup"
            and e["kind"] == "searchsploit"]
    assert skip and "no sandbox" in skip[0]["reason"]
    assert graph.by_type("exploit_reference") == []
    assert "hypothesize_searchsploit_adapter" not in _event_names(audit)
    assert graph.by_type("adapter_attempt") == []


def test_runtime_failure_is_an_audited_skip_not_fake_evidence(monkeypatch,
                                                              tmp_path):
    sbx = _searchsploit_sandbox(stdout="", ok=False, exit_code=1,
                                error="tool failed")
    graph, audit, _counts = _enrich(monkeypatch, Path(tmp_path), sbx,
                                    registry=production_registry())
    names = _event_names(audit)
    assert "hypothesize_adapter_failure" in names
    assert "hypothesize_searchsploit_adapter" not in names
    assert graph.by_type("exploit_reference") == []
    assert graph.by_type("adapter_attempt") == []   # failed runs leave
                                                    # NO attempt node
    assert "exploitdb_adapter_evidence_refused" not in names
    enrich = _h_node(graph)["properties"]["enrichment"]
    assert enrich.get("exploit_available", False) is False
    ok, reason = audit.verify()
    assert ok, reason


# ---- 10. no host fallback --------------------------------------------------------------

def test_no_host_fallback_refuses(tmp_path):
    """A sandbox object without a callable spawn() (or None) is refused:
    Mode B never falls back to host-side or in-process execution."""
    names = {}
    for i, bad in enumerate((None, object(), "docker://fake")):
        audit = AuditLog(tmp_path / f"a{i}.jsonl")
        record, _out = execute_adapter(
            production_registry(), _prepared(), sandbox=bad, audit=audit,
            full_output=True)
        assert record.executed is False
        assert record.outcome == "refused"
        names[i] = _event_names(audit)
    assert all("adapter_refused" in v for v in names.values())


# ---- 11. duplicate-query prevention (deterministic either/or) ---------------------------

def test_adapter_mode_omits_the_legacy_table_lookup(monkeypatch, tmp_path):
    """With the adapter registered, the legacy --colorless text-table
    query NEVER runs — exactly one searchsploit execution per check."""
    sbx = _searchsploit_sandbox()
    _enrich(monkeypatch, Path(tmp_path), sbx, registry=production_registry())
    ss_argv = [a for a, _t in sbx.spawned if a[0] == TOOL_EXECUTABLE]
    assert len(ss_argv) == 1
    assert "--colorless" not in ss_argv[0]
    assert ss_argv[0] == [TOOL_EXECUTABLE, "-j", "-t", TERM_CVE]

    # without the registry the LEGACY behavior is byte-identical
    sbx2 = _searchsploit_sandbox(
        stdout="Apache Struts RCE\nsome hit line\n")
    _enrich(monkeypatch, Path(tmp_path), sbx2, registry=None)
    legacy = [a for a, _t in sbx2.spawned if a[0] == TOOL_EXECUTABLE]
    assert legacy == [["searchsploit", "--colorless", TERM_CVE]]


def test_registry_without_the_adapter_behaves_like_none(monkeypatch,
                                                        tmp_path):
    reg = AdapterRegistry()              # registered NOTHING
    sbx = _searchsploit_sandbox(
        stdout="Apache Struts RCE\nsome hit line\n")
    _enrich(monkeypatch, Path(tmp_path), sbx, registry=reg)
    legacy = [a for a, _t in sbx.spawned if a[0] == TOOL_EXECUTABLE]
    assert legacy == [["searchsploit", "--colorless", TERM_CVE]]


def test_hypothesize_subagent_wires_the_registry_through(monkeypatch,
                                                         tmp_path):
    import kryonsec.purple.enrichment as enr
    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.hypothesize import (
        HypothesisSet,
        HypothesizeSubagent,
    )

    captured = {}

    def fake_enrich(cfg, graph, audit, sandbox=None, adapter_registry=None):
        captured["sandbox"] = sandbox
        captured["registry"] = adapter_registry
        return {"hypotheses": 0, "enriched": 0, "no_cve": 0, "lookups": 0}

    monkeypatch.setattr(enr, "enrich_hypotheses", fake_enrich)
    reg = production_registry()
    sub = HypothesizeSubagent(
        cfg=KryonsecConfig(home=tmp_path / "home"),
        graph=EngagementGraph(engagement_id="e-wire"),
        audit=AuditLog(tmp_path / "w.jsonl"),
        llm_fn=lambda prompt: HypothesisSet(),
        sandbox=object(),
        adapter_registry=reg,
    )
    sub.run()
    assert captured["registry"] is reg
    assert captured["sandbox"] is not None


# ---- 12. audit and evidence lineage ------------------------------------------------------

def test_evidence_nodes_lineage_and_audit_chain(monkeypatch, tmp_path):
    sbx = _searchsploit_sandbox()
    graph, audit, _ = _enrich(monkeypatch, Path(tmp_path), sbx,
                              registry=production_registry())
    attempt = graph.by_type("adapter_attempt")[0]
    refs = graph.by_type("exploit_reference")
    assert {n["label"] for n in refs} == {
        "EDB-31615", "EDB-21671", "EDB-55555"}
    # read the attempt back through the validated 2B.2 collector
    records, invalid = collect_adapter_evidence(graph, audit)
    assert invalid == [] and len(records) == 1
    record = records[0]
    assert record.adapter_id == ADAPTER_ID
    assert record.verification == "not_verified"
    assert record.untrusted is True
    assert find_adapter_attempt_node(graph, record.request_id) is attempt
    # duplicate evidence recording is skipped (first observation wins)
    dup = record_exploitdb_evidence(
        graph, audit, run_record=record, term=TERM_CVE,
        references=parse_searchsploit_json(SAMPLE_JSON)[0],
        hypothesis_id="H1")
    assert dup == []
    ok, reason = audit.verify()
    assert ok, reason
    names = _event_names(audit)
    assert "exploitdb_adapter_evidence" in names
    assert any(e["event"] == "exploitdb_adapter_evidence"
               and e["duplicate_or_refused"] == 3 for e in _events(audit))
    # the produced lineage edges exist: attempt -> every reference node
    attempt_id = attempt["id"]
    for n in refs:
        assert any(e["source_node_id"] == attempt_id
                   and e["target_node_id"] == n["id"]
                   for e in graph.edges)


def test_find_adapter_attempt_node_knows_other_runs():
    reg = production_registry()
    prep = prepare_adapter_run(reg, ADAPTER_ID, target="t",
                               params={"term": TERM_CVE},
                               request_id="requestid9999")
    assert find_adapter_attempt_node(_graph(), prep.request_id) is None


# ---- 13. no automatic vulnerability confirmation ---------------------------------------

def test_references_never_confirm_or_upgrade_anything(monkeypatch, tmp_path):
    sbx = _searchsploit_sandbox()
    graph, audit, _ = _enrich(monkeypatch, Path(tmp_path), sbx,
                              registry=production_registry())
    h = _h_node(graph)
    # the hypothesis stays UNAPPROVED and un-upgraded (an "observed"
    # status means "a model proposed this", never "verified")
    assert h["status"] != "confirmed"
    assert h["properties"].get("approved", False) is False
    refs = graph.by_type("exploit_reference")
    assert refs
    for n in refs:
        p = n["properties"]
        assert p["verification"] == "not_verified"
        assert p["reference_only"] is True and p["untrusted"] is True
        # nothing in a reference claims the target is vulnerable
        blob = json.dumps(p)
        assert "vulnerable" not in blob
        assert p.get("confirmed") is None
    # enrichment flags stay REFERENCE-flags, never a confirmation
    enrich = h["properties"]["enrichment"]
    assert enrich["exploit_available"] is True   # "a reference exists"
    assert "confirmed" not in json.dumps(enrich)
    # gate-lifecycle audit events are untouched by enrichment
    names = _event_names(audit)
    for gate_event in ("gate_2_approved", "gate_3_approved",
                       "finding_confirmed"):
        assert gate_event not in names


def test_adapter_writes_only_the_declared_node_types(monkeypatch, tmp_path):
    sbx = _searchsploit_sandbox()
    graph, _audit, _ = _enrich(monkeypatch, Path(tmp_path), sbx,
                               registry=production_registry())
    types = {n["node_type"] for n in graph.nodes}
    assert types <= {"target", "hypothesis", "adapter_attempt",
                     "exploit_reference"}, types
    # no finding / capability / post-exploit nodes were created
    for banned in ("finding", "capability", "post_exploit_state"):
        assert graph.by_type(banned) == []


# ---- 14. no Gate 2 / Gate 3 bypass --------------------------------------------------------

def test_gates_default_were_never_granted(monkeypatch, tmp_path):
    """The registered adapter carries the standing its stage already has
    (HYPOTHESIZE enrichment needs no gate) — and a GATE-REQUIRED
    reclassification of the same id still refuses without a real grant.
    No gate machinery is touched or bypassed."""
    assert make_searchsploit_term_adapter().approvals == ()
    # a hypothetical gate-required variant is refused without the grant
    variant = make_searchsploit_term_adapter().model_copy(update={
        "stages": ("HYPOTHESIZE", "EXPLOIT"),
        "approvals": ("hypothesis_gate",)})
    reg = AdapterRegistry()
    reg.register(variant)
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target="t", params={"term": TERM_CVE},
        request_id="requestid9876")
    with tempfile.TemporaryDirectory() as td:
        record, _ = execute_adapter(
            reg, prep, sandbox=_searchsploit_sandbox(),
            audit=AuditLog(Path(td) / "g.jsonl"), full_output=True)
        assert record.executed is False
        assert record.outcome == "refused"
        assert "not granted" in record.error_excerpt
        # with the grant AND a real approved hypothesis on the graph,
        # the same variant DOES run: the gates are real, never theatrical
        g2 = _graph()
        _h = _h_node(g2)
        _h["properties"]["approved"] = True
        record2, _ = execute_adapter(
            reg, prep, sandbox=_searchsploit_sandbox(), graph=g2,
            hypothesis_id="H1",
            audit=AuditLog(Path(td) / "g2.jsonl"),
            approvals_granted={"hypothesis_gate"}, full_output=True)
        assert record2.executed is True
        # post_exploit_gate is nowhere in this adapter's requirement set:
        # approving Gate 2 never unlocks Gate 3 semantics
        assert variant.approvals == ("hypothesis_gate",)


# ---- 15. no Post-Exploit capability activation -------------------------------------------

def test_stages_and_registry_cannot_reach_post_exploit():
    adapter = make_searchsploit_term_adapter()
    assert adapter.stages == ("HYPOTHESIZE",)     # the ONLY stage
    assert "POST_EXPLOIT" not in adapter.stages
    assert "EXPLOIT" not in adapter.stages
    assert "post_exploit_gate" not in adapter.approvals
    reg = production_registry()
    assert reg.adapter_ids() == (ADAPTER_ID,)
    for listed in reg.list_adapters():
        assert listed.stages == ("HYPOTHESIZE",)
        assert listed.risk == "informational"    # never impactful
    # the gate contract modules stay untouched (imports still resolve)
    from kryonsec.purple.capability import capability_gate_text

    assert callable(capability_gate_text)


# ---- the ONE genuine integration test (opt-in, local database only) ----------------------


def _it_readiness() -> "tuple[bool, str]":
    """Real Docker + runsc + the pinned image; NO lab URL and NO egress
    (the ExploitDB copy lives inside the sandbox)."""
    if os.environ.get("KRYONSEC_SEARCHSPLOIT_IT") != "1":
        return False, "KRYONSEC_SEARCHSPLOIT_IT=1 not set"
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    from kryonsec.config import KryonsecConfig
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    if not ok:
        return False, f"docker daemon: {reason}"
    if not rc.runsc_registered():
        return False, "runsc runtime not registered"
    image = KryonsecConfig().sandbox_image
    if "@sha256:" not in image:
        return False, ("sandbox image is not digest-pinned in this "
                       "environment (rule 7) — set KRYONSEC_SANDBOX_IMAGE")
    if not rc.image_present(image):
        return False, f"pinned sandbox image absent: {image}"
    return True, ""


def test_real_searchsploit_term_it():
    """GENUINE adapter IT: real Docker + gVisor runsc sandbox running the
    real `searchsploit -j -t <benign term>` against the LOCAL ExploitDB
    copy in the image. Skipped silently otherwise. Never contacts the
    target or any third party (network standing: none)."""
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from kryonsec.config import KryonsecConfig
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig()
    sbx = KaliSandbox(cfg=cfg)      # NO egress policy: network none
    # a benign term VERIFIED live to match entries in the image's copy
    # (searchsploit AND-matches terms — multi-word queries can match
    # nothing, which is a valid answer but not a deployment check)
    safe_term = secure_term("openssl")
    reg = production_registry()
    audit = AuditLog(Path("tmp_ss_it_audit.jsonl"))
    graph = EngagementGraph(engagement_id="ss-it")
    graph.add_node("target", "local-lookup-only", {})
    prep = prepare_adapter_run(reg, ADAPTER_ID, target="local-lookup-only",
                               params={"term": safe_term})
    record, output = execute_adapter(reg, prep, sandbox=sbx, audit=audit,
                                     graph=graph, full_output=True)
    assert record.executed is True, record.error_excerpt
    assert record.verification == "not_verified"
    assert record.exit_code == 0
    refs, malformed = parse_searchsploit_json(output)
    assert malformed == 0
    assert refs, "the pinned image's ExploitDB copy must match 'openssl'"
    created = record_exploitdb_evidence(
        graph, audit, run_record=record, term=safe_term,
        references=refs, hypothesis_id="")
    assert len(created) == len(refs)
    for node in graph.by_type("exploit_reference"):
        assert node["properties"]["verification"] == "not_verified"
    ok2, reason2 = audit.verify()
    assert ok2, reason2
