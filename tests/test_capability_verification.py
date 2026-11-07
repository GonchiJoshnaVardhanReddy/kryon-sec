"""Phase 1D tests: independent capability verification.

Nothing here runs a real probe or touches the network — every sandbox
is a fake that replays prepared SpawnResults, exactly like
test_capability_handoff.py. The verification-contract registry ships
deliberately EMPTY (dormant, like the parser registry); each test
injects one explicit producer contract with guaranteed cleanup, so
registration never leaks out of a test.

The invariant under test throughout: the verdict derives ONLY from the
probe's own execution evidence inside the Mode B sandbox — never from
the claimed evidence string, a stored status word, or an exit code
alone.
"""

import json

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple import capability, capability_verify
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.capability import CapabilityRecord
from kryonsec.purple.capability_verify import (
    MAX_PROBE_TOKENS,
    VerificationContract,
    register_contract,
)
from kryonsec.purple.exploit import ExploitSubagent
from kryonsec.purple.post_exploit import PostExploitSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.views import ATTEMPT_CONFIRMED


# ---- fixtures ---------------------------------------------------------------

MARKER = "KRYONSEC-CAP-PROBE-OK"


def _sqlmap_contract():
    """The hypothetical future producer's verification contract: one
    static, bounded probe whose stdout must contain the exact marker —
    and whose argv REFERENCES the engagement target (Phase 2A binding:
    a marker-only probe that never touches the target cannot demonstrate
    an on-target capability)."""
    return VerificationContract(
        producer="sqlmap",
        method="sandbox_marker_probe",
        probe_argv=("python3", "-c",
                    f"probe target-corp.com; if unreachable, no"
                    f" print('{MARKER}')"),
        expect_marker=MARKER,
    )


@pytest.fixture
def sqlmap_contract(monkeypatch):
    """Register ONE producer's BOTH halves of trust (Phase 1B parser +
    Phase 1D contract); the (production-empty) registries are restored
    after the test."""
    _sqlmap_parser(monkeypatch)
    register_contract(_sqlmap_contract())
    yield _sqlmap_contract()
    capability_verify.CAPABILITY_VERIFICATION_CONTRACTS.clear()


def _sqlmap_parser(monkeypatch):
    """The matching first half of producer trust (Phase 1B parser)."""
    monkeypatch.setitem(
        capability.CAPABILITY_PARSERS, "sqlmap",
        lambda excerpt: "os-shell session established"
        if "is vulnerable" in excerpt else None)


CONFIRMED = SpawnResult(
    ok=True, exit_code=0,
    stdout="INFO: GET parameter 'txtLoginName' is 'AND boolean-based blind' — "
           "parameter 'id' is vulnerable sqlmap output")
PROBE_OK = SpawnResult(ok=True, exit_code=0, stdout=MARKER + "\n")
PROBE_MISS = SpawnResult(ok=True, exit_code=0, stdout="nothing suspicious")


class SwitchingSandbox:
    """Fake Mode B sandbox: the CONFIRMED tool output for the exploit
    plan's own argv, the contracted probe result for the probe argv
    (distinguishable by its leading ``python3`` token, the same way the
    exploit plan's spawns are distinguishable by tool name)."""

    def __init__(self, probe_result):
        self.probe_result = probe_result
        self.spawned = []

    def spawn(self, argv):
        self.spawned.append(argv)
        if argv[0] == "python3":
            return self.probe_result
        return CONFIRMED


def _attempt(graph, node_id="attempt-1", tool="sqlmap", **props):
    """An exploit_attempt node in exactly the shape an exploit run
    writes (the confirmed-at-read-time shape the verifier re-checks)."""
    return graph.add_node(
        "exploit_attempt", "H1:sqlmap",
        {"tool": tool, "ok": True, "exit_code": 0, "confirmed": True,
         "output_excerpt": "parameter 'id' is vulnerable",
         "hypothesis_id": "H1", "argv": ["sqlmap"], **props},
        provenance={"agent": "EXPLOIT", "source_type": "tool"},
        node_id=node_id)


def _record(graph, attempt_id="attempt-1", **overrides):
    """One claimed record node, lifecycle-exact: ``claimed`` and
    ``not_run`` because verification has not run yet (only the Phase 1D
    verifier may ever write ``verified``)."""
    props = {
        "capability": "shell", "tool": "sqlmap",
        "attempt_id": attempt_id, "attempt_label": "H1:sqlmap",
        "hypothesis_id": "H1", "target_host": "target-corp.com",
        "finding_id": "H1", "status": "claimed",
        "verification": "not_run",
        "evidence": "os-shell session established",
        "recorded_by": "EXPLOIT_PROGRAM",
    }
    props.update(overrides)
    return graph.add_node(
        "capability", f"capability:{props['attempt_label']}", props,
        provenance={"agent": "EXPLOIT", "source_type": "tool"})


def _graph(target="target-corp.com"):
    graph = EngagementGraph(engagement_id="e-verify")
    graph.add_node("target", target, {})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi on login",
        "target_asset": "/Login.asp",
        "rationale": "asp page",
        "cvss_vector": "",
        "tools": ["sqlmap"],
        "confidence": 0.8,
        "approved": True,
    })
    return graph


def _records(graph):
    nodes = graph.by_type("capability")
    return [(node, CapabilityRecord.model_validate(node["properties"]))
            for node in nodes]


def _verifier(tmp_path, graph, sandbox, target="target-corp.com"):
    from kryonsec.purple.capability_verify import CapabilityVerifier
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_verify.jsonl")
    return CapabilityVerifier(graph, audit, target, sandbox), audit


def _events(audit):
    return [json.loads(line) for line in open(audit.path, encoding="utf-8")
            if line.strip()]


def _event_names(audit):
    return [e["event"] for e in _events(audit)]


# ---- the empty contract registry keeps verification dormant ------------------

def test_production_registries_ship_empty():
    """Both halves of producer trust ship EMPTY — nothing claims, so
    nothing verifies, so post-exploitation stays dormant."""
    assert capability.CAPABILITY_PARSERS == {}
    assert capability_verify.CAPABILITY_VERIFICATION_CONTRACTS == {}
    assert capability_verify.contracts_ready() is False
    assert "EMPTY" in capability_verify.__doc__


def test_empty_contract_registry_skips_entirely(tmp_path):
    """With no contract registered, verification is a NO-OP: zero nodes,
    zero events, zero spawns — production behavior is byte-for-byte the
    pre-Phase-1D flow."""
    graph = _graph()
    _attempt(graph)
    _record(graph)
    sandbox = SwitchingSandbox(PROBE_OK)
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_dormant.jsonl")

    results = capability_verify.verify_claimed_records(
        graph, audit, "target-corp.com", sandbox, _records(graph))

    assert results == {}
    assert graph.by_type("capability_verification") == []
    assert sandbox.spawned == []
    assert not audit.path.exists()   # zero audit events: file never created


def test_parser_registered_without_contract_is_refused(tmp_path,
                                                       monkeypatch):
    """Phase 1B registration alone is not trust: the parser may claim,
    but with no verification contract the verdict is refused."""
    _sqlmap_parser(monkeypatch)
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph)
    sandbox = SwitchingSandbox(PROBE_OK)
    verifier, audit = _verifier(tmp_path, graph, sandbox)

    result = verifier.verify(*_records(graph)[0])

    assert result.status == "refused"
    assert "no verification contract" in " ".join(result.reasons)
    assert graph.by_type("capability")[0]["properties"] \
        ["verification"] == "not_run"
    assert sandbox.spawned == []      # refused before any execution
    names = _event_names(audit)
    assert "capability_verification_attempted" in names
    assert "capability_verification_refused" in names
    assert "capability_verified" not in names


# ---- contract registration itself is fail closed ------------------------------

def test_contract_registration_rejects_bad_shapes():
    """Bad contracts raise instead of registering — the registry shape
    is itself fail closed (static tokens, no newlines/placeholders)."""
    good = _sqlmap_contract()
    bad = [
        VerificationContract("", "m", good.probe_argv, MARKER),
        VerificationContract("tool", "", good.probe_argv, MARKER),
        VerificationContract("tool", "m", tuple(), MARKER),
        VerificationContract(
            "tool", "m", ("x",) * (MAX_PROBE_TOKENS + 1), MARKER),
        VerificationContract("tool", "m", ("py\n",), MARKER),
        VerificationContract("tool", "m", ("{target_host}",), MARKER),
        VerificationContract("tool", "m", ("ok",), ""),            # no marker
        VerificationContract("tool", "m", ("ok",), "m" * 65),      # oversize
        VerificationContract(
            "tool", "m", ("ok",), "m", capability=""),             # no class
    ]
    for contract in bad:
        with pytest.raises(ValueError):
            register_contract(contract)
    assert capability_verify.CAPABILITY_VERIFICATION_CONTRACTS == {}


# ---- the success contract ------------------------------------------------------

def test_success_contract_produces_verified(tmp_path, sqlmap_contract):
    """Registered producer + contract, CONFIRMED attempt still live, and
    a probe that reproduces the marker inside the sandbox -> verified:
    the node field is written by the verifier, the check node + verified_by
    lineage + audit events all exist."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph)
    sandbox = SwitchingSandbox(PROBE_OK)
    verifier, audit = _verifier(tmp_path, graph, sandbox)

    result = verifier.verify(*_records(graph)[0])

    assert result.status == "verified"
    assert result.method == "sandbox_marker_probe"
    assert result.marker_seen is True
    assert result.probe_exit_code == 0
    assert result.attempt_node_id == "attempt-1"
    assert record_node["properties"]["verification"] == "verified"

    checks = graph.by_type("capability_verification")
    assert len(checks) == 1
    assert checks[0]["properties"]["status"] == "verified"
    assert checks[0]["properties"]["method"] == "sandbox_marker_probe"
    lineage = graph.find_edges(relationship="verified_by")
    assert len(lineage) == 1
    assert lineage[0]["source_node_id"] == record_node["id"]
    assert lineage[0]["target_node_id"] == checks[0]["id"]

    names = _event_names(audit)
    assert names[0] == "capability_verification_attempted"
    assert "capability_verified" in names
    assert "capability_verification_refused" not in names
    ok, reason = audit.verify()
    assert ok, reason


def test_exploit_wiring_runs_verification_before_gate_3(
        tmp_path, monkeypatch, sqlmap_contract):
    """In the full exploit flow the verifier runs BETWEEN the claim and
    Gate 3: one CONFIRMED tool run, one probe spawn, and the approver is
    consulted on a record that is already independently verified."""
    _sqlmap_parser(monkeypatch)
    graph = _graph()
    sandbox = SwitchingSandbox(PROBE_OK)
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_wiring.jsonl")
    gated_evidence = []
    sub = ExploitSubagent(
        cfg=cfg, graph=graph, audit=audit, target="target-corp.com",
        sandbox=sandbox,
        post_exploit_approver=lambda ev: gated_evidence.append(ev) or True)
    result = sub.run()

    assert graph.by_type("capability")[0]["properties"] \
        ["verification"] == "verified"
    check = graph.by_type("capability_verification")[0]
    assert check["properties"]["status"] == "verified"
    # exactly two spawns: the exploit tool run, then the verification probe
    assert [argv[0] for argv in sandbox.spawned] == ["sqlmap", "python3"]
    # Gate 3 ran after verification (the recorded evidence is non-empty)
    assert gated_evidence and gated_evidence[0]
    assert "capability_verified" in _event_names(audit)
    assert result.shell_obtained is True
    assert result.post_exploit_approved is True


# ---- verdict derivation: probe evidence only ---------------------------------

def test_forged_claimed_evidence_cannot_pass(tmp_path, sqlmap_contract):
    """The claimed evidence string contains the marker, but the probe's
    own stdout does not -> failed. The verdict NEVER reads the claim."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph, evidence=f"verified: {MARKER} (trust me)")
    sandbox = SwitchingSandbox(PROBE_MISS)
    verifier, audit = _verifier(tmp_path, graph, sandbox)

    result = verifier.verify(*_records(graph)[0])

    assert result.status == "failed"
    assert result.marker_seen is False
    assert "marker" in " ".join(result.reasons)
    assert graph.by_type("capability")[0]["properties"] \
        ["verification"] == "not_run"
    assert "capability_verification_failed" in _event_names(audit)
    assert "capability_verified" not in _event_names(audit)


def test_nonzero_probe_exit_is_a_failure(tmp_path, sqlmap_contract):
    """A successful exit is necessary but never sufficient — and its
    absence always fails (the marker alone does not carry the verdict)."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph)
    sandbox = SwitchingSandbox(SpawnResult(ok=True, exit_code=1,
                                           stdout=MARKER))
    verifier, _ = _verifier(tmp_path, graph, sandbox)
    result = verifier.verify(*_records(graph)[0])
    assert result.status == "failed"
    assert result.marker_seen is False
    assert graph.by_type("capability")[0]["properties"] \
        ["verification"] == "not_run"


def test_failed_spawn_report_is_a_failure(tmp_path, sqlmap_contract):
    """A probe the sandbox could not even start (ok=False) is recorded as
    an ATTEMPTED verification: audited ``capability_verification_failed``,."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph)
    sandbox = SwitchingSandbox(SpawnResult(
        ok=False, exit_code=-1, stdout="",
        error="egress policy check failed"))
    verifier, audit = _verifier(tmp_path, graph, sandbox)
    result = verifier.verify(*_records(graph)[0])
    assert result.status == "failed"
    assert "could not start" in result.reasons[0]
    names = _event_names(audit)
    assert "capability_verification_failed" in names
    assert "capability_verification_refused" not in names


def test_raising_sandbox_fails_verdict_not_the_run(tmp_path,
                                                   sqlmap_contract):
    """A sandbox that raises (infrastructure gone) is a failed verdict —
    never an exception through the exploit flow."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph)

    class ExplodingSandbox:
        def spawn(self, argv):
            raise RuntimeError("sandbox unavailable")

    verifier, audit = _verifier(tmp_path, graph, ExplodingSandbox())
    result = verifier.verify(*_records(graph)[0])
    assert result.status == "failed"
    assert "sandbox" in " ".join(result.reasons).lower()
    assert "capability_verification_failed" in _event_names(audit)


# ---- fail-closed: stale, missing, contradictory, scope, lifecycle -------------

def test_stale_attempt_evidence_is_refused(tmp_path, sqlmap_contract):
    """The attempt no longer confirms at read time -> refused (the claim
    derived from reading the same evidence; if it no longer confirms, the
    record is stale)."""
    graph = _graph()
    _attempt(graph, output_excerpt="all finished, nothing found",
             confirmed=False)
    record_node = _record(graph)
    sandbox = SwitchingSandbox(PROBE_OK)
    verifier, _ = _verifier(tmp_path, graph, sandbox)
    result = verifier.verify(*_records(graph)[0])
    assert result.status == "refused"
    assert "stale" in " ".join(result.reasons)
    assert sandbox.spawned == []


def test_missing_attempt_reference_is_refused(tmp_path, sqlmap_contract):
    """A record pointing at an attempt that is not on the graph -> refused."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph, attempt_id="attempt-gone")
    sandbox = SwitchingSandbox(PROBE_OK)
    verifier, _ = _verifier(tmp_path, graph, sandbox)
    result = verifier.verify(record_node, CapabilityRecord.model_validate(
        record_node["properties"]))
    assert result.status == "refused"
    assert "missing from the graph" in " ".join(result.reasons)


def test_tool_mismatch_is_contradictory(tmp_path, sqlmap_contract):
    """The claimed attempt was produced by a different tool -> refused."""
    graph = _graph()
    _attempt(graph, tool="nikto")
    record_node = _record(graph)
    sandbox = SwitchingSandbox(PROBE_OK)
    verifier, _ = _verifier(tmp_path, graph, sandbox)
    result = verifier.verify(*_records(graph)[0])
    assert result.status == "refused"
    assert "contradictory" in " ".join(result.reasons)


def test_decided_lifecycle_records_are_refused(tmp_path, sqlmap_contract):
    """Verification happens BEFORE Gate 3 — approved/rejected records are
    the wrong record, and an already-verified one never re-verifies."""
    graph = _graph()
    _attempt(graph)
    for status in ("approved", "rejected"):
        node = _record(graph, attempt_label=f"H1:sqlmap:{status}",
                       status=status)
        sandbox = SwitchingSandbox(PROBE_OK)
        verifier, _ = _verifier(tmp_path, graph, sandbox)
        result = verifier.verify(node, CapabilityRecord.model_validate(
            node["properties"]))
        assert result.status == "refused", status
        assert "claimed" in " ".join(result.reasons)

    node = _record(graph, attempt_label="H1:sqlmap:pre-verified",
                   verification="verified")
    sandbox = SwitchingSandbox(PROBE_OK)
    verifier, _ = _verifier(tmp_path, graph, sandbox)
    result = verifier.verify(node, CapabilityRecord.model_validate(
        node["properties"]))
    assert result.status == "refused"
    assert "already verified" in " ".join(result.reasons)


def test_out_of_scope_host_is_refused(tmp_path, sqlmap_contract):
    """A capability pointing at another host is never verified — the
    capability is not portable out of engagement scope."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph, target_host="target-corp.com.evil.org")
    sandbox = SwitchingSandbox(PROBE_OK)
    verifier, _ = _verifier(tmp_path, graph, sandbox)
    result = verifier.verify(*_records(graph)[0])
    assert result.status == "refused"
    assert "scope" in " ".join(result.reasons)
    assert sandbox.spawned == []


# ---- contract binding (Phase 2A hardening of Phase 1D) ------------------------

def test_marker_only_probe_without_target_binding_is_refused(
        tmp_path, sqlmap_contract, monkeypatch):
    """Phase 2A: a registered contract whose probe argv never references
    the engagement target cannot verify anything — the marker alone is
    not independent evidence of an on-target capability."""
    from kryonsec.purple.capability_verify import VerificationContract, \
        register_contract
    _sqlmap_parser(monkeypatch)
    marker_only = VerificationContract(
        producer="sqlmap", method="sandbox_marker_probe",
        probe_argv=("python3", "-c", f"print('{MARKER}')"),
        expect_marker=MARKER)
    register_contract(marker_only)   # registration passes...
    try:
        graph = _graph()
        _attempt(graph)
        record_node = _record(graph)
        sandbox = SwitchingSandbox(PROBE_OK)
        verifier, audit = _verifier(tmp_path, graph, sandbox)
        result = verifier.verify(*_records(graph)[0])
        assert result.status == "refused"
        assert "not bound to the engagement target" in " ".join(
            result.reasons)
        assert sandbox.spawned == []     # never executed
        assert "capability_verified" not in _event_names(audit)
        assert graph.by_type("capability")[0]["properties"] \
            ["verification"] == "not_run"
    finally:
        capability_verify.CAPABILITY_VERIFICATION_CONTRACTS.clear()


def test_contract_capability_class_binding_mismatch(tmp_path,
                                                    sqlmap_contract):
    """Phase 2A: the contract names the one capability class it verifies;
    a record claiming a different class is refused (contradictory)."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph)
    record_node["properties"]["capability"] = "shell"  # schema-Literal only
    # no cross-class record shape exists under the published schema —
    # the binding contract is enforced at the record-vs-contract level:
    # simulate a contract bound to a different class than the record.
    from kryonsec.purple.capability_verify import VerificationContract, \
        register_contract
    register_contract(VerificationContract(
        producer="sqlmap", method="m",
        probe_argv=("python3", "-c", "probe target-corp.com"),
        expect_marker=MARKER, capability="fs-read"))
    try:
        sandbox = SwitchingSandbox(PROBE_OK)
        verifier, _ = _verifier(tmp_path, graph, sandbox)
        result = verifier.verify(*_records(graph)[0])
        assert result.status == "refused"
        assert "fs-read" in " ".join(result.reasons)
        assert "contradictory" in " ".join(result.reasons)
    finally:
        capability_verify.CAPABILITY_VERIFICATION_CONTRACTS.clear()


# ---- the Layer-2 gate guards the verification probe ---------------------------

def test_probe_allowlist_violation_fails_closed(tmp_path, sqlmap_contract):
    """A verifier whose Layer-2 gate does not know the probe template
    refuses BEFORE any spawn — probes are tool executions like any other."""
    graph = _graph()
    _attempt(graph)
    record_node = _record(graph)
    from kryonsec.purple.allowlist import ToolAllowlist
    sandbox = SwitchingSandbox(PROBE_OK)
    verifier, audit = _verifier(tmp_path, graph, sandbox)
    verifier.allowlist = ToolAllowlist(templates={"capif:other": ["true"]})

    result = verifier.verify(*_records(graph)[0])

    assert result.status == "refused"
    assert "Layer-2" in " ".join(result.reasons)
    assert sandbox.spawned == []      # gate refusal happens before spawn


def test_default_allowlist_is_derived_from_contracts_only(
        sqlmap_contract):
    """With no allowlist handed in, the verifier builds a strict one from
    the registered contracts — each producer's probe validates, nothing
    beyond the exact contracted argv does."""
    from kryonsec.purple.allowlist import AllowlistViolation
    from kryonsec.purple.capability_verify import CapabilityVerifier
    register_contract(VerificationContract(
        producer="other-tool", method="m", probe_argv=("id", "-u"),
        expect_marker="uid="))
    try:
        verifier = CapabilityVerifier(
            _graph(), None, "target-corp.com", None)
        verifier.allowlist.validate(
            "capif:sqlmap", list(_sqlmap_contract().probe_args()))
        verifier.allowlist.validate("capif:other-tool", ["id", "-u"])
        with pytest.raises(AllowlistViolation):
            verifier.allowlist.validate("capif:sqlmap", ["bash"])
        with pytest.raises(AllowlistViolation):
            verifier.allowlist.validate("capif:unknown", ["id", "-u"])
    finally:
        capability_verify.CAPABILITY_VERIFICATION_CONTRACTS.clear()


# ---- the full orchestrator transition, end to end, fake sandbox ----------------

def test_end_to_end_verified_then_approved_then_post_exploit(
        tmp_path, monkeypatch, sqlmap_contract):
    """CONFIRMED attempt -> claim -> INDEPENDENT verification (their
    probe inside the sandbox) -> Gate 3 approval -> the orchestrator
    routes to POST_EXPLOIT -> the subagent consumes the verified+approved
    record and runs the plan."""
    from kryonsec.purple.orchestrator import next_state
    _sqlmap_parser(monkeypatch)
    graph = _graph()

    class PostRunSandbox:
        """Exploit-side spawns see CONFIRMED output; the real PE plan
        spawns (enum scripts) get neutral one-line outputs."""

        def __init__(self):
            self.spawned = []
            self.probe_seen = False

        def spawn(self, argv):
            self.spawned.append(argv)
            if argv[0] == "python3":
                self.probe_seen = True
                return PROBE_OK
            if argv[0] == "sqlmap":
                return CONFIRMED
            return SpawnResult(ok=True, exit_code=0,
                               stdout='{"probe": "enum"}')

    sandbox = PostRunSandbox()
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_e2e.jsonl")
    exploit = ExploitSubagent(
        cfg=cfg, graph=graph, audit=audit, target="target-corp.com",
        sandbox=sandbox, post_exploit_approver=lambda ev: True)
    exploit_result = exploit.run()

    # three prerequisites recorded on the graph: genuine evidence,
    # independent verification, approval
    record = graph.by_type("capability")[0]
    assert record["properties"]["status"] == "approved"
    assert record["properties"]["verification"] == "verified"
    assert sandbox.probe_seen is True
    assert next_state("EXPLOIT", exploit_result) == "POST_EXPLOIT"
    names = _event_names(audit)
    assert "capability_recorded" in names
    assert "capability_verified" in names

    # the POST_EXPLOIT subagent consumes the record: plan runs
    pe_cfg = KryonsecConfig(home=tmp_path)
    pe_audit = AuditLog(tmp_path / "audit_pe.jsonl")
    pe = PostExploitSubagent(cfg=pe_cfg, graph=graph, audit=pe_audit,
                             target="target-corp.com", sandbox=sandbox)
    pe_result = pe.run()
    assert pe_result.status == "ok"
    assert any(argv[0].startswith("/opt/kryonsec/enum_")
               for argv in sandbox.spawned)
    pe_names = _event_names(pe_audit)
    assert "post_exploit_done" in pe_names
    assert "post_exploit_capability_refused" not in pe_names


def test_approved_but_unverified_cannot_run_post_exploit(
        tmp_path, sqlmap_contract):
    """Approval alone is never eligibility (Phase 1C holds under Phase
    1D): a record with verification still not_run is refused — even with
    a verification contract registered for its producer."""
    graph = _graph()
    _attempt(graph)
    _record(graph, status="approved", verification="not_run")

    class PostSandbox:
        def __init__(self):
            self.spawned = []

        def spawn(self, argv):
            self.spawned.append(argv)
            return SpawnResult(ok=True, exit_code=0, stdout='{"e": 1}')

    sandbox = PostSandbox()
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_pe_unverified.jsonl")
    pe = PostExploitSubagent(cfg=cfg, graph=graph, audit=audit,
                             target="target-corp.com", sandbox=sandbox)
    result = pe.run()

    assert result.status == "failed"
    assert sandbox.spawned == []      # nothing ran
    refused = [e for e in _events(audit)
               if e["event"] == "post_exploit_capability_refused"]
    assert refused and "independently verified" in refused[0]["reason"]
    ok, reason = audit.verify()
    assert ok, reason


def test_gate3_rejection_after_verification_stays_refused(
        tmp_path, monkeypatch, sqlmap_contract):
    """The inverse leg: successful verification but the approver says NO
    -> no approval, and the orchestrator must not route to POST_EXPLOIT."""
    from kryonsec.purple.orchestrator import next_state
    _sqlmap_parser(monkeypatch)
    graph = _graph()
    sandbox = SwitchingSandbox(PROBE_OK)
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_reject.jsonl")
    sub = ExploitSubagent(
        cfg=cfg, graph=graph, audit=audit, target="target-corp.com",
        sandbox=sandbox, post_exploit_approver=lambda ev: False)
    result = sub.run()

    assert result.shell_obtained is True
    assert result.post_exploit_approved is False
    assert graph.by_type("capability")[0]["properties"] \
        ["verification"] == "verified"   # verified, but never approved
    assert graph.by_type("capability")[0]["properties"]["status"] \
        in ("claimed", "rejected")
    assert next_state("EXPLOIT", result) != "POST_EXPLOIT"
