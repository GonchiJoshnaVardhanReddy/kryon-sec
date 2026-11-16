"""Phase 1B tests: the evidence-driven EXPLOIT -> POST_EXPLOIT handoff.

Nothing here runs a real exploit or touches the network — every sandbox
is a fake that replays prepared SpawnResults. The capability registry is
injected per-test via monkeypatch (it ships deliberately EMPTY); each
test states which future-tool-parse behavior it is standing in for.
"""

import json
from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple import capability
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.capability import (
    MAX_EVIDENCE_CHARS,
    CapabilityRecord,
    build_record,
    capability_gate_text,
    claim_from_attempt,
    host_in_scope,
)
from kryonsec.purple.exploit import ExploitSubagent
from kryonsec.purple.handoff import utc_now_iso
from kryonsec.purple.orchestrator import SubagentResult, next_state
from kryonsec.purple.post_exploit import PostExploitSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.views import ATTEMPT_CONFIRMED, attempt_outcome


# ---- fixtures --------------------------------------------------------------

class FakeSandbox:
    def __init__(self, result, second=None):
        self.result = result
        self.second = second
        self.spawned = []

    def spawn(self, argv):
        self.spawned.append(argv)
        if self.second is not None and self.spawned[-1][-1].startswith("https://"):
            return self.second
        return self.result


CONFIRMED = SpawnResult(
    ok=True, exit_code=0,
    stdout="INFO: GET parameter 'txtLoginName' is 'AND boolean-based blind' — "
           "parameter 'id' is vulnerable sqlmap output")


def _graph(target="target-corp.com"):
    graph = EngagementGraph(engagement_id="e-cap")
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


def _exploit(tmp_path, graph, sandbox, approver=None):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    return ExploitSubagent(
        cfg=cfg, graph=graph, audit=audit, target="target-corp.com",
        sandbox=sandbox, post_exploit_approver=approver), audit


def _post_exploit(tmp_path, graph, sandbox, target="target-corp.com"):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_pe.jsonl")
    return PostExploitSubagent(
        cfg=cfg, graph=graph, audit=audit, target=target,
        sandbox=sandbox), audit


def _events(audit):
    return [json.loads(l) for l in open(audit.path, encoding="utf-8")
            if l.strip()]


def _event_names(audit):
    return [e["event"] for e in _events(audit)]


def _shell_parser(monkeypatch, text="os-shell session established"):
    """Register a hypothetical future shell-yielding tool's parser. In
    this fake the tool's own confirmed verdict IS the shell evidence."""
    def parser(excerpt):
        return text if "is vulnerable" in excerpt else None
    monkeypatch.setitem(capability.CAPABILITY_PARSERS, "sqlmap", parser)
    return parser


# ---- the empty registry keeps the state dormant -----------------------------

def test_empty_registry_never_claims_a_capability(tmp_path):
    """The shipped registry is empty: even a CONFIRMED sqlmap run claims
    nothing — no capability node, no gate, EXPLOIT -> VERIFY."""
    assert capability.CAPABILITY_PARSERS == {}
    graph = _graph()
    sub, audit = _exploit(tmp_path, graph, FakeSandbox(CONFIRMED),
                          approver=lambda ev: True)
    result = sub.run()

    assert result.shell_obtained is False
    assert result.post_exploit_approved is False
    assert graph.by_type("capability") == []
    names = _event_names(audit)
    assert "capability_recorded" not in names
    assert "post_exploit_gate" not in names
    assert next_state("EXPLOIT", result) == "VERIFY"


def test_empty_registry_is_deliberate_and_dormant():
    """The registry must ship empty and the claim path documents why —
    POST_EXPLOIT may never light up because a parser exists by accident."""
    assert capability.CAPABILITY_PARSERS == {}
    assert "deliberately EMPTY" in capability.__doc__


# ---- claim derivation: execution evidence only ------------------------------

def test_claim_from_attempt_needs_registry_and_confirmed_evidence():
    """No parser on this tool -> no claim, whatever the attempt says."""
    attempt = {"id": "a-1", "label": "H1:sqlmap", "properties": {
        "tool": "sqlmap", "ok": True, "exit_code": 0, "confirmed": True,
        "output_excerpt": "parameter 'id' is vulnerable"}}
    assert claim_from_attempt(attempt, "target-corp.com") is None


def test_claim_from_attempt_refuses_unconfirmed_and_failed_runs(monkeypatch):
    _shell_parser(monkeypatch)
    confirmed = {"id": "a-1", "label": "H1:sqlmap", "properties": {
        "tool": "sqlmap", "ok": True, "exit_code": 0, "confirmed": True,
        "output_excerpt": "parameter 'id' is vulnerable"}}
    assert attempt_outcome(confirmed) == ATTEMPT_CONFIRMED
    claim = claim_from_attempt(confirmed, "target-corp.com")
    assert claim is not None and claim.status == "claimed"

    # a failed spawn is not execution evidence, with or without a forge
    failed = {"id": "a-2", "label": "H1:sqlmap", "properties": {
        "tool": "sqlmap", "ok": False, "exit_code": -1, "confirmed": False,
        "output_excerpt": "spawn failed"}}
    assert claim_from_attempt(failed, "target-corp.com") is None
    forged = dict(failed, properties=dict(
        failed["properties"], outcome="confirmed"))
    assert claim_from_attempt(forged, "target-corp.com") is None

    # an inconclusive run (tool ran, marker absent) claims nothing either
    ran_clean = {"id": "a-3", "label": "H1:sqlmap", "properties": {
        "tool": "sqlmap", "ok": True, "exit_code": 0, "confirmed": False,
        "output_excerpt": "all finished, nothing found"}}
    assert claim_from_attempt(ran_clean, "target-corp.com") is None


def test_parser_output_cannot_be_malformed_or_unbounded(monkeypatch):
    """A parser bug can never materialize as a (half-)valid record: wrong
    types or oversized garbage are refuse-or-bound at the schema."""
    # oversized evidence is bounded
    record = build_record(
        capability="shell", tool="sqlmap", attempt_id="a", attempt_label="H1:sqlmap",
        hypothesis_id="H1", target_host="target-corp.com", finding_id="H1",
        evidence=("x" * 100000), status="claimed")
    assert record is not None
    assert record.evidence == "x" * MAX_EVIDENCE_CHARS

    # secret-shaped evidence never survives the record boundary
    from secret_fixtures import aws_access_key
    record2 = build_record(
        capability="shell", tool="sqlmap", attempt_id="a", attempt_label="H1:sqlmap",
        hypothesis_id="H1", target_host="target-corp.com", finding_id="H1",
        evidence=f"session {aws_access_key()}", status="claimed")
    assert record2 is not None
    assert aws_access_key() not in record2.evidence

    # malformed source fields -> None, not an exception, not a record
    mismatched = build_record(
        capability="backdoor", tool="", attempt_id="", attempt_label="",
        hypothesis_id="", target_host="", evidence="", status="root")
    assert mismatched is None
    with pytest.raises(Exception):  # directly: an unknown lifecycle status
        CapabilityRecord(
            capability="shell", tool="t", attempt_id="a", attempt_label="l",
            hypothesis_id="h", target_host="t", status="ghosted", evidence="e")


# ---- exploit-side production + Gate 3 ---------------------------------------

def test_registry_claim_writes_a_provenance_backed_node(tmp_path, monkeypatch):
    """One confirmed attempt + registered parser -> one capability node
    whose record provably derives from that attempt and its finding."""
    _shell_parser(monkeypatch)
    graph = _graph()
    sub, audit = _exploit(tmp_path, graph, FakeSandbox(CONFIRMED),
                          approver=lambda ev: False)
    sub.run()

    attempts = graph.by_type("exploit_attempt")
    assert len(attempts) == 1
    node = graph.by_type("capability")[0]
    props = node["properties"]
    assert props["attempt_id"] == attempts[0]["id"]
    assert props["attempt_label"] == attempts[0]["label"] == "H1:sqlmap"
    assert props["hypothesis_id"] == "H1"
    assert props["finding_id"] == "H1"  # the finding the attempt confirmed
    assert props["target_host"] == "target-corp.com"
    assert props["recorded_by"] == "EXPLOIT_PROGRAM"
    assert node["provenance"] == {"agent": "EXPLOIT", "source_type": "tool"}
    # the evidence is the parsed output, never the LLM's word
    assert "os-shell" in props["evidence"]

    names = _event_names(audit)
    assert names.count("capability_recorded") == 1
    # gate rejected the claim -> the lifecycle was written exactly once
    decided = [e for e in _events(audit)
               if e["event"] == "capability_decision"]
    assert len(decided) == 1 and decided[0]["decision"] == "rejected"
    assert props["status"] == "rejected"
    ok, reason = audit.verify()
    assert ok, reason


def test_gate_shows_redacted_real_evidence_and_denies_by_default(
        tmp_path, monkeypatch):
    """Gate 3 receives the record's bounded redacted evidence — including
    when the parsed tool output itself carried a credential."""
    from secret_fixtures import aws_access_key

    seen = []
    _shell_parser(monkeypatch,
                  text=f"root shell {aws_access_key()} target-corp.com")
    graph = _graph()
    sub, audit = _exploit(
        tmp_path, graph, FakeSandbox(CONFIRMED),
        approver=lambda ev: seen.append(ev) or False)
    sub.run()

    assert len(seen) == 1
    gate_text = seen[0]
    assert aws_access_key() not in gate_text     # reviewer sees redacted text
    assert "root shell" in gate_text             # ...and the real capability
    assert "target-corp.com" in gate_text
    # non-approving default kept the engagement out of POST_EXPLOIT
    gate = [e for e in _events(audit) if e["event"] == "post_exploit_gate"][0]
    assert gate["approved"] is False
    assert "post_exploit_gate" in _event_names(audit)


def test_explicit_approval_moves_the_record_to_approved(
        tmp_path, monkeypatch):
    _shell_parser(monkeypatch)
    graph = _graph()
    sub, audit = _exploit(tmp_path, graph, FakeSandbox(CONFIRMED),
                          approver=lambda ev: True)
    result = sub.run()

    assert result.shell_obtained is True
    assert result.post_exploit_approved is True
    assert next_state("EXPLOIT", result) == "POST_EXPLOIT"
    node = graph.by_type("capability")[0]
    assert node["properties"]["status"] == "approved"
    decided = [e for e in _events(audit)
               if e["event"] == "capability_decision"]
    assert decided[0]["decision"] == "approved"   # audited explicitly
    ok, reason = audit.verify()
    assert ok, reason


def test_reviewer_failure_is_a_denial_and_is_audited(tmp_path, monkeypatch):
    """An exception in the approver flow must never approve: deny, mark
    the records rejected, audit the gate failure."""
    _shell_parser(monkeypatch)
    graph = _graph()
    sub, audit = _exploit(
        tmp_path, graph, FakeSandbox(CONFIRMED),
        approver=lambda ev: (_ for _ in ()).throw(RuntimeError("tty died")))
    result = sub.run()

    assert result.post_exploit_approved is False
    assert next_state("EXPLOIT", result) == "VERIFY"
    names = _event_names(audit)
    assert "post_exploit_gate_failed" in names
    assert [e["decision"] for e in _events(audit)
            if e["event"] == "capability_decision"] == ["rejected"]
    ok, reason = audit.verify()
    assert ok, reason


def test_malformed_claimed_records_are_excluded_from_the_gate(tmp_path):
    """One malformed + one valid claimed record: only the valid one
    gates; the malformed is audited and can never decide anything."""
    graph = EngagementGraph(engagement_id="e-cap")
    _add_record(graph, status="claimed")
    graph.add_node("capability", "capability:H9:simple-shell", {
        "capability": "shell", "tool": "sqlmap", "attempt_id": "",
        "attempt_label": "H9:simple-shell", "hypothesis_id": "H9",
        "target_host": "target-corp.com", "status": "claimed",
        "evidence": "forged by whoever wrote the report",
    })
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_g.jsonl")
    from kryonsec.purple.exploit import ExploitSubagent as _ES
    sub = _ES(cfg, graph, audit, "target-corp.com",
              FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                      error="x")))
    records, invalid = sub._claimed_capability_records()
    assert invalid == 1
    assert len(records) == 1
    assert records[0][1].attempt_label == "H1:sqlmap"
    assert "post_exploit_gate_invalid_record" in _event_names(audit)


def test_gate_with_only_forged_records_fails_closed(tmp_path, monkeypatch):
    """Detection claims True, every claimed record malformed -> no gate
    call, no approval, no POST_EXPLOIT, audited."""
    _shell_parser(monkeypatch)
    graph = _graph()
    sub, audit = _exploit(tmp_path, graph, FakeSandbox(CONFIRMED),
                          approver=lambda ev: True)
    with patch.object(sub, "_detect_shell", return_value=True):
        graph.add_node("capability", "capability:H9:simple-shell", {
            "capability": "shell",
        })
        result = sub.run()

    assert result.post_exploit_approved is False
    assert next_state("EXPLOIT", result) == "VERIFY"
    names = _event_names(audit)
    assert "post_exploit_gate_without_evidence" in names
    assert "post_exploit_gate" not in names


# ---- shell detection under sandbox failure ----------------------------------

def test_sandbox_failure_never_yields_a_claim(tmp_path, monkeypatch):
    """ok=False (docker down, unreachable image) is ATTEMPT_NOT-RUN: no
    parser runs, no claim, no gate — verified fail-closed."""
    _shell_parser(monkeypatch)
    graph = _graph()
    sandbox = FakeSandbox(SpawnResult(
        ok=False, exit_code=-1, stdout="", error="docker daemon down"))
    sub, audit = _exploit(tmp_path, graph, sandbox, approver=lambda ev: True)
    result = sub.run()

    assert result.shell_obtained is False
    assert graph.by_type("capability") == []
    assert attempt_outcome(graph.by_type("exploit_attempt")[0]) == "not-run"
    assert "post_exploit_gate" not in _event_names(audit)
    assert sandbox.spawned  # the run was attempted in the sandbox, not skipped


def test_unavailable_or_mismatched_sandbox_image_fails_closed(
        tmp_path, monkeypatch):
    """A spawn refusal (missing/mismatched image) records the refusal and
    can never be read as a capability — and no second, host-side attempt
    exists to fall back to."""
    _shell_parser(monkeypatch)
    graph = _graph()
    sandbox = FakeSandbox(SpawnResult(
        ok=False, exit_code=-1, stdout="", error="image digest mismatch"))
    sub, audit = _exploit(tmp_path, graph, sandbox, approver=lambda ev: True)
    result = sub.run()

    assert result.shell_obtained is False
    assert graph.by_type("capability") == []
    assert len(sandbox.spawned) == 1          # exactly one sandbox attempt —
    assert next_state("EXPLOIT", result) == "VERIFY"   # no host-side retry


def test_the_handoff_itself_never_executes_anything(tmp_path, monkeypatch):
    """Detection + gate + record lifecycle are pure graph/audit steps:
    the FakeSandbox spawn count equals the planned tool runs, before and
    after the capability evidence engages."""
    _shell_parser(monkeypatch)
    graph = _graph()
    sandbox = FakeSandbox(CONFIRMED)
    sub, audit = _exploit(tmp_path, graph, sandbox, approver=lambda ev: True)
    sub.run()

    assert len(sandbox.spawned) == 1  # the single planned sqlmap run
    assert graph.by_type("capability")[0]["properties"]["status"] == "approved"


# ---- detection is idempotent across runs ------------------------------------

def test_detection_writes_one_node_per_attempt(tmp_path, monkeypatch):
    _shell_parser(monkeypatch)
    graph = _graph()
    sub, audit = _exploit(tmp_path, graph, FakeSandbox(CONFIRMED),
                          approver=lambda ev: False)
    sub.run()
    with patch.object(sub, "_detect_shell",
                      wraps=sub._detect_shell) as spy:
        sub.run()
        # the second scan must not duplicate the claim node
        assert len(graph.by_type("capability")) == 1
        spy.assert_called_once()


# ---- POST_EXPLOIT consumption: fail closed ----------------------------------

def approved_record(**overrides):
    props = {
        "capability": "shell", "tool": "sqlmap",
        "attempt_id": "attempt-1", "attempt_label": "H1:sqlmap",
        "hypothesis_id": "H1", "target_host": "target-corp.com",
        "finding_id": "H1", "status": "approved",
        "verification": "verified",  # Phase 1C: eligible ⇔ both
        # Phase 6A: bound to the test graphs' engagement ("e-pe") and
        # stamped fresh — eligibility refuses unbound or expired records
        "engagement_id": "e-pe",
        "recorded_at": utc_now_iso(),
        "evidence": "os-shell session established",
        "recorded_by": "EXPLOIT_PROGRAM",
    }
    props.update(overrides)
    return props


class PostSandbox:
    """Replays one result per spawn, remembering what ran."""
    def __init__(self, results):
        self.results = list(results)
        self.spawned = []

    def spawn(self, argv):
        self.spawned.append(argv)
        r = self.results.pop(0) if self.results else \
            SpawnResult(ok=True, exit_code=0, stdout='{"probe": "enum"}')
        return r


def test_post_exploit_refuses_unapproved_records(tmp_path):
    """claimed / rejected records never run the plan — audited, failed."""
    for status in ("claimed", "rejected"):
        graph = EngagementGraph(engagement_id="e-pe")
        _add_record(graph, status=status)
        sandbox = PostSandbox([])
        cfg = KryonsecConfig(home=tmp_path)
        audit = AuditLog(tmp_path / f"audit_pe_{status}.jsonl")
        sub = PostExploitSubagent(
            cfg=cfg, graph=graph, audit=audit, target="target-corp.com",
            sandbox=sandbox)
        result = sub.run()

        assert result.status == "failed"
        assert sandbox.spawned == []
        refused = [e for e in _events(audit)
                   if e["event"] == "post_exploit_capability_refused"]
        assert refused and refused[0]["record_status"] == status
        assert "tool_spawn" not in _event_names(audit)


def test_post_exploit_refuses_malformed_records(tmp_path):
    graph = EngagementGraph(engagement_id="e-pe")
    graph.add_node("capability", "capability:H1:sqlmap", {
        "capability": "shell",  # missing everything else
    })
    sandbox = PostSandbox([])
    sub, audit = _post_exploit(tmp_path, graph, sandbox)
    result = sub.run()

    assert result.status == "failed"
    assert sandbox.spawned == []
    refused = [e for e in _events(audit)
               if e["event"] == "post_exploit_capability_refused"]
    assert refused and refused[0]["reason"] == "malformed capability record"
    ok, reason = audit.verify()
    assert ok, reason


def test_post_exploit_refuses_out_of_scope_capability_hosts(tmp_path):
    """An approved record pointing at another host is refused — the
    capability is not portable out of engagement scope."""
    graph = EngagementGraph(engagement_id="e-pe")
    _add_record(graph, target_host="other-host.example.net")
    sandbox = PostSandbox([])
    sub, audit = _post_exploit(tmp_path, graph, sandbox)
    result = sub.run()

    assert result.status == "failed"
    assert sandbox.spawned == []
    refused = [e for e in _events(audit)
               if e["event"] == "post_exploit_capability_refused"]
    assert refused and "scope" in refused[0]["reason"]


def test_approval_without_independent_verification_fails_closed(tmp_path):
    """Phase 1C: Gate 3 approval of a claimed capability must never make
    it executable — the record's independent verification is still
    not_run, so the state fails closed."""
    graph = EngagementGraph(engagement_id="e-pe")
    _add_record(graph)  # status approved
    sandbox = PostSandbox([])
    graph.by_type("capability")[0]["properties"]["verification"] = "not_run"
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_pe_gate.jsonl")
    sub = PostExploitSubagent(cfg=cfg, graph=graph, audit=audit,
                              target="target-corp.com", sandbox=sandbox)
    result = sub.run()

    assert result.status == "failed"
    assert sandbox.spawned == []      # nothing ran: approval ≠ eligibility
    refused = [e for e in _events(audit)
               if e["event"] == "post_exploit_capability_refused"]
    assert refused and "independently verified" in refused[0]["reason"]


def test_verification_without_approval_fails_closed(tmp_path):
    """The inverse leg of Phase 1C eligibility: independently verified
    evidence but no human approval (status claimed) -> refused."""
    graph = EngagementGraph(engagement_id="e-pe")
    graph.add_node(
        "capability", "capability:H1:sqlmap", approved_record(
            status="claimed", verification="verified"),
        provenance={"agent": "EXPLOIT", "source_type": "tool"})
    sandbox = PostSandbox([])
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit_pe_ver.jsonl")
    sub = PostExploitSubagent(cfg=cfg, graph=graph, audit=audit,
                              target="target-corp.com", sandbox=sandbox)
    result = sub.run()

    assert result.status == "failed"
    assert sandbox.spawned == []
    refused = [e for e in _events(audit)
               if e["event"] == "post_exploit_capability_refused"]
    assert refused and refused[0]["reason"] == "capability record is not approved"


def test_host_in_scope_matches_target_and_subdomains_only():
    assert host_in_scope("target-corp.com", "target-corp.com")
    assert host_in_scope("webmail.target-corp.com", "target-corp.com")
    assert host_in_scope("TARGET-CORP.COM.", "target-corp.com")
    assert not host_in_scope("target-corp.com.evil.org", "target-corp.com")
    assert not host_in_scope("target-corp.org", "target-corp.com")
    assert not host_in_scope("", "target-corp.com")
    assert not host_in_scope("target-corp.com", "")


def _add_record(graph, **overrides):
    props = approved_record(**overrides)
    graph.add_node("capability", f"capability:{props['attempt_label']}",
                   props, provenance={"agent": "EXPLOIT", "source_type": "tool"})


# ---- the full orchestrator transition, end to end, fake sandbox -------------

def test_end_to_end_transition_via_fake_sandbox(tmp_path, monkeypatch):
    """CONFIRMED attempt -> registry claim -> Gate 3 approve -> exact
    orchestrator routing to POST_EXPLOIT -> the subagent consumes the
    approved record and runs the plan in the (fake) sandbox -> VERIFY."""
    _shell_parser(monkeypatch)
    exploit_graph = _graph()
    exploit_sub, audit = _exploit(
        tmp_path, exploit_graph, FakeSandbox(CONFIRMED),
        approver=lambda ev: True)
    exploit_result = exploit_sub.run()

    # the orchestrator routes only on the reported, approved evidence
    assert next_state("EXPLOIT", exploit_result) == "POST_EXPLOIT"

    # Phase 1C: approval alone is never eligibility. The claimed evidence
    # must ALSO be independently verified before anything runs. No
    # capability-verification routine exists yet, so this step stands in
    # for that future verifier: the gate never touched this field.
    node = exploit_graph.by_type("capability")[0]
    assert node["properties"]["verification"] == "not_run"
    node["properties"]["verification"] = "verified"

    pe_sandbox = PostSandbox([])
    pe_sub, pe_audit = _post_exploit(
        tmp_path, exploit_graph, pe_sandbox)
    pe_result = pe_sub.run()

    assert pe_result.status == "ok"
    assert len(pe_sandbox.spawned) > 0
    # the enum scripts ran inside the (fake) sandbox, host-free
    assert any(argv[0].startswith("/opt/kryonsec/enum_")
               for argv in pe_sandbox.spawned)
    names = _event_names(pe_audit)
    assert "post_exploit_capability_refused" not in names
    assert "post_exploit_missing_capability" not in names
    assert "post_exploit_done" in names
    # POST_EXPLOIT itself never transitions anywhere new
    assert next_state("POST_EXPLOIT", pe_result) == "VERIFY"
    ok, reason = pe_audit.verify()
    assert ok, reason
