"""Batch 5B: the finding-verification contract registry.

What these tests lock down:
- one category, one registered method — the boolean probe is evidence
  for SQL injection and for nothing else;
- unsupported categories are honestly ``not_run`` with the real reason
  and are never probed with a method that would not be evidence for
  them (the false-positive fix);
- the contract's identity, budget and confidence limit travel with
  every attempt record;
- the verification tool must differ from the finding's own tool;
- only the registered method, on its own execution evidence, promotes
  a finding — banners, wording and exit codes never do.
"""

import json

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.exploit_contract import CATEGORY_UNKNOWN
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.verify import VerifySubagent, _boolean_probe_urls
from kryonsec.purple.verify_contract import (
    IMPLEMENTED_METHOD_TYPES,
    METHOD_BOOLEAN_CURL,
    SQLI_BOOLEAN_CONTRACT,
    VERIFY_APPROVAL_BASIS,
    VERIFY_STAGE,
    VerificationContract,
    finding_category,
    register_finding_contract,
    verification_contract_for,
)
from kryonsec.purple.views import (
    VERIFICATION_NOT_RUN,
    finding_verification_status,
    verification_status,
)


def _events(audit):
    return [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8")
            if l.strip()]


def _entries(audit):
    return [json.loads(l) for l in open(audit.path, encoding="utf-8")
            if l.strip()]


def _is_probe(url):
    return "1%3D1" in url or "1%3D2" in url


def _finding_graph(tool="sqlmap", asset="/showthread.asp?id=1"):
    graph = EngagementGraph(engagement_id="e-v")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi on thread", "target_asset": asset,
        "rationale": "evidence", "cvss_vector": "",
        "tools": [tool], "confidence": 0.8, "approved": True,
    })
    graph.add_node("exploit_attempt", f"H1:{tool}", {
        "tool": tool, "ok": True, "exit_code": 0, "confirmed": True,
        "argv": [tool], "output_excerpt": "is vulnerable",
    })
    graph.add_node("finding", "H1", {
        "tool": tool, "confirmed_by": f"sandbox {tool} output",
        "excerpt": "is vulnerable",
    })
    return graph


class DiffSandbox:
    """true == baseline, false differs: the vulnerable signature."""

    def __init__(self):
        self.calls = []

    def spawn(self, argv):
        url = argv[-1]
        self.calls.append(url)
        if not _is_probe(url):
            return SpawnResult(ok=True, exit_code=0, stdout="full page")
        is_true = "1%3D1" in url or "+AND+1%3D1" in url
        return SpawnResult(
            ok=True, exit_code=0,
            stdout="full page" if is_true else "empty result")


# ---- the registry ---------------------------------------------------------

def test_the_sqli_boolean_probe_is_registered():
    """The one method this project had is now a contract, scoped to the
    category it is evidence for."""
    contract = verification_contract_for("sqli")
    assert contract is SQLI_BOOLEAN_CONTRACT
    assert contract.method_type == METHOD_BOOLEAN_CURL
    assert contract.tool == "curl"          # independent of sqlmap
    assert contract.stage == VERIFY_STAGE
    assert contract.approval == VERIFY_APPROVAL_BASIS
    assert contract.max_probes == 3         # true + false + baseline
    assert contract.max_probe_seconds == 30
    assert any("numeric query parameter" in p for p in contract.prerequisites)
    assert contract.expected_observation.strip()
    assert contract.contradictory_observation.strip()
    assert contract.confidence_limit.strip()


def test_the_registry_starts_with_exactly_one_contract():
    """One registered method in production. Everything else is
    unsupported — and unsupported means honest, not borrowed."""
    assert IMPLEMENTED_METHOD_TYPES == frozenset({METHOD_BOOLEAN_CURL})
    assert list(verification_contract_for(c) is not None
                for c in ("sqli",)).count(True) == 1
    assert verification_contract_for("xss") is None
    assert verification_contract_for("command_injection") is None
    assert verification_contract_for("template_scan") is None
    assert verification_contract_for("web_scan") is None
    assert verification_contract_for(CATEGORY_UNKNOWN) is None


def test_registration_rejects_an_unimplemented_method_type():
    """A contract for a method nobody executes must never sit in the
    registry looking verified-able."""
    bad = VerificationContract(
        category="xss", method="banner grep", method_type="llm_vibes",
        tool="curl", prerequisites=("p",), max_probes=2,
        max_probe_seconds=30, expected_observation="e",
        contradictory_observation="c", confidence_limit="l")
    with pytest.raises(ValueError):
        register_finding_contract(bad)
    assert verification_contract_for("xss") is None


def test_registration_rejects_duplicate_category():
    with pytest.raises(ValueError):
        register_finding_contract(SQLI_BOOLEAN_CONTRACT)


def test_registration_rejects_unknown_and_never_verifiable_categories():
    base = dict(method="m", method_type=METHOD_BOOLEAN_CURL, tool="curl",
                prerequisites=("p",), max_probes=2, max_probe_seconds=30,
                expected_observation="e", contradictory_observation="c",
                confidence_limit="l")
    # a category no tool produces is dead configuration
    with pytest.raises(ValueError):
        register_finding_contract(
            VerificationContract(category="telepathy", **base))
    # 'unknown' can never be independently verified — a contract for it
    # would be a lie about coverage
    with pytest.raises(ValueError):
        register_finding_contract(
            VerificationContract(category=CATEGORY_UNKNOWN, **base))


def test_registration_rejects_wrong_stage_and_bad_bounds():
    def contract_with(**over):
        base = dict(
            category="sqli", method="m", method_type=METHOD_BOOLEAN_CURL,
            tool="curl", prerequisites=("p",), max_probes=3,
            max_probe_seconds=30, expected_observation="e",
            contradictory_observation="c", confidence_limit="l")
        base.update(over)
        return VerificationContract(**base)

    with pytest.raises(ValueError):
        register_finding_contract(contract_with(stage="EXPLOIT"))
    with pytest.raises(ValueError):
        register_finding_contract(contract_with(max_probes=1))
    with pytest.raises(ValueError):
        register_finding_contract(contract_with(max_probe_seconds=601))
    with pytest.raises(ValueError):
        register_finding_contract(contract_with(confidence_limit=""))
    with pytest.raises(ValueError):
        register_finding_contract(contract_with(expected_observation=""))
    with pytest.raises(ValueError):
        register_finding_contract(contract_with(prerequisites=()))


# ---- category derivation -----------------------------------------------------

@pytest.mark.parametrize("tool,category", [
    ("sqlmap", "sqli"),
    ("nikto", "web_scan"),
    ("dalfox", "xss"),
    ("", CATEGORY_UNKNOWN),
])
def test_finding_category_comes_from_the_producing_tool(tool, category):
    assert finding_category({"properties": {"tool": tool}}) == category
    assert finding_category({"properties": {}}) == CATEGORY_UNKNOWN


# ---- the contract path (sqli) ----------------------------------------------

def test_verified_attempt_carries_the_contract(tmp_path):
    """The attempt record names the contract it ran under: identity,
    budget, and what the method cannot establish."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    VerifySubagent(cfg, graph, audit, "target-corp.com", DiffSandbox()).run()

    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["category"] == "sqli"
    assert props["contract"]["category"] == "sqli"
    assert props["contract"]["method"] == "curl boolean probe"
    assert props["contract"]["tool"] == "curl"
    assert props["contract"]["stage"] == VERIFY_STAGE
    assert props["contract"]["max_probe_seconds"] == 30
    assert props["confidence_limit"] == SQLI_BOOLEAN_CONTRACT.confidence_limit
    assert finding_verification_status("H1", graph) == "verified"


def test_contract_budget_rides_the_fixed_argv(tmp_path):
    """The budget is enforced in the fixed argv (curl --max-time), the
    same fixed-template enforcement EXPLOIT uses."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()
    sandbox = DiffSandbox()

    VerifySubagent(cfg, graph, audit, "target-corp.com", sandbox).run()

    assert sandbox.calls  # probed at all
    for url in sandbox.calls:
        pass  # argv checked below via the audit entries
    spawns = [e for e in _entries(audit) if e["event"] == "tool_spawn"
              and e.get("state") == "VERIFY"]
    assert spawns
    for s in spawns:
        assert s["argv"][:4] == ["curl", "-sS", "--max-time", "30"]


def test_independence_refuses_the_findings_own_tool(tmp_path):
    """Re-running the finding's own tool is a repeat, not an independent
    check — refused, honestly not_run.

    The refusal is reachable when a registered contract's tool can
    produce findings in its own category: here a boolean-curl contract
    for the ``fetch`` category (curl IS a fetch tool), verified against
    a curl-produced finding. Registered temporarily, popped after."""
    from kryonsec.purple.verify_contract import FINDING_VERIFICATION_CONTRACTS

    contract = VerificationContract(
        category="fetch", method="curl boolean probe",
        method_type=METHOD_BOOLEAN_CURL, tool="curl",
        prerequisites=("in-scope URL",), max_probes=3,
        max_probe_seconds=30, expected_observation="responses differ",
        contradictory_observation="responses agree",
        confidence_limit="reachability only")
    try:
        register_finding_contract(contract)
        assert verification_contract_for("fetch") is contract

        cfg = KryonsecConfig(home=tmp_path)
        audit = AuditLog(tmp_path / "audit.jsonl")
        graph = _finding_graph(tool="curl")

        class NeverSpawn:
            def spawn(self, argv):  # pragma: no cover — must never happen
                raise AssertionError("spawn attempted")

        VerifySubagent(cfg, graph, audit, "target-corp.com",
                       NeverSpawn()).run()

        props = graph.by_type("verify_attempt")[0]["properties"]
        assert verification_status(graph.by_type("verify_attempt")[0]) \
            == VERIFICATION_NOT_RUN
        assert "not independent" in props["reason"]
        assert graph.by_type("finding")[0]["properties"].get("verified") \
            is not True
    finally:
        FINDING_VERIFICATION_CONTRACTS.pop("fetch", None)


# ---- unsupported categories (the false-positive fix) ------------------------

def test_non_sqli_finding_is_never_boolean_probed(tmp_path):
    """THE fix: a web_scan finding on a URL WITH a numeric parameter used
    to be probed with the boolean-SQL method — evidence for a category
    it does not belong to. Now: unsupported category, honest not_run,
    reachability evidence only, and never a curl boolean probe."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph(tool="nikto", asset="/scanner.php?id=1")

    class ProbeSandbox:
        def __init__(self):
            self.spawned = []

        def spawn(self, argv):
            self.spawned.append(argv)
            return SpawnResult(ok=True, exit_code=0, stdout="x")

    sandbox = ProbeSandbox()
    VerifySubagent(cfg, graph, audit, "target-corp.com", sandbox).run()

    tools = [argv[0] for argv in sandbox.spawned]
    assert "curl" not in tools          # the boolean probe never ran
    assert "http" in tools and "nc" in tools and "dig" in tools

    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["category"] == "web_scan"
    assert props["reason"] == (
        "no verification contract for category 'web_scan'")
    assert verification_status(graph.by_type("verify_attempt")[0]) \
        == VERIFICATION_NOT_RUN
    assert graph.by_type("finding")[0]["properties"].get("verified") \
        is not True
    # and the skip is audited with the real reason
    skipped = [e for e in _entries(audit) if e["event"] == "verify_skipped"]
    assert skipped and "no verification contract" in skipped[0]["reason"]


def test_an_xss_finding_with_numeric_param_is_not_sqli_verified(tmp_path):
    """dalfox on ?id=1: the numeric parameter is exactly what made the
    old hardcoded path mis-verify it. It must stay unverified."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph(tool="dalfox", asset="/comment.php?id=1")

    class AgreesWithAnything:
        def spawn(self, argv):
            if _is_probe(argv[-1]):
                is_true = "1%3D1" in argv[-1]
                return SpawnResult(ok=True, exit_code=0,
                                   stdout="page" if is_true else "other")
            return SpawnResult(ok=True, exit_code=0, stdout="page")

    VerifySubagent(cfg, graph, audit, "target-corp.com",
                   AgreesWithAnything()).run()

    # even though the sandbox would have "confirmed" a boolean probe,
    # no probe ran and the finding is not verified
    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["category"] == "xss"
    assert props["status"] == VERIFICATION_NOT_RUN
    assert graph.by_type("finding")[0]["properties"].get("verified") \
        is not True


def test_toolless_finding_reads_unknown_and_never_verifies(tmp_path):
    """A finding without a tool is category unknown — which no contract
    can ever cover, by registration rule. It still gets honest
    reachability evidence (secondary probes), never a category probe,
    and never a verified word."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()
    graph.by_type("finding")[0]["properties"].pop("tool")

    class ReachableOnly:
        def __init__(self):
            self.spawned = []

        def spawn(self, argv):
            self.spawned.append(argv)
            return SpawnResult(ok=True, exit_code=0, stdout="up")

    sandbox = ReachableOnly()
    VerifySubagent(cfg, graph, audit, "target-corp.com", sandbox).run()

    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["category"] == CATEGORY_UNKNOWN
    assert "no verification contract" in props["reason"]
    # reachability evidence, but no boolean probe and no promotion
    assert sandbox.spawned
    assert not any(_is_probe(argv[-1]) for argv in sandbox.spawned)
    assert verification_status(graph.by_type("verify_attempt")[0]) \
        == VERIFICATION_NOT_RUN
    assert graph.by_type("finding")[0]["properties"].get("verified") \
        is not True


# ---- promotion integrity ------------------------------------------------------

def test_a_stored_verified_word_alone_never_promotes(tmp_path):
    """Only the contract executor's execution evidence promotes: a
    verify_attempt whose ``verified`` word has no probe responses behind
    it reads not_run, and the finding stays unpromoted."""
    graph = _finding_graph()
    graph.add_node("verify_attempt", "H1", {
        "verified": True, "method": "curl boolean probe",
        "status": "verified",
    })
    assert finding_verification_status("H1", graph) == VERIFICATION_NOT_RUN


def test_exit_codes_and_banners_cannot_promote(tmp_path):
    """The verdict compares RESPONSES, not words: a true page that
    shouts 'vulnerable' still fails verification when the responses
    agree — wording is data, not evidence."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class ShoutySandbox:
        def spawn(self, argv):
            page = ("VULNERABLE!!! verified by scanner banner "
                    "exit code 0 - definitely exploitable")
            return SpawnResult(ok=True, exit_code=0, stdout=page)

    VerifySubagent(cfg, graph, audit, "target-corp.com", ShoutySandbox()).run()

    props = graph.by_type("verify_attempt")[0]["properties"]
    assert props["verified"] is False
    assert graph.by_type("finding")[0]["properties"].get("verified") \
        is not True


def test_verification_plan_names_the_registered_contracts(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()
    VerifySubagent(cfg, graph, audit, "target-corp.com", DiffSandbox()).run()
    plan = next(e for e in _entries(audit) if e["event"] == "verify_plan")
    assert plan["contracts"] == ["sqli"]
