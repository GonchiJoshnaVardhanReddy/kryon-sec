"""Tests for BLUE_TEAM + REPORT subagents (spec §4.2, §4.9)."""

import json

import pytest
from pydantic import ValidationError

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.blue_team import (
    BlueTeamSubagent,
    Remediation,
    RemediationSet,
    generate_remediations,
    render_blue_team_prompt,
)
from kryonsec.purple.orchestrator import BudgetTracker
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.report import (
    ReportSubagent,
    redact_secrets,
    render_report,
    validate_report,
)
from secret_fixtures import aws_access_key, github_token


def _graph(target="target-corp.com"):
    graph = EngagementGraph(engagement_id="e-bt")
    graph.add_node("target", target, {})
    graph.add_node("subdomain", "www." + target, {"source": "crt.sh"})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi on login",
        "target_asset": target,
        "rationale": "evidence",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tools": ["sqlmap"],
        "confidence": 0.8,
        "approved": True,
    })
    graph.add_node("hypothesis", "H2", {
        "title": "XSS on search",
        "target_asset": target,
        "rationale": "evidence",
        "cvss_vector": "",
        "tools": ["ffuf"],
        "confidence": 0.6,
        "approved": False,
    })
    return graph


# ---- BLUE_TEAM ----------------------------------------------------------

def test_blue_team_prompt_contains_hypotheses_and_decisions():
    prompt = render_blue_team_prompt(_graph())
    assert "H1" in prompt and "H2" in prompt
    assert "SQLi on login" in prompt
    assert "approved by operator: True" in prompt
    assert "approved by operator: False" in prompt


def test_blue_team_success(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()

    def llm(prompt):
        assert "H1" in prompt
        return RemediationSet(remediations=[
            Remediation(hypothesis_id="H1", title="Parameterize queries",
                        fix="Use prepared statements", detection="WAF rule X",
                        severity="critical"),
            Remediation(hypothesis_id="H2", title="Escape output",
                        fix="Context-aware encoding", severity="medium"),
        ])

    sub = BlueTeamSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=llm)
    result = sub.run()

    assert result.status == "ok"
    nodes = graph.by_type("remediation")
    assert len(nodes) == 2
    assert nodes[0]["properties"]["severity"] == "critical"

    events = [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "blue_team_done" in events
    assert events.count("remediation_proposed") == 2
    ok, reason = audit.verify()
    assert ok, reason


def test_blue_team_llm_failure(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()

    def dead(prompt):
        raise RuntimeError("no provider")

    sub = BlueTeamSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=dead)
    result = sub.run()

    assert result.status == "failed"
    assert graph.by_type("remediation") == []


def test_remediation_set_caps_at_20():
    items = [Remediation(hypothesis_id=f"H{i}", title="t", fix="f")
             for i in range(21)]
    with pytest.raises(ValidationError):
        RemediationSet(remediations=items)


def test_generate_remediations_gates_secrets(monkeypatch, tmp_path):
    """v1.1.1 leak: the instructor path called the hosted provider
    directly, so an exploit excerpt containing a secret bypassed chat()'s
    gate. With no local model up the prompt must go out redacted."""
    import builtins
    import sys

    cfg = KryonsecConfig(home=tmp_path)
    cfg.general_search_model = "gpt-4o-mini"
    cfg.openai_api_key = "sk-test"

    monkeypatch.setitem(sys.modules, "instructor", None)
    real_import = builtins.__import__

    def no_instructor(name, *args, **kwargs):
        if name == "instructor":
            raise ImportError("forced for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_instructor)
    monkeypatch.setattr("kryonsec.llm._ollama_model_ok", lambda c, m: False)

    captured = {}

    def fake_chat(cfg, messages, model, **kw):
        captured["messages"] = messages
        return ('{"remediations": [{"hypothesis_id": "H1", '
                '"title": "t", "fix": "f"}]}')

    monkeypatch.setattr("kryonsec.llm.chat", fake_chat)

    result = generate_remediations(
        cfg, "finding excerpt: the response leaked password=hunter2secret")
    assert result.remediations[0].hypothesis_id == "H1"
    sent = json.dumps(captured["messages"], ensure_ascii=False)
    assert "hunter2secret" not in sent
    assert "password=" in sent


def test_blue_team_records_budget_usage(tmp_path):
    """LLM states accrue usage so the budget guard can trip (spec §4.3)."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    budget = BudgetTracker(max_tokens=10)

    def llm(prompt):
        return RemediationSet(remediations=[
            Remediation(hypothesis_id="H1", title="t", fix="f")])

    sub = BlueTeamSubagent(cfg=cfg, graph=graph, audit=audit,
                           llm_fn=llm, budget=budget)
    assert sub.run().status == "ok"
    assert budget.used_tokens > 0
    assert budget.exhausted()


# ---- BLUE_TEAM static scanners (tool expansion Phase 5) ------------------

class _SpawnResult:
    def __init__(self, ok=True, exit_code=0, stdout=""):
        self.ok = ok
        self.exit_code = exit_code
        self.stdout = stdout


class _FakeSandbox:
    """Records argvs; answers from a {tool -> result} script."""

    def __init__(self, script):
        self.script = script
        self.argvs = []

    def spawn(self, argv):
        self.argvs.append(list(argv))
        # unscripted tools "fail" — keeps `ran` counts honest per test
        return self.script.get(argv[0],
                               _SpawnResult(ok=False, exit_code=-1))


def _events(audit):
    return [json.loads(l)["event"]
            for l in open(audit.path, encoding="utf-8") if l.strip()]


@pytest.mark.parametrize("tool,stdout,expected", [
    # JSON shapes first (trivy/checkov print JSON when configured)
    ("trivy", '{"Results": [{"Vulnerabilities": [{"a": 1}, {"b": 2}]}, '
              '{"Vulnerabilities": []}, {"Vulnerabilities": [{"c": 3}]}]}', 3),
    ("checkov", '{"failed_checks": [{"x": 1}, {"x": 2}]}', 2),
    # Phase 8 dependency scanners (JSON by flag). syft is NOT here: an SBOM
    # is a package inventory, not findings (M14) — see _count_packages.
    ("osv-scanner", '{"results": [{"packages": [{"vulnerabilities": ["a", "b"]}, '
                    '{"vulnerabilities": ["c"]}]}, {"packages": []}]}', 3),
    ("grype", '{"matches": [{"m": 1}, {"m": 2}]}', 2),
    # text shapes
    ("semgrep", "scanned 120 files\n42 findings", 42),
    ("bandit", "Issue: [B101]\nIssue: [B102]\nIssue: [B301]", 3),
    ("gitleaks", "Finding: aws-key\nFinding: github-pat", 2),
    ("trivy", "Total: 7 (HIGH: 3)", 7),
    ("checkov", "Passed checks: 12, Failed checks: 4", 4),
    ("hadolint", "/code/Dockerfile:3 DL3008\n/code/Dockerfile:9 DL3045", 2),
    # unknown shape -> None, never a guess
    ("semgrep", "nothing recognizable here", None),
    ("made-up-tool", "whatever", None),
])
def test_count_findings(tool, stdout, expected):
    from kryonsec.purple.blue_team import _count_findings
    assert _count_findings(tool, stdout) == expected


def test_count_packages_syft_sbom():
    """M14: the syft package count is an inventory, kept out of the
    findings count (which must stay None for an SBOM)."""
    from kryonsec.purple.blue_team import _count_findings, _count_packages

    sbom = '{"artifacts": [{"name": "flask"}, {"name": "django"}, {"name": "requests"}]}'
    assert _count_packages(sbom) == 3
    assert _count_findings("syft", sbom) is None
    assert _count_packages("not json") is None


def test_scan_plan_argv_shapes_validate():
    """The fixed plan must validate against the SHIPPED allowlist — if the
    templates and the plan drift apart, every spawn is rejected at runtime."""
    from kryonsec.purple.allowlist import ToolAllowlist
    from kryonsec.purple.blue_team import (
        BLUE_TEAM_SCAN_PLAN,
        HADOLINT_PLAN_ENTRY,
    )

    allow = ToolAllowlist()
    for tool, argv in BLUE_TEAM_SCAN_PLAN + [HADOLINT_PLAN_ENTRY]:
        allow.validate(argv[0], argv)
        allow.check_blocklist(argv)


def test_run_code_scanners_full_run(tmp_path):
    from kryonsec.purple.blue_team import run_code_scanners

    graph = _graph()
    audit = AuditLog(tmp_path / "audit.jsonl")
    sandbox = _FakeSandbox({
        "semgrep": _SpawnResult(stdout="12 findings in /code/app.py"),
        "bandit": _SpawnResult(exit_code=1, stdout="Issue: [B101] hardcoded"),
        "gitleaks": _SpawnResult(stdout="no leaks found"),
        "trivy": _SpawnResult(stdout='{"Results": [{"Vulnerabilities": [{}]}]}'),
        "checkov": _SpawnResult(stdout="Passed checks: 2, Failed checks: 5"),
        "hadolint": _SpawnResult(stdout="/code/Dockerfile:3 DL3008"),
        # Phase 8 SBOM/dependency scanners
        "syft": _SpawnResult(
            stdout='{"artifacts": [{"name": "flask"}, {"name": "requests"}]}'),
        "osv-scanner": _SpawnResult(stdout='{"results": []}'),
        "grype": _SpawnResult(stdout='{"matches": [{"v": {}}, {"v": {}}]}'),
    })

    ran = run_code_scanners(graph, sandbox, audit, has_dockerfile=True)
    assert ran == 9
    assert len(sandbox.argvs) == 9
    # every scanner reads the fixed /code mount, never the host path
    # (grype spells it dir:/code — same fixed literal, prefix notation)
    assert all(
        any(a == "/code" or a == "dir:/code"
            or a.startswith("/code/") or a.startswith("dir:/code/")
            for a in argv)
        for argv in sandbox.argvs)

    nodes = {n["label"]: n["properties"] for n in graph.by_type("scanner_result")}
    assert set(nodes) == {"semgrep", "bandit", "gitleaks", "trivy",
                          "checkov", "hadolint", "syft", "osv-scanner",
                          "grype"}
    assert nodes["semgrep"]["findings_count"] == 12
    assert nodes["trivy"]["findings_count"] == 1
    assert nodes["checkov"]["findings_count"] == 5
    assert nodes["gitleaks"]["excerpt"] == "no leaks found"
    # Phase 8 counters: grype counts matches; syft is an SBOM — its package
    # count is an inventory (packages_count), never a findings_count (M14)
    assert "findings_count" not in nodes["syft"]
    assert nodes["syft"]["packages_count"] == 2
    assert nodes["grype"]["findings_count"] == 2

    events = _events(audit)
    assert events.count("tool_spawn") == 9
    assert events.count("tool_result") == 9
    assert "scanners_done" in events
    ok, reason = audit.verify()
    assert ok, reason


def test_hadolint_only_with_dockerfile(tmp_path):
    from kryonsec.purple.blue_team import run_code_scanners

    audit = AuditLog(tmp_path / "audit.jsonl")
    sandbox = _FakeSandbox({})
    run_code_scanners(_graph(), sandbox, audit, has_dockerfile=False)
    tools = [argv[0] for argv in sandbox.argvs]
    assert "hadolint" not in tools
    assert len(tools) == 8


def test_failing_scanner_is_audited_skip(tmp_path):
    """A spawn failure skips the evidence node but never kills the run."""
    from kryonsec.purple.blue_team import run_code_scanners

    graph = _graph()
    audit = AuditLog(tmp_path / "audit.jsonl")
    sandbox = _FakeSandbox({
        "bandit": _SpawnResult(ok=False, exit_code=-1, stdout=""),
        "semgrep": _SpawnResult(stdout="1 findings"),
    })

    ran = run_code_scanners(graph, sandbox, audit)
    assert ran == 1
    labels = [n["label"] for n in graph.by_type("scanner_result")]
    assert labels == ["semgrep"]
    # the failure is still on the audit trail
    results = [json.loads(l) for l in open(audit.path, encoding="utf-8")
               if l.strip()]
    bandit = next(r for r in results
                  if r["event"] == "tool_result" and r["tool"] == "bandit")
    assert bandit["ok"] is False


def test_exit_code_one_is_findings_not_failure(tmp_path):
    """bandit/gitleaks exit 1 when they FIND something — the evidence node
    is still written, with the findings count."""
    from kryonsec.purple.blue_team import run_code_scanners

    graph = _graph()
    audit = AuditLog(tmp_path / "audit.jsonl")
    sandbox = _FakeSandbox({
        "bandit": _SpawnResult(exit_code=1, stdout="Issue: [B101]\nIssue: [B102]"),
    })

    ran = run_code_scanners(graph, sandbox, audit)
    assert ran == 1
    node = graph.by_type("scanner_result")[0]
    assert node["properties"]["exit_code"] == 1
    assert node["properties"]["findings_count"] == 2


def test_scanners_fail_closed_on_empty_allowlist(tmp_path):
    from kryonsec.purple.allowlist import ToolAllowlist
    from kryonsec.purple.blue_team import run_code_scanners

    graph = _graph()
    audit = AuditLog(tmp_path / "audit.jsonl")
    sandbox = _FakeSandbox({})

    ran = run_code_scanners(graph, sandbox, audit,
                            allowlist=ToolAllowlist(templates={}))
    assert ran == 0
    assert sandbox.argvs == []  # nothing ever spawned
    assert graph.by_type("scanner_result") == []
    events = _events(audit)
    assert events.count("scanner_rejected_by_allowlist") == 8
    ok, reason = audit.verify()
    assert ok, reason


def test_prompt_renders_scanner_evidence():
    graph = _graph()
    graph.add_node("scanner_result", "bandit", {
        "tool": "bandit", "exit_code": 1, "stdout_chars": 900,
        "excerpt": "Issue: [B101] hard-coded password",
        "findings_count": 2,
    })
    prompt = render_blue_team_prompt(graph)
    assert "SCANNER EVIDENCE" in prompt
    assert "bandit: exit code 1, ~2 findings" in prompt
    assert "Issue: [B101] hard-coded password" in prompt
    # findings_count missing -> no count claim, still evidence
    graph.add_node("scanner_result", "semgrep", {
        "tool": "semgrep", "exit_code": 0, "stdout_chars": 10, "excerpt": "x",
    })
    prompt2 = render_blue_team_prompt(graph)
    assert "semgrep: exit code 0" in prompt2
    assert "semgrep: exit code 0, ~" not in prompt2


def test_remediation_mapping_fields_optional():
    r = Remediation(hypothesis_id="H1", title="t", fix="f")
    assert r.cwe == "" and r.owasp == "" and r.attack == ""
    r2 = Remediation(hypothesis_id="H1", title="t", fix="f",
                     cwe="CWE-89", owasp="A03:2021-Injection", attack="T1190")
    assert r2.cwe == "CWE-89"


def test_subagent_runs_scanners_before_llm(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    code = tmp_path / "victim"
    code.mkdir()
    (code / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    sandbox = _FakeSandbox({
        "semgrep": _SpawnResult(stdout="3 findings"),
        "bandit": _SpawnResult(stdout="Issue: [B101]"),
        "gitleaks": _SpawnResult(stdout="no leaks"),
        "trivy": _SpawnResult(stdout="Total: 0"),
        "checkov": _SpawnResult(stdout="Failed checks: 1"),
        "hadolint": _SpawnResult(stdout="/code/Dockerfile:3 DL3008"),
    })

    seen = {}

    def llm(prompt):
        seen["prompt"] = prompt
        seen["scanner_nodes"] = len(graph.by_type("scanner_result"))
        return RemediationSet(remediations=[
            Remediation(hypothesis_id="semgrep", title="t", fix="f")])

    sub = BlueTeamSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=llm,
                           sandbox=sandbox, code_folder=str(code))
    assert sub.run().status == "ok"

    # the scanner evidence existed BEFORE the LLM saw the prompt, and the
    # prompt contains it
    assert seen["scanner_nodes"] == 6  # 5 + hadolint (Dockerfile present)
    assert "bandit: exit code" in seen["prompt"]
    events = _events(audit)
    assert events.index("tool_spawn") < events.index("remediation_proposed")
    enter = json.loads(
        next(l for l in open(audit.path, encoding="utf-8")
             if l.strip() and json.loads(l)["event"] == "state_enter"))
    assert enter["code_scan"] is True
    # the remediation node carries the suggested mappings
    assert graph.by_type("remediation")[0]["properties"]["cwe"] == ""


def test_subagent_scanner_crash_does_not_kill_llm(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()

    class ExplodingSandbox:
        def spawn(self, argv):
            raise RuntimeError("docker exploded")

    def llm(prompt):
        assert "SCANNER EVIDENCE" in prompt
        return RemediationSet(remediations=[
            Remediation(hypothesis_id="H1", title="t", fix="f")])

    sub = BlueTeamSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=llm,
                           sandbox=ExplodingSandbox(), code_folder="/tmp/x")
    assert sub.run().status == "ok"
    assert "scanners_failed" in _events(audit)
    assert graph.by_type("scanner_result") == []


def test_subagent_without_sandbox_stays_pure_llm(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()

    def llm(prompt):
        assert "no code folder scanned" in prompt
        return RemediationSet(remediations=[
            Remediation(hypothesis_id="H1", title="t", fix="f")])

    sub = BlueTeamSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=llm)
    assert sub.run().status == "ok"
    events = _events(audit)
    assert "tool_spawn" not in events


# ---- REPORT ----------------------------------------------------------

def _remediated_graph():
    graph = _graph()
    for h, sev in (("H1", "critical"), ("H2", "medium")):
        graph.add_node("remediation", h, {
            "title": f"fix {h}",
            "fix": f"steps {h}",
            "detection": f"rule {h}",
            "severity": sev,
        })
    return graph


def test_report_renders_everything(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _remediated_graph()

    report = render_report(
        graph, audit, "e-bt",
        completed_states=["INIT", "RECON_PASSIVE", "HYPOTHESIZE"],
        halt_reason=None,
    )
    assert "# Security Test Report" in report
    assert "target-corp.com" in report
    assert "www.target-corp.com" in report
    assert "SQLi on login" in report
    assert "Fix for H1" in report
    assert "approved" in report
    assert audit.head_hash() in report
    # no exploit_attempt nodes => the report must NOT claim testing happened
    assert "No testing was done against the website" in report


def test_report_validation_clean(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _remediated_graph()
    report = render_report(graph, audit, "e-bt")
    assert validate_report(report, graph) == []


def test_report_validation_catches_missing_hypothesis(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _remediated_graph()
    report = render_report(graph, audit, "e-bt")
    # drop H2 from the report text
    broken = report.replace("H2", "XX")
    problems = validate_report(broken, graph)
    assert any("H2" in p for p in problems)


def test_report_subagent_writes_file(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _remediated_graph()

    sub = ReportSubagent(cfg=cfg, graph=graph, audit=audit, engagement_id="e-bt")
    sub.completed_states = ["INIT", "RECON_PASSIVE"]
    sub.halt_reason = "Zone B requires Linux"
    result = sub.run()

    assert result.status == "ok"
    report_path = tmp_path / "engagements" / "e-bt" / "report.md"
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "The engagement stopped early" in content
    assert "No testing was done against the website" in content
    events = [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "report_written" in events
    # M3: the fingerprint printed in the report must be the chain head
    # AFTER report_written was appended — not a pre-append snapshot
    idx = content.find("final fingerprint")
    assert idx != -1
    hash_line = next(
        l.strip().strip("`") for l in content[idx:].splitlines()
        if l.strip().strip("`")
        and all(c in "0123456789abcdef" for c in l.strip().strip("`"))
    )
    assert hash_line == audit.head_hash(), (
        f"report fingerprint {hash_line!r} != chain head {audit.head_hash()!r}")


@pytest.mark.parametrize("secret,expected", [
    ("sk-proj-abc123def456ghi789jkl", True),
    ("password: hunter2secret", True),
    ("BEGIN PRIVATE KEY", False),  # partial text — must not redact innocuous text
    # patterns only the SHARED detector (secrets.py) has — the report's
    # old private list missed all three
    (aws_access_key(), True),          # AWS access key
    (github_token(), True),            # GitHub token
    ("postgres://user:hunter2secret@db.example/x", True),  # conn string
])
def test_redact_secrets(secret, expected):
    text = f"leak: {secret}"
    redacted = redact_secrets(text)
    assert (secret not in redacted) is expected
    if expected:
        assert "«SECRET_" in redacted


def test_redact_secrets_keeps_password_label():
    """Only the value goes; the label stays so the report stays readable."""
    redacted = redact_secrets("config: password=hunter2secret end")
    assert "password=" in redacted
    assert "hunter2secret" not in redacted


def test_redact_jwt():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0TWs-abc"
    assert jwt not in redact_secrets(f"token={jwt}")


def test_report_claims_testing_only_with_real_attempts(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "exit_code": 0, "confirmed": True,
        "argv": ["sqlmap", "-u", "http://target-corp.com/Login.asp", "--batch"],
        "output_excerpt": "parameter 'id' is vulnerable",
    })

    report = render_report(graph, audit, "e-bt")
    assert "Tools were run against the target" in report
    assert "No testing was done" not in report
    # the attempt summary lists the tool, and the hypothesis shows
    # tested/confirmed status
    assert "H1:sqlmap" in report
    assert "confirmed by the test tool" in report
    assert "Tested: yes" in report
    # H2 was not tested
    assert "Tested: no" in report
    # the repeatable-steps section shows the command a tester can re-run
    assert "How the testing was done" in report
    assert "### Steps for H1:sqlmap" in report
    # (the safety reminder wraps across lines — normalize whitespace)
    assert "you are allowed to test" in " ".join(report.split())


def test_report_shows_verified_badge(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "exit_code": 0, "confirmed": True,
        "argv": ["sqlmap", "-u", "http://t/Login.asp", "--batch"],
        "output_excerpt": "is vulnerable",
    })
    graph.add_node("finding", "H1", {"tool": "sqlmap"})
    graph.add_node("verify_attempt", "H1", {
        "verified": True, "method": "curl boolean probe",
        "true_len": 5000, "false_len": 0,
    })

    report = render_report(graph, audit, "e-bt")
    assert "second tool re-tested it and agreed" in report


def test_report_shows_unverified_warning_when_disagreeing(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "exit_code": 0, "confirmed": True,
        "argv": ["sqlmap", "-u", "http://t/Login.asp", "--batch"],
        "output_excerpt": "is vulnerable",
    })
    graph.add_node("finding", "H1", {"tool": "sqlmap"})
    graph.add_node("verify_attempt", "H1", {
        "verified": False, "method": "curl boolean probe",
        "true_len": 500, "false_len": 500,
    })

    report = render_report(graph, audit, "e-bt")
    assert "treat this finding with care" in report


def test_empty_graph_report(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-empty")
    report = render_report(graph, audit, "e-empty", completed_states=["INIT"])
    assert "none found" in report
    assert "No issues were suggested" in report
    assert validate_report(report, graph) == []


# ---- Phase 6: evidence normalizer, CVSS calculator, dedup, enrichment ----

def test_normalize_evidence_strips_ansi_and_whitespace():
    from kryonsec.purple.report import normalize_evidence
    noisy = "\x1b[31m[!]\x1b[0m vulnerable\r\n   to  \t SQL\r\ninjection"
    assert normalize_evidence(noisy) == "[!] vulnerable to SQL injection"


def test_normalize_evidence_truncates_uniformly():
    from kryonsec.purple.report import normalize_evidence
    out = normalize_evidence("A" * 500, max_chars=200)
    assert len(out) == 201  # 200 chars + ellipsis
    assert out.endswith("…")


def test_normalize_evidence_empty():
    from kryonsec.purple.report import normalize_evidence
    assert normalize_evidence("") == ""


@pytest.mark.parametrize("vector,expected", [
    # official CVSS 3.1 examples (first.org calculator)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # no prefix
    # malformed / missing -> None, never a guess
    ("", None),
    ("AV:N/AC:L/PR:N/UI:N/S:U", None),          # missing C/I/A
    ("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None),  # bad metric value
    ("not a vector at all", None),
])
def test_cvss_base_score(vector, expected):
    from kryonsec.purple.report import cvss_base_score
    assert cvss_base_score(vector) == expected


@pytest.mark.parametrize("score,expected", [
    (None, "unknown"), (0.0, "none"), (3.9, "low"), (4.0, "medium"),
    (6.9, "medium"), (7.0, "high"), (8.99, "high"), (9.0, "critical"),
    (10.0, "critical"),
])
def test_cvss_severity(score, expected):
    from kryonsec.purple.report import cvss_severity
    assert cvss_severity(score) == expected


def test_report_shows_calculated_score_and_enrichment(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    # _graph's H1 already carries the 9.8 vector
    graph.by_type("hypothesis")[0]["properties"]["enrichment"] = {
        "cve": "CVE-2024-1234",
        "cvss_score": 9.8, "severity": "CRITICAL",
        "kev": True, "epss": 0.94, "epss_percentile": 0.99,
        "cpes": ["cpe:2.3:a:vendor:product:1.0"],
        "exploits": ["Exploit-DB 12345"], "exploit_available": True,
    }
    report = render_report(graph, audit, "e-bt")
    assert "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in report
    assert "calculated base score: 9.8" in report
    assert "critical" in report
    assert "CVE-2024-1234" in report
    assert "YES — fix first" in report  # KEV
    assert "cpe:2.3:a:vendor:product:1.0" in report
    assert validate_report(report, graph) == []


def test_report_enrichment_partial_data(tmp_path):
    """A failed lookup leaves keys out — unknown must never look like 'no'."""
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.by_type("hypothesis")[0]["properties"]["enrichment"] = {
        "cve": "CVE-2024-5678", "kev": None, "epss": None,
    }
    report = render_report(graph, audit, "e-bt")
    assert "CVE-2024-5678" in report
    assert "unknown (lookup failed)" in report
    assert "Chance it gets exploited soon (EPSS score): unknown" in report


def test_dedup_merges_same_tools_and_asset(tmp_path):
    from kryonsec.purple.report import dedup_hypotheses

    graph = _graph()
    # H2 in _graph is (ffuf, target-corp.com) — add a duplicate suggestion
    graph.add_node("hypothesis", "H3", {
        "title": "search page may reflect input",
        "target_asset": "target-corp.com",
        "rationale": "same idea again",
        "cvss_vector": "",
        "cve": "CVE-2024-0001",
        "tools": ["ffuf"],
        "confidence": 0.9,  # higher than H2's 0.6 — must win
    })
    # nodes pointing at H3 must be remapped to H2
    graph.add_node("remediation", "H3", {"title": "t", "fix": "f"})
    graph.add_node("exploit_attempt", "H3:ffuf", {"tool": "ffuf"})
    graph.add_node("finding", "H3", {"tool": "ffuf"})
    audit = AuditLog(tmp_path / "audit.jsonl")

    merged = dedup_hypotheses(graph, audit)
    assert merged == 1
    labels = [n["label"] for n in graph.by_type("hypothesis")]
    assert labels == ["H1", "H2"]
    # H2 kept the higher confidence and gained the CVE
    h2 = graph.by_type("hypothesis")[1]["properties"]
    assert h2["confidence"] == 0.9
    assert h2["cve"] == "CVE-2024-0001"
    assert h2["merged_from"] == ["H3"]
    # every pointer was remapped, nothing orphaned
    assert [n["label"] for n in graph.by_type("remediation")] == ["H2"]
    assert [n["label"] for n in graph.by_type("exploit_attempt")] == ["H2:ffuf"]
    assert [n["label"] for n in graph.by_type("finding")] == ["H2"]
    events = [json.loads(l)["event"]
              for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "hypotheses_merged" in events
    ok, reason = audit.verify()
    assert ok, reason


def test_dedup_noop_when_unique(tmp_path):
    from kryonsec.purple.report import dedup_hypotheses

    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()  # H1 (sqlmap) and H2 (ffuf) differ in tools
    assert dedup_hypotheses(graph, audit) == 0
    assert len(graph.by_type("hypothesis")) == 2
    # nothing merged -> no hypotheses_merged event (audit has no file yet
    # because zero events were written — that IS the assertion)
    assert not audit.path.exists()


def test_report_subagent_merges_duplicates_before_rendering(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("hypothesis", "H3", {
        "title": "dup", "target_asset": "target-corp.com",
        "rationale": "r", "cvss_vector": "", "tools": ["ffuf"],
        "confidence": 0.5,
    })
    sub = ReportSubagent(cfg=cfg, graph=graph, audit=audit, engagement_id="e-d")
    assert sub.run().status == "ok"
    assert len(graph.by_type("hypothesis")) == 2
    content = (tmp_path / "engagements" / "e-d" / "report.md").read_text(
        encoding="utf-8")
    assert "H3" not in content
    assert validate_report(content, graph) == []


def test_validate_report_catches_unmerged_duplicate(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("hypothesis", "H3", {
        "title": "dup", "target_asset": "target-corp.com",
        "rationale": "r", "cvss_vector": "", "tools": ["ffuf"],
        "confidence": 0.5,
    })
    # render WITHOUT the subagent's dedup — validation must flag it
    report = render_report(graph, audit, "e-dup")
    problems = validate_report(report, graph)
    assert any("H3" in p and "not merged" in p for p in problems)


def test_validate_report_catches_missing_enrichment(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.by_type("hypothesis")[0]["properties"]["enrichment"] = {
        "cve": "CVE-2024-9999"}
    report = render_report(graph, audit, "e-enr")
    broken = report.replace("CVE-2024-9999", "CVE-0000-0000")
    problems = validate_report(broken, graph)
    assert any("CVE-2024-9999" in p for p in problems)


def test_validate_report_rejects_ansi_in_output(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    report = render_report(graph, audit, "e-ansi")
    problems = validate_report(report + "\n\x1b[31mred\x1b[0m\n", graph)
    assert any("ANSI" in p for p in problems)


def test_report_attempt_excerpts_are_normalized(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "exit_code": 0, "confirmed": True,
        "argv": ["sqlmap", "-u", "http://t/Login.asp", "--batch"],
        "output_excerpt": "\x1b[33m[WARNING]\x1b[0m the   \t parameter\n'id' is vulnerable",
    })
    report = render_report(graph, audit, "e-norm")
    assert "\x1b[" not in report
    assert "the parameter 'id' is vulnerable" in report
    assert validate_report(report, graph) == []


def test_report_fixes_show_mapping_suggestions(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("remediation", "H1", {
        "title": "Parameterize queries", "fix": "prepared statements",
        "detection": "waf rule", "severity": "critical",
        "cwe": "CWE-89", "owasp": "A03:2021-Injection", "attack": "T1190",
    })
    report = render_report(graph, audit, "e-map")
    assert "CWE-89" in report
    assert "A03:2021-Injection" in report
    assert "T1190" in report
    assert "suggested, not verified" in report
    assert validate_report(report, graph) == []


# ---- Phase 8E: SBOM scanners in the report ---------------------------------

def test_report_renders_scanner_section_and_sbom_summary(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("scanner_result", "syft", {
        "tool": "syft", "exit_code": 0, "stdout_chars": 100,
        "excerpt": '{"artifacts": [...]}', "packages_count": 42,
    })
    graph.add_node("scanner_result", "grype", {
        "tool": "grype", "exit_code": 0, "stdout_chars": 100,
        "excerpt": '{"matches": [...]}', "findings_count": 3,
    })
    report = render_report(graph, audit, "e-sbom")

    assert "Code scanning results" in report
    assert "SBOM: 42 packages identified (syft)" in report
    assert "grype" in report
    assert validate_report(report, graph) == []


def test_report_scanner_section_absent_without_nodes(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    report = render_report(_graph(), audit, "e-nosc")
    assert "Code scanning results" in report
    assert "No code scanners ran" in report


def test_report_osv_ghsa_cwe_nuclei_rows(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("hypothesis", "H1", {
        "title": "Log4Shell on login", "target_asset": "/login",
        "rationale": "log4j", "tools": ["nuclei"], "cvss_vector": "",
        "confidence": 0.7, "approved": False,
        "enrichment": {
            "cve": "CVE-2021-44228",
            "cwes": ["CWE-502"],
            "osv_severity": "HIGH",
            "osv_aliases": ["GHSA-7rjr-3q55-vv33"],
            "affected_packages": ["log4j-core"],
            "ghsa_id": "GHSA-7rjr-3q55-vv33",
            "ghsa_severity": "HIGH",
            "patched_versions": [">=2.15.0"],
            "nuclei_templates": [{"id": "log4shell-rce", "severity": "critical"}],
        },
    })
    report = render_report(graph, audit, "e-p8c")
    assert "CWE-502" in report
    assert "OSV database" in report and "HIGH" in report
    assert "log4j-core" in report
    assert "GitHub Advisory GHSA-7rjr-3q55-vv33" in report
    assert "fixed in >=2.15.0" in report
    assert "log4shell-rce" in report
    assert validate_report(report, graph) == []


# ---- Phase 8F: timeline + owasp_api + audit ts ------------------------------

def test_audit_write_adds_iso_timestamp(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.write({"event": "state_enter", "state": "RECON_PASSIVE"})
    entry = json.loads(open(audit.path, encoding="utf-8").read().splitlines()[0])
    # ISO-8601 UTC, seconds precision — presentation only, the chain
    # hashes whatever fields exist (old chains still verify)
    assert entry["ts"].endswith("+00:00") or entry["ts"].endswith("Z")
    assert "T" in entry["ts"]
    ok, reason = audit.verify()
    assert ok, reason


def test_report_renders_timeline_from_audit(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.write({"event": "engagement_created", "engagement_id": "e-tl",
                 "target": "target-corp.com"})
    audit.write({"event": "state_enter", "state": "RECON_PASSIVE",
                 "target": "target-corp.com"})
    audit.write({"event": "state_enter", "state": "HYPOTHESIZE"})
    report = render_report(_graph(), audit, "e-tl")

    assert "## Timeline" in report
    assert "RECON_PASSIVE" in report
    assert "HYPOTHESIZE" in report
    assert audit.head_hash() in report


def test_report_owasp_api_mapping_rendered(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _graph()
    graph.add_node("remediation", "H1", {
        "title": "Add object-level authz", "fix": "check tenant ownership",
        "detection": "log 403s per tenant", "severity": "high",
        "cwe": "", "owasp": "", "attack": "",
        "owasp_api": "API1:2023-BOLA",
    })
    report = render_report(graph, audit, "e-api")
    assert "API1:2023-BOLA" in report
    assert validate_report(report, graph) == []


def test_build_timeline_bounded_and_tolerant(tmp_path):
    from kryonsec.purple.report import build_timeline

    audit = AuditLog(tmp_path / "audit.jsonl")
    for i in range(150):
        audit.write({"event": "state_enter", "state": f"S{i % 10}"})
    timeline = build_timeline(audit)
    assert len(timeline) == 100  # bounded
    # a nonexistent audit path is an empty timeline, not a crash
    missing = AuditLog(tmp_path / "nope" / "missing.jsonl")
    assert build_timeline(missing) == []
