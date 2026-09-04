"""Tests for RECON_ACTIVE + VERIFY subagents (spec §4.2, Zone B)."""

import json

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import (
    ReconActiveSubagent,
    parse_nmap_services,
)
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.verify import VerifySubagent, _boolean_probe_urls


# ---- nmap parsing --------------------------------------------------------

NMAP_SAMPLE = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for testasp.vulnweb.com (44.229.226.2)
Host is up (0.045s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 8.5
443/tcp open  https   Microsoft IIS httpd 8.5 (TLS)
Service detection performed. 1 service on 1 host.
"""


def test_parse_nmap_services_extracts_open_ports():
    services = parse_nmap_services(NMAP_SAMPLE)
    assert services == [
        {"port": 80, "proto": "tcp", "service": "http",
         "version": "Microsoft IIS httpd 8.5"},
        {"port": 443, "proto": "tcp", "service": "https",
         "version": "Microsoft IIS httpd 8.5 (TLS)"},
    ]


def test_parse_nmap_ignores_closed_ports():
    out = "80/tcp  open   http\n443/tcp closed https\n"
    services = parse_nmap_services(out)
    assert [s["port"] for s in services] == [80]


# ---- RECON_ACTIVE --------------------------------------------------------

class FakeSandbox:
    def __init__(self, result):
        self.result = result
        self.spawned = []

    def spawn(self, argv):
        self.spawned.append(argv)
        return self.result


def _events(audit):
    return [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8")
            if l.strip()]


def test_recon_active_creates_service_nodes(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra")
    fake = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=NMAP_SAMPLE))

    result = ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()
    assert result.status == "ok"
    assert fake.spawned[0][0] == "nmap"
    assert "t.com" in fake.spawned[0]

    services = graph.by_type("service")
    assert len(services) == 2
    assert services[0]["label"] == "t.com:80/tcp"
    assert services[0]["properties"]["service"] == "http"
    assert services[0]["properties"]["version"] == "Microsoft IIS httpd 8.5"

    events = _events(audit)
    assert "recon_active_done" in events
    assert "tool_spawn" in events
    ok, reason = audit.verify()
    assert ok, reason


def test_recon_active_failure_fails_state_not_engagement(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra2")
    fake = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                   error="sandbox timeout"))

    result = ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()
    assert result.status == "failed"
    assert graph.by_type("service") == []
    assert "recon_active_failed" in _events(audit)


# ---- VERIFY: probe URL building ------------------------------------------

def test_boolean_probe_urls_builds_true_false_pair():
    true_url, false_url = _boolean_probe_urls(
        "http://t.com/showthread.asp?id=1")
    assert "id=1+AND+1%3D1" in true_url or "id=1%20AND%201%3D1" in true_url
    assert "id=1+AND+1%3D2" in false_url or "id=1%20AND%201%3D2" in false_url


def test_boolean_probe_urls_none_without_query():
    assert _boolean_probe_urls("http://t.com/Login.asp") is None


# ---- VERIFY subagent -----------------------------------------------------

def _finding_graph():
    graph = EngagementGraph(engagement_id="e-v")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi on thread", "target_asset": "/showthread.asp?id=1",
        "rationale": "evidence", "cvss_vector": "",
        "tools": ["sqlmap"], "confidence": 0.8, "approved": True,
    })
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "ok": True, "exit_code": 0, "confirmed": True,
        "argv": ["sqlmap"], "output_excerpt": "is vulnerable",
    })
    graph.add_node("finding", "H1", {
        "tool": "sqlmap", "confirmed_by": "sandbox sqlmap output",
        "excerpt": "is vulnerable",
    })
    return graph


def test_verify_confirms_when_responses_differ(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class DiffSandbox:
        def __init__(self):
            self.calls = []

        def spawn(self, argv):
            self.calls.append(argv[-1])
            is_true = "1%3D1" in argv[-1] or "+AND+1%3D1" in argv[-1]
            return SpawnResult(
                ok=True, exit_code=0,
                stdout="full page content" if is_true else "empty result",
            )

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", DiffSandbox())
    result = sub.run()

    assert result.status == "ok"
    # both probes ran (true + false)
    assert len(sub.sandbox.calls) == 2
    verify_nodes = graph.by_type("verify_attempt")
    assert len(verify_nodes) == 1
    assert verify_nodes[0]["properties"]["verified"] is True
    # the finding node itself is now marked verified
    assert graph.by_type("finding")[0]["properties"]["verified"] is True
    assert "finding_verified" in _events(audit)
    ok, reason = audit.verify()
    assert ok, reason


def test_verify_fails_when_responses_identical(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class SameSandbox:
        def spawn(self, argv):
            return SpawnResult(ok=True, exit_code=0, stdout="same page")

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", SameSandbox())
    sub.run()

    verify_nodes = graph.by_type("verify_attempt")
    assert verify_nodes[0]["properties"]["verified"] is False
    assert "finding_verification_failed" in _events(audit)
    assert graph.by_type("finding")[0]["properties"].get("verified") is not True


def test_verify_skips_when_probe_fails(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class DeadSandbox:
        def spawn(self, argv):
            return SpawnResult(ok=False, exit_code=-1, stdout="",
                               error="curl failed")

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", DeadSandbox())
    result = sub.run()
    assert result.status == "ok"  # does not halt the engagement
    verify_nodes = graph.by_type("verify_attempt")
    assert verify_nodes[0]["properties"]["verified"] is False
    assert "verify_skipped" in _events(audit)


def test_verify_no_findings_is_ok(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-v2")

    class UnusedSandbox:
        def spawn(self, argv):  # pragma: no cover
            raise AssertionError("should not spawn anything")

    result = VerifySubagent(cfg, graph, audit, "t.com", UnusedSandbox()).run()
    assert result.status == "ok"
    assert "verify_done" in _events(audit)
