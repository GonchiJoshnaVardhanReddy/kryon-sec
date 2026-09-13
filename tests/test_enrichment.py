"""Tests for hypothesis enrichment (tool expansion Phase 3).

KEV/EPSS/NVD caching + audited failures, searchsploit sandbox search,
and the enrich_hypotheses wiring. The network layer is injected/mocked
so tests run fully offline; the target is never contacted by design.
"""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.enrichment import (
    enrich_hypotheses,
    epss_for,
    extract_cve_ids,
    kev_cves,
    sanitize_searchsploit_term,
    searchsploit_hits,
)
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.storage import init_db, reset_engine


@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    c = KryonsecConfig(home=tmp_path / "home")
    c.database_url = f"sqlite:///{tmp_path / 'enrichment.db'}"
    init_db(c)
    yield c
    reset_engine()


@pytest.fixture()
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


def _kev_payload(*cves):
    return json.dumps({
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "vulnerabilities": [{"cveID": c} for c in cves],
    }).encode()


def _epss_payload(cve, epss="0.94321", percentile="0.99666"):
    return json.dumps({"data": [
        {"cve": cve, "epss": epss, "percentile": percentile},
    ]}).encode()


# ---- CVE extraction + term sanitization ------------------------------------

def test_extract_cve_ids_finds_and_dedupes():
    text = "Likely CVE-2021-44228 (Log4Shell); see also cve-2021-44228 " \
           "and CVE-2014-0160 in older notes."
    assert extract_cve_ids(text, "") == ["CVE-2021-44228", "CVE-2014-0160"]


def test_extract_cve_ids_no_false_positives():
    assert extract_cve_ids("SQL injection in login form", "no cve here") == []


def test_sanitize_searchsploit_term_strips_metacharacters():
    term = sanitize_searchsploit_term(
        'SQLi on /Login.asp?id=1 ; rm -rf / " $(whoami)')
    assert term == "SQLi on Login.asp id 1 rm -rf whoami"
    for ch in ";$&|<>\"'`\\":
        assert ch not in term


def test_sanitize_searchsploit_term_caps_length():
    assert len(sanitize_searchsploit_term("word " * 100)) <= 60


# ---- KEV catalog -------------------------------------------------------------

def test_kev_fetches_and_parses(cfg):
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               return_value=_kev_payload("CVE-2021-44228", "CVE-2014-0160")):
        cves = kev_cves(cfg)
    assert cves == {"CVE-2021-44228", "CVE-2014-0160"}


def test_kev_uses_cache(cfg):
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               return_value=_kev_payload("CVE-2021-44228")):
        assert kev_cves(cfg) == {"CVE-2021-44228"}
    # fetch now fails — the cached catalog must still answer
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               side_effect=RuntimeError("network down")):
        assert kev_cves(cfg) == {"CVE-2021-44228"}


def test_kev_fetch_failure_is_none_not_empty(cfg):
    """None means 'unknown' — never treat a failed fetch as 'not in KEV'."""
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               side_effect=RuntimeError("network down")):
        assert kev_cves(cfg) is None


def test_kev_refuses_non_allowlisted_host(cfg):
    from kryonsec.purple.zonea import ZoneAViolation

    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               side_effect=ZoneAViolation("denied")):
        assert kev_cves(cfg) is None


# ---- EPSS ---------------------------------------------------------------------

def test_epss_fetches_and_parses(cfg):
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               return_value=_epss_payload("CVE-2021-44228")):
        record = epss_for(cfg, "cve-2021-44228")
    assert record == {"epss": pytest.approx(0.94321), "percentile": "0.99666"}


def test_epss_uses_cache(cfg):
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               return_value=_epss_payload("CVE-2021-44228")):
        epss_for(cfg, "CVE-2021-44228")
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               side_effect=RuntimeError("network down")):
        assert epss_for(cfg, "CVE-2021-44228")["epss"] == pytest.approx(0.94321)


def test_epss_unknown_cve_is_none(cfg):
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               return_value=json.dumps({"data": []}).encode()):
        assert epss_for(cfg, "CVE-2030-00001") is None


def test_epss_failure_is_none(cfg):
    with patch("kryonsec.purple.enrichment._zone_a_fetch",
               side_effect=RuntimeError("network down")):
        assert epss_for(cfg, "CVE-2021-44228") is None


# ---- searchsploit (sandbox-local ExploitDB) -----------------------------------

class _FakeSandbox:
    def __init__(self, ok=True, exit_code=0, stdout=""):
        self.argvs = []
        self._result = SimpleNamespace(
            ok=ok, exit_code=exit_code, stdout=stdout)

    def spawn(self, argv):
        self.argvs.append(argv)
        return self._result


def test_searchsploit_validates_and_runs(audit):
    from kryonsec.purple.allowlist import ToolAllowlist

    sandbox = _FakeSandbox(stdout="\n".join([
        "EXPLOIT TITLE", "Apache Struts RCE", "Exploit DB 4pwn",
    ]))
    hits = searchsploit_hits(
        sandbox, audit, "CVE-2017-5638", allowlist=ToolAllowlist())

    assert sandbox.argvs == [["searchsploit", "--colorless", "CVE-2017-5638"]]
    assert "Apache Struts RCE" in hits
    events = [json.loads(l) for l in open(audit.path, encoding="utf-8") if l.strip()]
    spawns = [e for e in events if e["event"] == "tool_spawn"]
    assert len(spawns) == 1
    assert spawns[0]["state"] == "HYPOTHESIZE"
    ok, reason = audit.verify()
    assert ok, reason


def test_searchsploit_failure_is_none_with_audit(audit):
    from kryonsec.purple.allowlist import ToolAllowlist

    sandbox = _FakeSandbox(ok=False, exit_code=1, stdout="")
    assert searchsploit_hits(
        sandbox, audit, "CVE-2017-5638", allowlist=ToolAllowlist()) is None
    events = [json.loads(l) for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert any(e["event"] == "tool_result" and e["ok"] is False for e in events)


def test_searchsploit_rejects_metacharacter_term(audit):
    """A term outside the {term} template pattern is rejected by the
    allowlist — enrichment must record it and return None, not raise."""
    from kryonsec.purple.allowlist import ToolAllowlist

    sandbox = _FakeSandbox()
    assert searchsploit_hits(
        sandbox, audit, "x; rm -rf /", allowlist=ToolAllowlist()) is None
    assert sandbox.argvs == []  # never spawned
    events = [json.loads(l) for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert any(e["event"] == "enrichment_lookup" and not e["ok"] for e in events)


# ---- enrich_hypotheses ---------------------------------------------------------

def _hypothesis_graph():
    graph = EngagementGraph(engagement_id="e-enrich")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "Log4Shell in the login service",
        "target_asset": "/login",
        "rationale": "stack mentions log4j, likely CVE-2021-44228",
        "cve": "CVE-2021-44228",
        "tools": ["nuclei"],
        "confidence": 0.8,
    })
    graph.add_node("hypothesis", "H2", {
        "title": "SQLi on login form",
        "target_asset": "/Login.asp?id=1",
        "rationale": "classic ASP page with numeric id parameter",
        "tools": ["sqlmap"],
        "confidence": 0.6,
    })
    return graph


def _patch_apis(monkeypatch, *, nvd=None, kev=None, epss=None):
    """Patch the three API layers; anything left as None stays 'failed'."""
    monkeypatch.setattr("kryonsec.copilot.cve.lookup_cve",
                        lambda cfg, cve: nvd)
    monkeypatch.setattr("kryonsec.purple.enrichment.kev_cves",
                        lambda cfg: kev)
    monkeypatch.setattr("kryonsec.purple.enrichment.epss_for",
                        lambda cfg, cve: epss)


def test_enrich_writes_properties_and_skips_cveless(cfg, audit, monkeypatch):
    _patch_apis(
        monkeypatch,
        nvd={"id": "CVE-2021-44228", "cvss_score": 10.0,
             "severity": "CRITICAL",
             "cpes": ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*:*"]},
        kev={"CVE-2021-44228"},
        epss={"epss": 0.94, "percentile": "0.99666"},
    )
    graph = _hypothesis_graph()
    counts = enrich_hypotheses(cfg, graph, audit, sandbox=None)

    assert counts["hypotheses"] == 2
    assert counts["enriched"] == 1
    assert counts["no_cve"] == 1

    h1 = graph.by_type("hypothesis")[0]
    enrich = h1["properties"]["enrichment"]
    assert enrich["cve"] == "CVE-2021-44228"
    assert enrich["cvss_score"] == 10.0
    assert enrich["severity"] == "CRITICAL"
    assert enrich["cpes"] == ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*:*"]
    assert enrich["kev"] is True
    assert enrich["epss"] == pytest.approx(0.94)

    # H2 has no CVE anywhere in its text — no enrichment block at all
    h2 = [n for n in graph.by_type("hypothesis") if n["label"] == "H2"][0]
    assert "enrichment" not in h2["properties"]

    events = [json.loads(l) for l in open(audit.path, encoding="utf-8") if l.strip()]
    kinds = [e["kind"] for e in events if e["event"] == "enrichment_lookup"]
    assert "nvd" in kinds and "kev" in kinds and "epss" in kinds
    # no sandbox: searchsploit is a visible skip, never a silent one
    skips = [e for e in events if e["event"] == "enrichment_lookup"
             and e["kind"] == "searchsploit"]
    assert len(skips) == 1 and "no sandbox" in skips[0]["reason"]
    done = [e for e in events if e["event"] == "enrichment_done"][0]
    assert done["enriched"] == 1
    ok, reason = audit.verify()
    assert ok, reason


def test_enrich_failures_are_audited_skips_not_errors(cfg, audit, monkeypatch):
    """Every API down + no sandbox: hypotheses still run, enrichment is
    simply absent — and the audit says exactly what failed."""
    _patch_apis(monkeypatch, nvd=None, kev=None, epss=None)
    graph = _hypothesis_graph()

    counts = enrich_hypotheses(cfg, graph, audit, sandbox=None)
    assert counts["enriched"] == 1  # node marked, but with only the cve id
    enrich = graph.by_type("hypothesis")[0]["properties"]["enrichment"]
    assert enrich["cve"] == "CVE-2021-44228"
    assert "kev" not in enrich  # unknown — NOT False (that would mean 'checked, absent')
    assert "epss" not in enrich

    events = [json.loads(l) for l in open(audit.path, encoding="utf-8") if l.strip()]
    failed = [e for e in events if e["event"] == "enrichment_lookup" and not e["ok"]]
    assert {e["kind"] for e in failed} >= {"nvd", "kev", "epss", "searchsploit"}
    ok, reason = audit.verify()
    assert ok, reason


def test_enrich_searchsploit_hits_mark_exploit_available(cfg, audit, monkeypatch):
    _patch_apis(monkeypatch, kev=set(), epss=None)
    graph = _hypothesis_graph()
    sandbox = _FakeSandbox(stdout="Apache Log4j RCE (CVE-2021-44228)")

    enrich_hypotheses(cfg, graph, audit, sandbox=sandbox)

    assert sandbox.argvs == [["searchsploit", "--colorless", "CVE-2021-44228"]]
    enrich = graph.by_type("hypothesis")[0]["properties"]["enrichment"]
    assert enrich["exploit_available"] is True
    assert "Apache Log4j RCE" in enrich["exploits"][0]


def test_enrich_empty_graph_is_noop(cfg, audit):
    graph = EngagementGraph(engagement_id="e-empty")
    counts = enrich_hypotheses(cfg, graph, audit, sandbox=None)
    assert counts == {"hypotheses": 0, "enriched": 0, "no_cve": 0, "lookups": 0}


def test_enrich_kev_catalog_fetched_once_for_many_hypotheses(
        cfg, audit, monkeypatch):
    _patch_apis(monkeypatch, kev={"CVE-2021-44228"})
    graph = _hypothesis_graph()
    graph.add_node("hypothesis", "H3", {
        "title": "Heartbleed on the portal", "target_asset": "/",
        "rationale": "old openssl, likely CVE-2014-0160", "tools": ["nmap"],
        "confidence": 0.5,
    })
    calls = []

    def fake_kev(cfg):
        calls.append(1)
        return {"CVE-2021-44228", "CVE-2014-0160"}

    monkeypatch.setattr("kryonsec.purple.enrichment.kev_cves", fake_kev)
    enrich_hypotheses(cfg, graph, audit, sandbox=None)

    assert len(calls) == 1  # one catalog fetch per run, not per hypothesis


# ---- NVD record CPE extraction (copilot.cve) ----------------------------------

def test_nvd_record_extracts_cpes(monkeypatch):
    from kryonsec.copilot.cve import _from_nvd

    payload = json.dumps({"vulnerabilities": [{"cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T00:00:00Z",
        "lastModified": "2021-12-20T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "Log4Shell"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
        "references": [],
        "configurations": [{"nodes": [
            {"cpeMatch": [
                {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*:*"},
                {"criteria": "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*:*"},
                {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*:*"},
            ]},
        ]}],
    }}]}).encode()

    class _Resp:
        def read(self):
            return payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("kryonsec.copilot.cve.urllib.request.urlopen",
               return_value=_Resp()):
        record = _from_nvd("CVE-2021-44228")

    assert record["cvss_score"] == 10.0
    assert record["cpes"] == [
        "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*:*",
    ]  # deduped, order kept


# ---- HYPOTHESIZE integration ----------------------------------------------------

def test_hypothesize_subagent_enriches_after_proposing(tmp_path, monkeypatch):
    from kryonsec.purple.hypothesize import Hypothesis, HypothesisSet
    from kryonsec.purple.hypothesize import HypothesizeSubagent

    _patch_apis(
        monkeypatch,
        nvd={"id": "CVE-2021-44228", "cvss_score": 10.0,
             "severity": "CRITICAL", "cpes": []},
        kev={"CVE-2021-44228"},
        epss={"epss": 0.9, "percentile": "0.99"},
    )
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-int")
    graph.add_node("target", "target-corp.com", {})

    def fake_llm(prompt):
        return HypothesisSet(hypotheses=[
            Hypothesis(
                id="H1", title="Log4Shell on login",
                target_asset="/login", rationale="log4j in stack",
                cve="CVE-2021-44228", tools=["nuclei"], confidence=0.8,
            ),
        ])

    sub = HypothesizeSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=fake_llm)
    result = sub.run()

    assert result.status == "ok"
    enrich = graph.by_type("hypothesis")[0]["properties"]["enrichment"]
    assert enrich["kev"] is True
    assert enrich["severity"] == "CRITICAL"
    events = [json.loads(l) for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "enrichment_done" in [e["event"] for e in events]
    ok, reason = audit.verify()
    assert ok, reason


def test_hypothesize_subagent_enrichment_crash_never_fails_state(
        tmp_path, monkeypatch):
    from kryonsec.purple.hypothesize import Hypothesis, HypothesisSet
    from kryonsec.purple.hypothesize import HypothesizeSubagent

    def exploding_enrich(*a, **k):
        raise RuntimeError("enrichment exploded")

    monkeypatch.setattr(
        "kryonsec.purple.enrichment.enrich_hypotheses", exploding_enrich)
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-crash")
    graph.add_node("target", "target-corp.com", {})

    def fake_llm(prompt):
        return HypothesisSet(hypotheses=[
            Hypothesis(id="H1", title="t", target_asset="/x",
                       rationale="r", tools=["nmap"]),
        ])

    sub = HypothesizeSubagent(cfg=cfg, graph=graph, audit=audit, llm_fn=fake_llm)
    result = sub.run()

    # hypothesis proposed, state ok, crash audited
    assert result.status == "ok"
    assert len(graph.by_type("hypothesis")) == 1
    events = [json.loads(l) for l in open(audit.path, encoding="utf-8") if l.strip()]
    assert "enrichment_failed" in [e["event"] for e in events]
    ok, reason = audit.verify()
    assert ok, reason

