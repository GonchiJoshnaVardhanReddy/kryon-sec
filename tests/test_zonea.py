"""Tests for RECON_PASSIVE Zone A (spec v2.1.1 §8.3).

The core invariant: passive recon sends ZERO packets to the target. The
network layer is injected/mocked so tests run fully offline.
"""

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_passive import EngagementGraph, ReconPassiveSubagent
from kryonsec.purple.zonea import (
    DOMAIN_RE,
    ZoneAViolation,
    _same_domain,
    _zone_a_fetch,
    crt_sh_subdomains,
    normalize_target,
    validate_target,
)


# ---- target normalization / validation --------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("http://testasp.vulnweb.com/", "testasp.vulnweb.com"),
    ("https://example.com/path/page?q=1", "example.com"),
    ("example.com:8080", "example.com"),
    ("example.com", "example.com"),
    ("  Example.COM.  ", "example.com"),
    ("sub.example.com/path", "sub.example.com"),
])
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


@pytest.mark.parametrize("bad", ["", "not a domain", "http://", "localhost", "999.999"])
def test_validate_target_rejects_garbage(bad):
    with pytest.raises(ValueError):
        validate_target(bad)


def test_validate_target_accepts_urls():
    assert validate_target("http://testasp.vulnweb.com/") == "testasp.vulnweb.com"


# ---- Zone A egress allowlist ----------------------------------------------

def test_zone_a_refuses_non_allowlisted_host():
    with pytest.raises(ZoneAViolation):
        _zone_a_fetch("https://evil.example.com/data")


def test_zone_a_refuses_the_target_itself():
    with pytest.raises(ZoneAViolation):
        _zone_a_fetch("https://target-corp.com/")  # no packets to the target


# ---- domain scoping --------------------------------------------------------

@pytest.mark.parametrize("sub, domain, expected", [
    ("target-corp.com", "target-corp.com", True),
    ("www.target-corp.com", "target-corp.com", True),
    ("deep.api.target-corp.com", "target-corp.com", True),
    ("target-corp.com.evil.com", "target-corp.com", False),  # lookalike
    ("target-corp.org", "target-corp.com", False),  # other TLD
    ("nottarget-corp.com", "target-corp.com", False),  # prefix trick
])
def test_same_domain_scoping(sub, domain, expected):
    assert _same_domain(sub, domain) is expected


# ---- subagent behavior -----------------------------------------------------

def _make_sub(tmp_path, fetchers):
    cfg = KryonsecConfig()
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-test")
    return ReconPassiveSubagent(
        cfg=cfg, graph=graph, audit=audit, target="target-corp.com", fetchers=fetchers,
    ), audit, graph


def test_recon_passive_collects_subdomains(tmp_path):
    from kryonsec.purple.zonea import PassiveResult

    def fake_crt(domain):
        return PassiveResult(source="crt.sh", subdomains=[
            "target-corp.com", "www.target-corp.com", "api.target-corp.com",
        ])

    sub, audit, graph = _make_sub(tmp_path, [fake_crt])
    result = sub.run()

    assert result.status == "ok"
    labels = {n["label"] for n in graph.by_type("subdomain")}
    assert labels == {"www.target-corp.com", "api.target-corp.com"}
    # target node exists, but is not also a subdomain node
    assert graph.by_type("target")[0]["label"] == "target-corp.com"


def test_recon_passive_dedupes_across_sources(tmp_path):
    from kryonsec.purple.zonea import PassiveResult

    def source_a(domain):
        return PassiveResult(source="a", subdomains=["www.target-corp.com"])

    def source_b(domain):
        return PassiveResult(source="b", subdomains=["www.target-corp.com", "mail.target-corp.com"])

    sub, audit, graph = _make_sub(tmp_path, [source_a, source_b])
    sub.run()
    labels = [n["label"] for n in graph.by_type("subdomain")]
    assert sorted(labels) == ["mail.target-corp.com", "www.target-corp.com"]


def test_recon_passive_source_failure_does_not_kill_state(tmp_path):
    def broken(domain):
        raise RuntimeError("source down")

    def working(domain):
        from kryonsec.purple.zonea import PassiveResult
        return PassiveResult(source="ok", subdomains=["www.target-corp.com"])

    sub, audit, graph = _make_sub(tmp_path, [broken, working])
    result = sub.run()
    assert result.status == "ok"
    assert len(graph.by_type("subdomain")) == 1

    ok, reason = audit.verify()
    assert ok, reason


def test_recon_passive_audits_every_call(tmp_path):
    from kryonsec.purple.zonea import PassiveResult

    def fake(domain):
        return PassiveResult(source="crt.sh", subdomains=["www.target-corp.com"])

    sub, audit, graph = _make_sub(tmp_path, [fake])
    sub.run()

    with open(audit.path, encoding="utf-8") as f:
        import json
        events = [json.loads(line)["event"] for line in f if line.strip()]
    assert "state_enter" in events
    assert "passive_source_ok" in events


def test_crt_sh_parses_names(tmp_path):
    """crt.sh JSON parsing: wildcard removal, newline-separated names."""
    import json as _json
    from unittest.mock import patch

    payload = _json.dumps([
        {"name_value": "*.target-corp.com"},
        {"name_value": "www.target-corp.com\napi.target-corp.com"},
        {"name_value": "evil.com"},  # out of scope — dropped
    ]).encode()

    with patch("kryonsec.purple.zonea._zone_a_fetch", return_value=payload):
        result = crt_sh_subdomains("target-corp.com")

    assert "target-corp.com" in result.subdomains  # wildcard base
    assert "www.target-corp.com" in result.subdomains
    assert "api.target-corp.com" in result.subdomains
    assert "evil.com" not in result.subdomains


def test_wayback_subdomains_extracts_hosts():
    """Wayback CDX rows -> in-scope subdomain hosts only."""
    import json as _json
    from unittest.mock import patch

    rows = _json.dumps([
        ["com,target-corp)/", "20200101", "http://target-corp.com/"],
        ["com,target-corp,api)/", "20200102", "http://api.target-corp.com/v1"],
        ["com,target-corp,www)/", "20200103", "https://www.target-corp.com/login"],
        ["com,evil)/", "20200104", "http://evil.com/target-corp"],
    ]).encode()

    from kryonsec.purple.zonea import wayback_subdomains

    with patch("kryonsec.purple.zonea._zone_a_fetch", return_value=rows):
        result = wayback_subdomains("target-corp.com")

    assert result.source == "wayback"
    assert result.subdomains == ["api.target-corp.com", "www.target-corp.com"]
    # the apex and out-of-scope hosts are excluded
    assert "target-corp.com" not in result.subdomains
    assert "evil.com" not in result.subdomains


def test_wayback_subdomains_network_failure_is_empty():
    from unittest.mock import patch

    from kryonsec.purple.zonea import wayback_subdomains

    with patch(
        "kryonsec.purple.zonea._zone_a_fetch",
        side_effect=RuntimeError("archive down"),
    ):
        result = wayback_subdomains("target-corp.com")

    assert result.subdomains == []
    assert result.source == "wayback"


def test_default_fetchers_include_both_sources():
    from kryonsec.purple.recon_passive import ReconPassiveSubagent

    cfg = KryonsecConfig()
    sub = ReconPassiveSubagent(
        cfg=cfg, graph=None, audit=None, target="x.com",
    )
    names = {f.__name__ for f in sub.fetchers}
    assert names == {"crt_sh_subdomains", "wayback_subdomains"}
