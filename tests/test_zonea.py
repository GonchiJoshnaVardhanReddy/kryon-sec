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


def test_recon_passive_collects_paths_as_nodes(tmp_path):
    from kryonsec.purple.zonea import PassiveResult

    def fake_wayback(domain):
        return PassiveResult(
            source="wayback",
            subdomains=[],
            paths=["/login", "/admin", "/api/v1?x=2"],
        )

    sub, audit, graph = _make_sub(tmp_path, [fake_wayback])
    result = sub.run()

    assert result.status == "ok"
    assert [n["label"] for n in graph.by_type("path")] == ["/login", "/admin", "/api/v1?x=2"]

    ok, reason = audit.verify()
    assert ok, reason


def test_prompt_includes_paths():
    """Thin targets (no subdomains) still give the LLM path evidence."""
    from kryonsec.purple.hypothesize import render_hypothesize_prompt

    graph = EngagementGraph(engagement_id="e-thin")
    graph.add_node("target", "testasp.vulnweb.com", {})
    graph.add_node("path", "/", {"source": "wayback"})
    graph.add_node("path", "/login.asp", {"source": "wayback"})

    prompt = render_hypothesize_prompt(graph)
    assert "testasp.vulnweb.com" in prompt
    assert "/login.asp" in prompt
    # subdomains section shows the "none found" fallback
    assert "(none found)" in prompt


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
    """Wayback CDX rows -> in-scope subdomain hosts + cleaned path list."""
    import json as _json
    from unittest.mock import patch

    rows = _json.dumps([
        ["urlkey", "timestamp", "original"],  # CDX header row
        ["com,target-corp)/", "20200101", "http://target-corp.com/"],
        ["com,target-corp,api)/", "20200102", "http://api.target-corp.com/v1"],
        ["com,target-corp,www)/", "20200103", "https://www.target-corp.com/login?x=1"],
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
    # paths are scheme-less, deduped, in order
    assert result.paths == ["/", "/v1", "/login?x=1"]


def test_wayback_subdomains_dedupes_paths():
    import json as _json
    from unittest.mock import patch

    rows = _json.dumps([
        ["com,target-corp)/", "20200101", "http://target-corp.com/a"],
        ["com,target-corp)/", "20200201", "http://target-corp.com/a"],  # dup
    ]).encode()

    from kryonsec.purple.zonea import wayback_subdomains

    with patch("kryonsec.purple.zonea._zone_a_fetch", return_value=rows):
        result = wayback_subdomains("target-corp.com")

    assert result.paths == ["/a"]


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


# ---- tool-expansion Phase 2 (2026-09-13): new Zone A sources ----------------

def test_in_scope_subdomains_filters_names():
    from kryonsec.purple.zonea import _in_scope_subdomains

    names = [
        "www.target-corp.com",
        "target-corp.com",        # the apex — in scope, kept
        "*.api.target-corp.com",  # wildcard stripped
        "target-corp.com.evil.com",  # lookalike — dropped
        "target-corp.org",        # other TLD — dropped
        "not a domain!",          # malformed — dropped
        "",                       # empty — dropped
    ]
    assert _in_scope_subdomains(names, "target-corp.com") == [
        "api.target-corp.com", "target-corp.com", "www.target-corp.com",
    ]


def test_shodan_keyless_is_skipped_not_failed():
    from kryonsec.purple.zonea import shodan_subdomains

    result = shodan_subdomains("target-corp.com", api_key=None)
    assert result.subdomains == []
    assert result.skipped and "shodan_api_key" in result.skipped


def test_shodan_parses_labels():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple.zonea import shodan_subdomains

    payload = _json.dumps({
        "domain": "target-corp.com",
        "subdomains": ["www", "api", "mail"],
        "data": [],
    }).encode()
    with patch("kryonsec.purple.zonea._zone_a_fetch", return_value=payload):
        result = shodan_subdomains("target-corp.com", api_key="sh-key")

    assert result.skipped is None
    assert result.subdomains == [
        "api.target-corp.com", "mail.target-corp.com", "www.target-corp.com",
    ]


def test_censys_keyless_is_skipped_not_failed():
    from kryonsec.purple.zonea import censys_subdomains

    # either credential missing -> skipped, never a failure
    assert censys_subdomains("target-corp.com").skipped
    assert censys_subdomains("target-corp.com", api_id="id").skipped
    assert censys_subdomains("target-corp.com", api_secret="sec").skipped


def test_censys_posts_search_and_scopes_names():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple.zonea import censys_subdomains

    payload = _json.dumps({
        "result": {"hits": [
            {"names": ["www.target-corp.com", "api.target-corp.com"]},
            {"names": ["evil.com"]},  # out of scope — dropped
        ]},
    }).encode()
    captured: dict = {}

    def fake_fetch(url, timeout=20, headers=None, data=None):
        captured["url"] = url
        captured["headers"] = headers or {}
        captured["data"] = data
        return payload

    with patch("kryonsec.purple.zonea._zone_a_fetch", side_effect=fake_fetch):
        result = censys_subdomains(
            "target-corp.com", api_id="cid", api_secret="csecret")

    assert result.subdomains == ["api.target-corp.com", "www.target-corp.com"]
    assert captured["url"] == "https://search.censys.io/api/v2/hosts/search"
    assert captured["headers"]["Authorization"].startswith("Basic ")
    # POST body is the search query, not a GET query string
    assert _json.loads(captured["data"]) == {
        "q": "names: target-corp.com", "per_page": 100}


def test_otx_passive_dns_scopes_hostnames():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple.zonea import otx_passive_dns

    payload = _json.dumps({
        "passive_dns": [
            {"hostname": "www.target-corp.com"},
            {"hostname": "mail.target-corp.com"},
            {"hostname": "evil.com"},          # out of scope — dropped
            {"hostname": "target-corp.com.evil.com"},  # lookalike — dropped
        ],
    }).encode()
    with patch("kryonsec.purple.zonea._zone_a_fetch", return_value=payload):
        result = otx_passive_dns("target-corp.com")

    assert result.subdomains == [
        "mail.target-corp.com", "www.target-corp.com"]


def test_ripestat_whois_extracts_notes_only():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple.zonea import ripestat_whois

    payload = _json.dumps({"data": {"records": [
        {"key": "registrar", "value": "Example Registrar, Inc."},
        {"key": "creation date", "value": "2010-01-01T00:00:00Z"},
        {"key": "noise-not-wanted", "value": "x"},  # filtered out
        {"key": "", "value": "no key either"},      # filtered out
    ]}}).encode()
    with patch("kryonsec.purple.zonea._zone_a_fetch", return_value=payload):
        result = ripestat_whois("target-corp.com")

    assert result.subdomains == []
    assert "registrar: Example Registrar, Inc." in result.notes
    assert any(n.startswith("creation date:") for n in result.notes)
    assert not any("noise" in n for n in result.notes)


def test_ripestat_asn_builds_notes_from_chain_and_network_info():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple.zonea import ripestat_asn

    chain = _json.dumps({"data": {"resolve": [
        {"A": {"records": ["203.0.113.10", "203.0.113.10", "not-an-ip"]}},
    ]}}).encode()
    info = _json.dumps({"data": {
        "asn": "64512", "holder": "ACME Networks", "prefix": "203.0.113.0/24",
    }}).encode()

    def fake_fetch(url, timeout=20, headers=None, data=None):
        return chain if "dns-chain" in url else info

    with patch("kryonsec.purple.zonea._zone_a_fetch", side_effect=fake_fetch):
        result = ripestat_asn("target-corp.com")

    assert result.subdomains == []
    assert result.notes[0] == "resolves (per RIPEstat) to: 203.0.113.10"
    assert "announced by 64512 (ACME Networks) in prefix 203.0.113.0/24" \
        in result.notes


def test_ripestat_asn_no_ips_is_empty_not_error():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple.zonea import ripestat_asn

    chain = _json.dumps({"data": {"resolve": []}}).encode()
    with patch("kryonsec.purple.zonea._zone_a_fetch", return_value=chain):
        result = ripestat_asn("target-corp.com")

    assert result.subdomains == []
    assert result.notes == []


def test_zone_a_allowlist_includes_phase8_hosts():
    from kryonsec.purple.zonea import ZONE_A_ALLOWED_HOSTS

    # Phase 8 passive sources: RDAP bootstrap, GitHub API, HackerTarget DNS
    # history — every new fetch goes through the same host allowlist
    assert "data.iana.org" in ZONE_A_ALLOWED_HOSTS
    assert "api.github.com" in ZONE_A_ALLOWED_HOSTS
    assert "api.hackertarget.com" in ZONE_A_ALLOWED_HOSTS


# ---- RDAP WHOIS (Phase 8) --------------------------------------------------

def test_rdap_whois_extracts_registry_notes():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import rdap_whois

    bootstrap = _json.dumps({
        "services": [[["com", "net"], ["https://rdap.example-registry.net"]]],
    }).encode()
    rdap_record = _json.dumps({
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"},
            {"eventAction": "expiration", "eventDate": "2027-01-02T00:00:00Z"},
        ],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]],
        }],
        "status": ["client transfer prohibited"],
        "nameservers": [{"ldhName": "NS1.target-corp.com"}],
    }).encode()
    calls: list = []

    def fake_fetch(url, timeout=20, headers=None, data=None, **kw):
        calls.append((url, kw))
        return bootstrap if "data.iana.org" in url else rdap_record

    with patch.object(zonea, "_zone_a_fetch", side_effect=fake_fetch):
        result = rdap_whois("target-corp.com")

    assert result.subdomains == []  # whois is notes-only
    assert "registrar: Example Registrar Inc." in result.notes
    assert "registration: 2020-01-02" in result.notes
    assert "expiration: 2027-01-02" in result.notes
    assert "status: client transfer prohibited" in result.notes
    assert "nameservers: ns1.target-corp.com" in result.notes
    # the registry query went to the IANA-derived base, not a fixed host
    registry_calls = [c for c in calls if "iana.org" not in c[0]]
    assert len(registry_calls) == 1
    assert registry_calls[0][0] == "https://rdap.example-registry.net/domain/target-corp.com"


def test_rdap_whois_extends_allowlist_only_with_bootstrap_host():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import ZONE_A_ALLOWED_HOSTS, rdap_whois

    bootstrap = _json.dumps({
        "services": [[["com"], ["https://rdap.verisign.com"]]],
    }).encode()

    def fake_fetch(url, timeout=20, headers=None, data=None, **kw):
        if "data.iana.org" in url:
            return bootstrap
        # the RDAP query must allow ONLY base list + the bootstrap host
        assert kw.get("allowed_hosts") == set(ZONE_A_ALLOWED_HOSTS) | {"rdap.verisign.com"}
        return b'{"events": []}'

    with patch.object(zonea, "_zone_a_fetch", side_effect=fake_fetch):
        result = rdap_whois("target-corp.com")

    assert result.notes == []


def test_rdap_whois_failures_are_empty_not_errors():
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import rdap_whois

    # bootstrap unreachable -> empty
    with patch.object(zonea, "_zone_a_fetch", side_effect=OSError("down")):
        assert rdap_whois("target-corp.com").subdomains == []
    # TLD absent from bootstrap -> empty, no second fetch
    with patch.object(
        zonea, "_zone_a_fetch",
        return_value=b'{"services": [["zzz", ["https://rdap.nowhere"]]]}',
    ):
        assert rdap_whois("target-corp.com").subdomains == []


# ---- GitHub recon (Phase 8) ------------------------------------------------

def test_github_recon_keyless_finds_orgs_and_repos():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import github_recon

    users = _json.dumps({"items": [{"login": "target-corp"}]}).encode()
    repos = _json.dumps({"items": [
        # repo whose name hides a subdomain-shaped hostname
        {"full_name": "target-corp/www.target-corp.com",
         "name": "www.target-corp.com"},
        # ordinary repo — note only, no subdomain
        {"full_name": "target-corp/legacy-api", "name": "legacy-api"},
    ]}).encode()
    code = _json.dumps({"items": []}).encode()

    def fake_fetch(url, timeout=20, headers=None, data=None, **kw):
        # every request stays on the allowlisted GitHub API host
        assert url.startswith("https://api.github.com/")
        for path, payload in (
            ("/search/users", users), ("/search/repositories", repos),
            ("/search/code", code),
        ):
            if path in url:
                return payload
        raise AssertionError(f"unexpected url {url}")

    with patch.object(zonea, "_zone_a_fetch", side_effect=fake_fetch):
        result = github_recon("target-corp.com")  # no token

    assert result.subdomains == ["www.target-corp.com"]
    assert "github org/user: target-corp" in result.notes
    assert "github repo: target-corp/www.target-corp.com" in result.notes
    assert "github repo: target-corp/legacy-api" in result.notes
    # keyless code search is an explicit operator hint, not a silent gap
    assert any("GITHUB_TOKEN" in n for n in result.notes)


def test_github_recon_token_adds_code_hits_without_fetching_them():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import github_recon

    empty = _json.dumps({"items": []}).encode()
    code = _json.dumps({"items": [{
        "repository": {"full_name": "ex-employee/scripts"},
        "path": "deploy/config.env",
    }]}).encode()
    seen_headers: list = []
    seen_urls: list = []

    def fake_fetch(url, timeout=20, headers=None, data=None, **kw):
        seen_urls.append(url)
        if "/search/code" in url:
            seen_headers.append(headers or {})
            return code
        return empty

    with patch.object(zonea, "_zone_a_fetch", side_effect=fake_fetch):
        result = github_recon("target-corp.com", token="gh-token")

    assert "github code hit (not fetched): ex-employee/scripts/deploy/config.env" \
        in result.notes
    assert not any("GITHUB_TOKEN" in n for n in result.notes)  # token present
    # the token went out as a bearer header and was never logged anywhere
    assert seen_headers[0]["Authorization"] == "Bearer gh-token"
    # raw file contents are NEVER fetched — only the three search endpoints
    assert len(seen_urls) == 3


def test_github_recon_rate_limit_is_empty_not_error():
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import github_recon

    with patch.object(zonea, "_zone_a_fetch", side_effect=OSError("rate limited")):
        result = github_recon("target-corp.com", token="gh-token")

    assert result.subdomains == []
    assert result.skipped is None  # a fact of life for the free API, not a skip


# ---- HackerTarget DNS history (Phase 8) -------------------------------------

def test_hackertarget_hostsearch_parses_host_ip_pairs():
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import hackertarget_hostsearch

    body = (
        "www.target-corp.com,1.2.3.4\n"
        "mail.target-corp.com,5.6.7.8\n"
        "evil.com,9.9.9.9\n"          # out of scope — dropped
        "not-a-host\n"                # malformed line — ignored
    ).encode()

    with patch.object(zonea, "_zone_a_fetch", return_value=body):
        result = hackertarget_hostsearch("target-corp.com")

    assert result.subdomains == ["mail.target-corp.com", "www.target-corp.com"]
    assert result.notes == ["historical records point at: 1.2.3.4, 5.6.7.8"]


def test_hackertarget_rate_limit_is_clean_empty():
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import hackertarget_hostsearch

    for body in (b"API count exceeded - increase quota", b"error check params"):
        with patch.object(zonea, "_zone_a_fetch", return_value=body):
            result = hackertarget_hostsearch("target-corp.com")
        assert result.subdomains == []
        assert result.notes == []
        assert result.skipped is None  # audited empty, not a failure


# ---- cloud asset discovery (Phase 8) ----------------------------------------

def test_cloud_asset_notes_classifies_by_provider():
    from kryonsec.purple.zonea import cloud_asset_notes

    result = cloud_asset_notes([
        "cdn.target-corp.com.s3.amazonaws.com",
        "app.target-corp.com.azurewebsites.net",
        "www.target-corp.com",  # not cloud — ignored
    ])

    assert result.subdomains == []  # notes-only source
    assert result.notes == [
        "cloud (amazonaws): 1 asset(s): cdn.target-corp.com.s3.amazonaws.com",
        "cloud (azurewebsites): 1 asset(s): app.target-corp.com.azurewebsites.net",
    ]


def test_cloud_asset_notes_empty_when_no_cloud_hosts():
    from kryonsec.purple.zonea import cloud_asset_notes

    result = cloud_asset_notes(["www.target-corp.com", "mail.target-corp.com"])
    assert result.notes == []
    assert cloud_asset_notes(None).notes == []


def test_recon_passive_runs_cloud_asset_pass_and_audits_it(tmp_path):
    from kryonsec.purple.zonea import PassiveResult

    def s3ish(domain):
        return PassiveResult(
            source="crt.sh",
            subdomains=["cdn.target-corp.com.s3.amazonaws.com",
                        "www.target-corp.com"],
        )

    s3ish.__name__ = "crt_sh_subdomains"
    sub, audit, graph = _make_sub(tmp_path, [s3ish])
    sub.run()

    # the cloud pass becomes an osint note in the graph
    cloud_nodes = [n for n in graph.by_type("osint_note")
                   if n["label"] == "cloud-assets"]
    assert len(cloud_nodes) == 1
    assert any("amazonaws" in note for note in cloud_nodes[0]["properties"]["notes"])
    # ...and a passive_source_ok audit event, like every source
    import json as _json
    events = [_json.loads(line) for line in audit.path.read_text().splitlines()]
    assert any(
        e.get("event") == "passive_source_ok" and e.get("source") == "cloud-assets"
        for e in events)


# ---- crt.sh certificate enrichment (Phase 8) --------------------------------

def test_crt_sh_notes_latest_certificate_issuer():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import crt_sh_subdomains

    payload = _json.dumps([
        {"name_value": "old.target-corp.com",
         "entry_timestamp": "2024-01-01T00:00:00Z",
         "issuer_name": "CN=Old CA", "not_before": "2023-12-01T00:00:00Z",
         "not_after": "2024-03-01T00:00:00Z"},
        {"name_value": "www.target-corp.com\napi.target-corp.com",
         "entry_timestamp": "2026-06-01T00:00:00Z",
         "issuer_name": "CN=Let's Encrypt R11",
         "not_before": "2026-06-01T00:00:00Z",
         "not_after": "2026-09-01T00:00:00Z"},
    ]).encode()

    with patch.object(zonea, "_zone_a_fetch", return_value=payload):
        result = crt_sh_subdomains("target-corp.com")

    assert result.notes == [
        "latest cert issuer: Let's Encrypt R11 "
        "(2026-06-01 → 2026-09-01, 2 name(s))"
    ]


def test_crt_sh_enrichment_never_fails_the_source():
    import json as _json
    from unittest.mock import patch

    from kryonsec.purple import zonea
    from kryonsec.purple.zonea import crt_sh_subdomains

    # entry_timestamp missing entirely — max() over defaults must not crash
    payload = _json.dumps([{"name_value": "www.target-corp.com"}]).encode()
    with patch.object(zonea, "_zone_a_fetch", return_value=payload):
        result = crt_sh_subdomains("target-corp.com")

    assert result.subdomains == ["www.target-corp.com"]
    # issuer is empty -> no note, but the subdomains still land
    assert result.notes == []


def test_zone_a_fetchers_list_for_config():
    from kryonsec.purple.recon_passive import zone_a_fetchers

    cfg = KryonsecConfig()
    fetchers = zone_a_fetchers(cfg)
    # keyed sources are included even without keys — they skip visibly;
    # Phase 8 adds rdap, github, hackertarget (cloud-assets is a local pass,
    # not a fetcher in this list)
    assert {f.__name__ for f in fetchers} == {
        "crt_sh_subdomains", "wayback_subdomains", "otx_passive_dns",
        "ripestat_whois", "ripestat_asn", "rdap_whois", "github",
        "hackertarget_hostsearch", "shodan", "censys",
    }


def test_zone_a_fetchers_pass_keys_through():
    from unittest.mock import patch

    from kryonsec.purple import recon_passive, zonea
    from kryonsec.purple.recon_passive import zone_a_fetchers

    cfg = KryonsecConfig()
    cfg.shodan_api_key = "sh-key"
    cfg.censys_api_id = "cid"
    cfg.censys_api_secret = "csecret"
    cfg.github_token = "gh-token"

    seen: dict = {}

    def fake_shodan(domain, api_key=None):
        seen["shodan"] = api_key
        return _pr("shodan")

    def fake_censys(domain, api_id=None, api_secret=None):
        seen["censys"] = (api_id, api_secret)
        return _pr("censys")

    def fake_github(domain, token=None):
        seen["github"] = token
        return _pr("github")

    # patch every source the list runs so the test stays offline: the plain
    # functions are bound in recon_passive's namespace (imported at module
    # load), the closures (shodan/censys/github) import from zonea at call
    # time — so both namespaces need patching
    with patch.object(zonea, "shodan_subdomains", fake_shodan), \
         patch.object(zonea, "censys_subdomains", fake_censys), \
         patch.object(zonea, "github_recon", fake_github), \
         patch.object(recon_passive, "crt_sh_subdomains",
                      lambda d, **k: _pr("crt.sh")), \
         patch.object(recon_passive, "wayback_subdomains",
                      lambda d, **k: _pr("wayback")), \
         patch.object(recon_passive, "otx_passive_dns",
                      lambda d: _pr("otx")), \
         patch.object(recon_passive, "ripestat_whois",
                      lambda d: _pr("ripestat-whois")), \
         patch.object(recon_passive, "ripestat_asn",
                      lambda d: _pr("ripestat-asn")), \
         patch.object(recon_passive, "rdap_whois",
                      lambda d: _pr("rdap")), \
         patch.object(recon_passive, "hackertarget_hostsearch",
                      lambda d: _pr("hackertarget")):
        for fetcher in zone_a_fetchers(cfg):
            fetcher("target-corp.com")

    assert seen["shodan"] == "sh-key"
    assert seen["censys"] == ("cid", "csecret")
    assert seen["github"] == "gh-token"


def _pr(source):
    from kryonsec.purple.zonea import PassiveResult
    return PassiveResult(source=source, subdomains=[])


def test_recon_passive_skipped_source_is_notice_not_failure(tmp_path):
    from kryonsec.purple.zonea import PassiveResult

    def keyless(domain):
        return PassiveResult(
            source="shodan", subdomains=[],
            skipped="no shodan_api_key configured (kryonsec setup)")

    keyless.__name__ = "shodan"  # the audit records the fetcher's name

    def working(domain):
        return PassiveResult(source="crt.sh", subdomains=["www.target-corp.com"])

    sub, audit, graph = _make_sub(tmp_path, [keyless, working])
    result = sub.run()

    assert result.status == "ok"
    # the working source still landed
    assert [n["label"] for n in graph.by_type("subdomain")] == ["www.target-corp.com"]
    # the skip is a visible audit notice
    import json
    with open(audit.path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    skips = [e for e in events if e["event"] == "passive_source_skipped"]
    assert len(skips) == 1
    assert skips[0]["source"] == "shodan"
    assert "shodan_api_key" in skips[0]["reason"]
    # and never an ok/failure event for the skipped source
    assert not any(e["event"] == "passive_source_ok" and e["source"] == "shodan"
                   for e in events)
    ok, reason = audit.verify()
    assert ok, reason


def test_recon_passive_notes_become_osint_nodes(tmp_path):
    from kryonsec.purple.zonea import PassiveResult

    def whois(domain):
        return PassiveResult(
            source="ripestat-whois", subdomains=[],
            notes=["registrar: Example Registrar", "creation date: 2010-01-01"])

    sub, audit, graph = _make_sub(tmp_path, [whois])
    result = sub.run()

    assert result.status == "ok"
    notes_nodes = graph.by_type("osint_note")
    assert len(notes_nodes) == 1
    assert notes_nodes[0]["label"] == "ripestat-whois"
    assert notes_nodes[0]["properties"]["notes"] == [
        "registrar: Example Registrar", "creation date: 2010-01-01"]
    ok, reason = audit.verify()
    assert ok, reason


def test_prompt_includes_osint_notes():
    from kryonsec.purple.hypothesize import render_hypothesize_prompt

    graph = EngagementGraph(engagement_id="e-notes")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("osint_note", "ripestat-whois", {
        "notes": ["registrar: Example Registrar", "creation date: 2010-01-01"],
    })

    prompt = render_hypothesize_prompt(graph)
    assert "[ripestat-whois] registrar: Example Registrar" in prompt
    assert "[ripestat-whois] creation date: 2010-01-01" in prompt


# ---- sandboxed passive enumeration (Phase 2) --------------------------------

class _FakeSpawn:
    def __init__(self, ok: bool, exit_code: int, stdout: str):
        self.ok = ok
        self.exit_code = exit_code
        self.stdout = stdout


class _FakeSandbox:
    """Stands in for KaliSandbox.spawn: records argv, replays results."""

    def __init__(self, results: list[_FakeSpawn]):
        self.results = list(results)
        self.argvs: list[list[str]] = []

    def spawn(self, argv):
        self.argvs.append(argv)
        return self.results.pop(0)


def test_sandbox_passive_fetcher_runs_all_three_tools(tmp_path):
    from kryonsec.purple.allowlist import ToolAllowlist
    from kryonsec.purple.recon_passive import sandbox_passive_fetcher

    sandbox = _FakeSandbox([
        _FakeSpawn(True, 0, "www.target-corp.com\napi.target-corp.com\n"),
        _FakeSpawn(True, 0, "www.target-corp.com\nmail.target-corp.com\n"),
        _FakeSpawn(True, 0, "vpn.target-corp.com\n"),
    ])
    audit = AuditLog(tmp_path / "audit.jsonl")
    fetch = sandbox_passive_fetcher(sandbox, audit, allowlist=ToolAllowlist())

    result = fetch("target-corp.com")

    assert result.source == "sandbox-passive"
    assert result.subdomains == [
        "api.target-corp.com", "mail.target-corp.com",
        "vpn.target-corp.com", "www.target-corp.com",
    ]
    # argv lists match what the allowlist actually validates
    tools = [argv[0] for argv in sandbox.argvs]
    assert tools == ["subfinder", "amass", "assetfinder"]
    for argv in sandbox.argvs:
        assert "target-corp.com" in argv
    assert "-passive" in sandbox.argvs[0]      # subfinder
    assert "-passive" in sandbox.argvs[1]      # amass
    # every spawn + result is audited with the RECON_PASSIVE state
    import json
    with open(audit.path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    spawns = [e for e in events if e["event"] == "tool_spawn"]
    assert len(spawns) == 3
    assert all(e["state"] == "RECON_PASSIVE" for e in spawns)
    assert len([e for e in events if e["event"] == "tool_result"]) == 3
    ok, reason = audit.verify()
    assert ok, reason


def test_sandbox_passive_fetcher_scopes_output(tmp_path):
    from kryonsec.purple.allowlist import ToolAllowlist
    from kryonsec.purple.recon_passive import sandbox_passive_fetcher

    sandbox = _FakeSandbox([
        _FakeSpawn(True, 0, "www.target-corp.com\n"
                            "evil.com\n"                  # other domain
                            "target-corp.com.evil.com\n"  # lookalike
                            "target-corp.com\n"),         # the apex (target node)
        _FakeSpawn(False, 1, ""),  # amass fails — must not kill the others
        _FakeSpawn(True, 0, "api.target-corp.com\n"),
    ])
    audit = AuditLog(tmp_path / "audit.jsonl")
    fetch = sandbox_passive_fetcher(sandbox, audit, allowlist=ToolAllowlist())

    result = fetch("target-corp.com")

    # only hosts strictly under the target count
    assert result.subdomains == ["api.target-corp.com", "www.target-corp.com"]
    # the failed tool produced a tool_result event with ok=False
    import json
    with open(audit.path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    results = [e for e in events if e["event"] == "tool_result"]
    assert [e["ok"] for e in results] == [True, False, True]
