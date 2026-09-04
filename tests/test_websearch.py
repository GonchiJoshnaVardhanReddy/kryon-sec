"""Tests for the Copilot web search tool (spec §3.7)."""

import time

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.websearch import (
    _cache_key,
    _clean_url,
    _from_ddg,
    _from_ddg_api,
    _from_mojeek,
    _from_wikipedia,
    _strip_tags,
    search_web,
)
from kryonsec.storage import init_db, reset_engine


@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    c = KryonsecConfig(home=tmp_path / "home")
    c.database_url = f"sqlite:///{tmp_path / 'websearch.db'}"
    init_db(c)
    yield c
    reset_engine()

# a realistic slice of the DDG html endpoint markup
SAMPLE_HTML = """
<div class="result results_links results_links_deep web-result ">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnvd.nist.gov%2Fvuln%2Fdetail%2FCVE-2024-1234">CVE-2024-1234 - NVD</a>
  </h2>
  <a class="result__snippet" href="...">This vulnerability allows remote code execution in &lt;product&gt; when...</a>
</div>
<div class="result">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="https://example.org/advisory">Vendor advisory</a>
  </h2>
  <a class="result__snippet" href="...">The vendor released a patch in version 2.1. Read more.</a>
</div>
"""

# Mojeek markup: results use <a class="ob" ...> links + <p class="s"> snippets
MOJEEK_HTML = """
<ul class="results-standard">
<li><h2><a class="ob" href="https://owasp.org/www-community/attacks/SQL_Injection"
  data-ct="OWASP SQL Injection">OWASP SQL Injection <em>Attack</em></a></h2>
<p class="s">SQL injection is a code injection technique used to attack data-driven applications.</p></li>
<li><h2><a class="ob" href="https://portswigger.net/web-security/sql-injection">SQL Injection | Web Security Academy</a></h2>
<p class="s">Learn about SQL injection vulnerabilities and how to exploit them.</p></li>
</ul>
"""

DDG_API_JSON = """
{
  "Heading": "SQL injection",
  "AbstractText": "SQL injection is a code injection technique.",
  "AbstractURL": "https://en.wikipedia.org/wiki/SQL_injection",
  "RelatedTopics": [
    {"FirstURL": "https://owasp.org/sql", "Text": "OWASP - SQL injection resource"},
    {"Name": "Topic", "Topics": [
      {"FirstURL": "https://portswigger.net/sql", "Text": "PortSwigger - SQLi labs"}
    ]}
  ]
}
"""

WIKI_JSON = """
{"query": {"search": [
  {"title": "SQL injection", "snippet": "SQL injection is a code injection technique used to attack data-driven applications."},
  {"title": "Web application security", "snippet": "This is <span class=\\"searchmatch\\">security</span> of web apps."}
]}}
"""


def _patch_urlopen(monkeypatch, page: str):
    class Resp:
        def read(self):
            return page.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        "kryonsec.copilot.websearch.urllib.request.urlopen",
        lambda req, timeout: Resp(),
    )


# ---- helpers -----------------------------------------------------------

def test_strip_tags_unescapes_entities():
    assert _strip_tags("<b>RCE</b> in &lt;product&gt;") == "RCE in <product>"


def test_clean_url_unwraps_ddg_redirect():
    raw = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fnvd.nist.gov%2Fvuln"
    assert _clean_url(raw) == "https://nvd.nist.gov/vuln"


def test_clean_url_plain_url_untouched():
    assert _clean_url("https://example.org/advisory") == "https://example.org/advisory"


def test_cache_key_stable_and_case_insensitive():
    assert _cache_key("SQL injection") == _cache_key(" sql injection ")


# ---- parsing -----------------------------------------------------------

def test_from_ddg_parses_results(monkeypatch):
    _patch_urlopen(monkeypatch, SAMPLE_HTML)
    results = _from_ddg("CVE-2024-1234")
    assert results is not None
    assert len(results) == 2
    assert results[0]["title"] == "CVE-2024-1234 - NVD"
    assert results[0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    assert "remote code execution" in results[0]["snippet"]
    assert results[1]["url"] == "https://example.org/advisory"


def test_from_ddg_network_failure_returns_none(monkeypatch):
    def boom(req, timeout):
        raise OSError("network unreachable")

    monkeypatch.setattr(
        "kryonsec.copilot.websearch.urllib.request.urlopen", boom)
    assert _from_ddg("anything") is None


def test_from_ddg_no_results_empty_list(monkeypatch):
    _patch_urlopen(monkeypatch, "<html><body>nothing here</body></html>")
    assert _from_ddg("query") == []


def test_from_ddg_lite_fallback_when_html_empty(monkeypatch):
    """When the html endpoint serves a JS page (zero parsed results),
    fall back to the lite endpoint."""
    calls: list[str] = []

    class Resp:
        def __init__(self, page: str):
            self.page = page

        def read(self):
            return self.page.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        url = req.full_url
        calls.append(url)
        if "html.duckduckgo.com" in url:
            return Resp("<html><body>JS only</body></html>")
        assert "lite.duckduckgo.com" in url
        # the lite endpoint receives the query as a POST body
        assert req.data == b"q=fallback+test"
        return Resp("""
        <a rel="nofollow" href="https://example.com/page" class="result-link">Example page</a>
        <td class="result-snippet">A page about security</td>
        """)

    monkeypatch.setattr(
        "kryonsec.copilot.websearch.urllib.request.urlopen", fake_urlopen)
    results = _from_ddg("fallback test")
    assert len(calls) == 2  # html tried, then lite
    assert results is not None
    assert results[0]["title"] == "Example page"
    assert results[0]["url"] == "https://example.com/page"
    assert results[0]["snippet"] == "A page about security"


def test_from_ddg_falls_back_to_mojeek(monkeypatch):
    """DDG's web endpoints bot-challenge some IPs — Mojeek is the next
    source in the chain and has no bot wall."""
    calls: list[str] = []

    class Resp:
        def __init__(self, page: str):
            self.page = page

        def read(self):
            return self.page.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        calls.append(req.full_url)
        if "duckduckgo.com" in req.full_url:
            return Resp("<html><body>anomaly challenge page</body></html>")
        assert "mojeek.com" in req.full_url
        return Resp(MOJEEK_HTML)

    monkeypatch.setattr(
        "kryonsec.copilot.websearch.urllib.request.urlopen", fake_urlopen)
    results = _from_ddg("sql injection")
    # html + lite challenged, Mojeek answered
    assert len(calls) == 3
    assert results is not None and len(results) == 2
    assert results[0]["title"] == "OWASP SQL Injection Attack"
    assert results[0]["url"] == "https://owasp.org/www-community/attacks/SQL_Injection"
    assert "code injection technique" in results[0]["snippet"]
    assert results[1]["url"] == "https://portswigger.net/web-security/sql-injection"


def test_from_ddg_falls_back_to_ddg_api(monkeypatch):
    """Last resort: the Instant Answer JSON API (a real API — no bot
    wall)."""
    calls: list[str] = []

    class Resp:
        def __init__(self, page: str):
            self.page = page

        def read(self):
            return self.page.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        calls.append(req.full_url)
        if "api.duckduckgo.com" in req.full_url:
            return Resp(DDG_API_JSON)
        return Resp("<html><body>challenge</body></html>")

    monkeypatch.setattr(
        "kryonsec.copilot.websearch.urllib.request.urlopen", fake_urlopen)
    results = _from_ddg("sql injection")
    assert len(calls) == 4  # html, lite, mojeek, api
    assert results is not None
    assert results[0]["title"] == "SQL injection"
    assert results[0]["url"] == "https://en.wikipedia.org/wiki/SQL_injection"
    assert "code injection technique" in results[0]["snippet"]
    urls = [r["url"] for r in results]
    assert "https://owasp.org/sql" in urls
    # direct URLs pass through untouched (no DDG redirect to expand)
    assert "https://portswigger.net/sql" in urls


def test_from_ddg_all_sources_dead_returns_none(monkeypatch):
    def boom(req, timeout):
        raise OSError("network unreachable")

    monkeypatch.setattr(
        "kryonsec.copilot.websearch.urllib.request.urlopen", boom)
    assert _from_ddg("anything") is None


def test_from_mojeek_skips_own_nav_links(monkeypatch):
    _patch_urlopen(
        monkeypatch,
        '<a class="ob" href="https://www.mojeek.com/about">About Mojeek</a>'
        '<p class="s">about the engine</p>'
        '<a class="ob" href="https://real.example/page">Real page</a>'
        '<p class="s">real snippet</p>',
    )
    results = _from_mojeek("q")
    assert len(results) == 1
    assert results[0]["url"] == "https://real.example/page"


def test_from_ddg_api_invalid_json_returns_empty(monkeypatch):
    _patch_urlopen(monkeypatch, "<html>not json</html>")
    assert _from_ddg_api("q") == []


def test_ddg_topic_url_expands_redirect(monkeypatch):
    from kryonsec.copilot.websearch import _expand_ddg_topic_url

    assert _expand_ddg_topic_url(
        "https://duckduckgo.com/Code_injection"
    ) == "https://en.wikipedia.org/wiki/Code_injection"
    assert _expand_ddg_topic_url(
        "https://owasp.org/sql"
    ) == "https://owasp.org/sql"


# ---- Wikipedia source -----------------------------------------------------

def test_from_wikipedia_parses_results(monkeypatch):
    _patch_urlopen(monkeypatch, WIKI_JSON)
    results = _from_wikipedia("sql injection")
    assert results is not None
    assert len(results) == 2
    assert results[0]["title"] == "SQL injection"
    assert results[0]["url"] == "https://en.wikipedia.org/wiki/SQL_injection"
    assert "code injection technique" in results[0]["snippet"]
    # snippet markup is stripped
    assert "<span" not in results[1]["snippet"]
    assert "security" in results[1]["snippet"]


def test_from_wikipedia_error_json_returns_empty(monkeypatch):
    _patch_urlopen(monkeypatch, '{"error": "unknown"}')
    assert _from_wikipedia("q") == []


def test_from_ddg_falls_back_to_wikipedia(monkeypatch):
    """When every earlier source answers with nothing (bot-challenged),
    Wikipedia is the final keyless source that still answers."""
    calls: list[str] = []

    class Resp:
        def __init__(self, page: str):
            self.page = page

        def read(self):
            return self.page.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        calls.append(req.full_url)
        if "en.wikipedia.org" in req.full_url:
            return Resp(WIKI_JSON)
        return Resp("<html><body>challenge</body></html>")

    monkeypatch.setattr(
        "kryonsec.copilot.websearch.urllib.request.urlopen", fake_urlopen)
    results = _from_ddg("sql injection")
    assert len(calls) == 5  # html, lite, mojeek, api, wiki
    assert results is not None
    assert results[0]["title"] == "SQL injection"


# ---- search_web: cache behavior -----------------------------------------

def test_search_web_uses_cache_and_skips_fetch(monkeypatch, cfg):
    def never(req, timeout):
        raise AssertionError("must not fetch — cache should serve")

    monkeypatch.setattr(
        "kryonsec.copilot.websearch.urllib.request.urlopen", never)

    # seed the cache directly
    from kryonsec.copilot.websearch import _to_cache
    _to_cache(cfg, "cache test", [{"title": "t", "url": "u", "snippet": "s"}])

    results = search_web(cfg, "cache test")
    assert results == [{"title": "t", "url": "u", "snippet": "s"}]


def test_search_web_stale_cache_refetches(monkeypatch, cfg):
    # seed a stale cache entry (fetched "2 days ago")
    from kryonsec.storage import SystemKnowledge, get_session as db_session

    with db_session(cfg) as s:
        s.add(SystemKnowledge(
            category="web_search", key=_cache_key("stale query"),
            value={"fetched_at": time.time() - 2 * 24 * 3600,
                   "results": [{"title": "old", "url": "u", "snippet": "s"}]},
        ))
        s.commit()

    _patch_urlopen(monkeypatch, SAMPLE_HTML)
    results = search_web(cfg, "stale query")
    assert results is not None
    assert results[0]["title"] == "CVE-2024-1234 - NVD"  # fresh, not stale


def test_search_web_empty_query(monkeypatch, cfg):
    assert search_web(cfg, "   ") == []
