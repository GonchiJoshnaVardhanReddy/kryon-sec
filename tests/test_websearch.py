"""Tests for the Copilot web search tool (spec §3.7)."""

import time

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.websearch import (
    _cache_key,
    _clean_url,
    _from_ddg,
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
