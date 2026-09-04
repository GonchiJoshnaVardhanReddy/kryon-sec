"""Web search (spec v2.1.1 §3.7): Copilot-mode general web search.

Egress allowlist: only DuckDuckGo's HTML endpoint (no API key, no
tracking param). Results are titles + snippet text + URLs, cached in
system_knowledge keyed by the query hash so repeat queries work
offline. Never used in Purple mode — engagement data stays local.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import re
import time
import urllib.parse
import urllib.request
from typing import Any

from ..config import KryonsecConfig
from ..storage import SystemKnowledge, get_session as db_session

log = logging.getLogger(__name__)

DDG_URL = "https://html.duckduckgo.com/html/?q={query}"
DDG_TIMEOUT_S = 15
MAX_RESULTS = 5
CACHE_TTL_S = 24 * 3600  # one day — search results go stale fast
CACHE_CATEGORY = "web_search"

# result link + snippet lines from the HTML endpoint
_RESULT_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.S,
)
_SNIPPET_RE = re.compile(
    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.S
)


def _cache_key(query: str) -> str:
    return hashlib.sha256(query.strip().lower().encode("utf-8")).hexdigest()[:16]


def _from_cache(cfg: KryonsecConfig, query: str) -> list[dict[str, Any]] | None:
    try:
        with db_session(cfg) as s:
            row = (
                s.query(SystemKnowledge)
                .filter_by(category=CACHE_CATEGORY, key=_cache_key(query))
                .one_or_none()
            )
            if not row:
                return None
            value = dict(row.value)
            if time.time() - value.get("fetched_at", 0) > CACHE_TTL_S:
                return None  # stale
            return value.get("results")
    except Exception as e:
        log.debug("cache read failed: %s", e)
        return None


def _to_cache(cfg: KryonsecConfig, query: str, results: list[dict]) -> None:
    try:
        with db_session(cfg) as s:
            row = (
                s.query(SystemKnowledge)
                .filter_by(category=CACHE_CATEGORY, key=_cache_key(query))
                .one_or_none()
            )
            payload = {"fetched_at": time.time(), "results": results}
            if row:
                row.value = payload
            else:
                s.add(SystemKnowledge(
                    category=CACHE_CATEGORY, key=_cache_key(query), value=payload,
                ))
            s.commit()
    except Exception as e:
        log.debug("cache write failed: %s", e)


def _strip_tags(fragment: str) -> str:
    text = re.sub(r"<[^>]+>", "", fragment)
    return html.unescape(text).strip()


def _clean_url(raw_url: str) -> str:
    """The HTML endpoint wraps URLs in a redirect (uddg=). Unwrap it."""
    if "uddg=" in raw_url:
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(raw_url).query)
        if "uddg" in params:
            return params["uddg"][0]
    return raw_url


def _from_ddg(query: str) -> list[dict[str, Any]] | None:
    """Fetch and parse the DuckDuckGo HTML results page."""
    url = DDG_URL.format(query=urllib.parse.quote_plus(query))
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        })
        with urllib.request.urlopen(req, timeout=DDG_TIMEOUT_S) as r:
            page = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        log.info("DDG fetch failed for %r: %s", query, e)
        return None

    results: list[dict[str, Any]] = []
    links = _RESULT_RE.findall(page)
    snippets = _SNIPPET_RE.findall(page)
    for i, (href, title) in enumerate(links[:MAX_RESULTS]):
        snippet = _strip_tags(snippets[i]) if i < len(snippets) else ""
        results.append({
            "title": _strip_tags(title),
            "url": _clean_url(html.unescape(href)),
            "snippet": snippet,
        })
    return results


def search_web(cfg: KryonsecConfig, query: str) -> list[dict[str, Any]] | None:
    """Search the web. Cache first (1-day TTL), DuckDuckGo second.

    Returns a list of {title, url, snippet} dicts, or None when the
    fetch failed (caller shows a friendly offline message).
    """
    query = query.strip()
    if not query:
        return []

    cached = _from_cache(cfg, query)
    if cached is not None:
        return cached

    results = _from_ddg(query)
    if results:
        _to_cache(cfg, query, results)
    return results
