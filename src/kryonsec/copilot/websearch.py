"""Web search (spec v2.1.1 §3.7): Copilot-mode general web search.

Egress allowlist: DuckDuckGo's endpoints and Mojeek (no API keys, no
tracking params). Sources are tried in order until one answers: DDG html
endpoint, DDG lite (POST), Mojeek, DDG Instant Answer JSON API — the web
endpoints bot-challenge some IPs, so no single source is trusted.
Results are titles + snippet text + URLs, cached in system_knowledge
keyed by the query hash so repeat queries work offline. Never used in
Purple mode — engagement data stays local.
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
DDG_LITE_URL = "https://lite.duckduckgo.com/lite/?q={query}"
DDG_API_URL = "https://api.duckduckgo.com/?q={query}&format=json&no_html=1&skip_disambig=1"
MOJEEK_URL = "https://www.mojeek.com/search?q={query}"
WIKI_SEARCH_URL = (
    "https://en.wikipedia.org/w/api.php?action=query&list=search"
    "&srlimit={limit}&srsearch={query}&format=json"
)
DDG_TIMEOUT_S = 15
MAX_RESULTS = 5
CACHE_TTL_S = 24 * 3600  # one day — search results go stale fast
CACHE_CATEGORY = "web_search"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# result link + snippet lines from the HTML endpoint
_RESULT_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.S,
)
_SNIPPET_RE = re.compile(
    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.S
)

# lite endpoint: simple links + <td class="result-snippet">
_LITE_LINK_RE = re.compile(
    r'<a[^>]+href="([^"]+)"[^>]*class="result-link"[^>]*>(.*?)</a>',
    re.S,
)
_LITE_SNIPPET_RE = re.compile(
    r'class="result-snippet"[^>]*>(.*?)</td>', re.S
)
_LITE_BARE_LINK_RE = re.compile(
    r'<a[^>]+href="(http[^"]+)"[^>]*>(.*?)</a>', re.S
)

# Mojeek: independent index, serves plain HTML to every client
_MOJEEK_LINK_RE = re.compile(
    r'<a class="ob" href="([^"]+)"[^>]*>(.*?)</a>', re.S
)
_MOJEEK_SNIPPET_RE = re.compile(
    r'<p class="s">(.*?)</p>', re.S
)
_MOJEEK_BARE_LINK_RE = re.compile(
    r'<h2><a href="(http[^"]+)"[^>]*>(.*?)</a>', re.S
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


def _fetch(url: str, data: bytes | None = None) -> str | None:
    headers = {"User-Agent": USER_AGENT}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=DDG_TIMEOUT_S) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        log.info("search fetch failed for %s: %s", url, e)
        return None


def _from_ddg_html(query: str) -> list[dict[str, Any]] | None:
    page = _fetch(DDG_URL.format(query=urllib.parse.quote_plus(query)))
    if page is None:
        return None
    links = _RESULT_RE.findall(page)
    snippets = _SNIPPET_RE.findall(page)
    return [
        {
            "title": _strip_tags(title),
            "url": _clean_url(html.unescape(href)),
            "snippet": _strip_tags(snippets[i]) if i < len(snippets) else "",
        }
        for i, (href, title) in enumerate(links[:MAX_RESULTS])
    ]


def _from_ddg_lite(query: str) -> list[dict[str, Any]] | None:
    """The lite endpoint. Results come via POST (the GET page is just an
    empty search form); the html endpoint often serves a 202 bot-challenge
    instead of results."""
    body = urllib.parse.urlencode({"q": query}).encode("utf-8")
    page = _fetch(DDG_LITE_URL.format(query=""), data=body)
    if page is None:
        return None
    links = _LITE_LINK_RE.findall(page) or _LITE_BARE_LINK_RE.findall(page)
    snippets = _LITE_SNIPPET_RE.findall(page)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for href, title in links:
        href = html.unescape(href)
        url_out = _clean_url(href)
        # skip DDG's own navigation links
        if "duckduckgo.com" in url_out and "uddg=" not in href:
            continue
        if url_out in seen:
            continue
        seen.add(url_out)
        snippet = (
            _strip_tags(snippets[len(seen) - 1])
            if len(seen) - 1 < len(snippets) else ""
        )
        results.append({
            "title": _strip_tags(title) or url_out,
            "url": url_out,
            "snippet": snippet,
        })
        if len(results) >= MAX_RESULTS:
            break
    return results


def _from_mojeek(query: str) -> list[dict[str, Any]] | None:
    """Mojeek — an independent crawler index with no bot wall. Used when
    DuckDuckGo's web endpoints serve a challenge page."""
    page = _fetch(MOJEEK_URL.format(query=urllib.parse.quote_plus(query)))
    if page is None:
        return None
    links = _MOJEEK_LINK_RE.findall(page) or _MOJEEK_BARE_LINK_RE.findall(page)
    snippets = _MOJEEK_SNIPPET_RE.findall(page)
    results: list[dict[str, Any]] = []
    for href, title in links:
        href = html.unescape(href)
        if "mojeek.com" in href:
            continue
        if any(r["url"] == href for r in results):
            continue
        snippet = (
            _strip_tags(snippets[len(results)])
            if len(results) < len(snippets) else ""
        )
        results.append({
            "title": _strip_tags(title) or href,
            "url": href,
            "snippet": snippet,
        })
        if len(results) >= MAX_RESULTS:
            break
    return results


def _from_ddg_api(query: str) -> list[dict[str, Any]] | None:
    """DuckDuckGo Instant Answer API — a real JSON API (no key, no bot
    wall). Gives topic abstracts + related links rather than a full SERP,
    so it is the last resort, not the first stop."""
    page = _fetch(DDG_API_URL.format(query=urllib.parse.quote_plus(query)))
    if page is None:
        return None
    try:
        data = json.loads(page)
    except (ValueError, TypeError):
        return []
    results: list[dict[str, Any]] = []
    if data.get("AbstractText"):
        results.append({
            "title": data.get("Heading") or query,
            "url": data.get("AbstractURL") or "",
            "snippet": data["AbstractText"],
        })
    for topic in data.get("RelatedTopics", []):
        entries = topic.get("Topics", [topic]) if "Topics" in topic else [topic]
        for entry in entries:
            first, text = entry.get("FirstURL"), entry.get("Text")
            if first and text:
                results.append({
                    "title": text.split(" - ", 1)[0],
                    # DDG API sometimes gives duckduckgo.com/<topic> redirect
                    # links — rewrite to the topic's Wikipedia article
                    "url": _expand_ddg_topic_url(first),
                    "snippet": text,
                })
        if len(results) >= MAX_RESULTS:
            break
    return results[:MAX_RESULTS]


def _expand_ddg_topic_url(url: str) -> str:
    if url.startswith("https://duckduckgo.com/"):
        topic = url[len("https://duckduckgo.com/"):].strip("/")
        return ("https://en.wikipedia.org/wiki/"
                + urllib.parse.quote(topic.replace(" ", "_")))
    return url


def _from_wikipedia(query: str) -> list[dict[str, Any]] | None:
    """Wikipedia's search API — keyless JSON, serves arbitrary queries
    (the DDG Instant Answer API only covers topics it has abstracts
    for). Article snippets are plain text, URLs are stable. The API
    prefixes each snippet with the (bolded) article title — stripped
    here so the display doesn't show the title twice."""
    page = _fetch(WIKI_SEARCH_URL.format(
        query=urllib.parse.quote_plus(query), limit=MAX_RESULTS))
    if page is None:
        return None
    try:
        data = json.loads(page)
        hits = data["query"]["search"]
    except (ValueError, TypeError, KeyError):
        return []
    results: list[dict[str, Any]] = []
    for hit in hits[:MAX_RESULTS]:
        title = hit.get("title", "")
        snippet = _strip_tags(hit.get("snippet", ""))
        if title and snippet.lower().startswith(title.lower()):
            snippet = snippet[len(title):].lstrip()
        results.append({
            "title": title,
            "url": "https://en.wikipedia.org/wiki/"
                   + urllib.parse.quote(title.replace(" ", "_")),
            "snippet": snippet,
        })
    return results


def _from_ddg(query: str) -> list[dict[str, Any]] | None:
    """Fetch and parse web results, trying sources in order until one
    returns results: DDG html endpoint, DDG lite (POST), Mojeek, DDG
    Instant Answer API, Wikipedia search. Returns None only when every
    fetch failed (the caller shows a friendly offline message), an empty
    list when sources answered but had zero results."""
    fetched_any = False
    sources = (
        _from_ddg_html, _from_ddg_lite, _from_mojeek,
        _from_ddg_api, _from_wikipedia,
    )
    for source in sources:
        results = source(query)
        if results:
            return results
        if results is not None:
            fetched_any = True
    return [] if fetched_any else None


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
