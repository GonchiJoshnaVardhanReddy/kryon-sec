"""Hypothesis enrichment (tool expansion Phase 3, 2026-09-13).

After the LLM proposes hypotheses, this module adds public-risk context
to each one: NVD/CPE data, CISA KEV membership, EPSS score, and public
exploit availability (ExploitDB via searchsploit in the sandbox).

RAG was deliberately deferred (user decision) — these are free public
APIs only. Every fetch goes to a third party (NVD, CISA, FIRST, or the
sandbox-local ExploitDB database); the TARGET is never contacted. Every
lookup is audited; every failure is an audited skip — enrichment can
never fail the HYPOTHESIZE state.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from ..config import KryonsecConfig
from .audit import AuditLog
from .recon_passive import EngagementGraph
from .zonea import _zone_a_fetch

log = logging.getLogger(__name__)

# Hosts enrichment may contact (the target is never among them by
# construction — these are the risk-data providers, same fetch guard as
# Zone A: bounded read + redirect re-check).
ENRICHMENT_ALLOWED_HOSTS = {
    "www.cisa.gov",  # KEV catalog
    "api.first.org",  # EPSS
}
# NVD is reached through copilot.cve.lookup_cve (existing approved path,
# spec §3.2) — it keeps its own cache + fetch.

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"
ENRICHMENT_TIMEOUT_S = 30
CACHE_TTL_S = 24 * 3600  # KEV/EPSS change daily at most
KEV_CACHE = ("kev", "catalog")
EPSS_CACHE_CATEGORY = "epss"

MAX_EXPLOIT_LINES = 5  # searchsploit hits surfaced per hypothesis

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cve_ids(*texts: str) -> list[str]:
    """CVE ids mentioned in hypothesis text (title/rationale), deduped,
    order of appearance. The LLM often cites the CVE it is reasoning
    about even when the structured field is empty."""
    seen: list[str] = []
    for text in texts:
        for m in _CVE_ID_RE.findall(text or ""):
            cve_id = m.upper()
            if cve_id not in seen:
                seen.append(cve_id)
    return seen


def _cache_get(cfg: KryonsecConfig, category: str, key: str) -> Any | None:
    try:
        from ..storage import SystemKnowledge, get_session as db_session

        with db_session(cfg) as s:
            row = (
                s.query(SystemKnowledge)
                .filter_by(category=category, key=key)
                .one_or_none()
            )
            if not row:
                return None
            payload = dict(row.value)
            if time.time() - payload.get("fetched_at", 0) > CACHE_TTL_S:
                return None  # stale
            return payload.get("data")
    except Exception as e:
        log.debug("enrichment cache read failed: %s", e)
        return None


def _cache_put(cfg: KryonsecConfig, category: str, key: str, data: Any) -> None:
    try:
        from ..storage import SystemKnowledge, get_session as db_session

        with db_session(cfg) as s:
            row = (
                s.query(SystemKnowledge)
                .filter_by(category=category, key=key)
                .one_or_none()
            )
            payload = {"fetched_at": time.time(), "data": data}
            if row:
                row.value = payload
            else:
                s.add(SystemKnowledge(category=category, key=key, value=payload))
            s.commit()
    except Exception as e:
        log.debug("enrichment cache write failed: %s", e)


def kev_cves(cfg: KryonsecConfig) -> set[str] | None:
    """The CISA known-exploited-vulnerability catalog as a set of CVE ids.
    None = fetch failed (callers treat as 'unknown', never as 'not in KEV').
    Cached for a day; ~1.5 MB JSON, bounded by the same read cap as Zone A."""
    cached = _cache_get(cfg, *KEV_CACHE)
    if cached is not None:
        return set(cached)
    try:
        body = _zone_a_fetch(
            KEV_URL, timeout=ENRICHMENT_TIMEOUT_S,
            allowed_hosts=ENRICHMENT_ALLOWED_HOSTS,
        )
        data = json.loads(body)
        cves = {
            v.get("cveID", "").upper()
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        }
    except Exception as e:
        log.info("KEV catalog fetch failed: %s", e)
        return None
    _cache_put(cfg, *KEV_CACHE, sorted(cves))
    return cves


def epss_for(cfg: KryonsecConfig, cve_id: str) -> dict[str, Any] | None:
    """EPSS score for a CVE ({'epss': float, 'percentile': str}) or None.
    Cached for a day."""
    cve_id = cve_id.strip().upper()
    cached = _cache_get(cfg, EPSS_CACHE_CATEGORY, cve_id)
    if cached is not None:
        return cached
    try:
        body = _zone_a_fetch(
            EPSS_URL.format(cve_id=cve_id),
            timeout=ENRICHMENT_TIMEOUT_S,
            allowed_hosts=ENRICHMENT_ALLOWED_HOSTS,
        )
        entries = json.loads(body).get("data", [])
        if not entries:
            return None
        record = {
            "epss": float(entries[0].get("epss", 0.0)),
            "percentile": str(entries[0].get("percentile", "")),
        }
    except Exception as e:
        log.info("EPSS fetch failed for %s: %s", cve_id, e)
        return None
    _cache_put(cfg, EPSS_CACHE_CATEGORY, cve_id, record)
    return record


def sanitize_searchsploit_term(text: str) -> str:
    """Reduce hypothesis text to a safe searchsploit term: the {term}
    allowlist pattern is alnum/space/dash/dot — anything else is dropped
    (not escaped; argv is exec'd directly, so strip, never transform)."""
    term = re.sub(r"[^A-Za-z0-9 .\-]+", " ", text)
    term = re.sub(r"\s+", " ", term).strip()
    return term[:60]


def searchsploit_hits(
    sandbox,
    audit: AuditLog,
    term: str,
    allowlist=None,
) -> list[str] | None:
    """Search the ExploitDB copy inside the sandbox (local database, no
    egress). Returns up to MAX_EXPLOIT_LINES result lines, [] when the
    search ran but found nothing, None when it could not run."""
    from .allowlist import AllowlistViolation, ToolAllowlist

    allow = allowlist or ToolAllowlist()
    argv = ["searchsploit", "--colorless", term]
    try:
        allow.validate(argv[0], argv)
        allow.check_blocklist(argv)
    except AllowlistViolation as e:
        audit.write({
            "event": "enrichment_lookup",
            "kind": "searchsploit",
            "term": term,
            "ok": False,
            "reason": f"rejected by allowlist: {str(e)[:150]}",
        })
        return None
    audit.write({
        "event": "tool_spawn",
        "state": "HYPOTHESIZE",
        "tool": "searchsploit",
        "argv": argv,
    })
    result = sandbox.spawn(argv)
    audit.write({
        "event": "tool_result",
        "state": "HYPOTHESIZE",
        "tool": "searchsploit",
        "ok": result.ok,
        "exit_code": result.exit_code,
        "output_chars": len(result.stdout),
    })
    if not result.ok:
        return None
    lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ][-MAX_EXPLOIT_LINES:]  # searchsploit prints a trailing table — tail
    return lines


def enrich_hypotheses(
    cfg: KryonsecConfig,
    graph: EngagementGraph,
    audit: AuditLog,
    sandbox=None,
) -> dict[str, int]:
    """Add public-risk context to every hypothesis node that names a CVE.

    Writes node.properties["enrichment"] = {cve, cvss_score, severity,
    cpes, kev, epss, epss_percentile, exploits, exploit_available}.
    Returns counts for the summary audit event. Never raises.
    """
    counts = {"hypotheses": 0, "enriched": 0, "no_cve": 0, "lookups": 0}
    nodes = graph.by_type("hypothesis")
    if not nodes:
        return counts
    counts["hypotheses"] = len(nodes)

    kev: set[str] | None = None  # fetched lazily, once per run

    for node in nodes:
        props = node.get("properties", {})
        cve_ids = extract_cve_ids(
            props.get("cve", ""), props.get("title", ""), props.get("rationale", ""),
        )
        if not cve_ids:
            counts["no_cve"] += 1
            continue
        # one CVE per hypothesis is the common case; take the first
        cve_id = cve_ids[0]
        enrichment: dict[str, Any] = {"cve": cve_id}

        # NVD / CPE (existing copilot path: cache first, NVD second)
        record = None
        try:
            from ..copilot.cve import lookup_cve

            record = lookup_cve(cfg, cve_id)
        except Exception as e:
            log.info("NVD lookup failed for %s: %s", cve_id, e)
        if record:
            enrichment["cvss_score"] = record.get("cvss_score")
            enrichment["severity"] = record.get("severity")
            cpes = record.get("cpes") or []
            if cpes:
                enrichment["cpes"] = cpes
        audit.write({
            "event": "enrichment_lookup",
            "kind": "nvd",
            "hypothesis_id": node["label"],
            "cve": cve_id,
            "ok": record is not None,
        })
        counts["lookups"] += 1

        # KEV membership (catalog fetched at most once per run)
        if kev is None:
            kev = kev_cves(cfg)
            audit.write({
                "event": "enrichment_lookup",
                "kind": "kev",
                "ok": kev is not None,
                "catalog_size": len(kev) if kev else 0,
            })
            counts["lookups"] += 1
        if kev is not None:
            enrichment["kev"] = cve_id in kev

        # EPSS score
        epss = epss_for(cfg, cve_id)
        audit.write({
            "event": "enrichment_lookup",
            "kind": "epss",
            "hypothesis_id": node["label"],
            "cve": cve_id,
            "ok": epss is not None,
        })
        counts["lookups"] += 1
        if epss:
            enrichment["epss"] = epss["epss"]
            enrichment["epss_percentile"] = epss["percentile"]

        # ExploitDB (sandbox-local database; skipped cleanly without one)
        term = sanitize_searchsploit_term(cve_id) or sanitize_searchsploit_term(
            props.get("title", ""))
        if sandbox is None:
            audit.write({
                "event": "enrichment_lookup",
                "kind": "searchsploit",
                "term": term,
                "ok": False,
                "reason": "no sandbox available (ExploitDB search skipped)",
            })
        elif term:
            hits = searchsploit_hits(sandbox, audit, term)
            audit.write({
                "event": "enrichment_lookup",
                "kind": "searchsploit",
                "hypothesis_id": node["label"],
                "term": term,
                "ok": hits is not None,
                "hits": len(hits) if hits else 0,
            })
            counts["lookups"] += 1
            if hits:
                enrichment["exploits"] = hits
                enrichment["exploit_available"] = True

        props["enrichment"] = enrichment
        node["properties"] = props
        counts["enriched"] += 1

    audit.write({"event": "enrichment_done", **counts})
    return counts
