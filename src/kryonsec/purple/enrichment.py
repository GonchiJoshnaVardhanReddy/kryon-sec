"""Hypothesis enrichment (tool expansion Phase 3 + Phase 8, 2026-09).

After the LLM proposes hypotheses, this module adds public-risk context
to each one: NVD/CPE/CWE data, CISA KEV membership, EPSS score, OSV
(aliases/severity/affected packages), GitHub Advisory (GHSA id/severity/
patched versions), and public exploit availability (ExploitDB via
searchsploit + nuclei template metadata, both sandbox-local).

RAG was deliberately deferred (user decision) — these are free public
APIs only. Every fetch goes to a third party (NVD, CISA, FIRST, OSV,
GitHub, or the sandbox-local databases); the TARGET is never contacted.
Every lookup is audited; every failure is an audited skip — enrichment
can never fail the HYPOTHESIZE state.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from ..config import KryonsecConfig
from .adapter_searchsploit import (
    ADAPTER_ID as SEARCHSPLOIT_ADAPTER_ID,
    parse_searchsploit_json,
    record_exploitdb_evidence,
    secure_term,
)
from .adapters import AdapterError, execute_adapter, prepare_adapter_run
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
    "api.osv.dev",  # OSV (Phase 8)
    "api.github.com",  # GitHub Advisory Database (Phase 8)
}
# NVD is reached through copilot.cve.lookup_cve (existing approved path,
# spec §3.2) — it keeps its own cache + fetch.

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"
OSV_URL = "https://api.osv.dev/v1/vulns/{cve_id}"
GHSA_URL = "https://api.github.com/advisories?cve_id={cve_id}"
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


def osv_record(cfg: KryonsecConfig, cve_id: str) -> dict[str, Any] | None:
    """OSV (Phase 8): aliases, severity, affected packages for a CVE.
    Keyless. None = fetch failed or CVE unknown — never a state failure."""
    cve_id = cve_id.strip().upper()
    cached = _cache_get(cfg, "osv", cve_id)
    if cached is not None:
        return cached
    try:
        body = _zone_a_fetch(
            OSV_URL.format(cve_id=cve_id),
            timeout=ENRICHMENT_TIMEOUT_S,
            allowed_hosts=ENRICHMENT_ALLOWED_HOSTS,
        )
        data = json.loads(body)
    except Exception as e:
        log.info("OSV fetch failed for %s: %s", cve_id, e)
        return None
    record: dict[str, Any] = {}
    aliases = [str(a) for a in data.get("aliases", []) if a][:5]
    if aliases:
        record["osv_aliases"] = aliases
    # severity: the database_specific string (e.g. "HIGH") or the first
    # CVSS vector's base score pulled from the vector string
    severity = data.get("database_specific", {}).get("severity")
    if severity:
        record["osv_severity"] = str(severity)[:20]
    packages: list[str] = []
    for affected in data.get("affected", [])[:10]:
        pkg = affected.get("package", {}).get("name")
        if pkg and pkg not in packages:
            packages.append(str(pkg)[:80])
    if packages:
        record["affected_packages"] = packages[:10]
    if not record:
        return None  # record exists but nothing worth surfacing
    _cache_put(cfg, "osv", cve_id, record)
    return record


def ghsa_record(cfg: KryonsecConfig, cve_id: str) -> dict[str, Any] | None:
    """GitHub Advisory Database (Phase 8): GHSA id, severity, patched
    versions. Keyless. None = fetch failed or no advisory."""
    cve_id = cve_id.strip().upper()
    cached = _cache_get(cfg, "ghsa", cve_id)
    if cached is not None:
        return cached
    try:
        body = _zone_a_fetch(
            GHSA_URL.format(cve_id=cve_id),
            timeout=ENRICHMENT_TIMEOUT_S,
            allowed_hosts=ENRICHMENT_ALLOWED_HOSTS,
        )
        advisories = json.loads(body)
    except Exception as e:
        log.info("GHSA fetch failed for %s: %s", cve_id, e)
        return None
    if not advisories:
        return None
    adv = advisories[0]
    record: dict[str, Any] = {"ghsa_id": str(adv.get("ghsa_id", ""))[:30]}
    if adv.get("severity"):
        record["ghsa_severity"] = str(adv["severity"])[:20]
    patched = [
        str(v) for v in adv.get("vulnerabilities", [])
        if v.get("patched_versions")
    ][:5]
    if patched:
        record["patched_versions"] = [
            str(v["patched_versions"])[:80] for v in adv.get(
                "vulnerabilities", []) if v.get("patched_versions")
        ][:5]
    _cache_put(cfg, "ghsa", cve_id, record)
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


def nuclei_template_matches(
    sandbox,
    audit: AuditLog,
    term: str,
    allowlist=None,
) -> "list[dict] | None":
    """Search the baked nuclei templates inside the sandbox (local files,
    no egress). Returns the parsed match list ([] = ran, nothing matched;
    None = could not run)."""
    import json as _json

    from .allowlist import AllowlistViolation, ToolAllowlist

    allow = allowlist or ToolAllowlist()
    argv = [f"{_SCRIPT_DIR()}/nuclei_meta.py", term]
    try:
        allow.validate(argv[0], argv)
        allow.check_blocklist(argv)
    except AllowlistViolation as e:
        audit.write({
            "event": "enrichment_lookup",
            "kind": "nuclei_meta",
            "term": term,
            "ok": False,
            "reason": f"rejected by allowlist: {str(e)[:150]}",
        })
        return None
    audit.write({
        "event": "tool_spawn",
        "state": "HYPOTHESIZE",
        "tool": "nuclei_meta",
        "argv": argv,
    })
    result = sandbox.spawn(argv)
    audit.write({
        "event": "tool_result",
        "state": "HYPOTHESIZE",
        "tool": "nuclei_meta",
        "ok": result.ok,
        "exit_code": result.exit_code,
        "output_chars": len(result.stdout),
    })
    if not result.ok:
        return None
    try:
        payload = _json.loads(result.stdout)
    except ValueError:
        return None
    matches = payload.get("matches")
    return matches if isinstance(matches, list) else None


def _SCRIPT_DIR() -> str:
    from .allowlist import SANDBOX_SCRIPT_DIR

    return SANDBOX_SCRIPT_DIR


def _searchsploit_adapter(registry):
    """The registered searchsploit-term adapter from an injected
    registry, or None (unknown ids are refused everywhere — refusal
    here means the legacy lookup runs, deterministically)."""
    if registry is None:
        return None
    try:
        return registry.get(SEARCHSPLOIT_ADAPTER_ID)
    except AdapterError:
        return None


def _run_searchsploit_adapter(
    sandbox,
    registry,
    adapter,
    audit: AuditLog,
    graph: EngagementGraph,
    node: dict,
    term: str,
    enrichment: dict,
) -> bool:
    """Run the registered searchsploit-term adapter for ONE hypothesis.

    Returns True when the run executed. Never raises: every refusal and
    failure is an audited skip (enrichment can never fail the state).
    Observations become ``exploit_reference`` nodes (potential references
    ONLY, verification not_verified) plus the SAME enrichment surface
    the legacy path wrote, so downstream readers cannot drift.
    """
    try:
        safe_term = secure_term(term)
        prepared = prepare_adapter_run(
            registry, adapter.adapter_id, params={"term": safe_term})
    except (AdapterError, ValueError) as e:
        audit.write({
            "event": "hypothesize_adapter_failure",
            "adapter": adapter.adapter_id,
            "hypothesis_id": node.get("label", ""),
            "term": term[:60],
            "reason": str(e)[:200],
        })
        return False
    record, output = execute_adapter(
        registry, prepared, sandbox=sandbox, audit=audit, graph=graph,
        hypothesis_id=node.get("id", ""),
        full_output=True)
    if record.outcome == "refused" or not record.executed:
        audit.write({
            "event": "hypothesize_adapter_failure",
            "adapter": adapter.adapter_id,
            "request_id": record.request_id,
            "hypothesis_id": node.get("label", ""),
            "term": term[:60],
            "outcome": record.outcome,
            "reason": record.error_excerpt[:200],
        })
        return False
    references, malformed = parse_searchsploit_json(output)
    record_exploitdb_evidence(
        graph, audit,
        run_record=record,
        term=term,
        references=references,
        hypothesis_id=node.get("label", ""),
        malformations=malformed,
    )
    enrichment["exploit_references"] = [{
        "edb_id": r.edb_id,
        "title": r.title[:120],
        "exploit_type": r.exploit_type,
        "platform": r.platform,
    } for r in references]
    enrichment["exploit_available"] = bool(references)
    # the SAME consumer surface the legacy table-tail wrote (report
    # readers), composed from the parsed references — bounded lines,
    # never a verdict
    enrichment["exploits"] = [r.display_line() for r in references]
    audit.write({
        "event": "hypothesize_searchsploit_adapter",
        "adapter": adapter.adapter_id,
        "request_id": record.request_id,
        "hypothesis_id": node.get("label", ""),
        "term": term[:60],
        "references": len(references),
        "malformed": malformed,
    })
    return True


def enrich_hypotheses(
    cfg: KryonsecConfig,
    graph: EngagementGraph,
    audit: AuditLog,
    sandbox=None,
    adapter_registry=None,
) -> dict[str, int]:
    """Add public-risk context to every hypothesis node that names a CVE.

    Writes node.properties["enrichment"] = {cve, cvss_score, severity,
    cpes, kev, epss, epss_percentile, exploits, exploit_available}.
    Returns counts for the summary audit event. Never raises.

    ``adapter_registry`` (Phase 2B.4): when it carries the registered
    searchsploit-term adapter, the ExploitDB lookup runs through the
    ADAPTER path (structured JSON evidence nodes) and the legacy
    text-table lookup is OMITTED — one query per check, never both.
    A registry without the adapter behaves like no registry.
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
            # weakness types (Phase 8): CWE ids from the NVD record
            cwes = record.get("cwes") or []
            if cwes:
                enrichment["cwes"] = cwes
        audit.write({
            "event": "enrichment_lookup",
            "kind": "nvd",
            "hypothesis_id": node["label"],
            "cve": cve_id,
            "ok": record is not None,
        })
        counts["lookups"] += 1

        # OSV (Phase 8): aliases / severity / affected packages
        osv = osv_record(cfg, cve_id)
        audit.write({
            "event": "enrichment_lookup",
            "kind": "osv",
            "hypothesis_id": node["label"],
            "cve": cve_id,
            "ok": osv is not None,
        })
        counts["lookups"] += 1
        if osv:
            enrichment.update(osv)

        # GitHub Advisory Database (Phase 8): GHSA id / severity / patches
        ghsa = ghsa_record(cfg, cve_id)
        audit.write({
            "event": "enrichment_lookup",
            "kind": "ghsa",
            "hypothesis_id": node["label"],
            "cve": cve_id,
            "ok": ghsa is not None,
        })
        counts["lookups"] += 1
        if ghsa:
            enrichment.update(ghsa)

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

        # ExploitDB (sandbox-local database; skipped cleanly without one).
        # Phase 2B.4: when the searchsploit-term adapter is registered it
        # REPLACES the legacy table lookup — one query per check, never
        # both (deterministic either/or).
        term = sanitize_searchsploit_term(cve_id) or sanitize_searchsploit_term(
            props.get("title", ""))
        adapter = _searchsploit_adapter(adapter_registry)
        if sandbox is None:
            audit.write({
                "event": "enrichment_lookup",
                "kind": "searchsploit",
                "term": term,
                "ok": False,
                "reason": "no sandbox available (ExploitDB search skipped)",
            })
        elif adapter is not None and term:
            if _run_searchsploit_adapter(
                sandbox, adapter_registry, adapter, audit, graph, node,
                term, enrichment,
            ):
                counts["lookups"] += 1
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

        # Nuclei template metadata (Phase 8): is there a public template?
        # Another exploit-availability signal, local to the image.
        if sandbox is None:
            audit.write({
                "event": "enrichment_lookup",
                "kind": "nuclei_meta",
                "term": term,
                "ok": False,
                "reason": "no sandbox available (template search skipped)",
            })
        elif term:
            tmpl_matches = nuclei_template_matches(sandbox, audit, term)
            audit.write({
                "event": "enrichment_lookup",
                "kind": "nuclei_meta",
                "hypothesis_id": node["label"],
                "term": term,
                "ok": tmpl_matches is not None,
                "matches": len(tmpl_matches) if tmpl_matches else 0,
            })
            counts["lookups"] += 1
            if tmpl_matches:
                enrichment["nuclei_templates"] = tmpl_matches
                enrichment["exploit_available"] = True

        props["enrichment"] = enrichment
        node["properties"] = props
        counts["enriched"] += 1

    audit.write({"event": "enrichment_done", **counts})
    return counts
