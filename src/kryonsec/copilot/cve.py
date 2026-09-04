"""CVE lookup (spec v2.1.1 §3.6): local DB first, NVD API fallback.

System LTM caches CVE records in the `system_knowledge` table so lookups
work offline after the first fetch. Network access is restricted to the
NVD API only (an approved search API per spec §3.2).
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from typing import Any

from ..config import KryonsecConfig
from ..storage import SystemKnowledge, get_session as db_session

log = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
NVD_TIMEOUT_S = 15

CACHE_CATEGORY = "cve"


def _normalize(cve_id: str) -> str:
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise ValueError(f"not a CVE id: {cve_id!r}")
    if not CVE_ID_RE.match(cve_id):
        raise ValueError(f"not a CVE id: {cve_id!r}")
    return cve_id


def _from_cache(cfg: KryonsecConfig, cve_id: str) -> dict[str, Any] | None:
    try:
        with db_session(cfg) as s:
            row = (
                s.query(SystemKnowledge)
                .filter_by(category=CACHE_CATEGORY, key=cve_id)
                .one_or_none()
            )
            return dict(row.value) if row else None
    except Exception as e:
        log.debug("cache read failed: %s", e)
        return None


def _to_cache(cfg: KryonsecConfig, cve_id: str, record: dict[str, Any]) -> None:
    try:
        with db_session(cfg) as s:
            row = (
                s.query(SystemKnowledge)
                .filter_by(category=CACHE_CATEGORY, key=cve_id)
                .one_or_none()
            )
            if row:
                row.value = record
            else:
                s.add(SystemKnowledge(category=CACHE_CATEGORY, key=cve_id, value=record))
            s.commit()
    except Exception as e:
        log.debug("cache write failed: %s", e)


def _from_nvd(cve_id: str) -> dict[str, Any] | None:
    try:
        req = urllib.request.Request(
            NVD_URL.format(cve_id=cve_id),
            headers={"User-Agent": "kryonsec/1.0.0"},
        )
        with urllib.request.urlopen(req, timeout=NVD_TIMEOUT_S) as r:
            data = json.loads(r.read())
    except Exception as e:
        log.info("NVD fetch failed for %s: %s", cve_id, e)
        return None

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve", {})
    metrics = cve.get("metrics", {})

    score = None
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            score = metrics[key][0].get("cvssData", {}).get("baseScore")
            severity = metrics[key][0].get("cvssData", {}).get("baseSeverity")
            break

    descriptions = [
        d.get("value", "")
        for d in cve.get("descriptions", [])
        if d.get("lang") == "en"
    ]
    return {
        "id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_score": score,
        "severity": severity,
        "description": descriptions[0] if descriptions else "",
        "references": [r.get("url") for r in cve.get("references", [])[:10]],
    }


def lookup_cve(cfg: KryonsecConfig, cve_id: str) -> dict[str, Any] | None:
    """Look up a CVE. Cache first, NVD second. Returns None when unknown."""
    cve_id = _normalize(cve_id)

    record = _from_cache(cfg, cve_id)
    if record:
        return record

    record = _from_nvd(cve_id)
    if record:
        _to_cache(cfg, cve_id, record)
    return record
