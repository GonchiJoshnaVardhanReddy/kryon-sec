"""RECON_PASSIVE Zone A sources (spec v2.1.1 §8.3).

Zone A invariant: passive recon sends ZERO packets to the target. Every
source here is a third-party API that already knows about the domain —
crt.sh (certificate transparency), never the target's own servers.

API keys (when a source needs one) are injected per-call and never logged.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

USER_AGENT = "kryonsec/1.0.0 (passive-recon)"
TIMEOUT_S = 20

# Hostnames Zone A may contact — everything else is refused at this layer.
ZONE_A_ALLOWED_HOSTS = {
    "crt.sh",
    "web.archive.org",
    "otx.alienvault.com",
    "api.shodan.io",
    "search.censys.io",
    "stat.ripe.net",
}


class ZoneAViolation(Exception):
    """A source tried to contact a host outside the Zone A allowlist."""


DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)
TLD_RE = re.compile(r"^[a-z]{2,}$")  # real TLDs are alphabetic (com, net, io, …)


def validate_target(raw: str) -> str:
    """Normalize (URL -> domain) and validate the engagement target.

    Raises ValueError with a plain-words message when the input isn't a
    usable domain.
    """
    domain = normalize_target(raw)
    if not domain or not DOMAIN_RE.match(domain) or "." not in domain:
        raise ValueError(
            f"{raw!r} is not a valid domain. "
            "Use a domain like 'target-corp.com' (http:// prefix is fine, we strip it)."
        )
    tld = domain.rsplit(".", 1)[-1]
    if not TLD_RE.match(tld):
        raise ValueError(
            f"{raw!r} does not end in a real domain extension "
            f"('{tld}' is not alphabetic like 'com', 'net', 'io')."
        )
    return domain


@dataclass
class PassiveResult:
    source: str
    subdomains: list[str]
    # archived URLs (Wayback) — evidence for thin targets that have no
    # subdomains: "old ASP site, archived since 2013" is real signal.
    paths: list[str] = field(default_factory=list)
    # free-form context lines (registrar, ASN, registration age…) —
    # HYPOTHESIZE reads them as supporting evidence
    notes: list[str] = field(default_factory=list)
    # set when the source did not run (e.g. no API key) — audited as a
    # skip notice, distinct from a failure
    skipped: str | None = None


def _zone_a_fetch(
    url: str,
    timeout: int = TIMEOUT_S,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> bytes:
    """Fetch a Zone A URL. Refuses hosts outside the allowlist — including
    the hosts of redirects (urlopen follows 3xx silently otherwise, which
    would send packets to arbitrary hosts, possibly the target).
    data != None makes this a POST (Censys search)."""
    # a redirect handler that re-checks every hop against the allowlist
    class _ZoneARedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            host = urllib.parse.urlparse(newurl).hostname or ""
            if host not in ZONE_A_ALLOWED_HOSTS:
                raise ZoneAViolation(
                    f"Zone A egress denied: redirect to {host!r} not in allowlist"
                )
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_ZoneARedirectHandler)
    host = urllib.parse.urlparse(url).hostname or ""
    if host not in ZONE_A_ALLOWED_HOSTS:
        raise ZoneAViolation(f"Zone A egress denied: {host!r} not in allowlist")
    all_headers = {"User-Agent": USER_AGENT}
    if headers:
        all_headers.update(headers)
    req = urllib.request.Request(url, headers=all_headers, data=data)
    with opener.open(req, timeout=timeout) as r:
        # bounded read — a hostile/compromised source must not be able to
        # exhaust host memory
        return r.read(MAX_FETCH_BYTES)


MAX_FETCH_BYTES = 20 * 1024 * 1024  # 20 MB cap per Zone A response


def _same_domain(subdomain: str, domain: str) -> bool:
    """subdomain must be the domain itself or end with .domain — no
    lookalikes, no other TLDs (spec: scope enforcement)."""
    subdomain = subdomain.strip().lower().rstrip(".")
    domain = domain.strip().lower().rstrip(".")
    return subdomain == domain or subdomain.endswith("." + domain)


def normalize_target(raw: str) -> str:
    """Accept http(s)://host/path, host:port, or bare host — return the domain.

    Users naturally paste URLs; the recon sources want the bare domain.
    """
    raw = raw.strip()
    if "://" in raw:
        raw = urllib.parse.urlparse(raw).hostname or raw
    elif "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw:  # host:port
        raw = raw.split(":", 1)[0]
    return raw.strip().lower().rstrip(".")


def crt_sh_subdomains(domain: str, retries: int = 2) -> PassiveResult:
    """Query certificate transparency (crt.sh) for subdomains.

    crt.sh logs every TLS certificate ever issued for a domain — asking it
    is like asking a public library; the target never hears about it.
    crt.sh is occasionally slow/empty on first hit — retry with backoff.
    """
    import time

    domain = normalize_target(domain)
    # NOTE: no '%' wildcard prefix — crt.sh now rejects it ("Unsupported
    # use of '%'") with an HTML error page. The bare-domain query already
    # returns every cert whose name_value covers the domain and its
    # subdomains, so the wildcard was never needed.
    url = "https://crt.sh/?q=" + urllib.parse.quote(domain, safe="") + "&output=json"

    body = b""
    for attempt in range(retries + 1):
        try:
            body = _zone_a_fetch(url, timeout=30)
            records = json.loads(body)
            break
        except json.JSONDecodeError:
            if attempt < retries:
                log.info("crt.sh empty reply for %s (attempt %d) — retrying", domain, attempt + 1)
                time.sleep(4)
                continue
            log.warning("crt.sh returned non-JSON after %d attempts for %s", retries + 1, domain)
            return PassiveResult(source="crt.sh", subdomains=[])
        except urllib.error.HTTPError as e:
            if 500 <= e.code < 600 and attempt < retries:
                log.info("crt.sh HTTP %d for %s (attempt %d) — retrying", e.code, domain, attempt + 1)
                time.sleep(4)
                continue
            log.warning("crt.sh HTTP %d after %d attempts for %s — giving up", e.code, attempt + 1, domain)
            return PassiveResult(source="crt.sh", subdomains=[])
        except Exception:
            raise

    found: set[str] = set()

    for record in records:
        name_value = record.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower().rstrip(".")
            # wildcards: *.example.com -> keep the base
            if name.startswith("*."):
                name = name[2:]
            if name and _same_domain(name, domain) and re.match(r"^[a-z0-9.-]+$", name):
                found.add(name)

    return PassiveResult(source="crt.sh", subdomains=sorted(found))


def wayback_paths(domain: str, limit: int = 100, retries: int = 2) -> list[str]:
    """Query the Wayback Machine for archived URLs of the domain.

    The CDX API 503s under load and is slow (~15-20s measured from India
    even for tiny responses) — long timeout, retry with backoff.
    """
    import time

    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={urllib.parse.quote(domain, safe='')}/*&output=json&limit={limit}"
        "&collapse=urlkey"
    )
    body = b""
    for attempt in range(retries + 1):
        try:
            body = _zone_a_fetch(url, timeout=60)
            break
        except urllib.error.HTTPError as e:
            if 500 <= e.code < 600 and attempt < retries:
                log.info("wayback CDX %d (attempt %d) — retrying", e.code, attempt + 1)
                time.sleep(2)
                continue
            raise
        except TimeoutError:
            if attempt < retries:
                log.info("wayback CDX timed out (attempt %d) — retrying", attempt + 1)
                time.sleep(2)
                continue
            raise
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return []
    # rows[0] is the header; each row is [urlkey, timestamp, original, ...]
    return [row[2] for row in rows[1:] if len(row) >= 3 and row[2].startswith("http")]


def wayback_subdomains(domain: str, limit: int = 200) -> PassiveResult:
    """Derive subdomains AND archived URLs from the Wayback CDX API.

    A second, independent source of subdomain names: the archive's URL
    list includes hosts like api.example.com that certificates never
    covered. The archived URLs themselves are evidence too — technology
    and age hints for targets with no subdomains at all. Zero packets to
    the target — we ask the archive, not the target's servers.
    """
    domain = normalize_target(domain)
    try:
        paths = wayback_paths(domain, limit=limit)
    except Exception:
        # network/archive hiccup: empty result, never an exception upward
        log.warning("wayback CDX query failed for %s", domain, exc_info=True)
        return PassiveResult(source="wayback", subdomains=[], paths=[])

    found: set[str] = set()
    cleaned: list[str] = []
    for url in paths:
        host = urllib.parse.urlparse(url).hostname or ""
        host = host.strip().lower().rstrip(".")
        if not host or not _same_domain(host, domain):
            # out-of-scope hosts contribute nothing — not even paths
            continue
        if host != domain:
            found.add(host)

        # keep the path+query part (drop scheme/host — the prompt already
        # knows the target)
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        cleaned.append(path)

    return PassiveResult(
        source="wayback",
        subdomains=sorted(found),
        # dedupe, cap at 100 — enough for the prompt without flooding it
        paths=list(dict.fromkeys(cleaned))[:100],
    )


# ---- tool-expansion Phase 2 (2026-09-13): new Zone A sources ----------------
# All third-party APIs; zero packets to the target by construction. Keyed
# sources return a skipped result (audited notice) instead of failing.

_IP4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _in_scope_subdomains(names, domain: str) -> list[str]:
    """Filter a source's raw names to in-scope, well-formed subdomains."""
    out = set()
    for name in names:
        name = str(name).strip().lower().rstrip(".")
        if name.startswith("*."):
            name = name[2:]
        if name and _same_domain(name, domain) and re.match(r"^[a-z0-9.-]+$", name):
            out.add(name)
    return sorted(out)


def shodan_subdomains(domain: str, api_key: str | None = None) -> PassiveResult:
    """Shodan DNS domain data (https://api.shodan.io/dns/domain/<domain>).

    Shodan already scanned the internet — asking it is passive. Returns a
    skipped result when no API key is configured (never a failure)."""
    domain = normalize_target(domain)
    if not api_key:
        return PassiveResult(
            source="shodan", subdomains=[],
            skipped="no shodan_api_key configured (kryonsec setup)",
        )
    url = f"https://api.shodan.io/dns/domain/{urllib.parse.quote(domain)}?key={urllib.parse.quote(api_key)}"
    try:
        body = _zone_a_fetch(url)
        data = json.loads(body)
    except Exception:
        log.warning("shodan dns/domain query failed for %s", domain, exc_info=True)
        return PassiveResult(source="shodan", subdomains=[])
    # {"domain": "x.com", "subdomains": ["www", "api"], "data": [...]}
    labels = data.get("subdomains") or []
    return PassiveResult(
        source="shodan",
        subdomains=_in_scope_subdomains(
            (f"{label}.{domain}" for label in labels), domain),
    )


def censys_subdomains(
    domain: str,
    api_id: str | None = None,
    api_secret: str | None = None,
) -> PassiveResult:
    """Censys Search v2 hosts API — certificates/hostnames it has observed.

    Needs an API ID + secret (search.censys.io account)."""
    domain = normalize_target(domain)
    if not api_id or not api_secret:
        return PassiveResult(
            source="censys", subdomains=[],
            skipped="no censys_api_id/censys_api_secret configured (kryonsec setup)",
        )
    import base64

    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    url = "https://search.censys.io/api/v2/hosts/search"
    body = json.dumps({"q": f"names: {domain}", "per_page": 100}).encode()
    try:
        resp = _zone_a_fetch(
            url, headers={"Authorization": f"Basic {auth}"}, data=body,
        )
        data = json.loads(resp)
    except Exception:
        log.warning("censys hosts search failed for %s", domain, exc_info=True)
        return PassiveResult(source="censys", subdomains=[])
    names: list[str] = []
    for hit in (data.get("result") or {}).get("hits") or []:
        names.extend(hit.get("names") or [])
    return PassiveResult(
        source="censys", subdomains=_in_scope_subdomains(names, domain),
    )


def otx_passive_dns(domain: str) -> PassiveResult:
    """AlienVault OTX passive DNS — hostnames seen in exchanged indicators."""
    domain = normalize_target(domain)
    url = (
        "https://otx.alienvault.com/api/v1/indicators/domain/"
        f"{urllib.parse.quote(domain)}/passive_dns?limit=200"
    )
    try:
        resp = _zone_a_fetch(url)
        data = json.loads(resp)
    except Exception:
        log.warning("otx passive dns query failed for %s", domain, exc_info=True)
        return PassiveResult(source="otx", subdomains=[])
    hostnames = [
        entry.get("hostname") for entry in data.get("passive_dns") or []
    ]
    return PassiveResult(
        source="otx", subdomains=_in_scope_subdomains(hostnames, domain),
    )


def ripestat_whois(domain: str) -> PassiveResult:
    """RIPEstat whois — registrar, registration dates, nameservers.

    Notes-only source (no subdomains). Deviation from the plan recorded
    in docs/TOOL-EXPANSION-2026-09-13.md: rdap.org redirects to arbitrary
    per-TLD registry hosts, which cannot be safely allowlisted; RIPEstat
    serves the same data from one fixed host."""
    domain = normalize_target(domain)
    url = (
        "https://stat.ripe.net/data/whois/data.json"
        f"?resource={urllib.parse.quote(domain)}"
    )
    try:
        resp = _zone_a_fetch(url)
        data = json.loads(resp)
    except Exception:
        log.warning("ripestat whois query failed for %s", domain, exc_info=True)
        return PassiveResult(source="ripestat-whois", subdomains=[])
    notes: list[str] = []
    for record in (data.get("data") or {}).get("records") or []:
        key = str(record.get("key", "")).strip()
        value = str(record.get("value", "")).strip()
        if key and value and key.lower() in (
            "registrar", "creation date", "expiration date",
            "updated date", "nameservers", "domain status",
        ):
            notes.append(f"{key}: {value[:120]}")
    return PassiveResult(source="ripestat-whois", subdomains=[], notes=notes[:20])


def ripestat_asn(domain: str) -> PassiveResult:
    """RIPEstat ASN/BGP context — the AS number + prefix the domain's
    addresses sit in (resolved server-side by RIPE, not by us)."""
    domain = normalize_target(domain)
    chain_url = (
        "https://stat.ripe.net/data/dns-chain/data.json"
        f"?resource={urllib.parse.quote(domain)}"
    )
    try:
        resp = _zone_a_fetch(chain_url)
        data = json.loads(resp)
    except Exception:
        log.warning("ripestat dns-chain query failed for %s", domain, exc_info=True)
        return PassiveResult(source="ripestat-asn", subdomains=[])

    # collect resolved v4 addresses from the chain (structure varies)
    ips: list[str] = []
    for entry in (data.get("data") or {}).get("resolve") or []:
        records = (entry.get("A") or {}).get("records") or []
        ips.extend(a for a in records if _IP4_RE.match(str(a)))
    ips = sorted(set(ips))[:3]  # a few are plenty for the prompt
    if not ips:
        return PassiveResult(source="ripestat-asn", subdomains=[])

    notes = [f"resolves (per RIPEstat) to: {', '.join(ips)}"]
    info_url = (
        "https://stat.ripe.net/data/network-info/data.json"
        f"?resource={urllib.parse.quote(ips[0])}"
    )
    try:
        resp = _zone_a_fetch(info_url)
        info = json.loads(resp).get("data") or {}
    except Exception:
        info = {}
    if info.get("asn"):
        notes.append(
            f"announced by {info.get('asn')} ({info.get('holder', 'unknown holder')})"
            f" in prefix {info.get('prefix', '?')}"
        )
    return PassiveResult(source="ripestat-asn", subdomains=[], notes=notes)
