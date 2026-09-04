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


def _zone_a_fetch(url: str, timeout: int = TIMEOUT_S) -> bytes:
    """Fetch a Zone A URL. Refuses hosts outside the allowlist."""
    host = urllib.parse.urlparse(url).hostname or ""
    if host not in ZONE_A_ALLOWED_HOSTS:
        raise ZoneAViolation(f"Zone A egress denied: {host!r} not in allowlist")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


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
        "http://web.archive.org/cdx/search/cdx"
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
