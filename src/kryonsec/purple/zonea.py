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
import urllib.parse
import urllib.request
from dataclasses import dataclass

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
    crt.sh is occasionally slow/empty on first hit — retry a couple of times.
    """
    import time

    domain = normalize_target(domain)
    url = "https://crt.sh/?q=%" + urllib.parse.quote(domain, safe="") + "&output=json"

    body = b""
    for attempt in range(retries + 1):
        try:
            body = _zone_a_fetch(url, timeout=30)
            records = json.loads(body)
            break
        except json.JSONDecodeError:
            if attempt < retries:
                log.info("crt.sh empty reply for %s (attempt %d) — retrying", domain, attempt + 1)
                time.sleep(2)
                continue
            log.warning("crt.sh returned non-JSON after %d attempts for %s", retries + 1, domain)
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


def wayback_paths(domain: str, limit: int = 100) -> list[str]:
    """Query the Wayback Machine for archived URLs of the domain."""
    url = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url={urllib.parse.quote(domain, safe='')}/*&output=json&limit={limit}"
        "&collapse=urlkey"
    )
    body = _zone_a_fetch(url)
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return []
    # rows[0] is the header; each row is [urlkey, timestamp, original, ...]
    return [row[2] for row in rows[1:] if len(row) >= 3 and row[2].startswith("http")]
