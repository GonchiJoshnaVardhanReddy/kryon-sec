#!/usr/bin/env python3
"""Fixed verification probe (baked into the sandbox image).

argv: /opt/kryonsec/probe.py <url>

Fetches the URL with a fixed, non-configurable method (GET), fixed
timeout, no redirects, and prints a compact JSON summary: status code,
key headers, and a SHA256 of the body. VERIFY uses it as independent
evidence next to the curl boolean probe.

Deliberately minimal: no output of full bodies (the host bounds output
anyway), no options, no file access — the allowlist template pins the
argv to exactly [script, url].
"""

import hashlib
import json
import sys
import urllib.error
import urllib.request

TIMEOUT_S = 30


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: probe.py <url>"}))
        return 2
    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        print(json.dumps({"error": "not an http(s) url"}))
        return 2

    req = urllib.request.Request(
        url, headers={"User-Agent": "kryonsec-probe/1.0"}, method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            body = resp.read(1_000_000)  # bound the read, not just the print
            payload = {
                "url": url,
                "status": resp.status,
                "content_length": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "server": resp.headers.get("Server", ""),
                "content_type": resp.headers.get("Content-Type", ""),
            }
    except urllib.error.HTTPError as e:
        payload = {"url": url, "status": e.code, "http_error": str(e.reason)}
    except Exception as e:  # network failure, timeout, bad URL
        payload = {"url": url, "error": str(e)[:200]}

    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
