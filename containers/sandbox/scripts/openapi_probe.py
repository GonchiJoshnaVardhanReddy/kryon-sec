#!/usr/bin/env python3
"""OpenAPI / API-surface discovery probe (baked into the sandbox image).

argv: /opt/kryonsec/openapi_probe.py <url>

Fetches the well-known API-documentation paths (/openapi.json, /swagger.json,
/api-docs, /graphql) off the given base URL and prints a compact JSON summary
of what was found: per-path status + a parsed endpoint list when the response
is an OpenAPI/Swagger document. Endpoint names are bounded (50, 120 chars
each) — the host bounds output anyway, but this keeps one verbose spec from
drowning the rest of the tool output.

Fixed argv (no options, no file access) — the allowlist template pins it to
exactly [script, url].
"""

import json
import sys
import urllib.error
import urllib.request

TIMEOUT_S = 30
# the well-known doc paths, in probe order
DOC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/graphql")
MAX_ENDPOINTS = 50
MAX_ENDPOINT_LEN = 120


def _endpoints_from_spec(spec: dict) -> list[str]:
    """Paths (and methods) out of an OpenAPI/Swagger document, bounded."""
    endpoints: list[str] = []
    paths = spec.get("paths")
    if isinstance(paths, dict):
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            methods = sorted(
                m.upper() for m in item
                if isinstance(m, str) and m.lower() in (
                    "get", "post", "put", "patch", "delete", "head", "options"))
            label = f"{','.join(methods) or '?'} {path}"
            if label:
                endpoints.append(label[:MAX_ENDPOINT_LEN])
            if len(endpoints) >= MAX_ENDPOINTS:
                break
    return endpoints


def _probe(base_url: str, path: str) -> dict:
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(
        url, headers={"User-Agent": "kryonsec-probe/1.0"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            body = resp.read(1_000_000)  # bounded read
            entry = {"path": path, "status": resp.status}
            if path.endswith((".json",)) and resp.status == 200:
                try:
                    spec = json.loads(body)
                except ValueError:
                    spec = None
                if isinstance(spec, dict):
                    entry["spec_version"] = str(
                        spec.get("openapiVersion")
                        or spec.get("swagger") or spec.get("openapi") or "")
                    eps = _endpoints_from_spec(spec)
                    if eps:
                        entry["endpoints"] = eps
                        entry["endpoint_count"] = len(eps)
            return entry
    except urllib.error.HTTPError as e:
        # a 404 is the expected answer for most paths — not an error
        return {"path": path, "status": e.code}
    except Exception as e:  # timeout / connection refused / bad URL
        return {"path": path, "error": str(e)[:120]}
    return {"path": path, "status": 0}


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: openapi_probe.py <url>"}))
        return 2
    base_url = sys.argv[1]
    if not base_url.startswith(("http://", "https://")):
        print(json.dumps({"error": "not an http(s) url"}))
        return 2

    results = [_probe(base_url, path) for path in DOC_PATHS]
    # "found" is honest (M10): only HTTP 200 responses. Errors (timeouts,
    # refused connections) go to "unreachable" — a dead host must not read
    # as "found 4 API docs".
    print(json.dumps({
        "url": base_url,
        "probed": list(DOC_PATHS),
        "found": [r for r in results if r.get("status") == 200],
        "unreachable": [r for r in results if r.get("error")],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
