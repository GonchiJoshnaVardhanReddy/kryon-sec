#!/usr/bin/env python3
"""Read-only API security baseline probe (baked into the sandbox image).

argv: /opt/kryonsec/api_probe.py <url>

Examines ONE authorized http(s) base URL with a bounded set of
read-only HTTP requests and emits a compact JSON observation summary:
security headers, CORS configuration evidence, advertised HTTP methods
(OPTIONS = metadata only), and OpenAPI/Swagger document metadata.

REQUEST POLICY (frozen in code — the caller can never change it):
    - exactly ONE argument: the approved base URL (host + scheme from
      scope validation upstream); every request this script sends
      stays under that ONE host — a redirect to ANY other host is
      recorded and NEVER followed, and no secondary request is ever
      sent to another host;
    - GET and OPTIONS only. PUT / PATCH / DELETE and
      state-changing POST are structurally absent from this script;
    - redirects are disabled at the HTTP handler level: a redirect is
      an OBSERVATION (status + Location), never a follow-up request;
    - no credentials, tokens, cookies or session state are ever read,
      set or forwarded; the only headers sent are a fixed User-Agent,
      Accept, and — in exactly one request — a FIXED inert test origin
      (``https://kryonsec-cors-probe.invalid``) to observe origin
      reflection;
    - every response body read is capped (MAX_BODY_BYTES); an OpenAPI
      document at or over that bound is recorded as oversized and
      NOT parsed;
    - OpenAPI parsing is plain ``json.loads`` (no code execution, no
      YAML deserialization, no schema evaluation); ``$ref`` values are
      COUNTED, never resolved — a remote reference is never fetched;
    - request count, per-request timeout and output size are all
      bounded; no crawling, no fuzzing, no endpoint generation beyond
      the four fixed well-known documentation paths;
    - OPTIONS results are metadata (an ``Allow`` header is what the
      server ADVERTISES, not proof of authorization behavior).

OUTPUT CONTRACT: one JSON object {kind, url, status, requests_sent,
base, cors_probe, options, docs, limitations, errors}. Header values
are DATA from the server; a missing header or a permissive CORS value
is recorded as an observation — never claimed here as an exploitable
vulnerability (the host adapter hard-wires verification to
``not_verified``).

Exit codes: 0 = a payload with at least one HTTP response was emitted;
1 = no response from the target (payload still emitted, honest);
2 = usage error.
"""

import json
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

USER_AGENT = "kryonsec-api-probe/1.0"
#: the single, fixed, deliberately non-routable test origin for the
#: CORS reflection observation (never a customer origin, never reused)
CORS_TEST_ORIGIN = "https://kryonsec-cors-probe.invalid"
PER_REQUEST_TIMEOUT_S = 10
#: total requests bound: 3 base checks + up to 4 documentation paths
MAX_REQUESTS = 7
#: one response-body read bound, for every response (OpenAPI documents
#: at or over this are recorded as oversized, never parsed)
MAX_BODY_BYTES = 524_288
MAX_ENDPOINTS = 50
MAX_ENDPOINT_LEN = 120
MAX_REFS_LISTED = 20
MAX_HEADER_VALUE = 200
MAX_SAMPLE = 200

SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "referrer-policy",
    "permissions-policy", "server", "x-powered-by",
)
CORS_HEADERS = (
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "access-control-allow-headers",
    "vary",
)
DOC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/graphql")
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head",
                "options")


class _NoFollowRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are OBSERVATIONS, not instructions: never follow."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoFollowRedirect)


def _fixed_headers(origin: "str | None" = None) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if origin is not None:
        headers["Origin"] = origin
    return headers


def _selected_headers(headers) -> dict:
    """The observed security/CORS header set, bounded. A missing header
    shows as absence in this map — the summary lists what WAS present;
    the host adapter reads the well-known gaps explicitly. ``allow`` is
    included so an OPTIONS answer carries its advertised methods."""
    observed: dict = {}
    for name in ("allow", *SECURITY_HEADERS, *CORS_HEADERS):
        value = headers.get(name) if hasattr(headers, "get") else None
        if value is not None:
            observed[name] = str(value)[:MAX_HEADER_VALUE]
    return observed


def _redirect_observation(base_url: str, headers) -> dict:
    """A redirect, recorded: target host vs approved host. NEVER a
    follow-up request."""
    location = (headers.get("Location") or "")[:MAX_HEADER_VALUE]
    target_host = ""
    try:
        if location.startswith(("http://", "https://")):
            target_host = urlsplit(location).hostname or ""
        elif location.startswith("/"):
            target_host = urlsplit(base_url).hostname or ""
    except ValueError:
        target_host = ""
    approved = urlsplit(base_url).hostname or ""
    return {
        "location": location,
        "target_host": target_host,
        "same_host": bool(target_host) and target_host == approved,
        "cross_host": bool(target_host) and target_host != approved,
        "followed": False,
    }


def _request(base_url: str, path: str = "", *, method: str = "GET",
             origin: "str | None" = None) -> dict:
    """ONE bounded, host-locked request. Never follows redirects; never
    sends anything to a host other than the approved base host. The
    raw (capped) body travels in ``_body`` for doc parsing and is
    stripped before serialization."""
    url = base_url.rstrip("/") + path
    entry: dict = {"method": method, "path": path or "/", "url": url[:300]}
    req = urllib.request.Request(url, headers=_fixed_headers(origin),
                                 method=method)
    try:
        with _OPENER.open(req, timeout=PER_REQUEST_TIMEOUT_S) as resp:
            body = resp.read(MAX_BODY_BYTES)
            entry["status"] = resp.status
            entry["headers"] = _selected_headers(resp.headers)
            entry["content_type"] = (resp.headers.get("Content-Type")
                                     or "")[:MAX_HEADER_VALUE]
            entry["_body"] = body
            entry["body_bytes"] = len(body)
    except urllib.error.HTTPError as e:
        # a status IS the observation (405 = method not advertised,
        # 3xx = the redirect itself, ...)
        headers = e.headers or {}
        entry["status"] = e.code
        entry["headers"] = _selected_headers(headers)
        entry["content_type"] = (headers.get("Content-Type")
                                 or "")[:MAX_HEADER_VALUE]
        if headers.get("Location"):
            entry["redirect"] = _redirect_observation(base_url, headers)
    except Exception as e:  # timeout / connection refused / bad URL
        entry["error"] = str(e)[:MAX_HEADER_VALUE]
    return entry


def _origin_reflection(entry: dict) -> dict:
    """CORS reflection evidence from the fixed-origin probe: what the
    server returned, and whether it echoed the test origin verbatim.
    A permissive value is EVIDENCE, never a claim of exposure."""
    headers = entry.get("headers") or {}
    acao = headers.get("access-control-allow-origin", "")
    return {
        "status": entry.get("status"),
        "test_origin": CORS_TEST_ORIGIN,
        "access_control_allow_origin": acao[:MAX_HEADER_VALUE],
        "access_control_allow_credentials": headers.get(
            "access-control-allow-credentials", "")[:MAX_HEADER_VALUE],
        "vary": headers.get("vary", "")[:MAX_HEADER_VALUE],
        "origin_reflected": acao == CORS_TEST_ORIGIN,
        "wildcard": acao == "*",
        "error": entry.get("error"),
    }


def _collect_refs(value, out: "list[str]", *, depth: int = 0) -> None:
    """Bounded, depth-limited walk collecting ``$ref`` STRING values
    only (metadata). Nothing is resolved, fetched or evaluated."""
    if depth > 4 or len(out) >= 200:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "$ref" and isinstance(v, str):
                out.append(v[:MAX_HEADER_VALUE])
            else:
                _collect_refs(v, out, depth=depth + 1)
    elif isinstance(value, list):
        for v in value[:50]:
            _collect_refs(v, out, depth=depth + 1)


def _parse_document(body: bytes, path: str) -> dict:
    """Strict, bounded OpenAPI/Swagger metadata. json.loads only (no
    YAML, no code execution); refs are counted, never resolved; no
    operation is ever invoked."""
    doc: dict = {"path": path, "document_bytes": len(body)}
    if len(body) >= MAX_BODY_BYTES:
        doc["oversized"] = True
        doc["note"] = ("document at or over the size bound — metadata "
                       "only, not parsed")
        return doc
    try:
        spec = json.loads(body)
    except ValueError:
        doc["parsed"] = False
        doc["note"] = "response body is not a JSON document"
        return doc
    if not isinstance(spec, dict):
        doc["parsed"] = False
        doc["note"] = "document root is not an object"
        return doc
    doc["parsed"] = True
    doc["spec_version"] = str(
        spec.get("openapi") or spec.get("swagger") or "")[:40]
    doc["title"] = str((spec.get("info") or {}).get("title")
                       or "")[:MAX_HEADER_VALUE]
    endpoints: list = []
    refs: list = []
    paths = spec.get("paths")
    if isinstance(paths, dict):
        for op_path, item in paths.items():
            if len(endpoints) < MAX_ENDPOINTS and \
                    isinstance(item, dict):
                methods = sorted(
                    m.upper() for m in item
                    if isinstance(m, str) and m.lower() in HTTP_METHODS)
                endpoints.append(
                    f"{','.join(methods) or '?'} {op_path}"
                    [:MAX_ENDPOINT_LEN])
            _collect_refs(item, refs)
    doc["endpoints"] = endpoints
    doc["endpoint_count"] = len(endpoints)
    doc["endpoints_truncated"] = len(endpoints) >= MAX_ENDPOINTS
    doc["external_refs"] = [
        r for r in refs
        if r.startswith(("http://", "https://"))][:MAX_REFS_LISTED]
    doc["ref_count_total"] = len(refs)
    if doc["external_refs"]:
        doc["note"] = ("external $ref targets observed — never fetched, "
                       "never resolved, never followed")
    return doc


def _clean(entry: dict) -> dict:
    """Strip the raw-body carry and bound the public fields."""
    public = {k: v for k, v in entry.items()
              if k not in ("_body", "headers")}
    public["headers"] = entry.get("headers", {})
    return public


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"kind": "kryonsec_api_probe",
                          "error": "usage: api_probe.py <url>"}))
        return 2
    base_url = sys.argv[1]
    try:
        parts = urlsplit(base_url)
    except ValueError:
        parts = None
    if parts is None or parts.scheme not in ("http", "https") \
            or not parts.hostname:
        print(json.dumps({
            "kind": "kryonsec_api_probe",
            "error": "not an http(s) url",
        }))
        return 2

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sent = 0

    base = _request(base_url)
    sent += 1
    cors_entry = _request(base_url, origin=CORS_TEST_ORIGIN)
    sent += 1
    options = _request(base_url, method="OPTIONS")
    sent += 1

    found: list = []
    unreachable: list = []
    for doc_path in DOC_PATHS:
        if sent >= MAX_REQUESTS:
            unreachable.append({"path": doc_path,
                                "error": "request budget exhausted"})
            continue
        entry = _request(base_url, doc_path)
        sent += 1
        if "status" not in entry:
            unreachable.append({"path": doc_path,
                                "error": entry.get("error", "")})
            continue
        doc: dict = {
            "path": doc_path,
            "status": entry.get("status"),
            "content_type": entry.get("content_type", ""),
            "body_bytes": entry.get("body_bytes", 0),
            "redirect": entry.get("redirect"),
        }
        if entry.get("status") == 200 and entry.get("_body"):
            doc.update(_parse_document(entry["_body"], doc_path))
        found.append(doc)

    options_headers = options.get("headers") or {}
    payload = {
        "kind": "kryonsec_api_probe",
        "url": base_url[:500],
        "started_at": started_at,
        "requests_sent": sent,
        "status": "complete" if "status" in base else "error",
        "base": {
            "status": base.get("status"),
            "content_type": base.get("content_type", ""),
            "security_headers": base.get("headers", {}),
            "redirect": base.get("redirect"),
            "error": base.get("error"),
        },
        "cors_probe": _origin_reflection(cors_entry),
        "options": {
            "status": options.get("status"),
            "allow": options_headers.get("allow", ""),
            "cors": options_headers,
            "error": options.get("error"),
        },
        "docs": {
            "probed": list(DOC_PATHS),
            "found": found,
            "unreachable": unreachable,
        },
        "limitations": [
            "read-only GET/OPTIONS only — no state-changing method",
            "redirects are recorded, never followed",
            "one host only: the approved base URL's host",
            "no credentials, tokens or cookies are sent or stored",
            "OpenAPI refs are counted, never resolved or fetched",
            "OPTIONS results are advertised metadata, not proof of "
            "authorization behavior",
        ],
        "errors": [e for e in (
            base.get("error"), cors_entry.get("error"),
            options.get("error")) if e],
    }
    # the raw bodies never leave the script
    print(json.dumps(payload))
    return 0 if "status" in base else 1


if __name__ == "__main__":
    sys.exit(main())
