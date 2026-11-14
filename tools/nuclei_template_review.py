#!/usr/bin/env python3
"""Nuclei template SAFETY review (Phase 2B.8, Task 2).

Static, per-template review of the candidate nuclei-templates tree.
Directory membership NEVER establishes safety (the Phase 2B.7 audit
proved it: token-spray/, misconfiguration/ and one login/logout template
inside exposed-panels/ were inside dirs previously called "vetted").

Every candidate template is parsed and its request structure is
summarized, then the non-destructive reconnaissance gates are applied:

  reject when the template (any request block):
  - is not a valid http-type YAML template (parse fail, non-http block)
  - issues anything but GET requests (POST/PUT/PURGE/DELETE/... are
    state-changing by design; even a GET can change state on a badly
    designed application, so paths carry their own denylist below)
  - carries a request body or a raw HTTP request (unsafe raw bytes)
  - references a host other than the approved {{BaseURL}} root
    (third-party callbacks / exfiltration)
  - uses {{interactsh-url}} / OAST callbacks (external interaction)
  - sets unsafe: true, uses code/JS, network/file protocol blocks,
    local wordlists (payload fuzzing), or declares the "intrusive" tag

  reject when the PATH hits the state-change keyword denylist
  (shutdown/restart/purge/delete/... — a GET to such a path can still
  change state on a poorly designed application; over-rejection is the
  safe direction, the review table shows every rejection by name).

Output: one JSON review file with a row per template (id, path, gates
fired, request summary) so the human review — and the resulting
manifest — are reproducible and auditable. Templates missing from the
reviewed inventory, or whose contents changed, are refused by the
execution policy later; this tool produces that inventory.

Usage:
  python tools/nuclei_template_review.py <templates-root> [candidate-dir ...]

  <templates-root> is a checked-out nuclei-templates tree at the commit
  whose SHA is recorded in the emitted review file. Default candidates:
  http/exposures/configs and http/exposed-panels (the two dirs the
  corrected policy may draw from).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import yaml

# ---- the non-destructive gates -------------------------------------------

#: the ONLY http methods the recon policy allows
ALLOWED_METHODS = frozenset({"GET"})

#: paths containing these (case-insensitive) are state-change suspects
_PATH_DENYLIST = (
    "shutdown", "restart", "reboot", "poweroff", "purge", "delete",
    "remove", "destroy", "wipe", "flush", "kill", "stop", "halt",
    "suspend", "reset", "erase", "format", "drop", "truncate",
    "execute", "exec", "shell", "powercycle", "restore-factory",
    "factoryreset", "logout", "signout", "sign-out",
    "deactivate", "unlink", "revoke", "clear-cache", "clearcache",
    "migrate", "redeploy", "uninstall", "terminate", "abort",
    "deregister", "action=logout", "action=delete",
    "action=drop", "do=logout", "do=delete",
)

#: credential-bearing query parameters: even a GET can submit secrets
#: (?password=...) — sensitive-data transmission is refused. Matched
#: against the QUERY part only (after "?"): a path component that
#: merely NAMES a file (/.aws/credentials) is not a credential
#: submission, but any =-suffixed secret parameter is.
_CRED_QUERY = ("password=", "passwd=", "pwd=", "pass=", "user=", "username=",
               "token=", "secret=", "auth=", "apikey=", "api_key=",
               "credential=")

#: tokens that mean external interaction / non-http payloads
_OAST_TOKENS = ("{{interactsh-url", "{{oast", "interactsh-url")

#: the request-root token: every URL must be anchored here (or the
#: approved {{Hostname}}/{{BaseURL}} spellings nuclei resolves to it)
_APPROVED_ROOTS = ("{{baseurl}}", "{{base_url}}", "{{hostname}}")


def _walk_requests(doc: dict) -> "list[dict]":
    """Every request block of an http-type template (nuclei schema:
    `http:` holds a list of request dicts)."""
    blocks = doc.get("http")
    if not isinstance(blocks, list):
        return []
    return [b for b in blocks if isinstance(b, dict)]


def _non_http_blocks(doc: dict) -> "list[str]":
    """Other protocol blocks (network/file/dns/code) — rejected."""
    return [k for k in ("network", "file", "code", "dns", "ssl")
            if k in doc]


def _ext_hosts(text: str) -> "list[str]":
    """URL-ish host references that are NOT the approved root."""
    import re

    hosts = []
    for m in re.finditer(r"https?://([^/\s\"'{}]+)", text):
        h = m.group(1).lower()
        if not any(h.startswith(r.strip("{}").lower())
                   for r in _APPROVED_ROOTS):
            hosts.append(h)
    return hosts


def _traffic_fields(req: dict) -> str:
    """The fields that drive traffic to the network (path, headers,
    redirect config) — the ONLY places an external request could hide.
    Matcher words/DSL live in their own fields and are comparisons on
    the RESPONSE (they may legitimately quote documentation URLs); they
    never cause a request. Over-rejection here would silently drop
    safe detection templates, so this stays precise."""
    parts = []
    for key in ("path", "paths", "headers", "redirects",
                "max-redirects", "max_redirects", "host"):
        v = req.get(key)
        if v is not None:
            parts.append(json.dumps({key: v}, default=str))
    return " ".join(parts)


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def review_template(path: Path) -> dict:
    """The review row for ONE template file: summary + gates fired."""
    row: dict = {
        "file": path.name,
        "path": str(path),
        "sha256": _hash_file(path),
        "template_id": "",
        "gates": [],
        "requests": 0,
        "methods": [],
        "paths": [],
        "tags": [],
        "severity": "",
    }
    text = ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        doc = yaml.safe_load(text)
    except Exception as e:
        row["gates"].append(f"yaml_parse: {type(e).__name__}")
        return row
    if not isinstance(doc, dict):
        row["gates"].append("yaml_not_mapping")
        return row

    tid = doc.get("id")
    row["template_id"] = str(tid)[:120] if isinstance(tid, str) else ""
    if not row["template_id"]:
        row["gates"].append("no_id")

    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    tags = info.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    tags = [str(t) for t in tags] if isinstance(tags, list) else []
    row["tags"] = tags[:12]
    row["severity"] = str(info.get("severity") or "")[:20]
    if "intrusive" in (t.lower() for t in tags):
        row["gates"].append("tag_intrusive")

    for block in _non_http_blocks(doc):
        row["gates"].append(f"non_http_block:{block}")

    requests = _walk_requests(doc)
    if not requests:
        row["gates"].append("no_http_requests")
        return row
    row["requests"] = len(requests)

    if "payloads" in text:
        row["gates"].append("payloads_present")

    for i, req in enumerate(requests):
        method = str(req.get("method") or "GET").upper()
        row["methods"].append(method)
        if method not in ALLOWED_METHODS:
            row["gates"].append(f"r{i}_method_{method}")
        for key in ("body", "raw"):
            if key in req:
                row["gates"].append(f"r{i}_{key}_present")
        if req.get("unsafe"):
            row["gates"].append(f"r{i}_unsafe")
        for key in ("wordlists", "headers_override", "cookie_reuse"):
            if key in req:
                row["gates"].append(f"r{i}_{key}_present")
        # paths: request path plus matcher-ish url fields (nuclei
        # allows a single string OR a list of path strings)
        p = req.get("path")
        if isinstance(p, str):
            p = [p]
        for path_expr in (p if isinstance(p, list) else []):
            if isinstance(path_expr, str) and path_expr.strip():
                low = path_expr.lower()
                row["paths"].append(path_expr[:200])
                for kw in _PATH_DENYLIST:
                    if kw in low:
                        row["gates"].append(f"r{i}_path_keyword:{kw}")
                        break
                for cred in _CRED_QUERY:
                    query = low.split("?", 1)[-1]
                    if query != low and cred in query:
                        row["gates"].append(
                            f"r{i}_cred_in_path:{cred[:-1]}")
                        break
        for key in ("redirects", "max-redirects", "max_redirects"):
            if key in req:
                # redirect FOLLOWING is allowed for GET probes but is
                # recorded so the reviewer sees it
                row.setdefault("redirects", []).append(i)

        # traffic-driving fields only: an external REQUEST could hide
        # here; matcher words never cause a request (see _traffic_fields)
        blob = _traffic_fields(req)
        if "{{interactsh-url" in blob or "{{oast" in blob:
            row["gates"].append(f"r{i}_interactsh")
        ext = _ext_hosts(blob)
        if ext:
            row["gates"].append(f"r{i}_external_host:{ext[0][:60]}")

    # whole-document scan: OAST/callback refs hide in matchers too
    if any(t in text.lower() for t in _OAST_TOKENS):
        row["gates"].append("doc_interactsh")
    return row


def _write_manifest(rows: "list[dict]", git_sha: str, out: Path) -> None:
    """The runtime manifest the execution policy enforces.

    Keys are the IMAGE paths (/opt/nuclei-templates/...) the adapter's
    frozen argv carries; values pin the reviewed template id and the
    sha256 of the reviewed file content. The Docker build verifies every
    entry against the baked tree (a mismatch FAILS the build), and the
    sandbox entrypoint re-verifies the argv's -t files against this
    manifest at every spawn (drift or an unreviewed file is refused —
    fail closed, never silently executed).
    """
    import datetime

    entries = {}
    for r in rows:
        if r["gates"]:
            continue
        # derive the image path from the reviewed file name + dir
        p = Path(r["path"])
        parent = p.parent.name
        sub = "exposures/configs" if parent == "configs" else parent
        img = f"/opt/nuclei-templates/http/{sub}/{p.name}"
        entries[img] = {"id": r["template_id"], "sha256": r["sha256"]}
    manifest = {
        "version": "phase-2b.8",
        "templates_commit": git_sha,
        "review_tool": "tools/nuclei_template_review.py",
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy": {
            "http_methods": ["GET"],
            "rejects": [
                "token-spray/ (credential validation/spraying)",
                "misconfiguration/ (state-changing POST/PURGE, raw "
                "HTTP, OAST/interactsh dependencies)",
                "login/logout and session-destroying paths",
                "non-GET methods, request bodies, raw HTTP",
                "credential-bearing query parameters",
                "external hosts, interactsh/OAST callbacks",
                "payloads/fuzzing, intrusive-tagged templates",
                "code/network/file/dns/ssl protocol blocks",
            ],
        },
        "templates": entries,
    }
    out.write_text(json.dumps(manifest, indent=1, sort_keys=True),
                   encoding="utf-8")
    print(f"manifest: {len(entries)} templates -> {out}")


def main(argv: "list[str]") -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    root = Path(argv[1]).resolve()
    candidates = [Path(a) for a in argv[2:]] or [
        root / "http" / "exposures" / "configs",
        root / "http" / "exposed-panels",
    ]
    # the tree's own commit, when available (reproducibility record)
    git_sha = ""
    git_dir = root / ".git"
    if git_dir.exists():
        try:
            git_sha = __import__("subprocess").run(
                ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                text=True, timeout=10).stdout.strip()
        except Exception:
            pass
    rows = []
    for cand in candidates:
        for path in sorted(cand.glob("*.yaml")):
            rows.append(review_template(path))
    approved = [r for r in rows if not r["gates"]]
    review = {
        "reviewed_at_commit": git_sha,
        "candidate_dirs": [str(c) for c in candidates],
        "reviewed": len(rows),
        "approved": len(approved),
        "rejected": len(rows) - len(approved),
        "rows": rows,
    }
    out = Path("tmp") / "nuclei_review.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(review, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in review.items() if k != "rows"},
                     indent=1))
    _write_manifest(rows, git_sha,
                    Path("src/kryonsec/purple/nuclei_manifest.json"))
    # compact rejection histogram so the human review knows what to see
    from collections import Counter

    hist = Counter(g.split(":")[0].split("_")[0]
                   for r in rows if r["gates"] for g in r["gates"])
    print("rejection histogram:", json.dumps(dict(hist), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
