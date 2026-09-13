#!/usr/bin/env python3
"""Post-exploit secret discovery (baked into the sandbox image).

argv: /opt/kryonsec/find_secrets.py <target>

EVIDENCE COLLECTION ONLY. Scans sandbox-VISIBLE files for secret-shaped
content (private keys, AWS/GCP/Azure tokens, JWTs, connection strings) and
prints findings as (path, kind, masked excerpt). The <target> argument is
engagement CONTEXT for the record.

Findings are always MASKED: the report records that a secret of kind X
exists at path Y — never the secret itself (CLAUDE.md: raw evidence and
credentials are never propagated further than the evidence store).
"""

import json
import os
import re
import sys

MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {"/proc", "/sys", "/dev", "/run"}
HOME_ONLY = True  # scan /home, /tmp, /evidence — not the whole rootfs

# kind -> regex; deliberately narrow to avoid a wall of false positives
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret": re.compile(r"(?i)aws.{0,30}?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    "db_connection": re.compile(
        r"(?i)\b(mysql|postgres(ql)?|mongodb(\+srv)?|redis)://[^\s'\"]{5,}"),
}


def _mask(text: str) -> str:
    return text[:8] + "…" if len(text) > 8 else "…"


def _scan_file(path: str, findings: list[dict]) -> None:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except OSError:
        return
    for kind, pat in SECRET_PATTERNS.items():
        m = pat.search(content)
        if m:
            findings.append({
                "path": path,
                "kind": kind,
                "masked_excerpt": _mask(m.group(0)),
            })
            if len(findings) >= 200:
                return


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    roots = ["/home", "/tmp", "/evidence"] if HOME_ONLY else ["/"]
    findings: list[dict] = []
    files = 0

    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files_list in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files_list:
                files += 1
                if files > MAX_FILES or len(findings) >= 200:
                    break
                _scan_file(os.path.join(dirpath, name), findings)
            if files > MAX_FILES:
                break

    print(json.dumps({
        "probe": "find_secrets",
        "target_context": target,
        "files_scanned": files,
        "findings": findings,
        "note": "all excerpts masked — secrets never leave the evidence store",
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
