#!/usr/bin/env python3
"""TLS/HTTPS security baseline probe (baked into the sandbox image).

argv: /opt/kryonsec/tls_probe.py <url>

Runs the image's real testssl binary (Kali package ``testssl.sh`` installs
it as ``/usr/bin/testssl`` — verified in the pinned image; the
``testssl.sh`` command name does NOT exist) against ONE authorized
``https://host:port`` target with a FROZEN, code-owned argument set and
emits a compact, bounded JSON observation summary on stdout.

SECURITY CONTRACT (why a wrapper script):
    - testssl only writes its JSON findings to a FILE (verified in the
      pinned image: ``--jsonfile``), never to stdout — the sandbox
      captures stdout only. This wrapper therefore owns the file
      lifecycle INSIDE the run and prints the parsed summary.
    - Every testssl flag is a LITERAL in this script's code. The caller
      supplies exactly one argument (the URL) and can never add, remove
      or reshape a flag: no shell, no eval, no extra options, no
      user-selected checks, no ``--phone-out`` (external reporting) —
      that flag is never set and cannot be turned on.
    - The target is the ONE approved host:port parsed from the scope-
      validated URL. No certificate-metadata-driven scanning of other
      hosts is possible: testssl is pointed at exactly that node.
    - ``--warnings batch``: a testing error never prompts (no TTY).
    - Bounded: the subprocess is killed after TESTSSL_TIMEOUT_S (the
      sandbox entrypoint kills at 300s regardless); findings are
      capped; a killed run still yields the partial findings testssl
      wrote so far (verified: JSON is written incrementally), marked
      ``status: partial``. A partial summary is an honest observation
      set, never padded to look complete.

OUTPUT CONTRACT (verified against testssl 3.2.4 in the pinned image):
    one JSON object: {kind, url, node, tool, tool_version, status,
    exit_code, argv_reference, started_at, findings, finding_count,
    truncated}. Each finding: {id, severity_as_reported, finding, cve,
    port}. ``severity_as_reported`` is testssl's OWN label (data about
    the match) — nothing here is a confirmed vulnerability and nothing
    here upgrades itself; the host adapter hard-wires verification to
    ``not_verified``.

Exit codes: 0 = an observation payload was emitted (complete or
partial); 2 = usage error (bad argv, not an https URL); 1 = the tool
ran but produced no usable output (the payload still describes it).
"""

import json
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

#: the REAL binary name in this image (Kali pkg testssl.sh -> /usr/bin/testssl)
TESTSSL_BIN = "/usr/bin/testssl"
#: findings file, INSIDE the run's /tmp tmpfs (dies with the container)
JSONFILE = "/tmp/kryonsec_tls_probe.json"
#: subprocess bound; the entrypoint kills at 300s regardless. Measured
#: live under the sandbox's exact caps: full run 185s / 203s.
TESTSSL_TIMEOUT_S = 240
MAX_FINDINGS = 120
MAX_FINDING_TEXT = 300
MAX_STDOUT_CAPTURE = 4_000

#: the frozen testssl invocation. Everything is a literal except the
#: node (host:port) parsed out of the approved URL. ``--ip one`` is NOT
#: set: it refuses IP-literal targets, and multi-A-record scanning is
#: impossible anyway because the node is ONE approved address.
_ARGV_TEMPLATE = (
    "--quiet",               # no banner (and no usage-terms prompt)
    "--color", "0",          # no escape codes in any output
    "--warnings", "batch",   # never prompt on a testing error
    "--connect-timeout", "10",
    "--jsonfile", JSONFILE,
    # <node> appended last: testssl requires the URI as the last param
)


def _parse_node(url: str) -> "tuple[str, str, int] | None":
    """host:port out of an approved https URL (path dropped — TLS is a
    host:port property). Returns (node, host, port) or None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname:
        return None
    port = parts.port if parts.port else 443
    return f"{parts.hostname}:{port}", parts.hostname, port


def _tool_version() -> str:
    """testssl's self-reported version string, bounded (a fast,
    offline ``--version`` call; empty when it cannot be read)."""
    try:
        proc = subprocess.run(
            [TESTSSL_BIN, "--version"], capture_output=True, text=True,
            timeout=30)
        m = re.search(r"testssl\s+version\s+(\S+)",
                      (proc.stdout or "") + (proc.stderr or ""))
        return (m.group(1) if m else "")[:20]
    except Exception:
        return ""


def _salvage_findings(text: str) -> "list[dict]":
    """Parse testssl's pretty JSON; on a truncated file (killed run)
    salvage the complete flat finding objects — never invent one."""
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]
        return []
    except ValueError:
        pass
    findings: list[dict] = []
    # the findings file is a flat array of flat objects: recover every
    # complete {...} block (nested values would break this — testssl
    # findings are flat; anything nested is skipped, not guessed)
    for m in re.finditer(r"\{[^{}]*\}", text):
        try:
            entry = json.loads(m.group(0))
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("id"):
            findings.append(entry)
    return findings


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"kind": "kryonsec_tls_probe",
                          "error": "usage: tls_probe.py <url>"}))
        return 2
    url = sys.argv[1]
    parsed = _parse_node(url)
    if parsed is None:
        print(json.dumps({
            "kind": "kryonsec_tls_probe",
            "error": "not an https url — TLS baseline inspection is "
                     "defined for https targets only",
        }))
        return 2
    node, _host, _port = parsed

    argv = [TESTSSL_BIN, *_ARGV_TEMPLATE, node]
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    status = "complete"
    exit_code = -1
    tool_stdout = ""
    killed = False
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=TESTSSL_TIMEOUT_S)
        exit_code = proc.returncode
        tool_stdout = (proc.stdout or "")[:MAX_STDOUT_CAPTURE]
    except subprocess.TimeoutExpired:
        killed = True
        status = "partial"

    try:
        with open(JSONFILE, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        text = ""

    findings_raw = _salvage_findings(text)
    truncated = len(findings_raw) > MAX_FINDINGS
    findings = []
    for entry in findings_raw[:MAX_FINDINGS]:
        cve = entry.get("cve")
        findings.append({
            "id": str(entry.get("id") or "")[:60],
            "severity_as_reported": str(
                entry.get("severity") or "")[:20],
            "finding": str(entry.get("finding") or "")[:MAX_FINDING_TEXT],
            "cve": str(cve)[:60] if cve else "",
            "port": str(entry.get("port") or "")[:10],
        })
    findings = [f for f in findings if f["id"]]

    if killed or (not findings and not tool_stdout and exit_code != 0):
        status = "partial" if killed else "error"

    payload = {
        "kind": "kryonsec_tls_probe",
        "url": url[:500],
        "node": node[:300],
        "tool": "testssl",
        "tool_version": _tool_version(),
        "status": status,
        "exit_code": exit_code,
        "argv_reference": [a if a != node else node[:300] for a in argv],
        "started_at": started_at,
        "findings": findings,
        "finding_count": len(findings),
        "truncated": truncated,
    }
    if killed:
        payload["limitations"] = [
            f"killed after {TESTSSL_TIMEOUT_S}s — partial findings only"]
    print(json.dumps(payload))
    return 0 if status in ("complete", "partial") else 1


if __name__ == "__main__":
    sys.exit(main())
