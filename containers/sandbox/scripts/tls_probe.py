#!/usr/bin/env python3
"""TLS/HTTPS security baseline probe (baked into the sandbox image).

argv: /opt/kryonsec/tls_probe.py <url>

Runs the image's real testssl binary (Kali package ``testssl.sh`` installs
it as ``/usr/bin/testssl`` — verified in the pinned image; the
``testssl.sh`` command name does NOT exist) against ONE authorized
``https://host:port`` target with a FROZEN, code-owned argument set and
emits a COMPACT, SELF-BOUNDED JSON summary on stdout.

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
      sandbox entrypoint kills at 300s regardless); a killed run still
      yields the partial findings testssl wrote so far (verified: JSON
      is written incrementally), marked ``status: partial``. A partial
      summary is an honest observation set, never padded to look
      complete.

BOUNDED-SUMMARY CONTRACT (Phase 2B.8 — the truncation fix):

    The sandbox host caps captured tool stdout at 20,000 chars
    (fail-closed on overflow — unchanged). A real full testssl run
    produces far more observation data than fits there, so the OLD
    wrapper's emit-everything payload was truncated and honestly
    REJECTED — useful observations were lost with it. This wrapper
    fixes that WITHOUT touching the host bound:

    testssl --jsonfile /tmp/kryonsec_tls_probe.json   (FULL output,
        captured in the run's private /tmp tmpfs — dies with the
        container, no host path)
        ↓
    defensive parse + salvage of the findings file (never invent one)
        ↓
    normalization: true totals + severity histogram + weak/protocol/
        certificate classification
        ↓
    OPTIONAL artifact: when the sandbox mounted the engagement
        evidence dir (read-write at the fixed /evidence — the ONLY rw
        host mount), the FULL redacted findings JSON is persisted
        there: fixed sanitized filename (no caller path input — path
        traversal is structurally impossible), O_CREAT|O_EXCL|O_NOFOLLOW
        (a symlinked dir or file is refused, an existing file is never
        clobbered), mode 0600, size-capped, patterns redacted, sha256 +
        byte count recorded. No evidence mount → no artifact, no error.
        ↓
    compact structured summary: header, TRUE counts, severity
        histogram, bounded top-N weak findings, bounded protocol and
        certificate observations, artifact reference, honest status.
        ↓
    SELF-BOUND: the serialized payload is measured against
        OUTPUT_BOUND_CHARS (10,000 — the raw stdout the entrypoint
        relays must stay well inside the host's 20,000-char cap after
        jq's JSON escaping). Over bound → drop the top-N weak findings
        tail first, then protocol/certificate bodies (counts, status,
        artifact ref and ALL honesty flags never drop), re-measure;
        the floor is a counts-only payload that is always valid JSON,
        always parseable, and always honest: ``summary_truncated:
        true`` records what was left out. The host's 20,000-char bound
        is never relied on as the safety mechanism — the wrapper
        refuses to emit anything that big.

HONESTY: counts and the histogram always reflect ALL salvaged findings,
even when the emitted selection is smaller. A truncated or partial run
is never presented as complete (status + limitations + truncation
flags). Malformed input is skipped, never interpreted; nothing is
fabricated to fill a section.

OUTPUT CONTRACT (v2, verified against testssl 3.2.4 in the pinned
image): one JSON object: {kind, version, url, node, tool, tool_version,
status, exit_code, argv_reference, started_at, finding_count_total,
finding_count_emitted, severity_histogram, findings (top-N weak),
protocols, certificates, truncated, selection_note, summary_truncated,
summary_bound_chars, artifact, limitations}. ``severity_as_reported``
is testssl's OWN label (data about the match) — nothing here is a
confirmed vulnerability and nothing here upgrades itself; the host
adapter hard-wires verification to ``not_verified``.

Exit codes: 0 = an observation payload was emitted (complete or
partial); 2 = usage error (bad argv, not an https URL); 1 = the tool
ran but produced no usable output (the payload still describes it).
"""

import hashlib
import json
import os
import re
import stat
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
MAX_STDOUT_CAPTURE = 4_000

#: the engagement evidence dir the sandbox mounts READ-WRITE at this
#: FIXED path when the run carries one (sandbox.py: the only rw host
#: mount). Absent → no artifact is written, silently and honestly.
EVIDENCE_DIR = "/evidence"

#: the self-bound on the RAW stdout this script prints. The host's
#: 20,000-char bound (max_tool_output_chars) is NOT changed; this stays
#: far under it so the entrypoint's jq re-serialization (which escapes
#: every quote/newline, growing the string) still fits with margin.
OUTPUT_BOUND_CHARS = 10_000
#: selection bounds for the summary's per-section lists
TOP_WEAK_FINDINGS = 20
TOP_PROTOCOLS = 12
TOP_CERTIFICATES = 12
MAX_FINDING_TEXT = 300
#: the full findings file is read at most this many bytes (tmpfs is
#: 100m; a real full run writes ~1-2MB; this bound keeps a pathological
#: file from stalling the summary — flagged honestly when hit)
FINDINGS_FILE_MAX_BYTES = 16_000_000
#: the persisted artifact is capped; an OVERSIZED source file omits the
#: artifact (reason recorded) instead of writing an unbounded copy
ARTIFACT_MAX_BYTES = 2_000_000

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

#: severities that mean "the tool reported a weakness" (mirrors the
#: host adapter's label set; OK/INFO stay observations-only)
_WEAK_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN"})
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                  "WARN": 4, "INFO": 5, "OK": 6}

#: redaction patterns applied to the PERSISTED artifact only (the
#: summary never carries raw blobs). Pattern-based best effort, counted.
_RE_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----(?:.|\n)+?-----END [A-Z0-9 ]+-----")
_RE_CRED = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api_?key|access_?key|"
    r"auth_?token|authorization|bearer)\b(\s*[=:]\s*)(\"[^\"]*\"|\S+)")
_RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")


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
    salvage the complete flat finding objects — never invent one.
    (Pure function over text; ``_read_findings_file`` owns the file
    lifecycle and calls this.)"""
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


def _read_findings_file() -> "tuple[list[dict], dict]":
    """The salvaged findings + honesty metadata about the file itself.

    A file over FINDINGS_FILE_MAX_BYTES is read only to the bound and
    flagged ``file_incomplete`` (never silently clipped); the salvage
    itself is ``_salvage_findings``.
    """
    meta = {"file_present": False, "file_bytes": 0, "file_incomplete": False}
    try:
        size = os.path.getsize(JSONFILE)
    except OSError:
        return [], meta
    meta["file_present"] = True
    read_to = min(size, FINDINGS_FILE_MAX_BYTES)
    meta["file_incomplete"] = size > read_to
    meta["file_bytes"] = size
    try:
        with open(JSONFILE, "rb") as fh:
            text = fh.read(read_to).decode("utf-8", errors="replace")
    except OSError:
        return [], meta
    return _salvage_findings(text), meta


def _classify(findings_raw: "list[dict]") -> "tuple[list[dict], list[dict], list[dict], dict[str, int]]":
    """Normalize the raw findings into (weak, protocols, certificates,
    histogram). Deterministic: severity-ranked weakest-first, file order
    within a rank. The histogram counts EVERY salvaged finding — the
    true totals the summary reports even when the selection is smaller.
    """
    histogram: dict[str, int] = {}
    weak: list[dict] = []
    protocols: list[dict] = []
    certificates: list[dict] = []
    for entry in findings_raw:
        fid = str(entry.get("id") or "")[:60]
        if not fid:
            continue     # an idless blob is skipped, not guessed
        sev = str(entry.get("severity") or "")[:20].upper()
        histogram[sev or "UNSPECIFIED"] = histogram.get(sev or "UNSPECIFIED",
                                                        0) + 1
        norm = {
            "id": fid,
            "severity_as_reported": sev,
            "finding": str(entry.get("finding") or "")[:MAX_FINDING_TEXT],
            "cve": str(entry.get("cve") or "")[:60] if entry.get("cve") else "",
            "port": str(entry.get("port") or "")[:10],
        }
        if fid.startswith(("SSLv", "TLS1")):
            protocols.append(norm)
        elif fid.startswith("cert_"):
            certificates.append(norm)
        if sev in _WEAK_SEVERITIES:
            weak.append(norm)
    weak.sort(key=lambda f: (_SEVERITY_RANK.get(
        f["severity_as_reported"], 9), f["id"]))
    return weak, protocols, certificates, histogram


def _redact(text: str) -> "tuple[str, int]":
    """Pattern redaction for the PERSISTED artifact: PEM blocks,
    credential assignments, AWS key ids. Returns (text, count)."""
    count = 0
    text, n = _RE_PEM.subn("<redacted-pem-block>", text)
    count += n
    text, n = _RE_CRED.subn(r"\1\2<redacted>", text)
    count += n
    text, n = _RE_AWS_KEY.subn("<redacted-aws-key>", text)
    count += n
    return text, count


def _artifact_filename(node: str) -> str:
    """A FIXED, sanitized filename — no caller-controlled path input
    exists, so traversal is structurally impossible. `10.0.0.5:443` ->
    `tls_probe_full_20260101T120000Z_10.0.0.5_443.json`."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", node)[:64] or "node"
    return f"tls_probe_full_{stamp}_{safe}.json"


def _persist_artifact(source_text: str, node: str) -> "dict | None":
    """Persist the FULL redacted findings JSON into the evidence dir.

    Guards, all fail-closed to ``None`` + reason: no /evidence mount;
    /evidence is a SYMLINK (refused — never traverse one); the write
    target exists (O_EXCL never clobbers) or is a symlink
    (O_NOFOLLOW); the source exceeds ARTIFACT_MAX_BYTES (oversized);
    any write error. The returned reference carries the sha256 and byte
    count of the bytes ACTUALLY WRITTEN (computed post-redaction — the
    integrity record matches the artifact on disk, not the source).
    """
    if not os.path.isdir(EVIDENCE_DIR) or os.path.islink(EVIDENCE_DIR):
        return None
    try:
        st = os.stat(EVIDENCE_DIR, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode):
            return None
    except OSError:
        return None
    if len(source_text.encode("utf-8", errors="replace")) > ARTIFACT_MAX_BYTES:
        return {"omitted": "oversized"}
    name = _artifact_filename(node)
    if "/" in name or name in (".", ".."):
        return {"omitted": "bad_name"}
    path = os.path.join(EVIDENCE_DIR, name)
    data, redactions = _redact(source_text)
    encoded = data.encode("utf-8", errors="replace")
    if len(encoded) > ARTIFACT_MAX_BYTES:
        return {"omitted": "oversized"}
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(encoded)
        except BaseException:
            try:
                os.unlink(path)     # never leave a partial artifact
            except OSError:
                pass
            raise
    except FileExistsError:
        return {"omitted": "exists"}
    except OSError as e:
        return {"omitted": f"write_failed: {e.__class__.__name__}"}
    os.chmod(path, 0o600)
    return {
        "name": name[:200],
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
        "redactions": redactions,
        "source_file": JSONFILE,
        "note": "redacted copy of the full testssl --jsonfile output",
    }


def _bounded_payload(payload: dict, sections: "list[str]") -> "tuple[dict, bool]":
    """Shrink the payload under OUTPUT_BOUND_CHARS, honestly.

    Drops the listed sections' LIST BODIES one item at a time (tail
    first) until the serialized payload fits. Counts, status, histogram,
    artifact ref and honesty flags are NEVER dropped. Returns the
    (possibly shrunk) payload + whether any body was dropped.
    """
    if len(json.dumps(payload, separators=(",", ":"))) <= OUTPUT_BOUND_CHARS:
        return payload, False
    dropped = False
    for key in sections:
        items = payload.get(key)
        if not isinstance(items, list):
            continue
        while items and len(
                json.dumps(payload, separators=(",", ":"))) \
                > OUTPUT_BOUND_CHARS:
            items.pop()
            dropped = True
        if len(json.dumps(payload, separators=(",", ":"))) \
                > OUTPUT_BOUND_CHARS:
            payload[key] = []     # section body dropped entirely
    if len(json.dumps(payload, separators=(",", ":"))) > OUTPUT_BOUND_CHARS:
        # floor: counts-only — always far under the bound
        for key in ("findings", "protocols", "certificates"):
            payload[key] = []
        dropped = True
    if dropped:
        payload["summary_truncated"] = True
        payload.setdefault("limitations", []).append(
            f"summary body trimmed to the {OUTPUT_BOUND_CHARS}-char "
            "self-bound; counts and the histogram reflect ALL findings")
    return payload, dropped


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

    findings_raw, file_meta = _read_findings_file()
    weak, protocols, certificates, histogram = _classify(findings_raw)
    if killed or (not findings_raw and not tool_stdout and exit_code != 0):
        status = "partial" if killed else "error"

    # the artifact: the FULL redacted findings file, only when the run
    # carries the engagement evidence mount (no mount -> no artifact,
    # no error); failures omit it with a reason, never fatally
    artifact = None
    if findings_raw and not file_meta["file_incomplete"]:
        raw_text = ""
        try:
            with open(JSONFILE, encoding="utf-8", errors="replace") as fh:
                raw_text = fh.read(FINDINGS_FILE_MAX_BYTES)
        except OSError:
            raw_text = ""
        if raw_text:
            artifact = _persist_artifact(raw_text, node)

    selection = weak[:TOP_WEAK_FINDINGS]
    payload = {
        "kind": "kryonsec_tls_probe",
        "version": 2,
        "url": url[:500],
        "node": node[:300],
        "tool": "testssl",
        "tool_version": _tool_version(),
        "status": status,
        "exit_code": exit_code,
        "argv_reference": [a if a != node else node[:300] for a in argv],
        "started_at": started_at,
        "finding_count_total": len(findings_raw),
        "finding_count_emitted": len(selection),
        "severity_histogram": dict(sorted(histogram.items())),
        "findings": selection,
        "protocols": protocols[:TOP_PROTOCOLS],
        "certificates": certificates[:TOP_CERTIFICATES],
        "truncated": len(weak) > len(selection)
                     or len(protocols) > TOP_PROTOCOLS
                     or len(certificates) > TOP_CERTIFICATES
                     or file_meta["file_incomplete"],
        "selection_note": (
            f"top-{len(selection)} weakest of {len(findings_raw)} "
            "salvaged findings; true totals above"
            if len(weak) > len(selection) or histogram else
            "all salvaged findings emitted"),
        "summary_truncated": False,
        "summary_bound_chars": OUTPUT_BOUND_CHARS,
        "artifact": artifact,
        "limitations": [],
    }
    if killed:
        payload["limitations"].append(
            f"killed after {TESTSSL_TIMEOUT_S}s — partial findings only")
    if file_meta["file_incomplete"]:
        payload["limitations"].append(
            f"findings file exceeded {FINDINGS_FILE_MAX_BYTES} bytes — "
            "salvage clipped, counts are for the salvaged prefix only")
    if artifact and artifact.get("omitted"):
        payload["limitations"].append(
            f"full-output artifact omitted: {artifact['omitted']}")
        payload["artifact"] = None
    elif artifact is None and findings_raw:
        payload["limitations"].append(
            "no evidence dir mounted in this run — full output not "
            "persisted (summary only)")

    payload, _shrunk = _bounded_payload(
        payload, ("findings", "protocols", "certificates"))
    print(json.dumps(payload))
    return 0 if status in ("complete", "partial") else 1


if __name__ == "__main__":
    sys.exit(main())
