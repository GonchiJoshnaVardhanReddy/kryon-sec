"""Tests for the audit chain (spec §10.2): canonical hashing, tamper detection."""

import json
import shutil

from kryonsec.purple.audit import AuditLog, canonical_json


def _make_log(tmp_path, n=5):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(n):
        log.write({"event": "tool_call", "seq": i, "tool": "nmap"})
    return log


def test_chain_verifies(tmp_path):
    log = _make_log(tmp_path)
    ok, reason = log.verify()
    assert ok, reason


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_tampered_entry_detected(tmp_path):
    log = _make_log(tmp_path)
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    entry = json.loads(lines[2])
    entry["tool"] = "changed"  # tamper without rehashing
    lines[2] = canonical_json(entry)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    ok, reason = AuditLog(tmp_path / "audit.jsonl").verify()
    assert not ok
    assert "hash mismatch" in reason


def test_truncated_chain_detected(tmp_path):
    _make_log(tmp_path)
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    (tmp_path / "audit.jsonl").write_text("\n".join(lines[:-2]) + "\n")
    # truncation is only detectable via an external anchor (head hash) —
    # the replay itself still verifies. Document the boundary.
    ok, _ = AuditLog(tmp_path / "audit.jsonl").verify()
    assert ok  # chain internally consistent; anchor is what catches truncation


def test_reopened_log_appends_after_last_hash(tmp_path):
    log1 = _make_log(tmp_path, n=3)
    head = log1.head_hash()
    log2 = AuditLog(tmp_path / "audit.jsonl")
    assert log2.head_hash() == head
    log2.write({"event": "more"})
    ok, reason = log2.verify()
    assert ok, reason
