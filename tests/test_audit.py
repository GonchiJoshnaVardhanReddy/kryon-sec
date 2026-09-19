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


# --- damaged chain tail (spec §10.2) ---------------------------------------

def test_torn_last_line_refuses_to_append(tmp_path):
    """A crash mid-write left half a line. Appending must not silently skip it.

    _load_last_hash used to `continue` past an unparseable line, so appends
    resumed from the previous hash and the torn line stayed in the file:
    verify() then failed with "unparseable JSON" forever, and nothing warned
    at write time.
    """
    import pytest

    from kryonsec.purple.audit import AuditChainError

    _make_log(tmp_path)
    path = tmp_path / "audit.jsonl"
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"event":"tool_call","has')   # torn write, no newline

    with pytest.raises(AuditChainError) as exc:
        AuditLog(path)
    # the message has to be actionable, not just "invalid JSON"
    assert "last line" in str(exc.value)
    assert "interrupted" in str(exc.value)


def test_corrupt_middle_line_refuses_to_append(tmp_path):
    import pytest

    from kryonsec.purple.audit import AuditChainError

    _make_log(tmp_path)
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = "not json at all"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainError, match="not the last"):
        AuditLog(path)


def test_entry_without_a_hash_refuses_to_append(tmp_path):
    """Valid JSON that isn't an audit entry is damage too."""
    import pytest

    from kryonsec.purple.audit import AuditChainError

    _make_log(tmp_path, n=2)
    path = tmp_path / "audit.jsonl"
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"event":"mystery"}\n')       # parsed, but has no hash

    with pytest.raises(AuditChainError):
        AuditLog(path)


def test_blank_lines_do_not_break_the_chain(tmp_path):
    """Trailing/embedded blank lines are not damage."""
    log = _make_log(tmp_path)
    head = log.head_hash()
    path = tmp_path / "audit.jsonl"
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n\n")

    reopened = AuditLog(path)
    assert reopened.head_hash() == head
    reopened.write({"event": "after_blank"})
    ok, reason = reopened.verify()
    assert ok, reason


def test_empty_file_is_genesis(tmp_path):
    from kryonsec.purple.audit import _GENESIS_PREV

    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    assert AuditLog(path).head_hash() == _GENESIS_PREV
