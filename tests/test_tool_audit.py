"""Dedicated tests for Mode A's tool-audit chain (`copilot/tool_audit.py`).

The MCP registry tests exercise this log only indirectly; its own guards
(pre-set hashes, damaged-file refusal, tampering, missing file) were
tested only against the purple twin. These tests lock the Mode A copy's
contract AND the deliberate wire-format parity with `purple/audit.py`.
"""

import json

import pytest

from kryonsec.copilot.tool_audit import (
    AuditChainError,
    ToolAuditLog,
    canonical_json,
)
from kryonsec.purple.audit import AuditLog as PurpleAuditLog


def _make_log(tmp_path, n=5):
    log = ToolAuditLog(tmp_path / "mcp.jsonl")
    for i in range(n):
        log.write({"event": "mcp_tool_invoked", "seq": i, "tool": "echo"})
    return log


def test_chain_verifies(tmp_path):
    log = _make_log(tmp_path)
    ok, reason = log.verify()
    assert ok, reason


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_same_wire_format_as_purple(tmp_path):
    """The copy exists to avoid a Mode A -> Mode B import; it must stay
    byte-identical on the wire, or replay tooling (and any future
    cross-check) would diverge silently."""
    entry = {"event": "parity", "ts": "2026-01-01T00:00:00+00:00", "n": 1}
    purple = PurpleAuditLog(tmp_path / "purple.jsonl")
    mode_a = ToolAuditLog(tmp_path / "modea.jsonl")
    assert purple.write(dict(entry)) == mode_a.write(dict(entry))


def test_tampered_entry_detected(tmp_path):
    _make_log(tmp_path)
    path = tmp_path / "mcp.jsonl"
    lines = path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["tool"] = "changed"  # tamper without rehashing
    lines[2] = canonical_json(entry)
    path.write_text("\n".join(lines) + "\n")
    ok, reason = ToolAuditLog(path).verify()
    assert not ok
    assert "hash mismatch" in reason


def test_broken_chain_detected(tmp_path):
    _make_log(tmp_path)
    path = tmp_path / "mcp.jsonl"
    lines = path.read_text().splitlines()
    del lines[1]  # drop a middle link
    path.write_text("\n".join(lines) + "\n")
    ok, reason = ToolAuditLog(path).verify()
    assert not ok
    assert "prev_hash mismatch" in reason


def test_damaged_file_refuses_to_append(tmp_path):
    path = tmp_path / "mcp.jsonl"
    path.write_text('{"event": "x", "hash": "abc"}\nnot json at all\n')
    with pytest.raises(AuditChainError):
        ToolAuditLog(path)


def test_write_refuses_pre_set_hashes(tmp_path):
    log = ToolAuditLog(tmp_path / "mcp.jsonl")
    for forged in ({"prev_hash": "0" * 64}, {"hash": "f" * 64}):
        with pytest.raises(ValueError):
            log.write({"event": "x", **forged})


def test_verify_on_missing_file_never_raises(tmp_path):
    """The docstring promises verify() never raises; a chain that was
    never written is simply not verified."""
    ok, reason = ToolAuditLog(tmp_path / "never-written.jsonl").verify()
    assert not ok
    assert "no audit file" in reason


def test_reopened_log_appends_after_last_hash(tmp_path):
    log1 = _make_log(tmp_path, n=3)
    head = log1.head_hash()
    log2 = ToolAuditLog(tmp_path / "mcp.jsonl")
    assert log2.head_hash() == head
    log2.write({"event": "more"})
    ok, reason = log2.verify()
    assert ok, reason
