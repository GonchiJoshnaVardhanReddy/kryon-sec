"""Tests for tool allowlist validation (spec §4.7, §8.1)."""

import pytest

from kryonsec.purple.allowlist import AllowlistViolation, ToolAllowlist


@pytest.fixture()
def allow():
    return ToolAllowlist()


def test_valid_nmap_argv(allow):
    allow.validate("nmap", ["nmap", "-Pn", "-sT", "-sV", "-sC", "--max-rate", "100", "-p", "80,443", "target.example.com"])


def test_wrong_arg_count_rejected(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("nmap", ["nmap", "-sV"])


def test_non_allowlisted_tool_rejected(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("masscan", ["masscan", "-p80", "1.2.3.0/24"])


def test_metasploit_not_allowlisted():
    allow = ToolAllowlist()
    with pytest.raises(AllowlistViolation):
        allow.validate("msfconsole", ["msfconsole", "-q"])


def test_sqlmap_technique_alternation(allow):
    argv = ["sqlmap", "-u", "http://t.example.com/page?id=1", "--batch",
            "--risk=1", "--level=1", "--technique=U", "--timeout=30", "--threads=1"]
    allow.validate("sqlmap", argv)


def test_sqlmap_bad_technique_rejected(allow):
    argv = ["sqlmap", "-u", "http://t.example.com/", "--batch",
            "--risk=9", "--level=1", "--technique=U", "--timeout=30", "--threads=1"]
    with pytest.raises(AllowlistViolation):
        allow.validate("sqlmap", argv)


def test_blocklist_catches_destructive(allow):
    with pytest.raises(AllowlistViolation):
        allow.check_blocklist(["bash", "-c", "rm -rf /"])


def test_blocklist_allows_normal_argv(allow):
    allow.check_blocklist(["nmap", "-sV", "-p", "80", "target.example.com"])
