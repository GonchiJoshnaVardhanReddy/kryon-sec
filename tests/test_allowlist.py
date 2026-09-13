"""Tests for tool allowlist validation (spec §4.7, §8.1)."""

import re
from pathlib import Path

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


# ---- new templates (tool expansion Phase 1) -------------------------------

@pytest.mark.parametrize("tool,argv", [
    # passive subdomain tools — must carry their -passive flag
    ("subfinder", ["subfinder", "-d", "target.com", "-passive", "-silent"]),
    ("amass", ["amass", "enum", "-passive", "-d", "target.com"]),
    ("assetfinder", ["assetfinder", "-silent", "target.com"]),
    # active recon
    ("naabu", ["naabu", "-host", "target.com", "-p", "80,443", "-rate", "100", "-silent"]),
    ("httpx", ["httpx", "-u", "http://target.com/", "-silent", "-status-code", "-title", "-tech-detect"]),
    ("rustscan", ["rustscan", "-a", "target.com", "-p", "80,443", "--no-banner", "-t", "2000"]),
    ("whatweb", ["whatweb", "-a", "3", "--no-errors", "--color=never", "http://target.com/"]),
    ("katana", ["katana", "-u", "http://target.com/", "-d", "2", "-silent"]),
    ("hakrawler", ["hakrawler", "-url", "http://target.com/", "-depth", "3"]),
    ("feroxbuster", ["feroxbuster", "-u", "http://target.com/FUZZ",
                     "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
                     "-t", "5", "--timeout", "30"]),
    ("sslscan", ["sslscan", "--no-failed", "--sleep", "100", "target.com"]),
    ("testssl.sh", ["testssl.sh", "--batch", "--severity=high", "--no-color", "https://target.com/"]),
    ("dnsx", ["dnsx", "-d", "target.com", "-silent"]),
    # exploit specialists
    ("dalfox", ["dalfox", "url", "http://target.com/?q=1", "--silence"]),
    ("commix", ["commix", "--url", "http://target.com/?id=1", "--batch"]),
    ("ssrfmap", ["ssrfmap", "-u", "http://target.com/?url=1", "-m", "fetch"]),
    ("arjun", ["arjun", "-u", "http://target.com/"]),
    ("tplmap", ["tplmap", "-u", "http://target.com/?name=1"]),
    ("jwt_tool", ["jwt_tool", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123_-DEF"]),
    ("wfuzz", ["wfuzz", "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
               "--hc", "404", "http://target.com/FUZZ", "-t", "5"]),
    ("kr", ["kr", "scan", "/opt/wordlists/routes.kx", "--host", "http://target.com/"]),
    ("graphql-cop", ["graphql-cop", "-u", "http://target.com/graphql", "-o", "json"]),
    ("searchsploit", ["searchsploit", "--colorless", "apache struts"]),
    # verify
    ("http", ["http", "--ignore-stdin", "--check-status", "http://target.com/"]),
    ("openssl", ["openssl", "s_client", "-connect", "target.com:443", "-brief"]),
    ("dig", ["dig", "target.com", "+short"]),
    ("nc", ["nc", "-z", "-w", "30", "target.com", "443"]),
    ("ncat", ["ncat", "-z", "-w", "30", "target.com", "443"]),
    ("/opt/kryonsec/probe.py", ["/opt/kryonsec/probe.py", "http://target.com/"]),
    # blue-team static analyzers (Phase 5) — fixed /code mount, read-only
    ("semgrep", ["semgrep", "--config=auto", "/code"]),
    ("bandit", ["bandit", "-r", "/code"]),
    ("gitleaks", ["gitleaks", "detect", "--source", "/code"]),
    ("trivy", ["trivy", "fs", "--scanners", "vuln", "/code"]),
    ("checkov", ["checkov", "-d", "/code"]),
    ("hadolint", ["hadolint", "/code/Dockerfile"]),
    # Phase 8 active recon: screenshots, DNS brute-force, API discovery
    ("gowitness", ["gowitness", "scan", "website", "--url", "http://target.com:8080/",
                   "--screenshot-path", "/evidence", "--no-console", "--disable-db"]),
    ("massdns", ["massdns", "-r", "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
                 "-t", "A", "-o", "S", "-w", "/tmp/massdns.out",
                 "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"]),
    ("/opt/kryonsec/openapi_probe.py",
     ["/opt/kryonsec/openapi_probe.py", "http://target.com:8080/"]),
])
def test_new_template_accepts_valid_argv(allow, tool, argv):
    allow.validate(tool, argv)


def test_blue_team_templates_reject_other_paths(allow):
    """The scanners read the fixed /code mount ONLY — a different path
    (e.g. /etc) must never validate."""
    with pytest.raises(AllowlistViolation):
        allow.validate("bandit", ["bandit", "-r", "/etc"])
    with pytest.raises(AllowlistViolation):
        allow.validate("hadolint", ["hadolint", "/code/../etc/passwd"])
    with pytest.raises(AllowlistViolation):
        allow.validate("semgrep", ["semgrep", "--config=auto", "/code", "-o", "/tmp/x"])


def test_passive_templates_require_passive_flag(allow):
    """subfinder WITHOUT -passive must be rejected — the zero-packet
    invariant of RECON_PASSIVE depends on the flag being in the template."""
    with pytest.raises(AllowlistViolation):
        allow.validate("subfinder", ["subfinder", "-d", "target.com", "-silent"])


def test_depth_rejects_out_of_range(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("katana", ["katana", "-u", "http://target.com/", "-d", "9", "-silent"])


def test_port_rejects_non_numeric(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("nc", ["nc", "-z", "-w", "30", "target.com", "https"])


def test_hostport_rejects_bare_host(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("openssl", ["openssl", "s_client", "-connect", "target.com", "-brief"])


def test_token_rejects_shell_metacharacters(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("jwt_tool", ["jwt_tool", "abc; rm -rf /"])


def test_term_rejects_shell_metacharacters(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("searchsploit", ["searchsploit", "--colorless", "apache; id"])


def test_embedded_alternation_accepts_each_choice(allow):
    for sev in ("low", "medium", "high", "critical"):
        allow.validate("testssl.sh",
                       ["testssl.sh", "--batch", f"--severity={sev}", "--no-color",
                        "https://target.com/"])


def test_embedded_alternation_rejects_unknown_choice(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("testssl.sh",
                       ["testssl.sh", "--batch", "--severity=info", "--no-color",
                        "https://target.com/"])


# ---- Phase 8 templates ------------------------------------------------------

def test_gowitness_screenshot_path_is_pinned_to_evidence(allow):
    """Screenshots go to the rw /evidence mount ONLY — any other path
    (e.g. /tmp, or a host path) must be rejected."""
    with pytest.raises(AllowlistViolation):
        allow.validate("gowitness", [
            "gowitness", "scan", "website", "--url", "http://target.com/",
            "--screenshot-path", "/tmp", "--no-console", "--disable-db"])
    with pytest.raises(AllowlistViolation):
        # --disable-db is required: the rootfs is read-only, a SQLite
        # result DB would crash the run
        allow.validate("gowitness", [
            "gowitness", "scan", "website", "--url", "http://target.com/",
            "--screenshot-path", "/evidence", "--no-console"])


def test_massdns_rejects_arbitrary_wordlist(allow):
    """The wordlist and resolvers are FIXED literals from the image — an
    attacker-influenced list must never validate."""
    with pytest.raises(AllowlistViolation):
        allow.validate("massdns", [
            "massdns", "-r", "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
            "-t", "A", "-o", "S", "-w", "/tmp/massdns.out",
            "/etc/passwd"])


def test_openapi_probe_takes_only_a_url(allow):
    """Fixed argv [script, url] — extra args or options are rejected."""
    with pytest.raises(AllowlistViolation):
        allow.validate("/opt/kryonsec/openapi_probe.py",
                       ["/opt/kryonsec/openapi_probe.py",
                        "http://target.com/", "--extra"])
    with pytest.raises(AllowlistViolation):
        allow.validate("/opt/kryonsec/openapi_probe.py",
                       ["/opt/kryonsec/openapi_probe.py", "target.com"])


# ---- entrypoint ↔ host allowlist sync (defense-in-depth Layer 2b) ---------
# A tool allowlisted on the host but missing from the sandbox entrypoint's
# ALLOWED_TOOLS would be rejected INSIDE the image on every spawn (the
# original nuclei bug). This test keeps the two lists from drifting.

_ENTRYPOINT = (
    Path(__file__).resolve().parents[1] / "containers" / "sandbox" / "entrypoint.sh"
)


def _entrypoint_tools() -> set[str]:
    text = _ENTRYPOINT.read_text(encoding="utf-8")
    # the array's closing paren sits on its own line at column 0 — a plain
    # non-greedy match would stop at the FIRST ")" (comments inside the
    # array contain parens, e.g. "run with -passive flags only")
    m = re.search(r"ALLOWED_TOOLS=\((.*?)^\)", text, re.DOTALL | re.MULTILINE)
    assert m, "ALLOWED_TOOLS array not found in entrypoint.sh"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_entrypoint_allowlist_in_sync():
    from kryonsec.purple.allowlist import EXPLOIT_ALLOWLIST_TEMPLATES

    missing = set(EXPLOIT_ALLOWLIST_TEMPLATES) - _entrypoint_tools()
    assert not missing, (
        f"host-allowlisted tools missing from sandbox entrypoint "
        f"ALLOWED_TOOLS (would be rejected inside the image): {sorted(missing)}"
    )
