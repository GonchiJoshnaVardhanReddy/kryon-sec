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
    ("graphql-cop", ["graphql-cop", "-t", "http://target.com/graphql", "-o", "json"]),
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
    # Phase 8D post-exploit (dormant — allowlisted + in image, not in the
    # fixed plan): impacket AD recon, bloodhound-python, cloud metadata.
    # The trailing context arg is a {term} (alnum + . : + , - space) — no
    # slashes, no credentials inline; creds arrive via operator context.
    ("GetNPUsers.py", ["GetNPUsers.py", "-dc-ip", "10.0.0.1",
                       "target-corp.com"]),
    ("GetUserSPNs.py", ["GetUserSPNs.py", "-dc-ip", "10.0.0.1",
                        "target-corp.com"]),
    ("GetADUsers.py", ["GetADUsers.py", "-dc-ip", "10.0.0.1", "target-corp.com"]),
    ("findDelegation.py", ["findDelegation.py", "-dc-ip", "10.0.0.1",
                           "target-corp.com"]),
    ("bloodhound-python", ["bloodhound-python", "--collection", "All",
                           "--domain", "target-corp.com", "--dc-ip", "10.0.0.1"]),
    ("/opt/kryonsec/cloud_meta.py", ["/opt/kryonsec/cloud_meta.py",
                                     "target-corp.com"]),
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


def test_impacket_secretsdump_is_not_allowlisted(allow):
    """Phase 8 adds the READ-ONLY impacket recon tools only — anything
    that extracts credentials or executes (secretsdump, atexec, wmiexec,
    smbexec, psexec) must stay off the list entirely."""
    for tool in ("secretsdump.py", "atexec.py", "wmiexec.py",
                 "smbexec.py", "psexec.py", "GetST.py", "ticketer.py"):
        with pytest.raises(AllowlistViolation):
            allow.validate(tool, [tool, "-dc-ip", "10.0.0.1", "target-corp.com"])


def test_impacket_template_pins_dc_ip_position(allow):
    """The -dc-ip value is a {target} (host/ip) token and comes FIRST —
    a free-form command line must never validate."""
    with pytest.raises(AllowlistViolation):
        allow.validate("GetNPUsers.py",
                       ["GetNPUsers.py", "target-corp.com/", "-dc-ip", "10.0.0.1"])


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


# ---- allowlisted tools must actually be INSTALLED in the image ------------
# The sync test above proves the entrypoint lists the tool. It says nothing
# about whether the tool exists on disk — a gap that shipped five silent
# spawn failures at once:
#   dnsx              allowlisted, stage-1 tool of the DEFAULT RECON_ACTIVE
#                     plan, never installed (Kali has a dnsx package; the
#                     apt list just never named it)
#   bloodhound-python \
#   jwt_tool          | one `pip install bloodhound.py jwt-tool graphql-cop`
#   graphql-cop       / line. pip is all-or-nothing, so ONE bad name aborted
#                     the whole command and a `|| WARN` hid it — and all
#                     three names were wrong (none exists on PyPI).
#   checkov           no Kali package (pkg.kali.org/pkg/checkov is a 404);
#                     the "pip fallback" the comment promised was never wired.
#
# apt's file lists can't be introspected from a unit test (that `httpx-toolkit`
# provides `httpx`, or that `exploitdb` provides `searchsploit`, is a Kali
# database fact), so this does not guess. Every tool instead DECLARES the token
# that proves its install below, and the test asserts that token really appears
# in Dockerfile.kali. Adding a tool to the allowlist without saying where the
# image gets it now fails here — which is the point.

_DOCKERFILE = (
    Path(__file__).resolve().parents[1] / "containers" / "sandbox" / "Dockerfile.kali"
)

# baked into the image by `COPY containers/sandbox/scripts/ /opt/kryonsec/`
_BAKED = "/opt/kryonsec"

_TOOL_SOURCE: dict[str, str] = {
    # passive subdomain tools — apt
    "subfinder": "subfinder",
    "amass": "amass",
    "assetfinder": "assetfinder",
    # active recon — apt (the package name is not always the binary name)
    "nmap": "nmap",
    "naabu": "naabu",
    "httpx": "httpx-toolkit",
    "rustscan": "rustscan",
    "whatweb": "whatweb",
    "katana": "katana",
    "hakrawler": "hakrawler",
    "feroxbuster": "feroxbuster",
    "sslscan": "sslscan",
    "testssl.sh": "testssl.sh",
    "dnsx": "dnsx",
    "gowitness": "gowitness",
    "massdns": "massdns",
    f"{_BAKED}/openapi_probe.py": _BAKED,
    # exploit
    "nuclei": "nuclei",
    "sqlmap": "sqlmap",
    "nikto": "nikto",
    "curl": "curl",
    "wget": "wget",
    "ffuf": "ffuf",
    "gobuster": "gobuster",
    "wfuzz": "wfuzz",
    "dalfox": "dalfox",
    "commix": "commix",
    "ssrfmap": "ssrfmap",
    "arjun": "arjun",
    "tplmap": "tplmap",
    "jwt_tool": "jwt_tool",
    "kr": "kiterunner",
    "graphql-cop": "graphql-cop",
    "searchsploit": "exploitdb",
    f"{_BAKED}/nuclei_meta.py": _BAKED,
    # verify
    "http": "httpie",
    "openssl": "openssl",
    "dig": "dnsutils",
    "nc": "netcat-traditional",
    "ncat": "nmap",
    f"{_BAKED}/probe.py": _BAKED,
    # post-exploit
    "linpeas.sh": "linpeas",
    "pspy64": "pspy",
    "linux-exploit-suggester.sh": "linux-exploit-suggester",
    f"{_BAKED}/enum_processes.py": _BAKED,
    f"{_BAKED}/enum_fs.py": _BAKED,
    f"{_BAKED}/enum_network.py": _BAKED,
    f"{_BAKED}/find_secrets.py": _BAKED,
    f"{_BAKED}/cloud_meta.py": _BAKED,
    "GetNPUsers.py": "impacket-scripts",
    "GetUserSPNs.py": "impacket-scripts",
    "GetADUsers.py": "impacket-scripts",
    "findDelegation.py": "impacket-scripts",
    "bloodhound-python": "bloodhound-python",
    # blue team
    "semgrep": "semgrep",
    "bandit": "bandit",
    "gitleaks": "gitleaks",
    "trivy": "trivy",
    "checkov": "checkov",
    "hadolint": "hadolint",
    "syft": "syft",
    "osv-scanner": "osv-scanner",
    "grype": "grype",
}


def test_every_allowlisted_tool_declares_an_image_source():
    from kryonsec.purple.allowlist import EXPLOIT_ALLOWLIST_TEMPLATES

    undeclared = set(EXPLOIT_ALLOWLIST_TEMPLATES) - set(_TOOL_SOURCE)
    assert not undeclared, (
        f"allowlisted tools with no declared image source: {sorted(undeclared)}. "
        f"Add each to _TOOL_SOURCE naming the Dockerfile.kali token that proves "
        f"the image installs it — then make sure that install really happens."
    )


def test_declared_image_sources_are_all_in_the_dockerfile():
    """The other half: a declaration that names something the Dockerfile does
    not actually contain is the same silent failure, one step later."""
    text = _DOCKERFILE.read_text(encoding="utf-8")
    missing = {
        tool: token for tool, token in _TOOL_SOURCE.items() if token not in text
    }
    assert not missing, (
        f"these tools declare an image source the Dockerfile never installs: "
        f"{sorted(missing.items())} — the spawn would fail inside the sandbox"
    )


def test_nothing_is_declared_that_is_not_allowlisted():
    """Keep the table from rotting: a stale entry hides a real removal."""
    from kryonsec.purple.allowlist import EXPLOIT_ALLOWLIST_TEMPLATES

    stale = set(_TOOL_SOURCE) - set(EXPLOIT_ALLOWLIST_TEMPLATES)
    assert not stale, f"_TOOL_SOURCE entries for tools no longer allowlisted: {sorted(stale)}"


def test_entrypoint_allowlist_in_sync():
    from kryonsec.purple.allowlist import EXPLOIT_ALLOWLIST_TEMPLATES

    missing = set(EXPLOIT_ALLOWLIST_TEMPLATES) - _entrypoint_tools()
    assert not missing, (
        f"host-allowlisted tools missing from sandbox entrypoint "
        f"ALLOWED_TOOLS (would be rejected inside the image): {sorted(missing)}"
    )


# ---- trailing-newline anchor (2026-09-18) ----------------------------------
# Templates were compiled as "^…$". Python's $ also matches just BEFORE a
# trailing newline, so an argv element ending in "\n" passed validation even
# though the character is outside every argument character class.

def test_trailing_newline_in_url_rejected(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("curl", ["curl", "-sS", "--max-time", "30", "http://t/\n"])


def test_trailing_newline_in_term_rejected(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("searchsploit", ["searchsploit", "--colorless", "-h\n"])


def test_trailing_newline_in_target_rejected(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("dig", ["dig", "../../etc\n", "+short"])


def test_plain_url_still_accepted(allow):
    r"""The \Z anchor must not tighten anything else."""
    allow.validate("curl", ["curl", "-sS", "--max-time", "30", "http://t/"])


def test_embedded_newline_rejected(allow):
    with pytest.raises(AllowlistViolation):
        allow.validate("curl", ["curl", "-sS", "--max-time", "30", "http://t/\nX"])
