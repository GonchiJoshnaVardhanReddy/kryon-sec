#!/bin/bash
# Kryonsec Zone B sandbox entrypoint (spec v2.1.1 §8.5).
# Receives tool argv as CONTAINER ARGUMENTS (docker run IMAGE tool arg1 arg2).
# Executes ONLY allowlisted tools. Defense-in-depth only — the authoritative
# allowlist check is ToolRunner Layer 2 on the host (src/kryonsec/purple/allowlist.py).
#
# KEEP IN SYNC with the host allowlist: tests/test_allowlist.py
# (test_entrypoint_allowlist_in_sync) fails the build when a host-allowlisted
# tool is missing here. Baked scripts (/opt/kryonsec/*.py) are listed by full path.

set -uo pipefail   # NOT -e: we must capture the tool's real exit code

TOOL="${1:-}"

ALLOWED_TOOLS=(
    # passive subdomain tools (run with -passive flags only)
    "subfinder" "amass" "assetfinder"
    # active recon
    "nmap" "naabu" "httpx" "rustscan" "whatweb" "katana" "hakrawler"
    "feroxbuster" "sslscan" "testssl.sh" "dnsx"
    # active recon (Phase 8): screenshots, DNS brute-force, API discovery
    "gowitness" "massdns" "/opt/kryonsec/openapi_probe.py"
    # exploit / testing
    "nuclei" "sqlmap" "nikto" "curl" "wget" "ffuf" "gobuster" "wfuzz"
    "dalfox" "commix" "ssrfmap" "arjun" "tplmap" "jwt_tool" "kr"
    "graphql-cop" "searchsploit"
    # verify
    "http" "openssl" "dig" "nc" "ncat"
    "/opt/kryonsec/probe.py"
    # post-exploit (evidence collection only)
    "linpeas.sh" "pspy64" "linux-exploit-suggester.sh"
    "/opt/kryonsec/enum_processes.py" "/opt/kryonsec/enum_fs.py"
    "/opt/kryonsec/enum_network.py" "/opt/kryonsec/find_secrets.py"
    # blue-team static analyzers (Phase 5) — run against /code read-only
    "semgrep" "bandit" "gitleaks" "trivy" "checkov" "hadolint" "kube-bench"
    # image-side extras kept from the original image (not host-allowlisted
    # today, harmless here — the HOST allowlist is the authoritative gate)
    "python3" "bloodhound-python"
)

if [[ -z "$TOOL" ]] || [[ ! " ${ALLOWED_TOOLS[*]} " =~ " ${TOOL} " ]]; then
    # stdout (not stderr): the host parses exactly one JSON payload there
    printf '{"error": "tool_not_in_allowlist", "tool": "%s"}\n' "$TOOL"
    exit 125
fi

# Execute; capture output and the REAL exit code
OUTFILE="$(mktemp /tmp/toolout.XXXXXX)"
timeout --signal=KILL 300 "$@" >"$OUTFILE" 2>&1
EXIT_CODE=$?

# Emit JSON payload on stdout — jq is installed in the image
printf '{"exit_code": %d, "stdout": %s}\n' "$EXIT_CODE" "$(jq -Rs '.' < "$OUTFILE")"

rm -f "$OUTFILE"
exit "$EXIT_CODE"
