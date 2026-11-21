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
    # ProjectDiscovery httpx under its REAL Kali binary name (the plain
    # `httpx` command does not exist in this image — debian/rules installs
    # it ONLY as httpx-toolkit); used by the httpx-probe adapter (2B.3)
    "httpx-toolkit"
    "feroxbuster" "sslscan" "testssl.sh" "dnsx"
    # active recon (Phase 8): screenshots, DNS brute-force, API discovery
    "gowitness" "massdns" "/opt/kryonsec/openapi_probe.py"
    # active recon (Phase 4 expansion, 2026-11-17): WAF fingerprinting,
    # content discovery, DNS enumeration (resolver-pinned), SMB/NetBIOS
    # (port-gated: only planned when 139/445 is observed open)
    "wafw00f" "dirsearch" "dnsenum" "fierce" "nbtscan" "smbmap" \
    "enum4linux-ng"
    # vetted TLS/API baseline adapters (Phase 2B.5): baked wrapper
    # scripts, fixed argv = [script, url]. tls_probe.py owns the image's
    # real testssl binary (/usr/bin/testssl) with frozen flags;
    # api_probe.py is read-only GET/OPTIONS against the ONE approved
    # base URL's host.
    "/opt/kryonsec/tls_probe.py" "/opt/kryonsec/api_probe.py"
    # exploit / testing
    "nuclei" "sqlmap" "nikto" "curl" "wget" "ffuf" "gobuster" "wfuzz"
    "dalfox" "commix" "ssrfmap" "arjun" "tplmap" "jwt_tool" "kr"
    "graphql-cop" "searchsploit"
    # nuclei template metadata search (Phase 8) — HYPOTHESIZE enrichment
    "/opt/kryonsec/nuclei_meta.py"
    # verify
    "http" "openssl" "dig" "nc" "ncat"
    "/opt/kryonsec/probe.py"
    # post-exploit (evidence collection only)
    "linpeas.sh" "pspy64" "linux-exploit-suggester.sh"
    "/opt/kryonsec/enum_processes.py" "/opt/kryonsec/enum_fs.py"
    "/opt/kryonsec/enum_network.py" "/opt/kryonsec/find_secrets.py"
    # post-exploit (Phase 8, DORMANT — allowlisted + in image, not in the
    # fixed plan; activates when a shell-producing tool exists)
    "/opt/kryonsec/cloud_meta.py"
    "GetNPUsers.py" "GetUserSPNs.py" "GetADUsers.py" "findDelegation.py"
    "bloodhound-python"
    # blue-team static analyzers (Phase 5) — run against /code read-only
    # (kube-bench deliberately NOT here: excluded from Phase 8's fixed plan
    # and not host-allowlisted — see the extras line below)
    "semgrep" "bandit" "gitleaks" "trivy" "checkov" "hadolint"
    # blue-team SBOM/dependency scanners (Phase 8)
    "syft" "osv-scanner" "grype"
    # blue-team binary/forensics dir-mode scanners (Phase 4): /code
    # read-only mount only (dir-mode tools; terrascan deferred: no Kali
    # package — Dockerfile note)
    "checksec" "exiftool"
    # blue-team file-granular binary tools (Phase 3, 2026-11-19): every
    # argv carries a typed {file} value under /code (host Layer-2 rule);
    # these are evidence readers only — never extraction or execution
    "strings" "xxd" "binwalk" "objdump" "ROPgadget" "r2" "gdb"
    # image-side extras kept from the original image (not host-allowlisted
    # today, harmless here — the HOST allowlist is the authoritative gate)
    "python3" "kube-bench"
)

if [[ -z "$TOOL" ]] || [[ ! " ${ALLOWED_TOOLS[*]} " =~ " ${TOOL} " ]]; then
    # stdout (not stderr): the host parses exactly one JSON payload there.
    # $TOOL is jq-encoded, never interpolated raw: a quote or backslash in the
    # name would otherwise emit malformed JSON, and this is the violation
    # report — the host must be able to read it to tell a rejection from a crash.
    printf '{"error": "tool_not_in_allowlist", "tool": %s}\n' \
        "$(printf '%s' "$TOOL" | jq -Rs '.')"
    exit 125
fi

# Nuclei template-policy gate (Phase 2B.8, defense-in-depth Layer 2b).
# Before every nuclei run: every -t value must be a manifest-approved
# template file with the exact reviewed sha256 (the one allowed
# directory value is the exact tree root — the legacy EXPLOIT-stage
# selection, unchanged); remote-template/OAST/update/local-file flags
# are refused. The gate prints its own JSON error and exits 125; fail
# closed even if the gate itself cannot run.
if [[ "$TOOL" == "nuclei" ]]; then
    GATE_OUT="$(python3 /opt/kryonsec/nuclei_gate.py "$@" 2>/dev/null)"
    GATE_RC=$?
    if [[ $GATE_RC -ne 0 ]]; then
        if [[ -n "$GATE_OUT" ]]; then
            printf '%s\n' "$GATE_OUT"
        else
            printf '{"error": "template_policy_gate_failed", "gate_rc": %d}\n' \
                "$GATE_RC"
        fi
        exit 125
    fi
fi

# Execute; capture output and the REAL exit code
OUTFILE="$(mktemp /tmp/toolout.XXXXXX)"
timeout --signal=KILL 300 "$@" >"$OUTFILE" 2>&1
EXIT_CODE=$?

# Emit JSON payload on stdout — jq is installed in the image
printf '{"exit_code": %d, "stdout": %s}\n' "$EXIT_CODE" "$(jq -Rs '.' < "$OUTFILE")"

rm -f "$OUTFILE"
exit "$EXIT_CODE"
