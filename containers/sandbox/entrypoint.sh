#!/bin/bash
# Kryonsec Zone B sandbox entrypoint (spec v2.1.1 §8.5).
# Receives tool argv as CONTAINER ARGUMENTS (docker run IMAGE tool arg1 arg2).
# Executes ONLY allowlisted tools. Defense-in-depth only — the authoritative
# allowlist check is ToolRunner Layer 2 on the host.

set -uo pipefail   # NOT -e: we must capture the tool's real exit code

TOOL="${1:-}"

ALLOWED_TOOLS=(
    "nmap" "dnsx" "subfinder"
    "sqlmap" "nikto" "gobuster" "ffuf"
    "curl" "wget" "nc" "ncat" "openssl" "python3"
    "linpeas.sh" "bloodhound-python"
)

if [[ -z "$TOOL" ]] || [[ ! " ${ALLOWED_TOOLS[*]} " =~ " ${TOOL} " ]]; then
    printf '{"error": "tool_not_in_allowlist", "tool": "%s"}\n' "$TOOL" >&2
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
