#!/usr/bin/env bash
# Kryonsec one-line installer (WSL / Linux / macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/GonchiJoshnaVardhanReddy/kryon-sec/main/install.sh | bash
#
# What it does:
#   1. checks for Python 3.11+
#   2. creates ~/.kryonsec/venv
#   3. installs kryonsec into it (from GitHub)
#   4. adds ~/.kryonsec/venv/bin to PATH (in .bashrc, idempotent)
#   5. builds the Zone B sandbox image when docker is available (Purple Team)
#   6. runs `kryonsec setup` (the wizard: LLM, tools, MCP)
set -euo pipefail

REPO="https://github.com/GonchiJoshnaVardhanReddy/kryon-sec"
KRYONSEC_HOME="${KRYONSEC_HOME:-$HOME/.kryonsec}"
VENV="$KRYONSEC_HOME/venv"

say() { printf '\033[36m==>\033[0m %s\n' "$1"; }
die() { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# ---- 1. python 3.11+ ------------------------------------------------------
PY=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
            PY="$candidate"
            break
        fi
    fi
done
[ -n "$PY" ] || die "Python 3.11+ not found. Install it first: https://www.python.org/downloads/"
say "using $($PY --version)"

# ---- 2. venv ---------------------------------------------------------------
say "creating virtualenv at $VENV"
"$PY" -m venv "$VENV" 2>/dev/null || {
    # some minimal installs lack ensurepip
    "$PY" -m venv --without-pip "$VENV"
    die "venv created without pip — install python3-venv / python3-pip and retry"
}

# ---- 3. install -------------------------------------------------------------
say "installing kryonsec (this pulls litellm, mcp, rich, …)"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet "git+$REPO.git"
"$VENV/bin/kryonsec" --version || die "installation failed"

# ---- 4. PATH (idempotent) ---------------------------------------------------
SHELL_RC="$HOME/.bashrc"
MARKER='# kryonsec'
if ! grep -q "$MARKER" "$SHELL_RC" 2>/dev/null; then
    printf '\n%s\nexport PATH="%s:$PATH"\n' "$MARKER" "$VENV/bin" >> "$SHELL_RC"
    say "added $VENV/bin to PATH in ~/.bashrc"
else
    say "PATH already set up in ~/.bashrc"
fi

# ---- 5. docker sandbox image (Linux only, optional) ------------------------
# Purple Team mode needs Docker + gVisor + the sandbox image. On the
# copilot-only path (or macOS/Windows) this is skipped — `kryonsec doctor`
# explains what's missing later.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker image inspect kryonsec/sandbox:latest >/dev/null 2>&1; then
        say "sandbox image already present"
    else
        say "building the Zone B sandbox image (kali + tools, ~4 min, ~2 GB)"
        TMP=$(mktemp -d)
        git clone --quiet --depth 1 "$REPO.git" "$TMP/kryonsec-src"
        docker build -q -t kryonsec/sandbox \
            -f "$TMP/kryonsec-src/containers/sandbox/Dockerfile.kali" \
            "$TMP/kryonsec-src" \
            || say "WARNING: sandbox image build failed — Purple Team will need it (see README)"
        rm -rf "$TMP"
    fi
else
    say "docker not found/running — skipped the sandbox image (Copilot works fine; Purple Team needs it)"
fi

# ---- 6. first-run wizard ----------------------------------------------------
say "starting setup wizard"
"$VENV/bin/kryonsec" setup

say "done — open a new terminal (or 'source ~/.bashrc') and run: kryonsec"
