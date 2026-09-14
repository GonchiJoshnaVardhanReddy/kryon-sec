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

# Clone the repo at a tag/branch/SHA ref (shallow) into $2.
clone_ref() {
    if git clone --quiet --depth 1 --branch "$1" "$REPO.git" "$2"; then
        return 0
    fi
    # commit SHAs can't be cloned via --branch; fetch the exact ref instead
    git init --quiet "$2" &&
        git -C "$2" fetch --quiet --depth 1 origin "$1" &&
        git -C "$2" checkout --quiet FETCH_HEAD
}

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
# Install a released version, not whatever is on main at this moment. The
# latest tag comes from git ls-remote (plain tags count — no GitHub Release
# needed, no API rate limits); a hardcoded fallback covers offline installs
# and repos without tags. KRYONSEC_VERSION overrides both ("@v1.3.0",
# "@main", "@<commit-sha>"). Bump FALLBACK_TAG on every release.
FALLBACK_TAG="v1.3.1"
if [ -n "${KRYONSEC_VERSION:-}" ]; then
    say "installing kryonsec${KRYONSEC_VERSION} (KRYONSEC_VERSION override)"
else
    LATEST_TAG="$(git ls-remote --tags --refs "$REPO.git" 2>/dev/null \
        | sed 's|.*refs/tags/||' | "$PY" -c '
import sys
def key(t):
    return [int(p) if p.isdigit() else 0 for p in t.lstrip("v").split(".")]
tags = [l.strip() for l in sys.stdin if l.strip()]
print(max(tags, key=key) if tags else "")')"
    if [ -n "$LATEST_TAG" ]; then
        KRYONSEC_VERSION="@$LATEST_TAG"
        say "installing latest release $LATEST_TAG"
    else
        KRYONSEC_VERSION="@$FALLBACK_TAG"
        say "no tags on the remote — using pinned $FALLBACK_TAG"
    fi
fi
say "installing kryonsec (this pulls litellm, mcp, rich, …)"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet "git+$REPO.git$KRYONSEC_VERSION"
"$VENV/bin/kryonsec" --version || die "installation failed"

# ---- 4. PATH (idempotent) ---------------------------------------------------
SHELL_RC="$HOME/.bashrc"
case "$SHELL" in
    *zsh) SHELL_RC="$HOME/.zshrc" ;;
esac
MARKER='# kryonsec'
if ! grep -q "$MARKER" "$SHELL_RC" 2>/dev/null; then
    printf '\n%s\nexport PATH="%s:$PATH"\n' "$MARKER" "$VENV/bin" >> "$SHELL_RC"
    say "added $VENV/bin to PATH in $SHELL_RC"
else
    say "PATH already set up in $SHELL_RC"
fi
# when this script is piped into bash, $SHELL is the caller's shell — fish
# users get nothing from the block above, so tell them what to run
case "$SHELL" in
    *fish) say "fish detected: run this once ->  set -U fish_user_paths $VENV/bin \$fish_user_paths" ;;
esac

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
        # same ref the package was installed from — image and package must match
        if clone_ref "${KRYONSEC_VERSION#@}" "$TMP/kryonsec-src"; then
            docker build -q -t kryonsec/sandbox \
                -f "$TMP/kryonsec-src/containers/sandbox/Dockerfile.kali" \
                "$TMP/kryonsec-src" \
                || say "WARNING: sandbox image build failed — Purple Team will need it (see README)"
        else
            say "WARNING: could not fetch sandbox sources (git missing or network down) — skipping image build"
        fi
        rm -rf "$TMP"
    fi
else
    say "docker not found/running — skipped the sandbox image (Copilot works fine; Purple Team needs it)"
fi

# ---- 6. first-run wizard ----------------------------------------------------
say "starting setup wizard"
"$VENV/bin/kryonsec" setup

say "done — open a new terminal (or 'source ~/.bashrc') and run: kryonsec"
