#!/usr/bin/env bash
# Kryonsec one-line installer (WSL / Linux / macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/GonchiJoshnaVardhanReddy/kryon-sec/main/install.sh | bash
#
# What it does:
#   1. installs missing prerequisites (git, curl) on apt systems
#   2. checks for Python 3.11+
#   3. creates ~/.kryonsec/venv
#   4. installs kryonsec into it (from GitHub)
#   5. adds ~/.kryonsec/venv/bin to PATH (in .bashrc, idempotent)
#   6. on Linux with sudo: installs Docker + gVisor (runsc) if missing,
#      then fetches the Zone B sandbox image — pulled from ghcr.io (fast),
#      falling back to a local build (slow) when the pull isn't available
#   7. offers to install Ollama + llama3.1 when no LLM is configured
#   8. runs `kryonsec setup` (the wizard: LLM, tools, MCP)
#   9. runs `kryonsec doctor` so the final state is visible, and prints
#      the exact command to run when PATH isn't active in this shell yet
set -euo pipefail

REPO="https://github.com/GonchiJoshnaVardhanReddy/kryon-sec"
KRYONSEC_HOME="${KRYONSEC_HOME:-$HOME/.kryonsec}"
VENV="$KRYONSEC_HOME/venv"

say() { printf '\033[36m==>\033[0m %s\n' "$1"; }
die() { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
    say "WARNING: running as root — kryonsec installs to /root/.kryonsec and"
    say "         the command will only exist for the root user"
fi

# ---- 0. prerequisites ------------------------------------------------------
# git powers the release-tag lookup and the sandbox source clone; curl powers
# every download below. Rather than dying halfway through with a confusing
# error, install whatever is missing when we have root/sudo on an apt system.
is_apt() { command -v apt-get >/dev/null 2>&1; }
have_sudo() { [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1; }
maybe_sudo() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

apt_install() {
    # install the named packages if we can; never fatal — the caller decides
    is_apt && have_sudo || return 1
    maybe_sudo apt-get update -qq >/dev/null 2>&1 || true
    # shellcheck disable=SC2086  # $* is a deliberate word-split package list
    maybe_sudo apt-get install -y -qq $* >/dev/null 2>&1
}

MISSING=""
for tool in git curl; do
    command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done
if [ -n "$MISSING" ]; then
    say "missing prerequisites:$MISSING — installing"
    # shellcheck disable=SC2086
    if apt_install $MISSING ca-certificates; then
        say "prerequisites installed"
    else
        say "WARNING: could not install$MISSING — the installer may not complete"
        say "         install them manually and re-run"
    fi
fi
command -v git >/dev/null 2>&1 ||
    say "WARNING: git is unavailable — the latest-tag lookup and the sandbox source clone will be skipped"

# Clone the repo at a tag/branch/SHA ref (shallow) into $2.
clone_ref() {
    if git clone --quiet --depth 1 --branch "$1" "$REPO.git" "$2"; then
        return 0
    fi
    # commit SHAs can't be cloned via --branch; fetch the exact ref instead.
    # advice off + stderr swallowed: the detached-HEAD chatter a tag fetch
    # produces looks like an error to users (it isn't — the checkout works)
    git init --quiet "$2" &&
        git -C "$2" fetch --quiet --depth 1 origin "$1" 2>/dev/null &&
        git -C "$2" -c advice.detachedHead=false checkout --quiet FETCH_HEAD 2>/dev/null
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
if ! "$PY" -m venv "$VENV" 2>/dev/null; then
    # Debian/Ubuntu split ensurepip into python3-venv — install it and retry
    # rather than leaving a half-built venv behind
    say "virtualenv failed — installing python3-venv"
    rm -rf "$VENV"
    apt_install python3-venv python3-pip || true
    if ! "$PY" -m venv "$VENV" 2>/dev/null; then
        die "could not create a virtualenv — install python3-venv / python3-pip and re-run"
    fi
fi

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
    # `|| true` is load-bearing: under `set -o pipefail` the assignment takes
    # the pipeline's status, so a failing git (not installed → 127, or GitHub
    # unreachable → 128) used to kill the script right here — the exact
    # offline case FALLBACK_TAG exists for. Without it the "no tags on the
    # remote" branch below was unreachable dead code.
    LATEST_TAG="$(git ls-remote --tags --refs "$REPO.git" 2>/dev/null \
        | sed 's|.*refs/tags/||' | "$PY" -c '
import sys
def key(t):
    return [int(p) if p.isdigit() else 0 for p in t.lstrip("v").split(".")]
tags = [l.strip() for l in sys.stdin if l.strip()]
print(max(tags, key=key) if tags else "")' || true)"
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
# ${SHELL:-}: not exported in many non-interactive environments (docker RUN,
# CI) — a bare $SHELL aborts the script under `set -u`
case "${SHELL:-}" in
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
case "${SHELL:-}" in
    *fish) say "fish detected: run this once ->  set -U fish_user_paths $VENV/bin \$fish_user_paths" ;;
esac

# ---- 5. docker + gvisor + sandbox image (Purple Team, Linux) ----------------
# Purple Team mode needs Docker + gVisor + the sandbox image. Instead of
# telling the user to install prerequisites by hand, do it here when we
# have root/sudo on an apt system (Debian/Ubuntu/Kali). Copilot-only paths
# and non-apt systems fall through — `kryonsec doctor` explains later.

# maybe_sudo / have_sudo / is_apt are defined in section 0.

# run docker as root when the current user can't talk to the daemon yet
# (fresh install: the docker group only applies after the next login)
dkr() {
    if docker info >/dev/null 2>&1; then
        docker "$@"
    else
        maybe_sudo docker "$@"
    fi
}

install_docker() {
    say "installing Docker (apt)"
    maybe_sudo apt-get update -qq || return 1
    # distro package: works on every apt system (incl. Kali and Ubuntu
    # releases the docker.com repo hasn't caught up with) and is plenty
    # for a gVisor sandbox host
    maybe_sudo apt-get install -y -qq docker.io || return 1
    # start the daemon — systemd where available (WSL needs it on), the
    # sysv script as a fallback
    maybe_sudo systemctl enable --now docker 2>/dev/null ||
        maybe_sudo service docker start 2>/dev/null || true
    sleep 2
}

install_gvisor() {
    say "installing gVisor (runsc)"
    maybe_sudo apt-get install -y -qq gnupg
    maybe_sudo mkdir -p /usr/share/keyrings
    if curl -fsSL https://gvisor.dev/archive.key |
        maybe_sudo gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg &&
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases/release main $(dpkg --print-architecture)" |
            maybe_sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null &&
        maybe_sudo apt-get update -qq &&
        maybe_sudo apt-get install -y -qq runsc; then
        : # apt path worked
    else
        # The apt repo is distro-independent but some apt builds refuse it
        # (seen on Ubuntu 26.04: "does not have a Release file"). Fall back
        # to the official direct-binary install — same runsc, no repo.
        say "apt repo unavailable — installing runsc binary directly"
        local arch
        arch="$(uname -m)"
        if ! curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/latest/${arch}/runsc" -o /tmp/runsc-install; then
            return 1
        fi
        maybe_sudo install -m 0755 /tmp/runsc-install /usr/local/bin/runsc || return 1
        rm -f /tmp/runsc-install
        # remove the broken repo line if we added one — apt update must stay clean
        maybe_sudo rm -f /etc/apt/sources.list.d/gvisor.list
    fi
    # registers runsc in /etc/docker/daemon.json and restarts the daemon
    maybe_sudo runsc install
    maybe_sudo systemctl restart docker 2>/dev/null ||
        maybe_sudo service docker restart 2>/dev/null || true
    sleep 2
}

if [ "$(uname -s)" = "Linux" ] && have_sudo && is_apt; then
    if ! command -v docker >/dev/null 2>&1; then
        install_docker ||
            say "WARNING: Docker install failed — Copilot works fine; Purple Team needs it"
    elif ! docker info >/dev/null 2>&1 && ! maybe_sudo docker info >/dev/null 2>&1; then
        # docker is installed but the daemon is down — try to start it
        maybe_sudo systemctl enable --now docker 2>/dev/null ||
            maybe_sudo service docker start 2>/dev/null || true
        sleep 2
    fi
    if dkr info >/dev/null 2>&1; then
        RUNTIMES="$(dkr info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}' 2>/dev/null)"
        case " $RUNTIMES " in
            *" runsc "*) : ;; # already registered
            *)
                install_gvisor ||
                    say "WARNING: gVisor install failed — Purple Team needs the runsc runtime"
                ;;
        esac
    fi
fi

# Registry image published by .github/workflows/sandbox-image.yml on every
# release tag. Pulling beats building: ready-made layers download in parallel
# and resume on failure, where a local build downloads ~50 tools (~2 GB)
# inside a Docker build and takes 30+ min on a slow link. The build path is
# kept forever as the fallback, so an older copy of this script never hard-breaks.
SANDBOX_REGISTRY_IMAGE="ghcr.io/gonchijoshnavardhanreddy/kryonsec-sandbox"

# Image refs to try, in order, one per line.
#
# KRYONSEC_SANDBOX_IMAGE wins and is the ONLY ref tried: it may carry a
# @sha256: digest, and quietly pulling some other image would defeat the pin
# the operator asked for. Otherwise: the release tag we installed (its image
# matches the code), then :latest, which the publish workflow always maintains.
#
# That :latest fallback is what keeps installs FAST. A tagged install used to
# ask for :vX.Y.Z, try exactly once, and drop to the 30+ min local build
# whenever that tag had not been published — which is most of the time, since
# the tag only appears if the workflow happened to run on that exact tag.
sandbox_image_refs() {
    if [ -n "${KRYONSEC_SANDBOX_IMAGE:-}" ]; then
        printf '%s\n' "$KRYONSEC_SANDBOX_IMAGE"
        return 0
    fi
    case "${KRYONSEC_VERSION:-}" in
        @v*) printf '%s:%s\n' "$SANDBOX_REGISTRY_IMAGE" "${KRYONSEC_VERSION#@}" ;;
    esac
    printf '%s:latest\n' "$SANDBOX_REGISTRY_IMAGE"
    return 0
}

# set by pull_sandbox_image — reported so an install log always says which
# image it actually got, not just which one it asked for
PULLED_IMAGE_REF=""

pull_sandbox_image() {
    if [ -n "${KRYONSEC_REGISTRY_TOKEN:-}" ]; then
        # private-repo path; public pulls need no login
        printf '%s' "$KRYONSEC_REGISTRY_TOKEN" |
            dkr login ghcr.io -u "${KRYONSEC_REGISTRY_USER:-kryonsec}" \
                --password-stdin >/dev/null 2>&1 || true
    fi
    # for-loop, NOT `... | while read`: a pipeline runs the body in a subshell
    # and the `return 0` below would never reach this function
    for REF in $(sandbox_image_refs); do
        if dkr pull "$REF"; then
            # config/doctor/runner expect the local name kryonsec/sandbox:latest
            dkr tag "$REF" kryonsec/sandbox:latest || return 1
            PULLED_IMAGE_REF="$REF"
            return 0
        fi
        say "  $REF is not available in the registry"
    done
    return 1
}

build_sandbox_image() {
    say "building the Zone B sandbox image (kali + ~50 tools, 2+ GB download)"
    say "this is the slow part — on a slow link it can take 30+ min; progress is shown below"
    TMP=$(mktemp -d)
    # same ref the package was installed from — image and package must match
    if clone_ref "${KRYONSEC_VERSION#@}" "$TMP/kryonsec-src"; then
        # no -q: stream the build steps so it never looks frozen, and
        # completed layers are cached, so a retry resumes where it stopped
        if ! dkr build --progress=plain -t kryonsec/sandbox \
            -f "$TMP/kryonsec-src/containers/sandbox/Dockerfile.kali" \
            "$TMP/kryonsec-src"; then
            say "WARNING: sandbox image build failed — sources kept at $TMP/kryonsec-src"
            say "retry later with: docker build --progress=plain -t kryonsec/sandbox -f $TMP/kryonsec-src/containers/sandbox/Dockerfile.kali $TMP/kryonsec-src"
            return 1
        fi
        rm -rf "$TMP"
        return 0
    fi
    say "WARNING: could not fetch sandbox sources (git missing or network down) — skipping image build"
    rm -rf "$TMP"
    return 1
}

if [ -n "${KRYONSEC_SKIP_SANDBOX:-}" ]; then
    say "KRYONSEC_SKIP_SANDBOX set — skipping the sandbox image"
    # no pipeline here: `sandbox_image_refs | head -1` would let pipefail turn
    # head's early exit into a SIGPIPE failure and `set -e` would abort
    _later_ref="${KRYONSEC_SANDBOX_IMAGE:-${SANDBOX_REGISTRY_IMAGE}:latest}"
    say "get it later with: docker pull $_later_ref && docker tag $_later_ref kryonsec/sandbox:latest"
elif dkr info >/dev/null 2>&1; then
    if dkr image inspect kryonsec/sandbox:latest >/dev/null 2>&1; then
        say "sandbox image already present"
    else
        say "fetching the Zone B sandbox image..."
        if pull_sandbox_image; then
            say "sandbox image pulled: $PULLED_IMAGE_REF"
        else
            say "registry pull unavailable — falling back to a local build"
            build_sandbox_image ||
                say "WARNING: no sandbox image — Purple Team will not start (Copilot is unaffected)"
        fi
    fi
else
    say "docker not available — skipped the sandbox image (Copilot works fine; Purple Team needs it)"
fi

# ---- 6. LLM preflight -------------------------------------------------------
# The wizard used to be the first place a missing LLM showed up, and its
# Ollama-down path aborted setup entirely. Make sure a usable LLM exists
# BEFORE the wizard starts: existing Ollama, an OPENAI_API_KEY, or an
# offered one-shot Ollama install.
ollama_up() {
    curl -fsS --max-time 4 "${OLLAMA_HOST:-http://localhost:11434}/api/tags" >/dev/null 2>&1
}

install_ollama() {
    say "installing Ollama (local LLM — nothing leaves your machine)"
    curl -fsSL https://ollama.com/install.sh | sh || return 1
    # start it: systemd unit when present, detached background server otherwise
    if ! (systemctl is-active --quiet ollama 2>/dev/null ||
          maybe_sudo systemctl enable --now ollama 2>/dev/null); then
        nohup ollama serve >/dev/null 2>&1 &
    fi
    # cold start can take a few seconds before /api/tags answers
    for _ in $(seq 1 15); do
        ollama_up && break
        sleep 1
    done
    ollama_up || return 1
    say "pulling llama3.1 (~5 GB download — the local model)"
    ollama pull llama3.1 || return 1
}

if ollama_up; then
    say "Ollama already running"
elif [ -n "${OPENAI_API_KEY:-}" ]; then
    say "OPENAI_API_KEY set — the wizard will use OpenAI"
else
    # curl|bash consumes stdin, so the answer must come from the terminal.
    # No terminal (CI) → read fails → skip (the wizard still offers OpenAI).
    printf '\033[36m==>\033[0m No LLM configured yet. Install Ollama + llama3.1 locally (~5 GB)? [Y/n] '
    REPLY=""
    read -r REPLY < /dev/tty 2>/dev/null || REPLY="n"
    case "$REPLY" in
        n*|N*)
            say "skipped — pick OpenAI in the wizard (have your API key ready)"
            ;;
        *)
            install_ollama ||
                say "WARNING: Ollama install failed — pick OpenAI in the wizard (have your API key ready)"
            ;;
    esac
fi

# ---- 7. first-run wizard ----------------------------------------------------
# curl|bash hands the wizard the INSTALL PIPE as stdin, so every prompt read
# install-script text as its answer, or hit EOF — input() raises EOFError,
# the traceback exits non-zero, and `set -e` killed the installer before
# doctor and the closing message ever ran. Give it the real terminal.
if [ -r /dev/tty ]; then
    say "starting setup wizard"
    "$VENV/bin/kryonsec" setup < /dev/tty ||
        say "setup wizard did not finish — run 'kryonsec setup' when you're ready"
else
    say "no terminal available — skipping the setup wizard"
    say "run 'kryonsec setup' in a terminal to configure your LLM"
fi

# ---- 8. verify + next steps --------------------------------------------------
# show the final state — doctor's exit code never fails the installer
# (it only says whether Copilot has storage + an LLM; the table above is
# the actual information the user needs)
"$VENV/bin/kryonsec" doctor || true

if command -v kryonsec >/dev/null 2>&1; then
    say "done — run: kryonsec"
else
    say "done — but the 'kryonsec' command is not active in THIS terminal yet."
    say "  run this now:  source $SHELL_RC"
    say "  (or open a new terminal — it works there automatically)"
fi
