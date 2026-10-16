#!/usr/bin/env bash
# Kryonsec installer (WSL / Linux / macOS).
#
#   curl -fsSL https://kryonsec.in/install.sh | KRYONSEC_KEY=KRYO-XXXX-XXXX-XXXX bash
#
# Beta accounts do not use a key. Sign in at the site and its dashboard prints
# the command with KRYONSEC_DOWNLOAD_URL set to a one-time link:
#
#   curl -fsSL https://kryonsec.in/install.sh | KRYONSEC_DOWNLOAD_URL='https://kryonsec.in/api/beta/download?t=dl_...' bash
#
# Kryonsec is commercial, closed-source software: there is no public repository
# to clone. The release below is a built wheel, and the membership key is what
# unlocks it, so this script does nothing useful without one.
#
# What it does:
#   1. installs missing prerequisites (curl) on apt systems
#   2. checks for Python 3.11+
#   3. creates ~/.kryonsec/venv
#   4. fetches the kryonsec release from kryonsec.in using your key, and
#      saves the key so Purple Team can use it later — or, for a beta account,
#      fetches the one-time link the dashboard gave you and saves no key
#   5. adds ~/.kryonsec/venv/bin to PATH (in .bashrc, idempotent)
#   6. on Linux with sudo: installs Docker + gVisor (runsc) if missing,
#      then fetches the Zone B sandbox image from ghcr.io.
#      On WSL2 talking to Docker Desktop it installs a daemon inside the
#      distro and moves the CLI onto it, because Docker Desktop's daemon
#      cannot host gVisor at all.
#   7. offers to install Ollama + llama3.1 when no LLM is configured
#   8. runs `kryonsec setup` (the wizard: LLM, tools, MCP)
#   9. runs `kryonsec doctor` so the final state is visible, and prints
#      the exact command to run when PATH isn't active in this shell yet
set -euo pipefail

SITE="${KRYONSEC_SITE:-https://kryonsec.in}"
DOWNLOAD_URL="$SITE/api/download"
# The membership key unlocks the download here and Purple Team later.
# KRYONSEC_LICENSE_KEY is the name the app itself reads, so accept both.
KEY="${KRYONSEC_KEY:-${KRYONSEC_LICENSE_KEY:-}}"
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

# A configured-but-unfetchable apt source does not only fail itself: apt
# refuses to install ANYTHING while one is present, so the error surfaces as
# "that package is unavailable" for an unrelated package, and the real cause
# scrolls by once in an `apt-get update` nobody was watching.
#
# This is not hypothetical. An earlier version of this script wrote a
# malformed gVisor deb line; the next run's `apt-get update` failed, so the
# Docker install aborted before it tried, and the visible symptom was
# "Docker install failed — Purple Team needs it" on a machine where gVisor
# was the actual problem. Removing the bad line is the only way out, since
# the user cannot install docker.io by hand either while it is there.
#
# Only a malformed one is removed: the documented line is recognized and
# left alone, so a user who added it correctly keeps it.
purge_broken_apt_sources() {
    # $1 is a test seam: the default is the only path that matters in
    # production, and the tests need to point it at a temp file.
    local f="${1:-/etc/apt/sources.list.d/gvisor.list}"
    [ -f "$f" ] || return 0
    if grep -q 'gvisor/releases release' "$f" 2>/dev/null; then
        return 0   # the documented line — leave it alone
    fi
    say "removing a malformed gVisor apt source left by an earlier run"
    # Never fatal. This runs at startup under `set -e`: a Copilot-only user
    # with no sudo must not have the installer die on a line about apt
    # sources they never wanted in the first place.
    maybe_sudo rm -f "$f" ||
        say "         could not remove it — apt may keep reporting errors"
    return 0
}
purge_broken_apt_sources

MISSING=""
for tool in curl; do
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

# ---- 1. python 3.11+ ------------------------------------------------------
# Newest-supported first, but 3.14 is deliberately absent from the list: it is
# new enough that parts of the dependency tree can still have no prebuilt
# wheel, so pip quietly falls back to compiling from source and the install
# looks hung for a very long time. A bare `python3` stays last, so a machine
# whose only interpreter is 3.14 still installs — it just gets told why it is
# slow.
PY=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
            PY="$candidate"
            break
        fi
    fi
done
[ -n "$PY" ] || die "Python 3.11+ not found. Install it first: https://www.python.org/downloads/"
say "using $($PY --version)"
if "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 14) else 1)' 2>/dev/null; then
    say "WARNING: Python 3.14 is very new. If the install below sits still for"
    say "         many minutes, pip is compiling a dependency from source."
    say "         Install 3.12 and re-run for a much faster install:"
    say "           sudo apt-get install -y python3.12 python3.12-venv"
fi

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
# Kryonsec is closed-source, so there is no repo to clone and no public tag
# list to read. The release ships as a built wheel and the site decides which
# version the key gets, which is why nothing here resolves a version at all.
#
# KRYONSEC_WHEEL overrides the download entirely — a URL or a local .whl. It
# is the escape hatch for air-gapped machines, and it is how support hands
# someone a build without going through the site.
WHEEL=""
if [ -n "${KRYONSEC_WHEEL:-}" ]; then
    say "installing from KRYONSEC_WHEEL override"
    WHEEL="$KRYONSEC_WHEEL"
elif [ -n "${KRYONSEC_DOWNLOAD_URL:-}" ]; then
    # The beta path, and the only reason it needs a branch of its own: pip
    # decides a wheel's name from the URL's last path segment and refuses a
    # wheel it cannot name, so a gated URL has to be fetched to a file first.
    # (KRYONSEC_WHEEL looks like it would do — it accepts a URL — but piping an
    # extensionless URL straight into pip fails with "Invalid wheel filename".)
    #
    # No key is asked for and none is saved: the URL carries a one-time
    # credential that the account's own dashboard minted, and there is no
    # membership key in the beta for Purple Team to read later.
    TMP_DIR="$(mktemp -d)"
    WHEEL="$TMP_DIR/kryonsec.whl"
    say "fetching the kryonsec release"
    if ! curl -fsSL --max-time 600 -o "$WHEEL" "$KRYONSEC_DOWNLOAD_URL"; then
        rm -rf "$TMP_DIR"
        die "could not download kryonsec — that link was refused, has expired, or $SITE is unreachable.
         Reload your dashboard at $SITE/dashboard for a fresh one."
    fi
else
    if [ -z "$KEY" ]; then
        die "a membership key is required. Re-run with:
           curl -fsSL $SITE/install.sh | KRYONSEC_KEY=KRYO-XXXX-XXXX-XXXX bash
         Request access at $SITE"
    fi
    TMP_DIR="$(mktemp -d)"
    WHEEL="$TMP_DIR/kryonsec.whl"
    say "fetching the kryonsec release"
    # -f makes the site's rejection a failure rather than saving an error page
    # as a "wheel", which pip would then report as a corrupt archive.
    if ! curl -fsSL --max-time 600 -o "$WHEEL" \
        "$DOWNLOAD_URL?key=$KEY&os=linux"; then
        rm -rf "$TMP_DIR"
        die "could not download kryonsec — the key was rejected, or $SITE is unreachable.
         Check the key, or request access again at $SITE"
    fi
fi

# Deliberately NOT --quiet: a tree this size takes minutes and pip prints
# nothing while it resolves and downloads, so a silent install reads as a
# hung one — which is exactly how it gets reported. The output is the
# reassurance that it is still working.
say "installing kryonsec (this pulls litellm, mcp, rich, … — takes a few minutes)"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install "$WHEEL"
"$VENV/bin/kryonsec" --version || die "installation failed"

# Remember the key. It gated the download, and Purple Team will ask for it
# again at the first engagement — making the user paste it twice, from an
# email they may no longer have open, is the kind of small friction that
# reads as broken. Failure here is not fatal: the app also reads
# KRYONSEC_LICENSE_KEY from the environment.
if [ -n "$KEY" ]; then
    if "$VENV/bin/python" - "$KEY" <<'PY'
import sys
from kryonsec.config import load_config
cfg = load_config()
cfg.license_key = sys.argv[1].strip()
cfg.save()
PY
    then
        say "membership key saved"
    else
        say "WARNING: could not save the membership key"
        say "         add it later under [license] in $KRYONSEC_HOME/config.toml"
    fi
fi

# uvx runs a Python CLI tool without installing it — npx for Python. It is
# what the wizard's `fetch` MCP preset starts, it ships with uv, and most
# machines do not have uv, so that preset failed on the very first run for
# everyone. Installed INTO the venv deliberately: it lands on the PATH this
# script already manages, needs no extra `curl | sh` from a third party, and
# goes away with the venv. Skipped when uv is already available; never fatal,
# because nothing in either mode depends on it.
if ! command -v uvx >/dev/null 2>&1; then
    if "$VENV/bin/pip" install --quiet uv; then
        say "installed uv (provides uvx, for the 'fetch' MCP server)"
    else
        say "WARNING: could not install uv — the 'fetch' MCP server needs it"
        say "         install it later with: $VENV/bin/pip install uv"
    fi
fi

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

# Make it live in THIS process too, not just the next shell. The wizard and
# doctor run below as subprocesses and resolve commands against the PATH they
# inherit — without this the wizard would warn that uvx is missing moments
# after we installed it, and the closing "run: kryonsec" hint would be a lie.
export PATH="$VENV/bin:$PATH"

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
    # A failing `apt-get update` must not abort this. apt still installs from
    # the package lists it already has, and bailing here is precisely how a
    # gVisor repo problem became a "Docker could not be installed" problem.
    maybe_sudo apt-get update -qq ||
        say "WARNING: apt-get update reported errors — trying the install anyway"
    # distro package: works on every apt system (incl. Kali and Ubuntu
    # releases the docker.com repo hasn't caught up with) and is plenty
    # for a gVisor sandbox host
    maybe_sudo apt-get install -y -qq docker.io || return 1
    # The socket is root-owned, so without this the daemon answers root and
    # nobody else — the installer's own probes fall back to sudo and look
    # fine, while `kryonsec` (which runs as the user) gets "permission
    # denied" the first time it reaches for Docker. Membership only takes
    # effect at the next login, so say so rather than pretending.
    if [ "$(id -u)" -ne 0 ]; then
        if ! id -nG 2>/dev/null | grep -qw docker; then
            maybe_sudo usermod -aG docker "$(id -un)" >/dev/null 2>&1 &&
                say "added $(id -un) to the docker group — log out and back in for it to apply"
        fi
    fi
    # start the daemon — systemd where available (WSL needs it on), the
    # sysv script as a fallback
    maybe_sudo systemctl enable --now docker 2>/dev/null ||
        maybe_sudo service docker start 2>/dev/null || true
    sleep 2
}

# Download gVisor's runsc package from the release bucket, verified against
# the checksum the bucket's own apt index states.
#
# This used to fetch `releases/release/latest/<arch>/runsc`, guessing at the
# architecture spelling. That URL does not exist. The bucket's release/ tree
# holds only dated directories (20260914.0/ and the like) containing tarballs
# — there is no `latest` and no bare `runsc` anywhere under it — so the
# fallback was a guaranteed 404 on every machine that reached it, which is how
# a user ends up with "apt repo unavailable" followed by "curl: (22) 404" and
# no runsc.
#
# What the bucket does publish, and what gVisor's apt repo serves, is the .deb
# under pool/. Its path and its SHA256 are both spelled out in the apt index,
# so both are read from there instead of guessed: the download is checked
# against the checksum the index states. That replaces an earlier check for an
# ELF header, which a .deb does not have — it is an ar archive — and which
# could not have caught a wrong-but-well-formed file anyway.
fetch_runsc() {
    local out="$1" arch index packages fields filename sha url sums
    # `|| true`: this script runs under `set -e`, and a missing dpkg would
    # otherwise abort the installer from inside an assignment.
    arch="$(dpkg --print-architecture 2>/dev/null || true)"
    case "$arch" in
        amd64 | arm64) ;;
        *)
            say "         architecture '${arch:-unknown}' — no gVisor package for it"
            return 1
            ;;
    esac

    # The index is filed under dpkg's architecture name (binary-amd64), not
    # the kernel's (x86_64) — the opposite of the dead URL above, which is
    # part of why that one never resolved.
    index="https://storage.googleapis.com/gvisor/releases/dists/release/main/binary-${arch}/Packages"
    packages="$(mktemp)"
    if ! curl -fsSL "$index" -o "$packages" 2>/dev/null; then
        say "         could not read the package index (${arch})"
        rm -f "$packages"
        return 1
    fi
    # One pass over the stanzas: track which package we are inside and take
    # the fields only while it is runsc. Plain awk, no dialect assumptions.
    fields="$(awk '
        /^Package: / { pkg = substr($0, 10) }
        pkg == "runsc" && /^Filename: / { fn = substr($0, 11) }
        pkg == "runsc" && /^SHA256: / { sha = substr($0, 9) }
        END { if (fn != "" && sha != "") print fn, sha }
    ' "$packages")"
    rm -f "$packages"
    if [ -z "$fields" ]; then
        say "         the index lists no runsc package for ${arch}"
        return 1
    fi
    filename="${fields%% *}"
    sha="${fields##* }"

    url="https://storage.googleapis.com/gvisor/releases/${filename}"
    say "         downloading $(basename "$filename") — this is a large file"
    # Progress stays visible here: ~170 MB with no output reads as a hang.
    if ! curl -fSL --progress-bar "$url" -o "$out"; then
        say "         download failed"
        rm -f "$out"
        return 1
    fi
    # Both spellings, because neither is guaranteed. If neither exists the
    # sum comes back empty, which fails the comparison — refusing is the
    # right direction to fail in.
    sums="$(sha256sum "$out" 2>/dev/null || shasum -a 256 "$out" 2>/dev/null || true)"
    if [ "${sums%% *}" != "$sha" ]; then
        say "         checksum does not match the index — not installing it"
        rm -f "$out"
        return 1
    fi
    return 0
}

install_gvisor() {
    say "installing gVisor (runsc)"
    maybe_sudo apt-get install -y -qq gnupg >/dev/null 2>&1
    maybe_sudo mkdir -p /usr/share/keyrings

    local gvisor_list=/etc/apt/sources.list.d/gvisor.list
    # The deb line is `deb [opts] URI SUITE COMPONENT`. It used to be written
    # with `/release` glued onto the URI and the architecture appended as a
    # second component, so apt went looking for
    # `.../gvisor/releases/release/dists/main/Release`, got a 404 from the
    # bucket, and reported "does not have a Release file" — which is the
    # gVisor error that then took Docker down with it.
    if curl -fsSL https://gvisor.dev/archive.key |
        maybe_sudo gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg &&
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" |
            maybe_sudo tee "$gvisor_list" >/dev/null &&
        maybe_sudo apt-get update -qq &&
        maybe_sudo apt-get install -y -qq runsc; then
        : # apt path worked
    else
        # Drop the repo line BEFORE falling back, on every path out of here.
        # It used to be removed only after a successful binary install, so a
        # failed download left a broken source behind — poisoning the next
        # run's `apt-get update`, and therefore its Docker install, forever.
        maybe_sudo rm -f "$gvisor_list"
        say "apt repo unavailable — installing runsc from gVisor's own package"
        fetch_runsc /tmp/runsc.deb || return 1
        # dpkg rather than install(1): this is gVisor's own .deb, so it brings
        # runsc AND the containerd shim and helper binaries under
        # usr/bin/gvisor-bin/, which a bare binary copied to /usr/local/bin
        # would leave missing. It declares no dependencies, so -i is enough.
        maybe_sudo dpkg -i /tmp/runsc.deb >/dev/null || return 1
        rm -f /tmp/runsc.deb
    fi
    # registers runsc in /etc/docker/daemon.json and restarts the daemon
    maybe_sudo runsc install
    maybe_sudo systemctl restart docker 2>/dev/null ||
        maybe_sudo service docker restart 2>/dev/null || true
    sleep 2
}

# true when the daemon the CLI is actually talking to has runsc registered
runsc_registered() {
    dkr info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}' 2>/dev/null |
        grep -qw runsc
}

if [ "$(uname -s)" = "Linux" ] && have_sudo && is_apt; then
    # Docker Desktop's daemon lives outside the distro, so no runtime
    # installed in here can ever reach it. Detect that FIRST: the CLI exists
    # and answers, so every "is Docker installed?" test below passes, the
    # gVisor install then writes a daemon.json for a daemon nothing is
    # talking to, and the whole thing reports success while Purple Team
    # still cannot start.
    DOCKER_OS=""
    if command -v docker >/dev/null 2>&1; then
        DOCKER_OS="$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
        [ -n "$DOCKER_OS" ] || DOCKER_OS="$(maybe_sudo docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
    fi
    case "$DOCKER_OS" in
        *"Docker Desktop"*)
            say "docker is currently Docker Desktop's, which cannot host gVisor"
            say "         its daemon runs outside this distro. Installing a"
            say "         Docker daemon in here and pointing the CLI at it."
            install_docker ||
                say "WARNING: Docker install failed — Purple Team needs it"
            # Docker Desktop leaves currentContext set to "desktop-linux" in
            # ~/.docker/config.json, so the new daemon on the default socket
            # is invisible to the CLI until this switch — every probe below
            # would still be reading Docker Desktop. Client-side only (it
            # edits that config file; no daemon involved), and deliberately
            # NOT under sudo, which would write root's config instead of the
            # user's and change nothing for them.
            docker context use default >/dev/null 2>&1 ||
                say "         run this yourself: docker context use default"
            if ! dkr info >/dev/null 2>&1; then
                say "WARNING: the distro's docker daemon is not up yet — start it with"
                say "         sudo service docker start   (or enable systemd in /etc/wsl.conf)"
            fi
            # The switch is not permanent: Docker Desktop re-creates and
            # re-selects its own context on every launch, and DOCKER_HOST
            # overrides the context outright. Without saying so, this fix
            # holds until the next reboot and then silently reverts.
            if dkr info --format '{{.OperatingSystem}}' 2>/dev/null | grep -q "Docker Desktop"; then
                say "WARNING: the CLI is still pointed at Docker Desktop. Two things put"
                say "         it back — DOCKER_HOST in your shell, and Docker Desktop"
                say "         itself, which re-selects its context on every launch. Turn"
                say "         off WSL integration for this distro (Settings > Resources >"
                say "         WSL Integration), or: unset DOCKER_HOST && docker context use default"
            fi
            ;;
    esac

    if ! command -v docker >/dev/null 2>&1; then
        install_docker ||
            say "WARNING: Docker install failed — Copilot works fine; Purple Team needs it"
    elif ! docker info >/dev/null 2>&1 && ! maybe_sudo docker info >/dev/null 2>&1; then
        # docker is installed but the daemon is down — try to start it
        maybe_sudo systemctl enable --now docker 2>/dev/null ||
            maybe_sudo service docker start 2>/dev/null || true
        sleep 2
    fi
    if dkr info >/dev/null 2>&1 && ! runsc_registered; then
        install_gvisor || true
        # Verify, do not assume. `runsc install` restarts "the daemon" — but
        # which daemon depends on how this host runs Docker, and on WSL2 the
        # CLI may be talking to one this script cannot touch at all.
        if ! runsc_registered; then
            # Still Docker Desktop after the switch above means the CLI could
            # not be moved off it (a Desktop restart can put it back). Nothing
            # run in here can add a runtime to that daemon, so name the real
            # problem rather than printing a retry that cannot help.
            DOCKER_OS="$(dkr info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
            case "$DOCKER_OS" in
                *"Docker Desktop"*)
                    say "WARNING: still talking to Docker Desktop's daemon, which cannot"
                    say "         load a runtime from inside WSL. Give the distro its own:"
                    say "           sudo apt-get install -y docker.io"
                    say "           docker context use default"
                    say "           sudo service docker start"
                    say "         then re-run this installer to add gVisor"
                    ;;
                *)
                    say "WARNING: gVisor install did not register runsc — Purple Team needs it"
                    say "         retry with: sudo runsc install && sudo systemctl restart docker"
                    ;;
            esac
        else
            say "gVisor (runsc) registered with Docker"
        fi
    fi
fi

# Registry image published by .github/workflows/sandbox-image.yml on every
# release tag. Pulling is the only path: ready-made layers download in
# parallel and resume on failure, where a local build downloaded ~50 tools
# (~2 GB) inside a Docker build and took 30+ min on a slow link. That build
# path needed the repository sources, which are no longer public, so it is
# gone rather than left in place to fail confusingly.
SANDBOX_REGISTRY_IMAGE="ghcr.io/gonchijoshnavardhanreddy/kryonsec-sandbox"

# The version we actually installed, straight from the package metadata. The
# old code read it off the git tag it installed from; with the release served
# as a wheel there is no tag to read, and the wheel knows its own version.
INSTALLED_VERSION="$("$VENV/bin/python" -c \
    'import importlib.metadata as m; print(m.version("kryonsec"))' 2>/dev/null || true)"

# Image refs to try, in order, one per line.
#
# KRYONSEC_SANDBOX_IMAGE wins and is the ONLY ref tried: it may carry a
# @sha256: digest, and quietly pulling some other image would defeat the pin
# the operator asked for. Otherwise: the image for the version we installed
# (so image and code match), then :latest, which the publish workflow always
# maintains — that fallback is what keeps installs fast when a tag's image was
# never published.
sandbox_image_refs() {
    if [ -n "${KRYONSEC_SANDBOX_IMAGE:-}" ]; then
        printf '%s\n' "$KRYONSEC_SANDBOX_IMAGE"
        return 0
    fi
    if [ -n "$INSTALLED_VERSION" ]; then
        printf '%s:v%s\n' "$SANDBOX_REGISTRY_IMAGE" "$INSTALLED_VERSION"
    fi
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
            # No local-build fallback any more: it needed the repository
            # sources, which are private. Say what to actually do instead of
            # dropping into a build that cannot fetch anything.
            say "WARNING: could not pull the sandbox image — Purple Team will not start."
            say "         Copilot mode is unaffected. Retry manually with:"
            say "           docker pull ${SANDBOX_REGISTRY_IMAGE}:latest"
            say "           docker tag ${SANDBOX_REGISTRY_IMAGE}:latest kryonsec/sandbox:latest"
            say "         If the image has been made private, set KRYONSEC_REGISTRY_TOKEN"
            say "         and KRYONSEC_REGISTRY_USER, then re-run this installer."
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
    # Ollama's installer unpacks a .tar.zst and exits before installing
    # anything when zstd is absent. Minimal images — a bare WSL2 Ubuntu, a
    # slim container, a fresh server install — do not ship it, and the
    # failure arrives as "Ollama install failed", which reads as a dead end
    # and sends the user to pick OpenAI instead of running one apt command.
    # Satisfy the dependency here, and name the command when we cannot.
    if ! command -v zstd >/dev/null 2>&1; then
        say "installing zstd (Ollama's installer needs it to unpack its archive)"
        apt_install zstd || true
        if ! command -v zstd >/dev/null 2>&1; then
            say "WARNING: zstd is missing and could not be installed automatically"
            say "         install it, then re-run this installer:"
            say "           Debian/Ubuntu:  sudo apt-get install -y zstd"
            say "           Fedora/RHEL:    sudo dnf install -y zstd"
            say "           Arch:           sudo pacman -S zstd"
        fi
    fi
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
