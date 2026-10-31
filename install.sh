#!/usr/bin/env bash
# Kryonsec installer (WSL / Linux / macOS).
#
#   curl -fsSL https://kryonsec.in/install.sh -o install.sh
#   KRYONSEC_KEY=KRYO-XXXX-XXXX-XXXX bash install.sh --profile=auto
#
# Beta accounts do not use a key. Sign in at the site and its dashboard prints
# the command with KRYONSEC_DOWNLOAD_URL set to a one-time link:
#
#   curl -fsSL https://kryonsec.in/install.sh -o install.sh
#   KRYONSEC_DOWNLOAD_URL='https://kryonsec.in/api/beta/download?t=dl_...' bash install.sh
#
# Kryonsec is commercial, closed-source software: there is no public repository
# to clone. The release below is a built wheel, and the membership key is what
# unlocks it, so this script does nothing useful without one.
#
# What it does:
#   1. checks prerequisites and stops with a repair command when a required
#      download tool is missing (it does not silently change the host)
#   2. checks for Python 3.11+
#   3. creates ~/.kryonsec/venv
#   4. fetches the kryonsec release from kryonsec.in using your key, and
#      saves the key so Purple Team can use it later — or, for a beta account,
#      fetches the one-time link the dashboard gave you and saves no key
#   5. adds ~/.kryonsec/venv/bin to PATH (in .bashrc, idempotent)
#   6. on the approved Purple profile: validates the selected Docker context,
#      asks before packages/group/service/daemon changes, and fetches a
#      release-matched digest-pinned sandbox image. It never switches contexts.
#   7. offers instructions for the optional Ollama provider; it does not run an
#      unverified third-party install script
#   8. runs `kryonsec setup` (the wizard: LLM, tools, MCP)
#   9. runs `kryonsec doctor` so the final state is visible, and prints
#      the exact command to run when PATH isn't active in this shell yet
set -euo pipefail

# The installer has two deliberately separate modes:
#
#   --dry-run / KRYONSEC_DRY_RUN=1
#       inspect the local state and print intended actions without downloading,
#       installing packages, editing config, changing PATH, or restarting a
#       service;
#   --profile copilot|purple|auto
#       copilot never attempts host changes; purple requires the isolated Zone B
#       path; auto installs Copilot and asks before attempting optional Purple
#       prerequisites on Linux.
#
# A privileged action is never inferred from the fact that this script is being
# run.  confirm_system_change() below requires a visible answer on the real
# terminal, or the explicit KRYONSEC_ASSUME_YES=1 opt-in for automation.
DRY_RUN="${KRYONSEC_DRY_RUN:-0}"
PROFILE="${KRYONSEC_PROFILE:-auto}"
REPAIR="${KRYONSEC_REPAIR:-0}"
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --repair) REPAIR=1 ;;
        --profile=*) PROFILE="${arg#--profile=}" ;;
        --profile)
            printf 'error: use --profile=copilot, --profile=purple, or --profile=auto\n' >&2
            exit 2
            ;;
        --yes) KRYONSEC_ASSUME_YES=1 ;;
        --help|-h)
            cat <<'USAGE'
Kryonsec installer

  --profile=auto       Install Copilot and ask before optional Purple setup
  --profile=copilot    Install Copilot only; never change Docker or services
  --profile=purple     Require Linux + Docker + gVisor + the release image
  --dry-run            Report local state and intended actions only
  --repair             Allow recovery of an incomplete installer-owned venv
  --yes                Explicitly approve prompted system changes (review first)

Environment equivalents: KRYONSEC_PROFILE, KRYONSEC_DRY_RUN,
KRYONSEC_REPAIR, KRYONSEC_ASSUME_YES=1.
USAGE
            exit 0
            ;;
        *)
            printf "error: unknown installer option '%s' (use --help)\n" "$arg" >&2
            exit 2
            ;;
    esac
done
case "$PROFILE" in
    auto|copilot|purple) ;;
    *) say "error: invalid profile '$PROFILE'" >&2; exit 2 ;;
esac

SITE="${KRYONSEC_SITE:-https://kryonsec.in}"
DOWNLOAD_URL="$SITE/api/download"
# The membership key unlocks the download here and Purple Team later.
# KRYONSEC_LICENSE_KEY is the name the app itself reads, so accept both.
KEY="${KRYONSEC_KEY:-${KRYONSEC_LICENSE_KEY:-}}"
KRYONSEC_HOME="${KRYONSEC_HOME:-$HOME/.kryonsec}"
VENV="$KRYONSEC_HOME/venv"

say() { printf '\033[36m==>\033[0m %s\n' "$1"; }
die() { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

confirm_system_change() {
    local description="$1" answer
    if [ "$DRY_RUN" = "1" ]; then
        say "DRY RUN: would $description"
        return 1
    fi
    if [ "${KRYONSEC_ASSUME_YES:-0}" = "1" ]; then
        say "approved by KRYONSEC_ASSUME_YES=1: $description"
        return 0
    fi
    if [ ! -r /dev/tty ]; then
        say "not applying system change without a terminal: $description"
        say "review it, then re-run with --yes or KRYONSEC_ASSUME_YES=1"
        return 1
    fi
    printf '\033[33m==>\033[0m This will %s. Continue? [y/N] ' "$description" >/dev/tty
    answer=""
    read -r answer < /dev/tty || answer="n"
    case "$answer" in
        y|Y|yes|YES) return 0 ;;
        *) say "skipped: $description"; return 1 ;;
    esac
}

if [ "$DRY_RUN" = "1" ]; then
    say "read-only dry run enabled — no downloads, writes, package changes, or service actions"
fi

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
    # Install the named packages only after the caller has obtained consent.
    # A failed update is reported, not hidden; the caller decides whether a
    # package install can safely continue with the existing package lists.
    is_apt && have_sudo || return 1
    if ! maybe_sudo apt-get update -qq; then
        say "WARNING: apt-get update reported errors; package sources need attention"
    fi
    # shellcheck disable=SC2086  # $* is a deliberate word-split package list
    maybe_sudo apt-get install -y -qq $*
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
# Detection is read-only.  The old installer removed this file at startup,
# which could delete an administrator's repository configuration without
# consent.  Repair is now an explicit, backed-up action below.
purge_broken_apt_sources() {
    # $1 is a test seam: the default is the only path that matters in
    # production, and the tests need to point it at a temp file.
    local f="${1:-/etc/apt/sources.list.d/gvisor.list}"
    [ -f "$f" ] || return 0
    if grep -q 'gvisor/releases release' "$f" 2>/dev/null; then
        return 0   # the documented line — leave it alone
    fi
    say "WARNING: a malformed gVisor apt source is present at $f"
    say "         it can prevent apt from installing unrelated packages"
    return 1
}

if ! purge_broken_apt_sources; then
    if [ "$REPAIR" = "1" ] && confirm_system_change \
        "back up $HOME's affected apt source and disable $HOME's malformed gVisor source"; then
        APT_SOURCE="/etc/apt/sources.list.d/gvisor.list"
        APT_BACKUP="${APT_SOURCE}.kryonsec.$(date +%Y%m%d%H%M%S).bak"
        maybe_sudo cp -p "$APT_SOURCE" "$APT_BACKUP" ||
            die "could not back up $APT_SOURCE; nothing was changed"
        maybe_sudo mv "$APT_SOURCE" "${APT_SOURCE}.disabled" ||
            die "could not disable $APT_SOURCE; restore from $APT_BACKUP if needed"
        say "apt source backed up at $APT_BACKUP and disabled"
    else
        say "repair skipped; Copilot can still install if no package action is needed"
    fi
fi

MISSING=""
for tool in curl; do
    command -v "$tool" >/dev/null 2>&1 || MISSING="$MISSING $tool"
done
if [ -n "$MISSING" ]; then
    say "missing prerequisites:$MISSING"
    # shellcheck disable=SC2086
    if confirm_system_change "install the required download prerequisites:$MISSING ca-certificates" \
        && apt_install $MISSING ca-certificates; then
        say "prerequisites installed"
    else
        die "cannot continue without:$MISSING — install them manually and re-run"
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
mkdir -p "$KRYONSEC_HOME"
if [ -x "$VENV/bin/python" ]; then
    if ! "$VENV/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        if [ "$REPAIR" = "1" ] && confirm_system_change \
            "move the incompatible Kryonsec virtualenv aside for repair"; then
            backup="$VENV.backup.$(date +%Y%m%d%H%M%S)"
            mv "$VENV" "$backup" || die "could not preserve the incompatible virtualenv at $backup"
            say "old virtualenv preserved at $backup"
        else
            die "$VENV exists but its Python is incompatible; re-run with --repair after reviewing the backup plan"
        fi
    else
        say "existing compatible virtualenv is ready: $VENV"
    fi
elif [ -e "$VENV" ]; then
    if [ "$REPAIR" = "1" ] && confirm_system_change \
        "move the incomplete Kryonsec virtualenv aside for repair"; then
        backup="$VENV.backup.$(date +%Y%m%d%H%M%S)"
        mv "$VENV" "$backup" || die "could not preserve the incomplete virtualenv at $backup"
        say "old virtualenv preserved at $backup"
    else
        die "$VENV exists but is incomplete; re-run with --repair after reviewing the backup plan"
    fi
fi

if [ ! -x "$VENV/bin/python" ]; then
    [ "$DRY_RUN" = "1" ] && {
        say "DRY RUN: would create a virtualenv at $VENV"
    } || {
        say "creating virtualenv at $VENV"
        # Create at the final path: venv scripts embed their interpreter path,
        # so a venv built elsewhere and moved here keeps a dead shebang.
        if ! "$PY" -m venv "$VENV" 2>/dev/null; then
            # Debian/Ubuntu split ensurepip into python3-venv.  This is a
            # privileged package action and requires a separate approval.
            if confirm_system_change "install Python venv support (python3-venv and python3-pip)" \
                && apt_install python3-venv python3-pip; then
                :
            else
                # The checks above guarantee $VENV held no working venv; this
                # only removes the half-created one from this attempt.
                rm -rf "$VENV"
                die "could not create a virtualenv — install python3-venv / python3-pip and re-run"
            fi
            "$PY" -m venv "$VENV" || {
                rm -rf "$VENV"
                die "could not create a virtualenv after installing venv support"
            }
        fi
    }
fi

# A dry run stops before any network or package operation.  It is deliberately
# useful even when the machine has no membership key: the operator can inspect
# the interpreter, existing venv, config path, and intended profile first.
if [ "$DRY_RUN" = "1" ]; then
    if [ -f "$KRYONSEC_HOME/config.toml" ]; then
        say "existing configuration detected: $KRYONSEC_HOME/config.toml (will be preserved)"
    else
        say "no configuration detected: setup will be required after installation"
    fi
    say "would fetch and verify a Kryonsec wheel into $VENV"
    case "$PROFILE" in
        copilot) say "would not inspect or modify Docker/gVisor (Copilot profile)" ;;
        purple) say "would validate Linux, the selected Docker daemon, gVisor, and the release image" ;;
        auto) say "would ask before attempting optional Linux Docker/gVisor/image setup" ;;
    esac
    exit 0
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

wheel_hash() {
    local file="$1" sums
    sums="$(sha256sum "$file" 2>/dev/null || shasum -a 256 "$file" 2>/dev/null || true)"
    printf '%s' "${sums%% *}"
}

verify_wheel_hash() {
    local file="$1" headers="${2:-}" expected actual
    expected="${KRYONSEC_WHEEL_SHA256:-}"
    if [ -z "$expected" ] && [ -n "$headers" ]; then
        expected="$(awk 'tolower($1) == "x-kryonsec-wheel-sha256:" {print $2}' "$headers" | tail -n 1 | tr -d '\r')"
    fi
    actual="$(wheel_hash "$file")"
    if [ -z "$actual" ]; then
        die "could not calculate the wheel SHA-256; install sha256sum or shasum and re-run"
    fi
    if [ -n "$expected" ]; then
        expected="$(printf '%s' "$expected" | sed 's/^sha256://' | tr '[:upper:]' '[:lower:]')"
        if [ "$actual" != "$expected" ]; then
            die "wheel SHA-256 does not match the release metadata; the artifact was not installed"
        fi
        say "wheel verified (SHA-256 $actual)"
    elif [ -n "$headers" ]; then
        die "release did not provide wheel verification metadata; the artifact was not installed"
    else
        say "local wheel override supplied without release metadata; use KRYONSEC_WHEEL_SHA256 to verify it"
    fi
}

download_wheel() {
    local out="$1" url="$2" key="${3:-}" headers status_file error_file code error
    headers="$(mktemp)"
    status_file="$(mktemp)"
    error_file="$(mktemp)"
    if [ -n "$key" ]; then
        if ! curl -fsSL --connect-timeout 20 --max-time 600 \
            -D "$headers" -H "X-Kryonsec-Key: $key" -o "$out" \
            -w '%{http_code}' "$url" >"$status_file" 2>"$error_file"; then
            code="$(cat "$status_file" 2>/dev/null || true)"
            rm -f "$headers" "$status_file" "$error_file" "$out"
            case "$code" in
                400|401|403) die "download refused (HTTP $code): check the membership key" ;;
                5*) die "download service failed (HTTP $code); retry later or contact support" ;;
                *) die "could not download the release (DNS, TLS, network, or timeout); check connectivity and retry" ;;
            esac
        fi
    else
        if ! curl -fsSL --connect-timeout 20 --max-time 600 \
            -D "$headers" -o "$out" -w '%{http_code}' "$url" \
            >"$status_file" 2>"$error_file"; then
            code="$(cat "$status_file" 2>/dev/null || true)"
            rm -f "$headers" "$status_file" "$error_file" "$out"
            case "$code" in
                400|401|403) die "download link was refused or has expired (HTTP $code); request a fresh link" ;;
                5*) die "download service failed (HTTP $code); retry later or contact support" ;;
                *) die "could not download the release (DNS, TLS, network, or timeout); check connectivity and retry" ;;
            esac
        fi
    fi
    code="$(cat "$status_file")"
    if [ "$code" != "200" ]; then
        rm -f "$headers" "$status_file" "$error_file" "$out"
        case "$code" in
            400|401|403) die "download refused (HTTP $code); check the key or request a fresh link" ;;
            5*) die "download service failed (HTTP $code); retry later or contact support" ;;
            *) die "unexpected download response (HTTP ${code:-unknown}); the wheel was not installed" ;;
        esac
    fi
    verify_wheel_hash "$out" "$headers"
    rm -f "$headers" "$status_file" "$error_file"
}

wheel_version() {
    "$PY" - "$1" <<'PY'
import sys
import zipfile

wheel = sys.argv[1]
with zipfile.ZipFile(wheel) as archive:
    metadata = next(
        name for name in archive.namelist()
        if name.endswith('.dist-info/METADATA')
    )
    for line in archive.read(metadata).decode('utf-8', 'replace').splitlines():
        if line.lower().startswith('version:'):
            print(line.split(':', 1)[1].strip())
            break
    else:
        raise SystemExit('wheel has no Version metadata')
PY
}

if [ -n "${KRYONSEC_WHEEL:-}" ]; then
    if [ -f "$KRYONSEC_WHEEL" ]; then
        say "installing from local KRYONSEC_WHEEL override"
        WHEEL="$KRYONSEC_WHEEL"
        verify_wheel_hash "$WHEEL"
    elif [[ "$KRYONSEC_WHEEL" == http://* || "$KRYONSEC_WHEEL" == https://* ]]; then
        TMP_DIR="$(mktemp -d)"
        WHEEL="$TMP_DIR/kryonsec.whl"
        say "fetching the wheel from KRYONSEC_WHEEL"
        download_wheel "$WHEEL" "$KRYONSEC_WHEEL"
    else
        die "KRYONSEC_WHEEL is neither a readable .whl file nor an HTTP(S) URL"
    fi
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
    download_wheel "$WHEEL" "$KRYONSEC_DOWNLOAD_URL"
else
    if [ -z "$KEY" ]; then
        die "a membership key is required. Re-run with:
           curl -fsSL $SITE/install.sh | KRYONSEC_KEY=KRYO-XXXX-XXXX-XXXX bash
         Request access at $SITE"
    fi
    TMP_DIR="$(mktemp -d)"
    WHEEL="$TMP_DIR/kryonsec.whl"
    say "fetching the kryonsec release"
    # The key is a header, not a query parameter.  The URL is intentionally
    # key-free so proxy/CDN/access logs cannot capture the membership secret.
    download_wheel "$WHEEL" "$DOWNLOAD_URL?os=linux" "$KEY"
fi

INSTALLED_VERSION="$("$VENV/bin/python" -c \
    'import importlib.metadata as m; print(m.version("kryonsec"))' 2>/dev/null || true)"
WHEEL_VERSION="$(wheel_version "$WHEEL" 2>/dev/null || true)"
if [ -n "$INSTALLED_VERSION" ] && [ "$INSTALLED_VERSION" = "$WHEEL_VERSION" ] && [ "${KRYONSEC_FORCE_UPGRADE:-0}" != "1" ]; then
    say "kryonsec $INSTALLED_VERSION is already installed; skipping package replacement"
else
    [ -n "$WHEEL_VERSION" ] || die "downloaded artifact is not a readable Kryonsec wheel"
    if [ -n "$INSTALLED_VERSION" ]; then
        say "upgrading Kryonsec $INSTALLED_VERSION to $WHEEL_VERSION"
    else
        say "installing Kryonsec $WHEEL_VERSION (dependency resolution may take a few minutes)"
    fi
    "$VENV/bin/pip" install --upgrade pip
    "$VENV/bin/pip" install --upgrade "$WHEEL"
fi
"$VENV/bin/kryonsec" --version || die "installation failed"

# Remember the key. It gated the download, and Purple Team will ask for it
# again at the first engagement — making the user paste it twice, from an
# email they may no longer have open, is the kind of small friction that
# reads as broken. Failure here is not fatal: the app also reads
# KRYONSEC_LICENSE_KEY from the environment.
if [ -n "$KEY" ]; then
    if "$VENV/bin/python" - "$KEY" <<'PY'
import sys
from pathlib import Path
from kryonsec.config import config_path, read_config, update_config_sections

key = sys.argv[1].strip()
path = config_path()
data = read_config(path)
if str(data.get("license", {}).get("key") or "") == key:
    print("already present")
else:
    update_config_sections(path, {"license": {"key": key}})
PY
    then
        say "membership key preserved in config (never printed)"
    else
        die "existing configuration could not be updated safely; it was not overwritten. Repair $KRYONSEC_HOME/config.toml and re-run"
    fi
fi

# uvx runs a Python CLI tool without installing it — npx for Python. It is
# what the wizard's `fetch` MCP preset starts, it ships with uv, and most
# machines do not have uv, so that preset failed on the very first run for
# everyone. Installed INTO the venv deliberately: it lands on the PATH this
# script already manages, needs no extra `curl | sh` from a third party, and
# goes away with the venv. Skipped when uv is already available; never fatal,
# because nothing in either mode depends on it.
if ! command -v uvx >/dev/null 2>&1 && [ ! -x "$VENV/bin/uvx" ]; then
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
PATH_BEGIN='# kryonsec PATH BEGIN (managed)'
PATH_END='# kryonsec PATH END (managed)'
if grep -qF "$PATH_BEGIN" "$SHELL_RC" 2>/dev/null; then
    path_tmp="$(mktemp)"
    awk -v begin="$PATH_BEGIN" -v end="$PATH_END" -v bin="$VENV/bin" '
        $0 == begin { print begin; print "export PATH=\"" bin ":$PATH\""; inside=1; next }
        $0 == end { print end; inside=0; next }
        !inside { print }
    ' "$SHELL_RC" > "$path_tmp" && mv "$path_tmp" "$SHELL_RC"
    say "updated the installer-managed PATH block in $SHELL_RC"
else
    printf '\n%s\nexport PATH="%s:$PATH"\n%s\n' \
        "$PATH_BEGIN" "$VENV/bin" "$PATH_END" >> "$SHELL_RC"
    say "added the installer-managed PATH block to $SHELL_RC"
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

# Never probe a different daemon as root.  Kryonsec runs as the current user,
# so a successful `sudo docker info` would be a false positive and could hide
# the permission problem the installed application will hit later.
dkr() {
    docker "$@"
}

install_docker() {
    say "installing Docker (apt)"
    apt_install docker.io || return 1
    # The socket is root-owned on a normal Engine install. Group membership is
    # a separate, visible system change and only applies after re-login.
    if [ "$(id -u)" -ne 0 ]; then
        if ! id -nG 2>/dev/null | grep -qw docker; then
            if confirm_system_change "add $(id -un) to the docker group (log out and back in afterward)"; then
                maybe_sudo usermod -aG docker "$(id -un)" || return 1
                say "added $(id -un) to the docker group — log out and back in for it to apply"
            else
                say "Docker installed, but this user still needs Docker socket permission"
            fi
        fi
    fi
    if confirm_system_change "enable and start the Docker service (this can interrupt Docker workloads)"; then
        if command -v systemctl >/dev/null 2>&1; then
            maybe_sudo systemctl enable --now docker || return 1
        elif command -v service >/dev/null 2>&1; then
            maybe_sudo service docker start || return 1
        else
            say "no supported service manager found; start Docker manually"
        fi
        sleep 2
    else
        say "Docker service was not started by Kryonsec"
    fi
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

backup_system_file() {
    local source="$1" backup
    [ -f "$source" ] || return 0
    backup="${source}.kryonsec.$(date +%Y%m%d%H%M%S).bak"
    maybe_sudo cp -p "$source" "$backup" || return 1
    printf '%s' "$backup"
}

valid_json_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    "$PY" - "$file" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    json.load(handle)
PY
}

install_gvisor() {
    if ! confirm_system_change \
        "install gVisor, edit Docker's runtime configuration, and prepare a Docker restart"; then
        return 1
    fi
    say "installing gVisor (runsc)"
    if ! apt_install gnupg; then
        say "gVisor prerequisite installation failed"
        return 1
    fi
    maybe_sudo mkdir -p /usr/share/keyrings

    local gvisor_list=/etc/apt/sources.list.d/gvisor.list
    local gvisor_backup docker_backup
    gvisor_backup="$(backup_system_file "$gvisor_list" || true)"
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
        say "apt repo unavailable — installing runsc from gVisor's own package"
        fetch_runsc /tmp/runsc.deb || return 1
        # dpkg rather than install(1): this is gVisor's own .deb, so it brings
        # runsc AND the containerd shim and helper binaries under
        # usr/bin/gvisor-bin/, which a bare binary copied to /usr/local/bin
        # would leave missing. It declares no dependencies, so -i is enough.
        maybe_sudo dpkg -i /tmp/runsc.deb >/dev/null || return 1
        rm -f /tmp/runsc.deb
    fi
    # `runsc install` edits daemon.json.  Preserve the previous file and refuse
    # to restart Docker if the resulting JSON is invalid.  A failed validation
    # restores the exact previous file instead of leaving Docker unable to
    # start.  The restart is separately approved because it interrupts running
    # containers.
    docker_backup="$(backup_system_file /etc/docker/daemon.json || true)"
    if ! maybe_sudo runsc install; then
        [ -n "$docker_backup" ] && maybe_sudo cp -p "$docker_backup" /etc/docker/daemon.json || true
        say "runsc could not register with Docker; the previous daemon configuration was preserved"
        return 1
    fi
    if ! valid_json_file /etc/docker/daemon.json; then
        say "gVisor produced invalid Docker daemon JSON; restoring the previous configuration"
        if [ -n "$docker_backup" ]; then
            maybe_sudo cp -p "$docker_backup" /etc/docker/daemon.json ||
                say "WARNING: restore failed — recover manually from $docker_backup"
        else
            maybe_sudo rm -f /etc/docker/daemon.json ||
                say "WARNING: could not remove the invalid new daemon configuration"
        fi
        return 1
    fi
    say "Docker daemon configuration validated"
    if ! confirm_system_change "restart Docker so the registered runsc runtime takes effect"; then
        say "Docker was not restarted; runsc will not be usable until an approved restart"
        return 1
    fi
    if command -v systemctl >/dev/null 2>&1; then
        maybe_sudo systemctl restart docker || return 1
    elif command -v service >/dev/null 2>&1; then
        maybe_sudo service docker restart || return 1
    else
        say "no supported service manager found; restart Docker manually"
        return 1
    fi
    sleep 2
}

# true when the daemon the CLI is actually talking to has runsc registered
runsc_registered() {
    dkr info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}' 2>/dev/null |
        grep -qw runsc
}

PURPLE_REQUESTED=0
if [ "$PROFILE" = "purple" ]; then
    PURPLE_REQUESTED=1
elif [ "$PROFILE" = "auto" ] && [ "$(uname -s)" = "Linux" ]; then
    if confirm_system_change \
        "attempt the optional Purple Team setup (Docker, gVisor, and a release sandbox image)"; then
        PURPLE_REQUESTED=1
    else
        say "Purple Team setup declined; installing Copilot only"
    fi
fi

if [ "$PURPLE_REQUESTED" = "1" ]; then
    [ "$(uname -s)" = "Linux" ] || die "Purple Team requires Linux or WSL2; use install.ps1 for Windows Copilot"

    if ! command -v docker >/dev/null 2>&1; then
        if is_apt && have_sudo && confirm_system_change \
            "install Docker Engine from the distribution package"; then
            install_docker || die "Docker installation failed; inspect the package-manager error and re-run"
        else
            die "Docker CLI is missing. Install Docker Engine in this Linux environment, then re-run; Docker Desktop is not silently substituted"
        fi
    fi

    if ! dkr info >/dev/null 2>&1; then
        die "Docker CLI is installed but the selected daemon is not reachable by this user; check the Docker context, DOCKER_HOST, service state, and socket permissions, then re-run"
    fi

    DOCKER_CONTEXT_NAME="$(dkr context show 2>/dev/null || true)"
    DOCKER_CONTEXTS="$(dkr context ls --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "${DOCKER_HOST:-}" ]; then
        say "Docker selection: DOCKER_HOST is set; Kryonsec will validate that endpoint and will not override it"
    fi
    say "Docker selection: context ${DOCKER_CONTEXT_NAME:-unknown}; available contexts: ${DOCKER_CONTEXTS//$'\n'/, }"
    CONTEXT_COUNT="$(printf '%s\n' "$DOCKER_CONTEXTS" | sed '/^$/d' | wc -l | tr -d ' ')"
    if [ "${CONTEXT_COUNT:-0}" -gt 1 ] && [ -z "${DOCKER_CONTEXT:-}" ] && [ -z "${DOCKER_HOST:-}" ]; then
        die "multiple Docker contexts are available and none was explicitly selected. Choose one yourself (for example export DOCKER_CONTEXT=<name>) and re-run; Kryonsec will not switch contexts"
    fi

    DOCKER_OS="$(dkr info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
    case "$DOCKER_OS" in
        *"Docker Desktop"*)
            die "the selected daemon is Docker Desktop, which cannot load a runsc runtime installed inside WSL. Select a native Linux Docker Engine context you administer; Kryonsec will not switch contexts or alter Docker Desktop"
            ;;
    esac

    if ! runsc_registered; then
        if is_apt && have_sudo && [ -z "${DOCKER_HOST:-}" ]; then
            if install_gvisor; then
                :
            else
                die "gVisor could not be installed or registered; the selected Docker daemon was not changed after a validation failure"
            fi
        else
            die "runsc is not registered with the selected Docker daemon. Install and register gVisor on that daemon host, then re-run; a local binary is not enough"
        fi
    fi
    runsc_registered || die "gVisor installation did not register runsc with the selected Docker daemon; no runc fallback is allowed"
    say "gVisor (runsc) is registered with the selected Docker daemon"
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

# Image refs to try.  KRYONSEC_SANDBOX_IMAGE wins and is the ONLY ref tried;
# otherwise the exact image tag for the installed release is used.  There is no
# latest fallback: release code and a mismatched sandbox are not equivalent.
sandbox_image_refs() {
    if [ -n "${KRYONSEC_SANDBOX_IMAGE:-}" ]; then
        printf '%s\n' "$KRYONSEC_SANDBOX_IMAGE"
        return 0
    fi
    if [ -n "$INSTALLED_VERSION" ]; then
        printf '%s:v%s\n' "$SANDBOX_REGISTRY_IMAGE" "$INSTALLED_VERSION"
    fi
    return 0
}

# set by pull_sandbox_image — reported so an install log always says which
# image it actually got, not just which one it asked for
PULLED_IMAGE_REF=""

pull_sandbox_image() {
    if [ -n "${KRYONSEC_REGISTRY_TOKEN:-}" ]; then
        # private-repo path; public pulls need no login.  A failed login is a
        # real authentication failure, not a reason to attempt an anonymous
        # pull and report a misleading "image missing" message.
        printf '%s' "$KRYONSEC_REGISTRY_TOKEN" |
            dkr login ghcr.io -u "${KRYONSEC_REGISTRY_USER:-kryonsec}" \
                --password-stdin >/dev/null 2>&1 || return 2
    fi
    # for-loop, NOT `... | while read`: a pipeline runs the body in a subshell
    # and the `return 0` below would never reach this function
    for REF in $(sandbox_image_refs); do
        if dkr pull "$REF"; then
            PULLED_IMAGE_REF="$REF"
            return 0
        fi
        say "  $REF is not available in the registry"
    done
    return 1
}

if [ "$PURPLE_REQUESTED" = "1" ]; then
    if [ -n "${KRYONSEC_SKIP_SANDBOX:-}" ]; then
        die "KRYONSEC_SKIP_SANDBOX was set, but the selected profile requires Purple Team. Run a Copilot install or remove the skip flag"
    fi
    IMAGE_REF="${KRYONSEC_SANDBOX_IMAGE:-}"
    if [ -z "$IMAGE_REF" ]; then
        IMAGE_REF="$(sandbox_image_refs | head -n 1)"
    fi
    [ -n "$IMAGE_REF" ] || die "no release-matched sandbox image reference is available"
    if ! dkr image inspect "$IMAGE_REF" >/dev/null 2>&1; then
        say "fetching the Zone B sandbox image $IMAGE_REF"
        pull_rc=0
        pull_sandbox_image || pull_rc=$?
        if [ "$pull_rc" -ne 0 ]; then
            case "$pull_rc" in
                2) die "sandbox registry authentication failed; check KRYONSEC_REGISTRY_TOKEN and KRYONSEC_REGISTRY_USER" ;;
                *) die "sandbox image pull failed (registry, DNS, TLS, or network); retry after checking access to GHCR" ;;
            esac
        fi
        IMAGE_REF="$PULLED_IMAGE_REF"
        say "sandbox image pulled: $IMAGE_REF"
    else
        say "sandbox image already present: $IMAGE_REF"
    fi

    IMAGE_DIGEST="$(dkr image inspect "$IMAGE_REF" --format '{{index .RepoDigests 0}}' 2>/dev/null || true)"
    case "$IMAGE_DIGEST" in
        *@sha256:*) ;;
        *) die "sandbox image has no registry digest; a tag or local image is not accepted for Purple Team" ;;
    esac
    # Persist only the resolved digest.  Existing config is parsed and updated
    # atomically; malformed config is never replaced by installer defaults.
    if ! "$VENV/bin/python" - "$IMAGE_DIGEST" <<'PY'
import sys
from kryonsec.config import config_path, read_config, update_config_sections

digest = sys.argv[1]
path = config_path()
data = read_config(path)
if str(data.get("sandbox", {}).get("image") or "") != digest:
    update_config_sections(path, {"sandbox": {"image": digest}})
PY
    then
        die "could not save the verified sandbox digest without overwriting configuration"
    fi
    say "sandbox image pinned to verified digest (reference withheld from logs)"
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
    # Do not execute an unpinned third-party install script from a product
    # installer.  Ollama is optional; the user can install it from its
    # official instructions and then re-run setup without changing Kryonsec.
    say "Ollama was not installed automatically (optional provider; external installer is not verified by Kryonsec)"
    say "         install it from https://ollama.com/download/linux, start it,"
    say "         pull a model (for example: ollama pull llama3.1), then run `kryonsec setup`"
    return 1
}

if ollama_up; then
    say "Ollama already running"
elif [ -n "${OPENAI_API_KEY:-}" ]; then
    say "OPENAI_API_KEY set — the wizard will use OpenAI"
else
    # curl|bash consumes stdin, so the answer must come from the terminal.
    # No terminal (CI) → read fails → skip (the wizard still offers OpenAI).
    printf '\033[36m==>\033[0m No LLM configured yet. Show the optional Ollama setup instructions? [Y/n] '
    REPLY=""
    read -r REPLY < /dev/tty 2>/dev/null || REPLY="n"
    case "$REPLY" in
        n*|N*)
            say "skipped — pick OpenAI or another configured provider in the wizard"
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
    SETUP_RC=0
    "$VENV/bin/kryonsec" setup < /dev/tty || SETUP_RC=$?
    if [ "$SETUP_RC" -ne 0 ]; then
        say "setup wizard did not finish — configuration was not claimed as complete; run 'kryonsec setup' when you're ready"
    fi
else
    SETUP_RC=2
    say "no terminal available — skipping the setup wizard"
    say "run 'kryonsec setup' in a terminal to configure your LLM"
fi

# ---- 8. verify + next steps --------------------------------------------------
# Show the final state.  A strict Purple profile is successful only when the
# actual selected daemon, registered runtime, digest-pinned image, and deep
# lifecycle smoke test all pass.  No runc fallback is treated as equivalent.
DOCTOR_ARGS=(doctor)
if [ "$PURPLE_REQUESTED" = "1" ]; then
    DOCTOR_ARGS+=(--deep --strict)
fi
DOCTOR_RC=0
"$VENV/bin/kryonsec" "${DOCTOR_ARGS[@]}" || DOCTOR_RC=$?

if [ "$PURPLE_REQUESTED" = "1" ] && [ "$DOCTOR_RC" -ne 0 ]; then
    die "installation did not complete the requested Purple Team profile. Copilot may be installed, but Purple Team is not ready; fix the FAIL/WARNING/SKIPPED rows above and re-run"
fi
if [ "$SETUP_RC" -ne 0 ] || [ ! -f "$KRYONSEC_HOME/config.toml" ] || \
   { [ "$PURPLE_REQUESTED" = "0" ] && [ "$DOCTOR_RC" -ne 0 ]; }; then
    say "Kryonsec is installed, but first-run configuration is still pending"
else
    say "Kryonsec Copilot is installed and configured"
fi

if command -v kryonsec >/dev/null 2>&1; then
    say "done — run: kryonsec"
else
    say "done — but the 'kryonsec' command is not active in THIS terminal yet."
    say "  run this now:  source $SHELL_RC"
    say "  (or open a new terminal — it works there automatically)"
fi
