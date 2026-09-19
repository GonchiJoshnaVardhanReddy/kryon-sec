"""Tests for install.sh's Docker + gVisor steps.

Nothing tested this script before, and the cost was a bug that hid itself
well: the gVisor deb line was written as

    deb [...] https://storage.googleapis.com/gvisor/releases/release main amd64

The deb format is `deb [opts] URI SUITE COMPONENT`, so that put `/release`
in the URI and the architecture in the component slot. apt went looking for
`.../gvisor/releases/release/dists/main/Release`, got a 404, and reported
"does not have a Release file".

What made it expensive is that a configured-but-unfetchable source does not
only fail itself — apt refuses to install anything while one exists. So the
*next* run's `apt-get update` failed, `install_docker` returned early, and
the visible symptom on a user's machine was:

    WARNING: Docker install failed — Purple Team needs it

Docker, not gVisor. The tests below pin each of the three failures that
composed it: the malformed line, the fatal `apt-get update`, and the
fallback that only guessed one architecture name and did not clean up the
repo line it left behind.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parent.parent / "install.sh"
SRC = INSTALL_SH.read_text(encoding="utf-8")

# Stubs for everything install.sh assumes exists. `maybe_sudo` runs the
# command directly — we are not root here and these tests must not need to be.
STUBS = """\
set -uo pipefail
say() { printf '==> %s\\n' "$1"; }
maybe_sudo() { "$@"; }
"""


def _function(name: str) -> str:
    """One shell function's source, lifted out of install.sh.

    Sourcing the whole script is not an option — it installs things. The
    functions here are self-contained apart from say/maybe_sudo, which the
    stubs supply.
    """
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", SRC, re.S | re.M)
    assert match, f"{name}() not found in install.sh"
    return match.group(0)


def _bash(body: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", STUBS + "\n" + body],
        capture_output=True, text=True, timeout=60,
    )


# ---- the malformed deb line ------------------------------------------------

def test_gvisor_deb_line_parses_as_uri_suite_component():
    """The whole bug, in one assertion.

    Reading the line the way apt does: everything after the bracketed
    options is URI, then suite, then component. An architecture appearing
    after the component is the signature of the old mistake.
    """
    match = re.search(r'echo "(deb \[arch=[^"]+)"', SRC)
    assert match, "no gVisor deb line found in install.sh"
    line = match.group(1)

    # drop the [opts] block; what remains is the part apt interprets
    after_options = line.split("] ", 1)[1]
    assert after_options == (
        "https://storage.googleapis.com/gvisor/releases release main"
    ), after_options


def test_gvisor_deb_line_does_not_glue_release_onto_the_uri():
    """`/releases/release` makes apt fetch `dists/main/Release`, which 404s."""
    match = re.search(r'echo "(deb \[arch=[^"]+)"', SRC)
    assert "/gvisor/releases/release " not in match.group(1)


# ---- a broken source must not take Docker down with it ---------------------

def test_docker_install_survives_a_failing_apt_get_update():
    """The regression that produced "Docker install failed".

    apt-get update returning non-zero used to abort the function before the
    install was attempted. apt installs fine from the lists it already has,
    so the update result must not be the gate.
    """
    result = _bash(f"""
APT_LOG=$(mktemp)
apt-get() {{
    echo "$*" >> "$APT_LOG"
    case "$1" in
        update) return 100 ;;   # a broken third-party source
        install) return 0 ;;
    esac
    return 0
}}
id() {{ echo 0; }}
systemctl() {{ return 0; }}
sleep() {{ :; }}
{_function("install_docker")}
install_docker && echo "RC=0" || echo "RC=1"
echo "--- apt calls ---"
cat "$APT_LOG"
""")
    assert "RC=0" in result.stdout, result.stdout + result.stderr
    assert "install -y -qq docker.io" in result.stdout


def _purge_case(content: str) -> str:
    """Write `content` as the gvisor source, purge it, report what happened."""
    return _bash(f"""
f=$(mktemp)
cat > "$f" <<'LIST'
{content}
LIST
{_function("purge_broken_apt_sources")}
purge_broken_apt_sources "$f"
if [ -f "$f" ]; then echo "LEFT"; else echo "REMOVED"; fi
""")


def test_a_malformed_gvisor_source_is_removed():
    """It has to go, or apt stays broken for every later install — and the
    user cannot install docker.io by hand either while it is there."""
    result = _purge_case(
        "deb [arch=amd64 signed-by=/k.gpg] "
        "https://storage.googleapis.com/gvisor/releases/release main amd64"
    )
    assert "REMOVED" in result.stdout, result.stdout + result.stderr


def test_the_documented_gvisor_source_is_left_alone():
    """A user who added it correctly from gVisor's docs keeps it."""
    result = _purge_case(
        "deb [arch=amd64 signed-by=/k.gpg] "
        "https://storage.googleapis.com/gvisor/releases release main"
    )
    assert "LEFT" in result.stdout


def test_purging_a_missing_file_is_not_an_error():
    """Runs unconditionally at startup, so it must survive a fresh machine."""
    result = _bash(f"""
{_function("purge_broken_apt_sources")}
purge_broken_apt_sources "$(mktemp -u)"
echo "RC=$?"
""")
    assert "RC=0" in result.stdout


def test_a_purge_that_cannot_delete_does_not_kill_the_installer():
    """Startup runs under `set -e`. A Copilot-only user with no sudo, and a
    file they cannot remove, must not lose the whole install over a line
    about apt sources they never asked for."""
    result = _bash(f"""
f=$(mktemp)
printf 'deb [arch=amd64] https://storage.googleapis.com/gvisor/releases/release main amd64\\n' > "$f"
maybe_sudo() {{ return 1; }}   # rm fails, as it would without sudo
set -e
{_function("purge_broken_apt_sources")}
purge_broken_apt_sources "$f"
echo "SURVIVED"
""")
    assert "SURVIVED" in result.stdout, result.stdout + result.stderr


# ---- the runsc binary fallback --------------------------------------------

def _fetch_runsc_body(mode: str, uname: str, dpkg: str) -> str:
    return f"""
CURL_LOG=$(mktemp)
export CURL_LOG CURL_MODE={mode}
curl() {{
    local out="" prev="" url=""
    for a in "$@"; do
        case "$a" in http*) url="$a" ;; esac
        [ "$prev" = "-o" ] && out="$a"
        prev="$a"
    done
    echo "$url" >> "$CURL_LOG"
    case "$CURL_MODE" in
        ok)   printf '\\177ELF\\002\\001\\001' > "$out"; return 0 ;;
        html) printf '<html>captive portal</html>' > "$out"; return 0 ;;
        *)    return 22 ;;
    esac
}}
uname() {{ echo "{uname}"; }}
dpkg() {{ echo "{dpkg}"; }}
{_function("fetch_runsc")}
"""


def _run_fetch_runsc(mode: str, uname: str = "x86_64", dpkg: str = "amd64"):
    return _bash(_fetch_runsc_body(mode, uname, dpkg) + """
out=$(mktemp)
if fetch_runsc "$out"; then echo "RC=0"; else echo "RC=1"; fi
echo "--- tried ---"
cat "$CURL_LOG"
""")


def test_fetch_runsc_uses_the_kernels_architecture_name():
    """The bucket files architectures as x86_64/aarch64, not amd64/arm64."""
    result = _run_fetch_runsc("ok", uname="x86_64")
    assert '"RC=0"' not in result.stdout  # sanity: RC is printed bare
    assert "RC=0" in result.stdout
    assert "release/latest/x86_64/runsc" in result.stdout


def test_fetch_runsc_handles_arm():
    result = _run_fetch_runsc("ok", uname="aarch64", dpkg="arm64")
    assert "RC=0" in result.stdout
    assert "release/latest/aarch64/runsc" in result.stdout


def test_fetch_runsc_translates_dpkg_names_when_uname_is_unhelpful():
    """A dpkg `amd64` must become the bucket's `x86_64`, not a 404."""
    result = _run_fetch_runsc("ok", uname="", dpkg="amd64")
    assert "RC=0" in result.stdout
    assert "release/latest/x86_64/runsc" in result.stdout
    assert "/amd64/runsc" not in result.stdout


def test_fetch_runsc_tries_every_name_before_giving_up():
    """One guess used to be the whole plan, and its failure was a bare
    `curl: (22) 404` with nothing to act on."""
    result = _run_fetch_runsc("fail", uname="x86_64", dpkg="amd64")
    assert "RC=1" in result.stdout
    tried = result.stdout.split("--- tried ---")[1]
    assert "release/latest/x86_64/runsc" in tried
    assert "release/latest/aarch64/runsc" in tried


def test_fetch_runsc_refuses_something_that_is_not_a_binary():
    """200 with an HTML body is what a proxy or captive portal returns.

    Installing that as /usr/local/bin/runsc would leave a broken runtime
    that looks installed — worse than the 404 it replaced.
    """
    result = _run_fetch_runsc("html", uname="x86_64")
    assert "RC=1" in result.stdout
    assert "not a binary" in result.stdout


# ---- the repo line must not survive a failed fallback ---------------------

def test_install_gvisor_drops_the_repo_file_before_falling_back():
    """The leak that made the bug self-perpetuating.

    The repo line used to be removed only *after* a successful binary
    install, so when the download 404'd (which it did) the broken source
    stayed on disk — and every later run's apt, including the Docker
    install, failed because of it. Order is the assertion.
    """
    body = _function("install_gvisor")
    assert body.index('rm -f "$gvisor_list"') < body.index("fetch_runsc")


def test_install_gvisor_removes_it_on_the_success_path_too():
    """Rewritten on every run, so a stale malformed line cannot linger."""
    assert 'tee "$gvisor_list"' in _function("install_gvisor")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
