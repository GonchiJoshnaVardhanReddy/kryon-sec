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

Docker, not gVisor. The tests below pin each of the failures that
composed it: the malformed line, the fatal `apt-get update`, and the
fallback that only guessed one architecture name and did not clean up the
repo line it left behind.

That fallback turned out to be broken in a second way, found later by
checking rather than by reasoning: the URL it fetched
(`releases/release/latest/<arch>/runsc`) does not exist at any architecture
spelling. The bucket's release/ tree holds only dated directories with
tarballs in them. So the code that exists to rescue a machine whose apt repo
is unreachable could not rescue anything, and its failure — a bare
`curl: (22) ... 404` — said nothing about why. The tests at the bottom pin
the replacement: read the path and the checksum out of the bucket's own apt
index, fetch the .deb, and refuse to install it unless the checksum matches.
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


# ---- the runsc package fallback --------------------------------------------
#
# The fallback fetched `releases/release/latest/<arch>/runsc`. Checked live,
# that is a 404: the bucket's release/ tree holds only dated directories
# (20260914.0/ and the like) with tarballs inside, and there is no `latest`
# and no bare runsc under it at any spelling. So the path that exists to save
# a machine whose apt repo is unreachable could never save anything.
#
# The artifact that does exist is the pool/ .deb, and the bucket's own apt
# index states its path AND its SHA256. Both are read from there now, which
# is the substantive change: the download is checked against a checksum the
# publisher asserts, not against a guess about file magic.

_INDEX = """\
Package: runsc
Architecture: {arch}
Version: 20260914.0
Filename: pool/20260914.0/binary-{arch}/runsc.deb
Size: 170572404
SHA256: {sha}
SHA512: irrelevant-to-this-test

Package: gvisor-tap-vsock
Architecture: {arch}
Version: 1.0.0
Filename: pool/1.0.0/binary-{arch}/tap.deb
SHA256: 0000000000000000
"""


def _run_fetch_runsc(
    *,
    arch: str = "amd64",
    sha: str = "d2f167823d81",
    index: bool = True,
    download: bool = True,
    summed: str | None = None,
):
    """Run fetch_runsc against a stub bucket.

    `index`/`download` False make that particular fetch fail. `summed` is
    what the local sha256sum reports; the default is "whatever the index
    said", i.e. the honest case.
    """
    if index:
        index_arm = (
            "cat > \"$out\" <<'IDX'\n"
            + _INDEX.format(arch=arch, sha=sha)
            + "IDX\n            return 0"
        )
    else:
        index_arm = "return 22"
    deb_arm = (
        "printf '!<arch>\\n' > \"$out\"; return 0" if download else "return 22"
    )
    summed = sha if summed is None else summed

    body = f"""
CURL_LOG=$(mktemp)
export CURL_LOG
curl() {{
    local out="" prev="" url=""
    for a in "$@"; do
        case "$a" in http*) url="$a" ;; esac
        [ "$prev" = "-o" ] && out="$a"
        prev="$a"
    done
    echo "$url" >> "$CURL_LOG"
    case "$url" in
        */Packages)
            {index_arm}
            ;;
        */pool/*)
            {deb_arm}
            ;;
    esac
    return 22
}}
dpkg() {{ echo "{arch}"; }}
sha256sum() {{ echo "{summed}  $1"; }}
{_function("fetch_runsc")}
"""
    return _bash(body + """
out=$(mktemp)
if fetch_runsc "$out"; then echo "RC=0"; else echo "RC=1"; fi
echo "--- tried ---"
cat "$CURL_LOG"
echo "--- artifact ---"
[ -s "$out" ] && echo "PRESENT" || echo "ABSENT"
""")


def _tried(result: subprocess.CompletedProcess) -> str:
    """The URLs the stub curl was asked for, in order."""
    after = result.stdout.split("--- tried ---", 1)[1]
    return after.split("--- artifact ---", 1)[0].strip()


def test_fetch_runsc_reads_the_package_path_out_of_the_index():
    """Path and checksum both come from the publisher's index.

    Reconstructing either from a naming convention is exactly how the
    `release/latest/...` URL got written in the first place.
    """
    result = _run_fetch_runsc()
    assert "RC=0" in result.stdout, result.stdout + result.stderr
    assert "/dists/release/main/binary-amd64/Packages" in _tried(result)
    assert (
        "https://storage.googleapis.com/gvisor/releases/pool/20260914.0/"
        "binary-amd64/runsc.deb" in _tried(result)
    )


def test_fetch_runsc_uses_dpkgs_architecture_name_not_the_kernels():
    """The index is filed binary-amd64/binary-arm64.

    uname says x86_64, which is what the old URL used and part of why it
    never resolved.
    """
    tried = _tried(_run_fetch_runsc())
    assert "binary-amd64" in tried
    assert "x86_64" not in tried


def test_fetch_runsc_handles_arm():
    result = _run_fetch_runsc(arch="arm64")
    assert "RC=0" in result.stdout
    assert "binary-arm64/Packages" in _tried(result)
    assert "binary-arm64/runsc.deb" in _tried(result)


def test_fetch_runsc_never_installs_an_artifact_that_fails_its_checksum():
    """The check the old ELF-magic test was reaching for, done properly.

    A proxy, a captive portal, or a truncated transfer can all hand back a
    well-formed file that is not the package. Only the publisher's own
    checksum can tell that apart, and a wrong /usr/bin/runsc looks installed
    while Purple Team cannot start — worse than the failure it replaced.
    """
    result = _run_fetch_runsc(summed="ffffffffffff")
    assert "RC=1" in result.stdout, result.stdout + result.stderr
    assert "checksum does not match" in result.stdout
    assert "ABSENT" in result.stdout  # not left on disk to be installed anyway


def test_fetch_runsc_refuses_a_package_index_it_cannot_read():
    result = _run_fetch_runsc(index=False)
    assert "RC=1" in result.stdout
    assert "could not read the package index" in result.stdout


def test_fetch_runsc_refuses_an_index_with_no_runsc_stanza():
    """The index parses, but says nothing about runsc — so there is no
    checksum to verify against and nothing to install."""
    result = _run_fetch_runsc(sha="")
    assert "RC=1" in result.stdout
    assert "lists no runsc package" in result.stdout


def test_fetch_runsc_refuses_a_failed_download():
    result = _run_fetch_runsc(download=False)
    assert "RC=1" in result.stdout
    assert "ABSENT" in result.stdout


def test_fetch_runsc_does_not_try_architectures_it_cannot_name():
    """No guessing: an architecture this script has no package for must
    stop, not fire off a spread of hopeful URLs."""
    for arch in ("riscv64", ""):
        result = _run_fetch_runsc(arch=arch)
        assert "RC=1" in result.stdout, arch
        assert _tried(result) == "", arch


def test_the_dead_release_latest_url_is_gone_from_the_script():
    """Pinned so it cannot come back: no *code* in install.sh may point at
    `releases/release/latest`, which has never existed. Comments are exempt —
    the note in fetch_runsc explaining why it was wrong is the point."""
    code = "\n".join(
        line for line in SRC.splitlines() if not line.lstrip().startswith("#")
    )
    assert "release/latest" not in code


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


def test_install_gvisor_installs_the_package_rather_than_copying_a_binary():
    """gVisor's .deb carries more than usr/bin/runsc.

    It also ships the containerd shim (usr/bin/containerd-shim-runsc-v1) and
    the helper binaries under usr/bin/gvisor-bin/, which gVisor uses for
    sentry prewarming and the metric server. `install -m 0755` of a single
    fetched binary — what the old fallback did — silently leaves all of them
    missing, so pin dpkg here.
    """
    body = _function("install_gvisor")
    assert "dpkg -i" in body
    assert "install -m 0755" not in body


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
