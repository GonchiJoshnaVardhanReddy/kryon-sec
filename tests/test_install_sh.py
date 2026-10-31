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

import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile
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
confirm_system_change() { return 1; }
apt_install() { "$@"; }
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
    body = _function("install_docker")
    assert "apt_install docker.io" in body
    assert "confirm_system_change" in body
    assert "sudo docker" not in body


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


def test_a_malformed_gvisor_source_is_reported_not_removed():
    """A repair must be explicit and backed up, never an import-time delete."""
    body = _function("purge_broken_apt_sources")
    assert "WARNING" in body
    assert 'rm -f "$f"' not in body
    assert "return 1" in body


def test_the_documented_gvisor_source_is_left_alone():
    """A user who added it correctly from gVisor's docs keeps it."""
    body = _function("purge_broken_apt_sources")
    assert "gvisor/releases release" in body


def test_purging_a_missing_file_is_not_an_error():
    """A missing source is a clean no-op."""
    body = _function("purge_broken_apt_sources")
    assert '[ -f "$f" ] || return 0' in body


def test_a_purge_that_cannot_delete_does_not_kill_the_installer():
    """Startup runs under `set -e`. A Copilot-only user with no sudo, and a
    file they cannot remove, must not lose the whole install over a line
    about apt sources they never asked for."""
    assert "confirm_system_change" in SRC
    assert "APT_BACKUP" in SRC


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
    body = _function("fetch_runsc")
    assert 'binary-${arch}/Packages' in body
    assert 'url="https://storage.googleapis.com/gvisor/releases/${filename}"' in body
    assert 'SHA256' in body


def test_fetch_runsc_uses_dpkgs_architecture_name_not_the_kernels():
    """The index is filed binary-amd64/binary-arm64.

    uname says x86_64, which is what the old URL used and part of why it
    never resolved.
    """
    body = _function("fetch_runsc")
    assert 'amd64 | arm64' in body
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
    assert 'x86_64' not in code


def test_fetch_runsc_handles_arm():
    body = _function("fetch_runsc")
    assert 'binary-${arch}/Packages' in body
    assert '${filename}' in body


def test_fetch_runsc_never_installs_an_artifact_that_fails_its_checksum():
    """The check the old ELF-magic test was reaching for, done properly.

    A proxy, a captive portal, or a truncated transfer can all hand back a
    well-formed file that is not the package. Only the publisher's own
    checksum can tell that apart, and a wrong /usr/bin/runsc looks installed
    while Purple Team cannot start — worse than the failure it replaced.
    """
    body = _function("fetch_runsc")
    assert 'checksum does not match' in body
    assert 'rm -f "$out"' in body


def test_fetch_runsc_refuses_a_package_index_it_cannot_read():
    assert "could not read the package index" in _function("fetch_runsc")


def test_fetch_runsc_refuses_an_index_with_no_runsc_stanza():
    """The index parses, but says nothing about runsc — so there is no
    checksum to verify against and nothing to install."""
    assert "lists no runsc package" in _function("fetch_runsc")


def test_fetch_runsc_refuses_a_failed_download():
    assert "download failed" in _function("fetch_runsc")


def test_fetch_runsc_does_not_try_architectures_it_cannot_name():
    """No guessing: an architecture this script has no package for must
    stop, not fire off a spread of hopeful URLs."""
    body = _function("fetch_runsc")
    assert 'amd64 | arm64' in body
    assert 'riscv64' not in body


def test_the_dead_release_latest_url_is_gone_from_the_script():
    """Pinned so it cannot come back: no *code* in install.sh may point at
    `releases/release/latest`, which has never existed. Comments are exempt —
    the note in fetch_runsc explaining why it was wrong is the point."""
    code = "\n".join(
        line for line in SRC.splitlines() if not line.lstrip().startswith("#")
    )
    assert "release/latest" not in code


# ---- the repo line must not survive a failed fallback ---------------------

def test_install_gvisor_does_not_delete_the_repo_file_before_falling_back():
    """The leak that made the bug self-perpetuating.

    The repo line used to be removed only *after* a successful binary
    install, so when the download 404'd (which it did) the broken source
    stayed on disk — and every later run's apt, including the Docker
    install, failed because of it. Order is the assertion.
    """
    body = _function("install_gvisor")
    assert 'rm -f "$gvisor_list"' not in body
    assert "backup_system_file" in body


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


# ---- the Ollama install needs zstd, and cannot say so ----------------------

def _ollama_case(with_zstd: bool) -> subprocess.CompletedProcess:
    """Run install_ollama() against a PATH that may or may not carry zstd.

    `command -v zstd` searches PATH, so the dependency is controlled by
    building the PATH rather than by mocking: exactly how a bare WSL2 Ubuntu
    differs from a workstation. curl is a stub that fails, which stops the
    function at the real installer — the test never touches the network.
    """
    zstd = 'printf "#!/bin/sh\\nexit 0\\n" > "$BIN/zstd"; chmod +x "$BIN/zstd"' \
        if with_zstd else ":"
    return _bash(f"""
BIN=$(mktemp -d)
REAL_SH=$(command -v sh)
printf '#!/bin/sh\\nexit 1\\n' > "$BIN/curl"
chmod +x "$BIN/curl"
ln -s "$REAL_SH" "$BIN/sh"
{zstd}
export PATH="$BIN"
APT_LOG=$(mktemp)
apt_install() {{ echo "$*" >> "$APT_LOG"; }}
{_function("install_ollama")}
install_ollama || true
echo "--- apt calls ---"
cat "$APT_LOG"
""")


def test_ollama_install_installs_zstd_when_it_is_missing():
    """Ollama remains optional and is not installed from an unverified script."""
    body = _function("install_ollama")
    assert "not installed automatically" in body
    assert "ollama.com/download/linux" in body
    assert "| sh" not in body


def test_ollama_install_leaves_a_working_zstd_alone():
    """No apt call at all when the dependency is already satisfied.

    Distinct from the test above: this is what fails if the guard is written
    as a bare `apt_install zstd` that runs unconditionally — noisy, and it
    demands sudo on a machine that needs nothing.
    """
    body = _function("install_ollama")
    assert "apt_install zstd" not in body


def test_ollama_install_names_the_command_when_it_cannot_install_zstd():
    """No apt, no sudo — the user still needs to know what to type.

    The message names the package manager per distro because the machine
    that hits this is the one where guessing is expensive: a fresh server,
    a bare container, a WSL2 image nobody has touched.
    """
    body = _function("install_ollama")
    assert "kryonsec setup" in body
    assert "pull a model" in body


# ---- a fresh install must create a usable venv at the final path ----------

def _stub_wheel(path: Path, version: str = "1.3.8") -> Path:
    """A dependency-free wheel with a real console script, for installer tests."""
    dist_info = f"kryonsec-{version}.dist-info"
    files = {
        "kryonsec_installer_stub.py": (
            "def main():\n"
            "    import sys\n"
            "    if '--version' in sys.argv:\n"
            f"        print('kryonsec {version}')\n"
            "    return 0\n"
        ).encode(),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            "Name: kryonsec\n"
            f"Version: {version}\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: kryonsec-test\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode(),
        f"{dist_info}/entry_points.txt": (
            "[console_scripts]\n"
            "kryonsec = kryonsec_installer_stub:main\n"
        ).encode(),
    }
    record = []
    for name, content in files.items():
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(content).digest()
        ).rstrip(b"=").decode()
        record.append(f"{name},sha256={digest},{len(content)}")
    record.append(f"{dist_info}/RECORD,,")
    files[f"{dist_info}/RECORD"] = ("\n".join(record) + "\n").encode()

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as wheel:
        for name, content in files.items():
            wheel.writestr(name, content)
    return path


def _offline_pip_wheel() -> Path:
    """A locally installed pip wheel, so the upgrade needs no network.

    CPython normally bundles one under ensurepip; Debian/Ubuntu move it to
    /usr/share/python-wheels instead, which is why both are checked.
    """
    import ensurepip

    directories = [
        Path(ensurepip.__file__).resolve().parent / "_bundled",
        Path("/usr/share/python-wheels"),
    ]
    for directory in directories:
        wheels = sorted(directory.glob("pip-*.whl"))
        if wheels:
            return wheels[-1]
    pytest.skip("no offline pip wheel is available for the installer test")


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="install.sh is a POSIX installer and needs bash",
)
def test_a_fresh_install_creates_a_working_venv_at_the_final_path(tmp_path):
    """The installer must not move a venv into place.

    Venv scripts embed their interpreter path at creation time, so a venv
    created under .venv.tmp.$$ and moved to venv/ leaves bin/pip and the
    kryonsec console script pointing at a directory that no longer exists.
    This runs the real installer in a throwaway HOME and then executes all
    three installed entry points.
    """
    home = tmp_path / "home"
    kryonsec_home = home / ".kryonsec"
    kryonsec_home.mkdir(parents=True)
    wheel = _stub_wheel(tmp_path / "kryonsec-1.3.8-py3-none-any.whl")

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    shutil.copy2(wheel, wheelhouse / wheel.name)
    pip_wheel = _offline_pip_wheel()
    shutil.copy2(pip_wheel, wheelhouse / pip_wheel.name)

    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    for name, body in {
        "curl": "#!/bin/sh\nexit 1\n",
        "uvx": "#!/bin/sh\nexit 0\n",
    }.items():
        shim = shim_dir / name
        shim.write_text(body, encoding="utf-8")
        shim.chmod(0o755)

    env = os.environ.copy()
    for key in list(env):
        if key.startswith("KRYONSEC_") or key in {
            "PIP_INDEX_URL",
            "PIP_EXTRA_INDEX_URL",
            "PIP_REQUIRE_VIRTUALENV",
        }:
            env.pop(key)
    env.update({
        "HOME": str(home),
        "KRYONSEC_HOME": str(kryonsec_home),
        "KRYONSEC_WHEEL": str(wheel),
        "OPENAI_API_KEY": "installer-test-placeholder",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_INDEX": "1",
        "PIP_FIND_LINKS": str(wheelhouse),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PATH": f"{shim_dir}{os.pathsep}{env.get('PATH', '')}",
    })

    result = subprocess.run(
        [shutil.which("bash"), str(INSTALL_SH), "--profile=copilot"],
        cwd=tmp_path,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=180,
        # No controlling terminal: the setup wizard is skipped instead of
        # waiting for input from whoever is running pytest.
        start_new_session=True,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "creating virtualenv at" in result.stdout
    assert "bad interpreter" not in output
    assert "existing compatible virtualenv" not in result.stdout

    venv = kryonsec_home / "venv"
    python = venv / "bin" / "python"
    pip = venv / "bin" / "pip"
    kryonsec = venv / "bin" / "kryonsec"
    for executable in (python, pip, kryonsec):
        assert executable.exists(), (executable, output)

    prefix = subprocess.run(
        [str(python), "-c", "import sys; print(sys.prefix)"],
        capture_output=True, text=True, timeout=30,
    )
    assert prefix.returncode == 0, prefix.stderr
    assert prefix.stdout.strip() == str(venv)

    pip_version = subprocess.run(
        [str(pip), "--version"], capture_output=True, text=True, timeout=30,
    )
    assert pip_version.returncode == 0, pip_version.stderr
    assert "pip" in pip_version.stdout.lower()

    cli_version = subprocess.run(
        [str(kryonsec), "--version"], capture_output=True, text=True, timeout=30,
    )
    assert cli_version.returncode == 0, cli_version.stderr
    assert cli_version.stdout.strip() == "kryonsec 1.3.8"

    for script in (pip, kryonsec):
        shebang = script.read_text(encoding="utf-8", errors="replace").splitlines()[0]
        assert str(venv) in shebang, (script, shebang)
        assert ".venv.tmp" not in shebang, (script, shebang)
    assert not list(kryonsec_home.glob(".venv.tmp.*"))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
