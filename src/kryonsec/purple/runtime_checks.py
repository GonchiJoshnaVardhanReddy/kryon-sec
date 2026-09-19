"""Shared Docker / gVisor / sandbox-image probes (spec §8.5/§8.6).

doctor.py and purple/runner.py both need to answer "can Zone B run here?"
Two hand-rolled copies had already drifted (different build hints, different
error wording) — one module, both callers.
"""

from __future__ import annotations

import shutil
import subprocess

PROBE_TIMEOUT_S = 10


def docker_server_ok() -> tuple[bool, str]:
    """Docker CLI present and the daemon answers. Returns (ok, detail)."""
    if not shutil.which("docker"):
        return False, "docker CLI not found"
    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=PROBE_TIMEOUT_S,
        )
        if out.returncode == 0:
            return True, f"OK (server {out.stdout.strip()})"
        return False, "daemon not reachable"
    except Exception as e:
        return False, str(e)


def docker_runtimes() -> str | None:
    """Docker's registered runtime list, or None if unreachable."""
    if not shutil.which("docker"):
        return None
    try:
        # .Runtimes is a Go map — `join` errors on it (moby#37584); range it
        out = subprocess.run(
            ["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
            capture_output=True, text=True, timeout=PROBE_TIMEOUT_S,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def docker_os_string() -> str:
    """Docker's self-reported operating system, or "" if unreadable.

    Docker Desktop reports "Docker Desktop" here; a daemon running inside
    the distro reports the distro ("Ubuntu 24.04.3 LTS"). On WSL2 that
    string is the only reliable way to tell the two apart — both answer
    `docker info` over a socket the CLI finds the same way.
    """
    if not shutil.which("docker"):
        return ""
    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{.OperatingSystem}}"],
            capture_output=True, text=True, timeout=PROBE_TIMEOUT_S,
        )
    except Exception:
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def docker_desktop_in_use() -> bool:
    """True when the docker CLI is talking to Docker Desktop's daemon."""
    return "docker desktop" in docker_os_string().lower()


# Why a Docker Desktop host can never pass the gVisor check, and what to do.
#
# Docker Desktop keeps its daemon outside the WSL distro, where nothing run
# inside the distro can add a runtime to it. `runsc install` writes the
# distro's /etc/docker/daemon.json and restarts the distro's daemon — while
# the CLI goes on talking to Docker Desktop's, which has never heard of
# runsc. The install looks successful, `kryonsec doctor` says the runtime is
# missing, and no amount of re-running fixes it, because the thing being
# configured is not the thing being asked. So this needs saying out loud,
# and the fix is a different daemon — not a retry.
GVISOR_INSTALL_CMDS = (
    "sudo apt-get install -y docker.io && sudo runsc install && "
    "sudo systemctl restart docker"
)


def gvisor_fix_hint() -> str:
    """The most accurate fix for a missing runsc runtime, in one line."""
    if docker_desktop_in_use():
        return (
            "runsc runtime not registered — Docker Desktop's daemon is in use "
            "and it cannot load a runtime from inside WSL. Install Docker in "
            f"the distro and use that instead: {GVISOR_INSTALL_CMDS} "
            "(enable systemd in /etc/wsl.conf, or start it with "
            "`sudo service docker start`)"
        )
    return (
        "runsc runtime not registered — gVisor missing. Install it with: "
        f"{GVISOR_INSTALL_CMDS}"
    )


def runsc_registered() -> bool:
    """True if the gVisor (runsc) runtime is registered with Docker."""
    runtimes = docker_runtimes()
    return runtimes is not None and "runsc" in runtimes


def image_present(image: str) -> bool:
    """True if the pinned sandbox image exists locally (tag or digest)."""
    try:
        out = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=PROBE_TIMEOUT_S,
        )
        return out.returncode == 0
    except Exception:
        return False
