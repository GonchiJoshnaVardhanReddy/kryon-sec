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
