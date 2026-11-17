"""Shared Docker / gVisor / sandbox-image probes (spec §8.5/§8.6).

doctor.py and purple/runner.py both need to answer "can Zone B run here?"
Two hand-rolled copies had already drifted (different build hints, different
error wording) — one module, both callers.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

PROBE_TIMEOUT_S = 10
# Container LIFECYCLE calls (create/start/rm) are not probes: a `runsc`
# cold start of the full sandbox image on WSL2 took longer than the probe
# timeout, which made a WORKING runtime report "timed out or could not
# start" in `doctor --deep`. The lifecycle timeout must tolerate a cold
# start without weakening any check (a hung start still fails cleanly).
SMOKE_TIMEOUT_S = 120

# Release images are accepted only after the installer resolves them to a
# registry digest.  Keeping the repository name here avoids several callers
# inventing slightly different image references.
SANDBOX_REGISTRY_IMAGE = (
    "ghcr.io/gonchijoshnavardhanreddy/kryonsec-sandbox"
)
SANDBOX_ENTRYPOINT = ("/entrypoint.sh",)
SANDBOX_REQUIRED_FILES = (
    "/entrypoint.sh",
    "/opt/kryonsec/probe.py",
    "/opt/kryonsec/openapi_probe.py",
)


def egress_firewall_ok() -> tuple[bool, str]:
    """Phase 1E preflight: can the host program the Zone B network
    boundary? Checks that iptables AND ip6tables are installed and that
    the DOCKER-USER chain is readable through a NON-interactive sudo
    (directly as root) — the runner's EgressGate needs exactly this
    before it will allow any Zone B tool to run.

    Returns (ok, detail). Never attempts to modify the firewall.
    """
    if not sys.platform.startswith("linux"):
        return False, (
            "egress firewall checks apply to Linux; Purple Team (Zone B) "
            "is unavailable on this host"
        )
    sudo = shutil.which("sudo")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        prefix: list[str] = []
    elif sudo:
        prefix = ["sudo", "-n"]
    else:
        return False, (
            "no sudo binary: the runner cannot program the Zone B egress "
            "firewall non-interactively (fail closed)"
        )
    problems = []
    for cmd in ("iptables", "ip6tables"):
        binary = shutil.which(cmd)
        if not prefix and not binary:
            problems.append(f"{cmd} not installed")
            continue
        try:
            proc = subprocess.run(
                (prefix + [cmd, "-S", "DOCKER-USER"]),
                capture_output=True, text=True, timeout=PROBE_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            problems.append(f"{cmd} via sudo -n probe failed: {e}")
            continue
        if proc.returncode == 0:
            continue
        stderr = (proc.stderr or "").strip()
        if prefix and ("a password is required" in stderr.lower()
                       or "incorrect password" in stderr.lower()
                       or "interactive authentication" in stderr.lower()):
            problems.append(
                f"sudo -n {cmd}: password cache required — either run "
                "`sudo -v` in this terminal right before starting "
                "Kryonsec (the sudo cache is per-terminal and "
                "time-limited), or add a scoped NOPASSWD sudoers rule "
                "for iptables/ip6tables to this user; non-interactive "
                "root is required to program the Zone B egress firewall "
                "at engagement start, so there is no weaker fallback")
        else:
            problems.append(
                f"{cmd}: DOCKER-USER chain unreadable ({stderr[:120] or 'exit ' + str(proc.returncode)})")
    if problems:
        return False, "; ".join(problems)
    detail_name = "root" if not prefix else "sudo -n"
    return True, (
        f"iptables and ip6tables DOCKER-USER chains readable ({detail_name}); "
        "the egress boundary can be programmed at engagement start"
    )


@dataclass(frozen=True)
class DockerContextInfo:
    """The Docker target selected by the current client configuration."""

    name: str = ""
    endpoint: str = ""
    contexts: tuple[str, ...] = ()
    docker_host_override: bool = False
    error: str = ""


@dataclass(frozen=True)
class DockerInfo:
    """Facts returned by the daemon selected by the Docker CLI."""

    server_version: str = ""
    operating_system: str = ""
    architecture: str = ""
    default_runtime: str = ""
    runtimes: tuple[str, ...] = ()
    rootless: bool = False


@dataclass(frozen=True)
class ImageInfo:
    """Safe metadata for a sandbox image on the selected daemon."""

    image_id: str = ""
    architecture: str = ""
    operating_system: str = ""
    entrypoint: tuple[str, ...] = ()
    user: str = ""
    repo_digests: tuple[str, ...] = ()
    labels: dict[str, str] | None = None


@dataclass(frozen=True)
class ImageCheck:
    status: str
    detail: str
    info: ImageInfo | None = None


def _run_docker(
        args: list[str], timeout: "int | float" = PROBE_TIMEOUT_S,
) -> subprocess.CompletedProcess:
    """Run one read-only Docker CLI query with a bounded timeout
    (lifecycle callers may extend it — see SMOKE_TIMEOUT_S)."""
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _safe_docker_failure(proc: subprocess.CompletedProcess) -> str:
    """Turn Docker's often noisy error into a useful, secret-free category."""
    text = f"{proc.stderr or ''} {proc.stdout or ''}".lower()
    if "permission denied" in text or "permission is required" in text:
        return "permission denied opening the selected Docker endpoint"
    if "context" in text and ("not found" in text or "does not exist" in text):
        return "the selected Docker context does not exist"
    if "cannot connect" in text or "is the docker daemon running" in text:
        return "Docker daemon is not reachable"
    if "timeout" in text or "timed out" in text:
        return "Docker CLI request timed out"
    return "Docker CLI request failed"


def _normalise_arch(value: str) -> str:
    value = (value or "").lower().strip()
    return {
        "x86_64": "amd64",
        "x86-64": "amd64",
        "aarch64": "arm64",
        "armv8": "arm64",
    }.get(value, value)


def _normalise_version(value: str) -> str:
    """Compare release labels whether a registry includes the leading ``v``."""
    value = (value or "").strip()
    return value[1:] if value.lower().startswith("v") else value


def safe_endpoint(value: str | None) -> str:
    """Return a Docker endpoint without userinfo, query, or fragment data."""
    value = (value or "").strip()
    if not value:
        return "default local endpoint"
    if value.startswith(("unix://", "npipe://")):
        return value
    try:
        parts = urlsplit(value)
        if not parts.scheme:
            return "configured endpoint"
        # Do not print userinfo.  SSH context URLs commonly contain a user
        # name, and custom endpoints sometimes contain credentials by
        # mistake.  Neither belongs in a diagnostic report.
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, "", ""))
    except (ValueError, UnicodeError):
        return "configured endpoint"


def docker_context_info() -> DockerContextInfo:
    """Report the selected context and effective endpoint without changing it."""
    if not shutil.which("docker"):
        return DockerContextInfo(error="docker CLI not found")

    try:
        current = _run_docker(["context", "show"])
        if current.returncode != 0:
            return DockerContextInfo(error=_safe_docker_failure(current))
        name = (current.stdout or "").strip() or "default"

        listed = _run_docker(["context", "ls", "--format", "{{.Name}}"])
        contexts = tuple(
            line.strip() for line in (listed.stdout or "").splitlines()
            if line.strip()
        ) if listed.returncode == 0 else ()

        host_override = bool(os.environ.get("DOCKER_HOST"))
        raw_endpoint = os.environ.get("DOCKER_HOST", "")
        if not raw_endpoint:
            inspected = _run_docker([
                "context", "inspect", name,
                "--format", "{{json .Endpoints.docker.Host}}",
            ])
            if inspected.returncode == 0:
                raw_endpoint = (inspected.stdout or "").strip()
                try:
                    decoded = json.loads(raw_endpoint)
                    if isinstance(decoded, str):
                        raw_endpoint = decoded
                except json.JSONDecodeError:
                    raw_endpoint = raw_endpoint.strip('"')

        return DockerContextInfo(
            name=name,
            endpoint=safe_endpoint(raw_endpoint),
            contexts=contexts,
            docker_host_override=host_override,
        )
    except (OSError, subprocess.TimeoutExpired):
        return DockerContextInfo(error="could not inspect Docker context")


def docker_info() -> DockerInfo | None:
    """Read server facts from the daemon selected by the Docker CLI."""
    if not shutil.which("docker"):
        return None
    try:
        proc = _run_docker(["info", "--format", "{{json .}}"])
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None
    runtimes = data.get("Runtimes") or {}
    runtime_names = tuple(str(k) for k in runtimes) if isinstance(runtimes, dict) else ()
    security = data.get("SecurityOptions") or []
    security_text = " ".join(str(item) for item in security).lower()
    return DockerInfo(
        server_version=str(data.get("ServerVersion") or ""),
        operating_system=str(data.get("OperatingSystem") or ""),
        architecture=_normalise_arch(str(data.get("Architecture") or "")),
        default_runtime=str(data.get("DefaultRuntime") or ""),
        runtimes=runtime_names,
        rootless="rootless" in security_text,
    )


def docker_version() -> tuple[str, str]:
    """Return (client, server) versions, or empty strings when unavailable."""
    if not shutil.which("docker"):
        return "", ""
    try:
        proc = _run_docker(["version", "--format", "{{json .}}"])
    except (OSError, subprocess.TimeoutExpired):
        return "", ""
    if proc.returncode != 0:
        return "", ""
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return "", ""
    client = data.get("Client") or {}
    server = data.get("Server") or {}
    return str(client.get("Version") or ""), str(server.get("Version") or "")


def runsc_info() -> tuple[str, str]:
    """Return (path, version) for local runsc, not daemon registration."""
    path = shutil.which("runsc")
    if not path:
        return "", ""
    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return path, "could not run runsc --version"
    if proc.returncode != 0:
        return path, "could not run runsc --version"
    first = (proc.stdout or proc.stderr or "").strip().splitlines()
    return path, (first[0][:120] if first else "version unavailable")


def image_inspect(image: str) -> ImageInfo | None:
    """Inspect an image on the selected daemon; never inspect a local file."""
    if not shutil.which("docker") or not image:
        return None
    try:
        proc = _run_docker(["image", "inspect", image, "--format", "{{json .}}"])
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None
    config = data.get("Config") or {}
    entrypoint = config.get("Entrypoint") or []
    if isinstance(entrypoint, str):
        entrypoint = [entrypoint]
    repo_digests = data.get("RepoDigests") or []
    labels = config.get("Labels") or {}
    return ImageInfo(
        image_id=str(data.get("Id") or ""),
        architecture=_normalise_arch(str(data.get("Architecture") or "")),
        operating_system=str(data.get("Os") or ""),
        entrypoint=tuple(str(value) for value in entrypoint),
        user=str(config.get("User") or ""),
        repo_digests=tuple(str(value) for value in repo_digests),
        labels={str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {},
    )


def validate_image(
    image: str,
    *,
    expected_version: str | None = None,
    server_architecture: str | None = None,
) -> ImageCheck:
    """Validate the metadata required by the Zone B entrypoint.

    A tag is deliberately a failure here, rather than a warning.  The
    installer resolves the release tag to a registry digest and stores that
    digest in config.toml.  Allowing a mutable tag through this function would
    make the actual toolset depend on whatever a registry serves later.
    """
    info = image_inspect(image)
    if info is None:
        return ImageCheck(
            "FAIL",
            f"image is not present on the selected Docker daemon: {image}; "
            "pull the documented release image and retry",
        )
    if not info.operating_system:
        return ImageCheck("FAIL", "image OS metadata is missing", info)
    if info.operating_system.lower() != "linux":
        return ImageCheck("FAIL", f"image OS is {info.operating_system}, not Linux", info)
    if info.entrypoint != SANDBOX_ENTRYPOINT:
        return ImageCheck(
            "FAIL",
            "image entrypoint is not /entrypoint.sh; this is not a compatible "
            "Kryonsec sandbox image",
            info,
        )
    if not info.architecture:
        return ImageCheck("FAIL", "image architecture metadata is missing", info)
    if server_architecture and info.architecture:
        expected_arch = _normalise_arch(server_architecture)
        if info.architecture != expected_arch:
            return ImageCheck(
                "FAIL",
                f"image architecture {info.architecture} does not match the "
                f"selected Docker daemon architecture {expected_arch}",
                info,
            )
    labels = info.labels or {}
    image_version = (
        labels.get("org.kryonsec.version")
        or labels.get("org.opencontainers.image.version")
    )
    if expected_version and image_version and (
        _normalise_version(image_version) != _normalise_version(expected_version)
    ):
        return ImageCheck(
            "FAIL",
            f"image version {image_version} does not match Kryonsec {expected_version}",
            info,
        )
    if expected_version and not image_version:
        return ImageCheck(
            "FAIL",
            "image has no Kryonsec release-version label; use the image built "
            "for this Kryonsec release",
            info,
        )
    else:
        version_note = f"image version {image_version}" if image_version else "image metadata valid"

    digest = next((d for d in info.repo_digests if "@sha256:" in d), "")
    if "@sha256:" not in image:
        return ImageCheck(
            "FAIL",
            f"{version_note}; configured ref is a mutable tag; resolved digest "
            f"{digest or info.image_id or 'unavailable'} — configure the digest "
            "before starting Purple Team",
            info,
        )
    requested_digest = image.split("@sha256:", 1)[1].lower()
    if digest and not digest.lower().endswith(requested_digest):
        return ImageCheck(
            "FAIL",
            "configured image digest does not match the digest reported by the "
            "selected Docker daemon",
            info,
        )
    if not info.user or info.user in ("0", "root"):
        return ImageCheck(
            "FAIL",
            "image runs as root; the Kryonsec sandbox must use the non-root "
            "kryonsec-runner user",
            info,
        )
    return ImageCheck("PASS", f"{version_note}; digest-pinned image is compatible", info)


def runtime_smoke_test(image: str) -> tuple[bool, str]:
    """Run the packaged entrypoint with runsc and clean up the test container.

    This is intentionally separate from image inspection.  ``docker info`` can
    list a runtime that is registered but unusable, and an image can have the
    right metadata while a required file is missing.  The command is harmless:
    it has no network, a read-only root, tight limits, and only asks the image's
    entrypoint to run a small Python file-existence check.  Lifecycle calls
    (create/start/rm) get the cold-start-tolerant SMOKE_TIMEOUT_S — a WSL2
    first start of the full image can exceed the fast probe timeout (caught
    genuinely in the Phase 1E.1 pre-flight) — while read-only queries stay
    bounded by PROBE_TIMEOUT_S.
    """
    if not shutil.which("docker"):
        return False, "docker CLI not found"
    name = f"kryonsec-preflight-{uuid.uuid4().hex[:12]}"
    # Resource caps: the memory cap stays deliberately tight (the probe
    # runs one file-existence check), but the pids cap must leave room
    # for runsc's OWN background tasks — the sentry's Go threads, the
    # gofer and the shim all live in the container's cgroup, and at
    # pids=32 bash's fork for the entrypoint's output-wrapping jq was
    # rejected ~15-35% of the time on WSL2 ("fork rejected by pids
    # controller" in the kernel log at every failure; failures were
    # cap-independent across 64m-2g of memory). 64 was clean over 40
    # consecutive runs (25/25 + 15/15). Measured on this combination,
    # not arbitrary; the real engagement runtime keeps its own caps in
    # purple/sandbox.py.
    create_args = [
        "create", "--name", name, "--runtime", "runsc", "--network", "none",
        "--read-only", "--tmpfs", "/tmp:size=16m", "--memory", "64m",
        "--cpus", "0.10", "--pids-limit", "64",
        "--user", "kryonsec-runner", "--entrypoint", "/entrypoint.sh",
        image, "python3", "-c",
        (
            "import os; required = "
            f"{SANDBOX_REQUIRED_FILES!r}; "
            "missing = [p for p in required if not os.path.isfile(p)]; "
            "raise SystemExit('missing: ' + ','.join(missing) if missing else 0)"
        ),
    ]
    created = False
    try:
        proc = _run_docker(create_args, timeout=SMOKE_TIMEOUT_S)
        if proc.returncode != 0:
            return False, _safe_docker_failure(proc)
        created = True
        inspected = _run_docker([
            "inspect", name, "--format", "{{.HostConfig.Runtime}}",
        ])
        if inspected.returncode != 0 or (inspected.stdout or "").strip() != "runsc":
            return False, "Docker did not record runsc as the container runtime"
        started = _run_docker(["start", "--attach", name],
                              timeout=SMOKE_TIMEOUT_S)
        if started.returncode != 0:
            detail = (started.stderr or started.stdout or "").strip()[:300]
            return False, (
                "runsc container was created but the sandbox entrypoint did not "
                f"complete successfully{(': ' + detail) if detail else ''}"
            )
        return True, "sandbox entrypoint and required files ran with runtime runsc"
    except (OSError, subprocess.TimeoutExpired):
        return False, "runtime smoke test timed out or could not start"
    finally:
        if created:
            try:
                _run_docker(["rm", "--force", name], timeout=SMOKE_TIMEOUT_S)
            except (OSError, subprocess.TimeoutExpired):
                pass


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
            return True, f"OK (server {out.stdout.strip() or 'version unavailable'})"
        # A daemon that is up but unreachable to this user is a different
        # problem with a different fix, and it is the one that appears right
        # after installing Docker in a distro: the socket is root-owned, so
        # "daemon not reachable" would send the user to restart a daemon
        # that is running fine. (Docker Desktop's socket is per-user, which
        # is why this does not come up until you leave it.)
        stderr = (out.stderr or "") + (out.stdout or "")
        if "permission denied" in stderr.lower():
            return False, (
                "daemon is running, but this user cannot open its socket — add "
                "yourself to the docker group: sudo usermod -aG docker $USER "
                "(then log out and back in)"
            )
        if "timeout" in stderr.lower() or "timed out" in stderr.lower():
            return False, "Docker daemon request timed out"
        return False, "daemon not reachable"
    except subprocess.TimeoutExpired:
        return False, "Docker daemon request timed out"
    except OSError:
        return False, "Docker CLI could not be started"


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


# Why a Docker Desktop host can fail the gVisor check, and what to do.
#
# Docker Desktop keeps its daemon outside the WSL distro, where nothing run
# inside the distro can add a runtime to it. `runsc install` writes the
# distro's /etc/docker/daemon.json and restarts the distro's daemon — while
# the CLI goes on talking to Docker Desktop's, which has never heard of
# runsc. The install looks successful, `kryonsec doctor` says the runtime is
# missing, and no amount of re-running fixes it, because the thing being
# configured is not the thing being asked. So this needs saying out loud,
# and the fix is a different daemon — not a retry.
#
# A context switch is a user decision, not an installer repair. Docker
# Desktop can select its own context again, and DOCKER_HOST overrides the
# context entirely. Kryonsec reports the selected context and never changes
# it behind the operator's back.
#
# No destructive command is embedded in this hint. If an apt source is
# malformed, the operator must inspect and back it up before deciding how to
# repair it.
DISTRO_DOCKER_FIX = (
    "choose a Docker daemon you administer, install gVisor on that same daemon "
    "host, register runsc, then restart Docker after backing up and validating "
    "its configuration"
)
DOCKER_CONTEXT_CAVEAT = (
    "Docker Desktop re-selects its own context every launch, so this can "
    "come back — turn off WSL integration for this distro (Docker Desktop "
    "> Settings > Resources > WSL Integration), and check `echo $DOCKER_HOST`"
)


def gvisor_fix_hint() -> str:
    """The most accurate fix for a missing runsc runtime, in one line.

    The hint deliberately names the selected daemon and the required manual
    action. The installer does not silently install packages, edit daemon
    configuration, switch contexts, or restart services.
    """
    if docker_desktop_in_use():
        return (
            "runsc runtime not registered — the selected Docker daemon is "
            "Docker Desktop, while the local WSL runsc cannot configure that "
            "external daemon. Select a daemon you administer and install "
            "gVisor on that same host. Kryonsec will not switch contexts or "
            "change Docker Desktop settings automatically. Safe next step: "
            f"{DISTRO_DOCKER_FIX}. {DOCKER_CONTEXT_CAVEAT}"
        )
    return (
        "runsc runtime not registered with the selected daemon — install gVisor "
        "on that daemon host, register runsc there, and restart that Docker "
        "service only after backing up and validating its configuration"
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
