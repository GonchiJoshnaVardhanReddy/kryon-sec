"""Read-only system detection for ``kryonsec doctor --fix``.

Everything in this module is a query.  It never creates a directory, installs
a package, starts a service, changes a firewall, or edits configuration.  The
repair engine consumes the snapshot and decides what (if anything) is safe to
offer.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ..config import KryonsecConfig, config_path
from .. import __version__

DEBIAN_IDS = frozenset({"debian", "ubuntu", "linuxmint", "pop", "raspbian"})
ARCH_IDS = frozenset({"arch", "omarchy", "manjaro", "endeavouros", "garuda"})


@dataclass(frozen=True)
class OsRelease:
    id: str = ""
    like: tuple[str, ...] = ()
    name: str = ""
    version: str = ""

    @property
    def supported_family(self) -> str:
        ids = {self.id, *self.like}
        if ids & DEBIAN_IDS:
            return "debian"
        if ids & ARCH_IDS:
            return "arch"
        return ""

    @property
    def display(self) -> str:
        return self.name or self.id or "unknown Linux"


@dataclass(frozen=True)
class DockerSnapshot:
    cli: str = ""
    server_ok: bool = False
    server_detail: str = ""
    context_name: str = ""
    context_endpoint: str = ""
    contexts: tuple[str, ...] = ()
    docker_host_override: bool = False
    server_version: str = ""
    architecture: str = ""
    default_runtime: str = ""


@dataclass(frozen=True)
class GvisorSnapshot:
    binary: str = ""
    version: str = ""
    registered: bool = False


@dataclass(frozen=True)
class ImageSnapshot:
    reference: str = ""
    present: bool = False
    architecture: str = ""
    operating_system: str = ""
    entrypoint: tuple[str, ...] = ()
    user: str = ""
    repo_digests: tuple[str, ...] = ()
    labels: dict[str, str] = field(default_factory=dict)
    validation_status: str = ""
    validation_detail: str = ""

    @property
    def digest(self) -> str:
        return next(
            (value for value in self.repo_digests if "@sha256:" in value), ""
        )


@dataclass(frozen=True)
class DiskSnapshot:
    path: str = ""
    free_gb: float = 0.0
    total_gb: float = 0.0

    @property
    def enough(self) -> bool:
        # The sandbox image is large; 10 GiB leaves room for a pull and the
        # container's writable layer without pretending to know the exact size.
        return self.free_gb >= 10.0


@dataclass(frozen=True)
class SystemSnapshot:
    platform: str
    is_linux: bool
    release: OsRelease
    package_manager: str
    python_version: str
    python_executable: str
    in_venv: bool
    venv_path: str
    home: str
    config_file: str
    config_exists: bool
    config_mode: int
    workspace: str
    kryonsec_version: str
    docker: DockerSnapshot
    gvisor: GvisorSnapshot
    image: ImageSnapshot
    firewall_ok: bool | None
    firewall_detail: str
    disk: DiskSnapshot

    @property
    def supported(self) -> bool:
        return self.is_linux and bool(self.release.supported_family)


def _read_os_release() -> OsRelease:
    path = Path("/etc/os-release")
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    like = tuple(
        part.strip().lower()
        for part in values.get("ID_LIKE", "").split()
        if part.strip()
    )
    return OsRelease(
        id=values.get("ID", "").lower(),
        like=like,
        name=values.get("PRETTY_NAME") or values.get("NAME", ""),
        version=values.get("VERSION_ID", ""),
    )


def _package_manager(release: OsRelease) -> str:
    family = release.supported_family
    candidates = (
        ("apt-get", ("debian",)),
        ("pacman", ("arch",)),
        ("dnf", ()),
        ("zypper", ()),
        ("apk", ()),
    )
    for binary, families in candidates:
        if families and family not in families:
            continue
        if shutil.which(binary):
            return binary
    return ""


def _venv_path(cfg: KryonsecConfig) -> str:
    override = os.environ.get("VIRTUAL_ENV", "")
    if override:
        return override
    candidate = cfg.home / "venv"
    if (candidate / "pyvenv.cfg").is_file():
        return str(candidate)
    return ""


def _config_mode(path: Path) -> int:
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return 0


def _disk(cfg: KryonsecConfig) -> DiskSnapshot:
    """Free space on the volume that will hold Kryonsec's home."""
    probe = cfg.home
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        usage = shutil.disk_usage(probe)
    except OSError:
        return DiskSnapshot(path=str(probe))
    return DiskSnapshot(
        path=str(probe),
        free_gb=round(usage.free / (1024 ** 3), 2),
        total_gb=round(usage.total / (1024 ** 3), 2),
    )


def _docker() -> DockerSnapshot:
    from ..purple import runtime_checks

    cli = shutil.which("docker") or ""
    ok, detail = runtime_checks.docker_server_ok() if cli else (False, "docker CLI not found")
    context = runtime_checks.docker_context_info()
    info = runtime_checks.docker_info() if ok else None
    return DockerSnapshot(
        cli=cli,
        server_ok=ok,
        server_detail=detail,
        context_name=context.name,
        context_endpoint=runtime_checks.safe_endpoint(context.endpoint),
        contexts=context.contexts,
        docker_host_override=context.docker_host_override,
        server_version=info.server_version if info else "",
        architecture=info.architecture if info else "",
        default_runtime=info.default_runtime if info else "",
    )


def _gvisor() -> GvisorSnapshot:
    from ..purple import runtime_checks

    path, version = runtime_checks.runsc_info()
    return GvisorSnapshot(
        binary=path,
        version=version,
        registered=runtime_checks.runsc_registered(),
    )


def _image(cfg: KryonsecConfig, docker: DockerSnapshot) -> ImageSnapshot:
    from ..purple import runtime_checks

    if not docker.server_ok:
        return ImageSnapshot(reference=cfg.sandbox_image)
    present = runtime_checks.image_present(cfg.sandbox_image)
    if not present:
        return ImageSnapshot(reference=cfg.sandbox_image, present=False)
    info = runtime_checks.image_inspect(cfg.sandbox_image)
    check = runtime_checks.validate_image(
        cfg.sandbox_image,
        expected_version=__version__,
        server_architecture=docker.architecture or None,
    )
    if info is None:
        return ImageSnapshot(
            reference=cfg.sandbox_image,
            present=True,
            validation_status=check.status,
            validation_detail=check.detail,
        )
    return ImageSnapshot(
        reference=cfg.sandbox_image,
        present=True,
        architecture=info.architecture,
        operating_system=info.operating_system,
        entrypoint=info.entrypoint,
        user=info.user,
        repo_digests=info.repo_digests,
        labels=dict(info.labels or {}),
        validation_status=check.status,
        validation_detail=check.detail,
    )


def _firewall() -> tuple[bool | None, str]:
    if not sys.platform.startswith("linux"):
        return None, "not checked on this host"
    from ..purple import runtime_checks

    return runtime_checks.egress_firewall_ok()


def detect_system(cfg: KryonsecConfig) -> SystemSnapshot:
    """One read-only snapshot of everything the repair planner needs."""
    release = _read_os_release() if sys.platform.startswith("linux") else OsRelease()
    path = config_path(cfg.home)
    docker = _docker()
    firewall_ok, firewall_detail = _firewall()
    return SystemSnapshot(
        platform=sys.platform,
        is_linux=sys.platform.startswith("linux"),
        release=release,
        package_manager=_package_manager(release),
        python_version=platform.python_version(),
        python_executable=sys.executable,
        in_venv=sys.prefix != getattr(sys, "base_prefix", sys.prefix),
        venv_path=_venv_path(cfg),
        home=str(cfg.home),
        config_file=str(path),
        config_exists=path.is_file(),
        config_mode=_config_mode(path),
        workspace=str(cfg.workspace),
        kryonsec_version=__version__,
        docker=docker,
        gvisor=_gvisor(),
        image=_image(cfg, docker),
        firewall_ok=firewall_ok,
        firewall_detail=firewall_detail,
        disk=_disk(cfg),
    )


__all__ = [
    "ARCH_IDS",
    "DEBIAN_IDS",
    "DiskSnapshot",
    "DockerSnapshot",
    "GvisorSnapshot",
    "ImageSnapshot",
    "OsRelease",
    "SystemSnapshot",
    "detect_system",
]
