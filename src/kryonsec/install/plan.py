"""Deterministic repair planning for ``kryonsec doctor --fix``.

The planner is pure: it reads a :class:`SystemSnapshot` and returns actions.
It never executes anything.  Three severities are deliberate:

``auto``
    unprivileged, local, reversible: create Kryonsec's own directories,
    tighten config permissions, pin an already-present image to its verified
    digest (with a config backup).

``approval``
    unprivileged but network/disk-affecting: pull an immutable image that is
    missing.  The exact command is shown and a fresh "yes" is required.

``manual``
    anything system-level: package installation, Docker service changes,
    docker-group membership, gVisor registration, daemon.json edits,
    firewall rules, sudoers.  Kryonsec prints the exact action and never runs
    it, so a repair cannot silently widen the host.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..config import KryonsecConfig
from .detect import SystemSnapshot

AUTO = "auto"
APPROVAL = "approval"
MANUAL = "manual"


@dataclass(frozen=True)
class RepairAction:
    stage: str
    key: str
    title: str
    kind: str
    detail: str = ""
    command: tuple[str, ...] = ()
    shell_hint: str = ""
    new_image: str = ""

    @property
    def executes(self) -> bool:
        return self.kind in (AUTO, APPROVAL) and bool(self.command)

    @property
    def exact_action(self) -> str:
        if self.shell_hint:
            return self.shell_hint
        if self.command:
            return " ".join(_quote(part) for part in self.command)
        return self.title


def _quote(value: str) -> str:
    if not value or any(ch.isspace() for ch in value):
        return repr(value)
    return value


@dataclass
class RepairPlan:
    actions: list[RepairAction] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, action: RepairAction) -> None:
        self.actions.append(action)

    def for_stage(self, stage: str) -> list[RepairAction]:
        return [action for action in self.actions if action.stage == stage]

    @property
    def automatic(self) -> list[RepairAction]:
        return [action for action in self.actions if action.kind == AUTO]

    @property
    def approvals(self) -> list[RepairAction]:
        return [action for action in self.actions if action.kind == APPROVAL]

    @property
    def manual(self) -> list[RepairAction]:
        return [action for action in self.actions if action.kind == MANUAL]


def _manual(stage: str, key: str, title: str, detail: str, *, shell: str = "") -> RepairAction:
    return RepairAction(stage, key, title, MANUAL, detail, shell_hint=shell)


def _docker_manual(snapshot: SystemSnapshot) -> list[RepairAction]:
    actions: list[RepairAction] = []
    docker = snapshot.docker
    if not docker.cli:
        if snapshot.release.supported_family == "debian":
            shell = "sudo apt-get update && sudo apt-get install -y docker.io"
        elif snapshot.release.supported_family == "arch":
            shell = "sudo pacman -S --needed docker docker-compose"
        else:
            shell = "install Docker Engine from https://docs.docker.com/engine/install/"
        actions.append(
            _manual(
                "CHECKING DOCKER",
                "install-docker",
                "Docker CLI is not installed",
                "Kryonsec will not install or start Docker for you. Review the "
                "package command, run it yourself, then start the daemon.",
                shell=shell,
            )
        )
        return actions
    if not docker.server_ok:
        detail = docker.server_detail
        if "permission denied" in detail.lower() or "cannot open its socket" in detail.lower():
            actions.append(
                _manual(
                    "CHECKING DOCKER",
                    "docker-group",
                    "This user cannot open the Docker socket",
                    "Add the user to the docker group, then log out and back "
                    "in so the new group membership applies. Kryonsec never "
                    "adds sudoers entries or changes group membership itself.",
                    shell="sudo usermod -aG docker $USER",
                )
            )
        else:
            actions.append(
                _manual(
                    "CHECKING DOCKER",
                    "start-docker",
                    "Docker daemon is not reachable",
                    "Start or repair the selected daemon yourself. Kryonsec "
                    "never restarts services or changes the Docker context.",
                    shell="sudo systemctl status docker",
                )
            )
    if docker.docker_host_override:
        actions.append(
            _manual(
                "CHECKING DOCKER",
                "docker-host",
                "DOCKER_HOST overrides the selected Docker context",
                "Unset DOCKER_HOST only if it is not the daemon you intend to "
                "use; Kryonsec will not switch contexts for you.",
                shell="unset DOCKER_HOST",
            )
        )
    return actions


def _gvisor_manual(snapshot: SystemSnapshot) -> list[RepairAction]:
    if not snapshot.is_linux:
        return [
            _manual(
                "CONFIGURING GVISOR",
                "gvisor-platform",
                "gVisor is only available on Linux",
                "Use WSL2 with a native Docker Engine or a Linux VM. Purple "
                "Team never falls back to runc.",
            )
        ]
    actions: list[RepairAction] = []
    if not snapshot.gvisor.binary:
        actions.append(
            _manual(
                "CONFIGURING GVISOR",
                "install-gvisor",
                "The runsc binary is not installed",
                "Install gVisor on the host that runs the selected Docker "
                "daemon. Kryonsec does not run a remote install script.",
                shell="https://gvisor.dev/docs/user_guide/install/",
            )
        )
    if snapshot.docker.server_ok and not snapshot.gvisor.registered:
        actions.append(
            _manual(
                "CONFIGURING GVISOR",
                "register-runsc",
                "runsc is not registered with the selected Docker daemon",
                "Back up /etc/docker/daemon.json, add the runsc runtime, "
                "validate the JSON, then restart Docker yourself. Kryonsec "
                "never edits daemon.json or restarts Docker.",
                shell=(
                    "sudo cp /etc/docker/daemon.json "
                    "/etc/docker/daemon.json.bak  # then add the runsc runtime"
                ),
            )
        )
    return actions


def _sandbox_actions(cfg: KryonsecConfig, snapshot: SystemSnapshot) -> list[RepairAction]:
    actions: list[RepairAction] = []
    image = snapshot.image
    if not snapshot.docker.server_ok:
        return actions
    if not image.present:
        if "@sha256:" in image.reference:
            actions.append(
                RepairAction(
                    "DOWNLOADING SANDBOX",
                    "pull-image",
                    f"Pull the immutable sandbox image {image.reference}",
                    APPROVAL,
                    "This downloads the release image. It is additive: no "
                    "existing image, container, volume, or cache is deleted.",
                    command=("docker", "pull", image.reference),
                )
            )
        else:
            actions.append(
                _manual(
                    "DOWNLOADING SANDBOX",
                    "pull-mutable-tag",
                    "The configured sandbox image is missing and uses a mutable tag",
                    "Install the release-matched, digest-pinned image with "
                    "`bash install.sh --profile=purple` (or the release "
                    "instructions). Kryonsec will not pull a `latest` or "
                    "other mutable tag as a fallback.",
                    shell="bash install.sh --profile=purple",
                )
            )
        return actions

    # The image is present.  A tag is not an identity: pin the digest the
    # daemon reported, with a config backup, so a later pull cannot change
    # what Purple Team executes.
    if "@sha256:" not in image.reference and image.digest and snapshot.config_exists:
        actions.append(
            RepairAction(
                "VERIFYING SANDBOX",
                "pin-digest",
                "Pin the present sandbox image to its verified digest",
                AUTO,
                f"{image.reference} -> {image.digest} (config backup kept)",
                command=(),
                new_image=image.digest,
            )
        )
    # A mutable tag is the one failure pinning can fix.  Anything else
    # (version, architecture, entrypoint, root user, missing metadata) is a
    # different image and needs an operator decision — never an automatic
    # delete or replacement.
    if image.validation_status == "FAIL" and "mutable tag" not in image.validation_detail:
        actions.append(
            _manual(
                "VERIFYING SANDBOX",
                "image-incompatible",
                "The sandbox image failed verification",
                image.validation_detail
                + " Kryonsec will not delete or replace the image.",
                shell="bash install.sh --profile=purple",
            )
        )
    return actions


def build_plan(cfg: KryonsecConfig, snapshot: SystemSnapshot) -> RepairPlan:
    """Turn a snapshot into an ordered, stage-tagged repair plan."""
    plan = RepairPlan()

    # CHECKING SYSTEM -----------------------------------------------------
    if not snapshot.is_linux:
        plan.add(
            _manual(
                "CHECKING SYSTEM",
                "platform",
                "Purple Team is Linux-only",
                "Copilot repairs can continue; Docker, gVisor, and the sandbox "
                "are skipped on this host.",
            )
        )
    elif not snapshot.release.supported_family:
        plan.add(
            _manual(
                "CHECKING SYSTEM",
                "distro",
                f"Unsupported distribution: {snapshot.release.display}",
                "Automatic package guidance is limited to Debian/Ubuntu and "
                "Arch/Omarchy. Follow the distribution's own Docker and gVisor "
                "instructions; Kryonsec will not guess package names.",
            )
        )
    if snapshot.disk.free_gb and not snapshot.disk.enough:
        plan.add(
            _manual(
                "CHECKING SYSTEM",
                "disk",
                f"Low disk space on {snapshot.disk.path}",
                f"{snapshot.disk.free_gb:.1f} GiB free; the sandbox image needs "
                "room. Free space yourself — Kryonsec never runs a broad "
                "image/cache prune or deletes evidence.",
            )
        )

    # CONFIGURING PYTHON --------------------------------------------------
    if tuple(int(part) for part in snapshot.python_version.split(".")[:2]) < (3, 11):
        plan.add(
            _manual(
                "CONFIGURING PYTHON",
                "python-version",
                f"Python {snapshot.python_version} is too old",
                "Kryonsec needs Python 3.11 or newer. Install it with the "
                "distribution package manager, then reinstall Kryonsec.",
                shell="python3 --version",
            )
        )
    if not snapshot.in_venv and not snapshot.venv_path:
        plan.add(
            _manual(
                "CONFIGURING PYTHON",
                "venv",
                "No Kryonsec virtual environment detected",
                "Create the installer-owned environment, then install the "
                "release into it. Kryonsec will not pip-install packages into "
                "a system Python.",
                shell=f"{snapshot.python_executable} -m venv {cfg.home / 'venv'}",
            )
        )

    # INSTALLING KRYONSEC -------------------------------------------------
    if not Path(snapshot.home).is_dir():
        plan.add(
            RepairAction(
                "INSTALLING KRYONSEC",
                "home",
                f"Create {snapshot.home}",
                AUTO,
                "Kryonsec's own configuration, session, and log directory.",
                command=("mkdir", "-p", snapshot.home),
            )
        )
    if not Path(snapshot.workspace).is_dir():
        plan.add(
            RepairAction(
                "INSTALLING KRYONSEC",
                "workspace",
                f"Create {snapshot.workspace}",
                AUTO,
                "The default workspace for file tools.",
                command=("mkdir", "-p", snapshot.workspace),
            )
        )
    if not snapshot.config_exists:
        plan.add(
            _manual(
                "INSTALLING KRYONSEC",
                "config",
                "No config.toml yet",
                "Run the setup wizard to choose a provider and write "
                "config.toml. Kryonsec will not guess an LLM provider or key.",
                shell="kryonsec setup",
            )
        )
    elif snapshot.config_mode & 0o077:
        plan.add(
            RepairAction(
                "INSTALLING KRYONSEC",
                "config-mode",
                f"Restrict {snapshot.config_file} to the owner",
                AUTO,
                f"Current mode {snapshot.config_mode:o}; config.toml can contain API keys.",
                command=("chmod", "600", snapshot.config_file),
            )
        )

    # CHECKING DOCKER -----------------------------------------------------
    if snapshot.is_linux:
        plan.actions.extend(_docker_manual(snapshot))

    # CONFIGURING GVISOR --------------------------------------------------
    if snapshot.is_linux:
        plan.actions.extend(_gvisor_manual(snapshot))

    # DOWNLOADING SANDBOX / VERIFYING SANDBOX -----------------------------
    if snapshot.is_linux:
        plan.actions.extend(_sandbox_actions(cfg, snapshot))

    # CHECKING FIREWALL ---------------------------------------------------
    if snapshot.is_linux and snapshot.docker.server_ok:
        if snapshot.firewall_ok is False:
            plan.add(
                _manual(
                    "CHECKING FIREWALL",
                    "egress",
                    "The Zone B egress firewall is not ready",
                    snapshot.firewall_detail
                    + " Kryonsec never changes firewall rules for you; the "
                    "runner programs the per-engagement boundary itself.",
                    shell="sudo iptables -S DOCKER-USER",
                )
            )

    return plan


def command_available(command: tuple[str, ...]) -> bool:
    """True when the executable named by a plan command exists on PATH."""
    return bool(command) and shutil.which(command[0]) is not None


__all__ = [
    "APPROVAL",
    "AUTO",
    "MANUAL",
    "RepairAction",
    "RepairPlan",
    "build_plan",
    "command_available",
]
