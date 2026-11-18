"""The ``kryonsec doctor --fix`` orchestrator.

Safety contract:

* the caller refuses to run as root;
* ``--dry-run`` performs zero writes and executes no repair action — the
  read-only detection queries (docker version/inspect, runsc --version) still
  run, because they are how the plan knows what to offer;
* automatic actions are local, unprivileged, and reversible;
* approved subprocesses are limited to a digest-pinned ``docker pull``, or
  the explicitly listed registration steps for a validated local build
  (``docker start`` of the already-verified loopback registry,
  ``docker tag``, and ``docker push`` to that loopback address).  Nothing is
  ever deleted or pruned, and no image is relabelled;
* every system-level change is printed as an exact manual action and never
  executed — no package install, service restart, firewall edit, daemon.json
  edit, sudoers change, or Docker context switch;
* configuration is backed up before it is modified, and the repair log is
  redacted with the existing secrets patterns.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..config import KryonsecConfig, config_path
from .detect import SystemSnapshot, detect_system
from .plan import APPROVAL, AUTO, MANUAL, RepairAction, RepairPlan, build_plan
from .progress import RepairReporter, STAGES
from .recovery import REGISTRY_CONTAINER

PULL_TIMEOUT_S = 30 * 60
PUSH_TIMEOUT_S = 30 * 60


class RepairRefused(RuntimeError):
    """The host is not in a state where an automated repair is safe."""


def _backup_config(cfg: KryonsecConfig) -> Path | None:
    """Copy config.toml beside itself, owner-readable, before changing it."""
    path = config_path(cfg.home)
    if not path.is_file():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, backup)
    try:
        backup.chmod(0o600)
    except OSError:
        pass
    return backup


def _validated_digest_reference(reference: str) -> str:
    """Fail closed unless the reference is a real, locally valid digest pin."""
    if "@sha256:" not in reference:
        raise RepairRefused(
            "refused: the sandbox image must be selected by an immutable digest"
        )
    from .. import __version__
    from ..purple import runtime_checks

    info = runtime_checks.docker_info()
    if info is None:
        raise RepairRefused(
            "refused: the selected Docker daemon did not report its architecture"
        )
    check = runtime_checks.validate_image(
        reference,
        expected_version=__version__,
        server_architecture=info.architecture,
    )
    if check.status != "PASS":
        raise RepairRefused(
            f"refused: {check.detail}"
        )
    return reference


def _write_image_reference(cfg: KryonsecConfig, reference: str) -> str:
    """Back up config.toml, persist a validated digest, or restore the old one."""
    reference = _validated_digest_reference(reference)
    old = cfg.sandbox_image
    backup = _backup_config(cfg)
    cfg.sandbox_image = reference
    try:
        cfg.save()
    except Exception:
        cfg.sandbox_image = old
        raise
    note = f"selected {reference}"
    if backup is not None:
        note += f" (backup {backup.name})"
    return note


def _execute_auto(cfg: KryonsecConfig, action: RepairAction) -> str:
    """Run one unprivileged local action and return a verification note."""
    if action.key in {"home", "workspace"}:
        target = Path(action.command[-1])
        target.mkdir(parents=True, exist_ok=True)
        if not target.is_dir():
            raise OSError(f"{target} was not created")
        return f"created {target}"
    if action.key == "config-mode":
        path = config_path(cfg.home)
        if not path.is_file():
            raise OSError(f"{path} disappeared before chmod")
        os.chmod(path, 0o600)
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise OSError(f"chmod left mode {mode:o}")
        return f"{path} is now {mode:o}"
    if action.key in {"pin-digest", "select-compatible-digest"}:
        note = _write_image_reference(cfg, action.new_image)
        if action.key == "pin-digest":
            note = note.replace("selected", "pinned", 1)
        return note
    raise OSError(f"no safe executor for automatic action {action.key!r}")


def _stream_docker_pull(
    command: tuple[str, ...],
    reporter: RepairReporter,
) -> tuple[bool, str]:
    """Run the approved pull, streaming Docker's real output as it arrives."""
    if not command or command[0] != "docker":
        return False, "refused: only `docker pull` may be executed"
    if not any(part.startswith("sha256:") or "@sha256:" in part for part in command):
        return False, "refused: the image reference is not digest-pinned"
    try:
        process = subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        return False, f"could not start docker: {exc}"
    last = ""
    try:
        assert process.stdout is not None
        for line in process.stdout:
            value = line.rstrip()
            if value:
                last = value
                reporter.line(value, verbose_only=False)
        code = process.wait(timeout=PULL_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return False, f"docker pull exceeded {PULL_TIMEOUT_S}s"
    if code != 0:
        return False, f"docker pull exited {code}" + (f": {last}" if last else "")
    return True, last or "pull completed"


def _loopback_registry_host(reference: str) -> str:
    """The host part of a local-registry reference, or a refusal."""
    value = str(reference or "")
    host = ""
    if value.startswith("["):
        end = value.find("]")
        host = value[1:end] if end > 0 else ""
    elif "/" in value:
        first = value.split("/", 1)[0]
        host = first.rsplit(":", 1)[0] if ":" in first else first
    if host not in {"127.0.0.1", "::1"}:
        raise RepairRefused(
            f"refused: registry reference {value!r} is not loopback-bound"
        )
    return host


def _registration_step_ok(
    command: tuple[str, ...], action: RepairAction
) -> bool:
    """Only the exact additive commands the planner approved may run."""
    if len(command) < 2 or command[0] != "docker":
        return False
    if command[1] == "start":
        return len(command) == 3 and command[2] == REGISTRY_CONTAINER
    if command[1] == "tag":
        return (
            len(command) == 4
            and command[2] == action.local_ref
            and command[3] == action.registry_ref
        )
    if command[1] == "push":
        return len(command) == 3 and command[2] == action.registry_ref
    return False


def _execute_registration(
    cfg: KryonsecConfig,
    action: RepairAction,
    reporter: RepairReporter,
) -> tuple[bool, str]:
    """Run the approved tag/push steps, then pin the digest Docker reports."""
    if not action.steps or not action.registry_ref:
        return False, "refused: registration steps are missing"
    try:
        _loopback_registry_host(action.registry_ref)
        for command in action.steps:
            if not _registration_step_ok(command, action):
                return False, f"refused: unexpected step {command!r}"
            if command[1] in {"tag", "push"}:
                _loopback_registry_host(command[-1])
    except RepairRefused as exc:
        return False, str(exc)

    last = ""
    for command in action.steps:
        try:
            proc = subprocess.run(
                list(command),
                capture_output=True,
                text=True,
                timeout=PUSH_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"{' '.join(command)} failed: {exc}"
        for line in (proc.stdout or "").splitlines():
            if line.strip():
                last = line.strip()
                reporter.line(last, verbose_only=False)
        if proc.returncode != 0:
            error = (proc.stderr or proc.stdout or "").strip()
            return False, (
                f"{' '.join(command)} exited {proc.returncode}"
                + (f": {error.splitlines()[-1]}" if error else "")
            )

    from ..purple import runtime_checks

    info = runtime_checks.image_inspect(action.registry_ref)
    if info is None:
        return False, "registry did not return the pushed image metadata"
    repo = action.registry_ref.rsplit(":", 1)[0]
    digests = [
        value
        for value in info.repo_digests
        if value.startswith(f"{repo}@sha256:")
    ]
    if not digests:
        return False, (
            "the registry did not publish an immutable digest; config is unchanged"
        )
    try:
        note = _write_image_reference(cfg, digests[0])
    except Exception as exc:
        return False, f"registry published {digests[0]} but config was not saved: {exc}"
    return True, f"{note}; registry digest verified by Docker"


def _ask_approval(action: RepairAction, input_fn: Callable[[str], str]) -> bool:
    prompt = (
        f"\nThis will run exactly:\n  {action.exact_action}\n"
        "Nothing is deleted. Type 'yes' to approve, anything else to skip: "
    )
    try:
        answer = input_fn(prompt)
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() == "yes"


def _print_action(reporter: RepairReporter, action: RepairAction, *, dry_run: bool) -> None:
    label = {
        AUTO: "automatic",
        APPROVAL: "needs approval",
        MANUAL: "manual",
    }.get(action.kind, action.kind)
    reporter.line(f"{label}: {action.title}")
    if action.kind == MANUAL:
        reporter.line(f"    {action.exact_action}")
    elif action.kind == APPROVAL:
        reporter.line(f"    {action.exact_action}")
    if action.detail:
        # A mismatch explanation is the point of the repair; never hide it
        # behind --verbose.
        recovery = {
            "select-compatible-digest",
            "register-local-image",
            "image-incompatible",
            "image-env-override",
        }
        reporter.line(
            f"    {action.detail}",
            verbose_only=action.key not in recovery,
        )
    if dry_run and action.kind == AUTO:
        reporter.line("    dry run: not executed", verbose_only=True)


def _system_stage(reporter: RepairReporter, snapshot: SystemSnapshot, plan: RepairPlan, stage: str, *, dry_run: bool) -> None:
    for action in plan.for_stage(stage):
        _print_action(reporter, action, dry_run=dry_run)


def run_fix(
    cfg: KryonsecConfig,
    *,
    dry_run: bool = False,
    verbose: bool = False,
    quiet: bool = False,
    input_fn: Callable[[str], str] = input,
) -> int:
    """Plan, optionally execute, and verify repairs; return doctor's verdict."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(
            "error: do not run `kryonsec doctor --fix` as root. "
            "Run it as the user who owns the Kryonsec installation.",
            file=sys.stderr,
        )
        return 2
    if dry_run:
        # A dry run may report on a home that does not exist yet; creating a
        # log directory would itself be a write.
        log_enabled = cfg.home.is_dir()
    else:
        log_enabled = True

    snapshot = detect_system(cfg)
    plan = build_plan(cfg, snapshot)
    executions: list[str] = []

    with RepairReporter(
        home=cfg.home,
        verbose=verbose,
        quiet=quiet,
        log_enabled=log_enabled,
    ) as reporter:
        # 1. CHECKING SYSTEM ------------------------------------------------
        with reporter.stage("CHECKING SYSTEM"):
            reporter.line(f"platform: {snapshot.platform}")
            reporter.line(
                f"distribution: {snapshot.release.display}"
                + (f" (family {snapshot.release.supported_family})" if snapshot.release.supported_family else " (unsupported)")
            )
            reporter.line(f"package manager: {snapshot.package_manager or 'not detected'}")
            reporter.line(
                f"disk: {snapshot.disk.free_gb:.1f} GiB free of "
                f"{snapshot.disk.total_gb:.1f} GiB at {snapshot.disk.path}"
            )
            if not snapshot.supported and snapshot.is_linux:
                reporter.line(
                    "Purple Team repair guidance is unavailable for this distribution.",
                    error=True,
                )
            _system_stage(reporter, snapshot, plan, "CHECKING SYSTEM", dry_run=dry_run)

        # 2. CONFIGURING PYTHON --------------------------------------------
        with reporter.stage("CONFIGURING PYTHON"):
            reporter.line(f"python: {snapshot.python_version} ({snapshot.python_executable})")
            reporter.line(
                f"virtual environment: {snapshot.venv_path or ('active' if snapshot.in_venv else 'not detected')}"
            )
            _system_stage(reporter, snapshot, plan, "CONFIGURING PYTHON", dry_run=dry_run)

        # 3. INSTALLING KRYONSEC -------------------------------------------
        with reporter.stage("INSTALLING KRYONSEC"):
            reporter.line(f"kryonsec: {snapshot.kryonsec_version}")
            reporter.line(f"home: {snapshot.home}")
            reporter.line(f"config: {snapshot.config_file} ({'present' if snapshot.config_exists else 'missing'})")
            for action in plan.for_stage("INSTALLING KRYONSEC"):
                _print_action(reporter, action, dry_run=dry_run)
                if action.kind != AUTO or dry_run:
                    continue
                try:
                    note = _execute_auto(cfg, action)
                except Exception as exc:
                    reporter.line(
                        f"automatic repair failed: {action.title}: {type(exc).__name__}: {exc}",
                        error=True,
                    )
                else:
                    reporter.line(f"done: {note}")
                    executions.append(f"{action.key}: {note}")

        # 4. CHECKING DOCKER -----------------------------------------------
        with reporter.stage("CHECKING DOCKER"):
            docker = snapshot.docker
            reporter.line(f"docker CLI: {docker.cli or 'not found'}")
            reporter.line(f"daemon: {docker.server_detail}")
            if docker.context_name:
                reporter.line(
                    f"context: {docker.context_name} ({docker.context_endpoint})"
                )
            if docker.architecture:
                reporter.line(
                    f"server: {docker.server_version} / {docker.architecture} / "
                    f"default runtime {docker.default_runtime or 'unknown'}"
                )
            _system_stage(reporter, snapshot, plan, "CHECKING DOCKER", dry_run=dry_run)

        # 5. CONFIGURING GVISOR --------------------------------------------
        with reporter.stage("CONFIGURING GVISOR"):
            reporter.line(
                f"runsc: {snapshot.gvisor.version or 'not installed'}"
                + (f" at {snapshot.gvisor.binary}" if snapshot.gvisor.binary else "")
            )
            reporter.line(
                "registered with selected daemon: "
                + ("yes" if snapshot.gvisor.registered else "no")
            )
            _system_stage(reporter, snapshot, plan, "CONFIGURING GVISOR", dry_run=dry_run)

        # 6. DOWNLOADING SANDBOX -------------------------------------------
        with reporter.stage("DOWNLOADING SANDBOX"):
            image = snapshot.image
            reporter.line(f"configured image: {image.reference}")
            reporter.line(f"source: {image.source or 'unknown'}")
            reporter.line(f"present locally: {'yes' if image.present else 'no'}")
            if image.version:
                reporter.line(f"image version: {image.version}")
            if image.validation_status == "FAIL":
                reporter.line(f"validation: {image.validation_detail}", error=True)
                best = image.best_candidate
                if best is not None:
                    digest_note = (
                        best.digest_reference
                        if best.digest_reference
                        else "no registry digest yet"
                    )
                    reporter.line(
                        f"compatible local candidate: {best.reference} "
                        f"(version {best.version}, {best.architecture}/{best.operating_system}, "
                        f"{digest_note})"
                    )
                else:
                    reporter.line("compatible local candidate: none found")
                if image.registry is not None and image.registry.present:
                    state = "running" if image.registry.running else "stopped"
                    binding = image.registry.address or "no loopback binding"
                    reporter.line(
                        f"developer registry: {image.registry.container} "
                        f"({state}, {binding})"
                    )
            for action in plan.for_stage("DOWNLOADING SANDBOX"):
                _print_action(reporter, action, dry_run=dry_run)
                if action.kind != APPROVAL or dry_run:
                    continue
                if not _ask_approval(action, input_fn):
                    reporter.line(
                        "skipped: no approval (the exact command is printed above "
                        "and in the READY summary)"
                    )
                    continue
                if action.key == "register-local-image":
                    ok, detail = _execute_registration(cfg, action, reporter)
                    if ok:
                        reporter.line(f"done: {detail}")
                        executions.append(f"{action.key}: {detail}")
                    else:
                        reporter.line(f"registration failed: {detail}", error=True)
                    continue
                ok, detail = _stream_docker_pull(action.command, reporter)
                if ok:
                    reporter.line(f"done: {detail}")
                    executions.append(f"{action.key}: {detail}")
                else:
                    reporter.line(f"pull failed: {detail}", error=True)

        # 7. VERIFYING SANDBOX ---------------------------------------------
        with reporter.stage("VERIFYING SANDBOX"):
            for action in plan.for_stage("VERIFYING SANDBOX"):
                _print_action(reporter, action, dry_run=dry_run)
                if action.kind != AUTO or dry_run:
                    continue
                try:
                    note = _execute_auto(cfg, action)
                except Exception as exc:
                    reporter.line(
                        f"automatic repair failed: {action.title}: "
                        f"{type(exc).__name__}: {exc}",
                        error=True,
                    )
                else:
                    reporter.line(f"done: {note}")
                    executions.append(f"{action.key}: {note}")
            after = detect_system(cfg)
            if after.image.present:
                reporter.line(
                    f"image verification: {after.image.validation_status} — "
                    f"{after.image.validation_detail}"
                )
            else:
                reporter.line("image verification: image is not present", error=True)

        # 8. CHECKING FIREWALL ---------------------------------------------
        with reporter.stage("CHECKING FIREWALL"):
            if snapshot.firewall_ok is None:
                reporter.line("firewall: not checked on this platform")
            else:
                reporter.line(
                    "firewall: " + ("ready" if snapshot.firewall_ok else "not ready")
                    + f" — {snapshot.firewall_detail}"
                )
            _system_stage(reporter, snapshot, plan, "CHECKING FIREWALL", dry_run=dry_run)

        # 9. FINAL VALIDATION ----------------------------------------------
        with reporter.stage("FINAL VALIDATION"):
            from ..doctor import run_doctor

            if quiet:
                # Keep the real doctor checks, but do not dump its full table
                # over the quiet stage output.
                import io

                from rich.console import Console

                from .. import doctor as doctor_module

                original = doctor_module.console
                doctor_module.console = Console(file=io.StringIO(), width=100)
                try:
                    verdict = run_doctor(cfg)
                finally:
                    doctor_module.console = original
            else:
                verdict = run_doctor(cfg)

        # 10. READY --------------------------------------------------------
        with reporter.stage("READY"):
            reporter.summary(f"  automatic actions applied: {len(executions)}")
            if executions:
                for note in executions:
                    reporter.summary(f"    {note}")
            if plan.manual:
                reporter.summary(f"  manual actions still required: {len(plan.manual)}")
                for action in plan.manual:
                    reporter.summary(f"    {action.title}")
                    reporter.summary(f"      {action.exact_action}")
            reporter.summary(
                "  doctor exit status: "
                + ("ready" if verdict == 0 else "needs attention")
            )
            if reporter.log_path is not None:
                reporter.summary(f"  log: {reporter.log_path}")
            elif dry_run:
                reporter.summary("  log: not written during a dry run")
    return verdict


__all__ = ["RepairRefused", "run_fix"]
