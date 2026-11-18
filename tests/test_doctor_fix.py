"""Repair planning and the safe parts of ``doctor --fix``.

These tests never install a package, start Docker, pull an image, change a
firewall, or touch the real user's home.  The system snapshot is constructed
by hand and every executor boundary is mocked.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.install import detect as detect_module
from kryonsec.install import fix as fix_module
from kryonsec.install.detect import (
    DiskSnapshot,
    DockerSnapshot,
    GvisorSnapshot,
    ImageSnapshot,
    OsRelease,
    SystemSnapshot,
)
from kryonsec.install.plan import APPROVAL, AUTO, MANUAL, build_plan
from kryonsec.install.progress import STAGES


def _snapshot(
    cfg: KryonsecConfig,
    *,
    release: OsRelease | None = None,
    docker: DockerSnapshot | None = None,
    gvisor: GvisorSnapshot | None = None,
    image: ImageSnapshot | None = None,
    firewall_ok: bool | None = True,
    config_exists: bool | None = None,
    config_mode: int = 0o600,
) -> SystemSnapshot:
    config = Path(cfg.home) / "config.toml"
    return SystemSnapshot(
        platform="linux",
        is_linux=True,
        release=release or OsRelease(id="arch", like=("arch",), name="Arch Linux"),
        package_manager="pacman",
        python_version="3.12.0",
        python_executable="/usr/bin/python3",
        in_venv=True,
        venv_path="/home/user/.kryonsec/venv",
        home=str(cfg.home),
        config_file=str(config),
        config_exists=config.is_file() if config_exists is None else config_exists,
        config_mode=config_mode,
        workspace=str(cfg.workspace),
        kryonsec_version="1.3.11",
        docker=docker
        or DockerSnapshot(
            cli="/usr/bin/docker",
            server_ok=True,
            server_detail="OK",
            context_name="default",
            context_endpoint="unix:///var/run/docker.sock",
            contexts=("default",),
            server_version="29.9.2",
            architecture="amd64",
            default_runtime="runsc",
        ),
        gvisor=gvisor
        or GvisorSnapshot(binary="/usr/local/bin/runsc", version="release-1", registered=True),
        image=image or ImageSnapshot(
            reference="kryonsec/sandbox@sha256:" + "a" * 64,
            present=True,
            architecture="amd64",
            operating_system="linux",
            entrypoint=("/entrypoint.sh",),
            user="kryonsec-runner",
            repo_digests=("kryonsec/sandbox@sha256:" + "a" * 64,),
            validation_status="PASS",
            validation_detail="compatible",
        ),
        firewall_ok=firewall_ok,
        firewall_detail="ready",
        disk=DiskSnapshot(path=str(cfg.home), free_gb=100.0, total_gb=500.0),
    )


@pytest.fixture()
def cfg(tmp_path: Path) -> KryonsecConfig:
    return KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")


def test_the_ten_stages_are_exact_and_ordered():
    assert STAGES == (
        "CHECKING SYSTEM",
        "CONFIGURING PYTHON",
        "INSTALLING KRYONSEC",
        "CHECKING DOCKER",
        "CONFIGURING GVISOR",
        "DOWNLOADING SANDBOX",
        "VERIFYING SANDBOX",
        "CHECKING FIREWALL",
        "FINAL VALIDATION",
        "READY",
    )


def test_omarchy_is_recognised_as_arch_family():
    release = OsRelease(id="omarchy", like=("arch",), name="Omarchy")
    assert release.supported_family == "arch"


def test_unsupported_distro_is_reported_not_guessed(cfg):
    plan = build_plan(
        cfg,
        _snapshot(cfg, release=OsRelease(id="gentoo", name="Gentoo")),
    )
    distro = [action for action in plan.actions if action.key == "distro"]
    assert distro and distro[0].kind == MANUAL
    assert "Unsupported distribution" in distro[0].title


def test_fresh_home_gets_local_directory_repairs(cfg):
    plan = build_plan(cfg, _snapshot(cfg, config_exists=False))
    keys = {action.key: action for action in plan.actions}
    assert keys["home"].kind == AUTO
    assert keys["workspace"].kind == AUTO
    assert keys["home"].command == ("mkdir", "-p", str(cfg.home))
    assert keys["config"].kind == MANUAL  # the wizard chooses a provider


def test_loose_config_permissions_are_an_automatic_repair(cfg, tmp_path):
    cfg.home.mkdir(parents=True)
    (cfg.home / "config.toml").write_text("provider = 'ollama'\n", encoding="utf-8")
    plan = build_plan(cfg, _snapshot(cfg, config_mode=0o644))
    action = next(action for action in plan.actions if action.key == "config-mode")
    assert action.kind == AUTO
    assert action.command == ("chmod", "600", str(cfg.home / "config.toml"))


def test_docker_group_problem_is_manual_and_never_sudoers(cfg):
    docker = DockerSnapshot(
        cli="/usr/bin/docker",
        server_ok=False,
        server_detail="daemon is running, but this user cannot open its socket",
    )
    plan = build_plan(cfg, _snapshot(cfg, docker=docker))
    action = next(action for action in plan.actions if action.key == "docker-group")
    assert action.kind == MANUAL
    assert "usermod -aG docker" in action.exact_action
    assert "sudoers" not in action.exact_action.lower()


def test_gvisor_registration_is_manual_and_backs_up_daemon_json(cfg):
    gvisor = GvisorSnapshot(binary="/usr/local/bin/runsc", version="release-1", registered=False)
    plan = build_plan(cfg, _snapshot(cfg, gvisor=gvisor))
    action = next(action for action in plan.actions if action.key == "register-runsc")
    assert action.kind == MANUAL
    assert "daemon.json.bak" in action.exact_action
    assert "restart" in action.detail.lower()


def test_firewall_change_is_never_automatic(cfg):
    plan = build_plan(cfg, _snapshot(cfg, firewall_ok=False))
    action = next(action for action in plan.actions if action.key == "egress")
    assert action.kind == MANUAL
    assert "iptables -S DOCKER-USER" in action.exact_action


def test_missing_digest_image_is_an_approval_with_an_immutable_command(cfg):
    image = ImageSnapshot(reference="kryonsec/sandbox@sha256:" + "b" * 64, present=False)
    plan = build_plan(cfg, _snapshot(cfg, image=image))
    action = next(action for action in plan.actions if action.key == "pull-image")
    assert action.kind == APPROVAL
    assert action.command == ("docker", "pull", image.reference)
    assert "@sha256:" in action.command[-1]


def test_missing_mutable_tag_is_manual_and_never_falls_back_to_latest(cfg):
    image = ImageSnapshot(reference="kryonsec/sandbox:latest", present=False)
    plan = build_plan(cfg, _snapshot(cfg, image=image))
    action = next(action for action in plan.actions if action.key == "pull-mutable-tag")
    assert action.kind == MANUAL
    assert "digest-pinned" in action.detail
    assert "latest" in action.detail


def test_present_tag_is_pinned_to_the_daemon_digest(cfg):
    cfg.home.mkdir(parents=True)
    (cfg.home / "config.toml").write_text("provider = 'ollama'\n", encoding="utf-8")
    digest = "kryonsec/sandbox@sha256:" + "c" * 64
    image = ImageSnapshot(
        reference="kryonsec/sandbox:ui-1.3.11",
        present=True,
        repo_digests=(digest,),
        architecture="amd64",
        operating_system="linux",
        entrypoint=("/entrypoint.sh",),
        user="kryonsec-runner",
        validation_status="FAIL",
        validation_detail=(
            "image version 1.3.11; configured ref is a mutable tag; resolved "
            f"digest {digest} — configure the digest before starting Purple Team"
        ),
    )
    plan = build_plan(cfg, _snapshot(cfg, image=image))
    action = next(action for action in plan.actions if action.key == "pin-digest")
    assert action.kind == AUTO
    assert action.new_image == digest
    # Pinning fixes the only failure; no contradictory manual action follows.
    assert not [action for action in plan.actions if action.key == "image-incompatible"]


def test_present_tag_is_not_pinned_when_config_does_not_exist(cfg):
    image = ImageSnapshot(
        reference="kryonsec/sandbox:ui-1.3.11",
        present=True,
        repo_digests=("kryonsec/sandbox@sha256:" + "d" * 64,),
        validation_status="PASS",
        validation_detail="compatible",
    )
    plan = build_plan(cfg, _snapshot(cfg, image=image, config_exists=False))
    assert not [action for action in plan.actions if action.key == "pin-digest"]


def test_dry_run_is_stage_complete_and_writes_nothing(cfg, monkeypatch, capsys):
    snapshot = _snapshot(cfg, config_exists=False)
    monkeypatch.setattr(fix_module, "detect_system", lambda _cfg: snapshot)
    monkeypatch.setattr("kryonsec.doctor.run_doctor", lambda _cfg: 0)

    verdict = fix_module.run_fix(cfg, dry_run=True, quiet=True)

    output = capsys.readouterr().out
    for stage in STAGES:
        assert stage in output
    assert "dry run: not executed" not in output  # quiet hides action detail
    assert "automatic actions applied: 0" in output
    assert cfg.home.exists() is False
    assert verdict == 0


def test_fix_creates_the_local_directories(cfg, monkeypatch):
    snapshot = _snapshot(cfg, config_exists=False)
    monkeypatch.setattr(fix_module, "detect_system", lambda _cfg: snapshot)
    monkeypatch.setattr("kryonsec.doctor.run_doctor", lambda _cfg: 0)

    fix_module.run_fix(cfg, quiet=True)

    assert cfg.home.is_dir()
    assert cfg.workspace.is_dir()
    # A log is written for a real run, never in the dry run above.
    logs = list((cfg.home / "logs").glob("doctor-fix-*.log"))
    assert logs
    # Redacted, but still owner-only local state.
    assert logs[0].stat().st_mode & 0o777 == 0o600


def test_fix_tightens_config_permissions(cfg, monkeypatch):
    cfg.home.mkdir(parents=True)
    path = cfg.home / "config.toml"
    path.write_text("provider = 'ollama'\n", encoding="utf-8")
    os.chmod(path, 0o644)
    snapshot = _snapshot(cfg, config_mode=0o644)
    monkeypatch.setattr(fix_module, "detect_system", lambda _cfg: snapshot)
    monkeypatch.setattr("kryonsec.doctor.run_doctor", lambda _cfg: 0)

    fix_module.run_fix(cfg, quiet=True)

    assert path.stat().st_mode & 0o777 == 0o600


def test_fix_pins_a_present_image_and_keeps_a_config_backup(cfg, monkeypatch):
    cfg.home.mkdir(parents=True)
    path = cfg.home / "config.toml"
    path.write_text("provider = 'ollama'\nsandbox_image = 'kryonsec/sandbox:ui-1.3.11'\n", encoding="utf-8")
    digest = "kryonsec/sandbox@sha256:" + "e" * 64
    image = ImageSnapshot(
        reference="kryonsec/sandbox:ui-1.3.11",
        present=True,
        repo_digests=(digest,),
        validation_status="FAIL",
        validation_detail=(
            "image version 1.3.11; configured ref is a mutable tag; resolved "
            f"digest {digest} — configure the digest before starting Purple Team"
        ),
    )
    snapshot = _snapshot(cfg, image=image)
    monkeypatch.setattr(fix_module, "detect_system", lambda _cfg: snapshot)
    monkeypatch.setattr("kryonsec.doctor.run_doctor", lambda _cfg: 0)
    # The digest itself was validated when the plan was built; this test pins
    # through the config writer without a live Docker daemon.
    monkeypatch.setattr(
        fix_module, "_validated_digest_reference", lambda reference: reference
    )
    calls: list[str] = []
    monkeypatch.setattr(
        fix_module,
        "_ask_approval",
        lambda action, input_fn: calls.append(action.key) or False,
    )

    fix_module.run_fix(cfg, quiet=True)

    assert cfg.sandbox_image == digest
    assert calls == []  # pinning is automatic, not an approval prompt
    assert list(cfg.home.glob("config.toml.bak-*"))


def test_fix_skips_a_pull_without_explicit_approval(cfg, monkeypatch, capsys):
    image = ImageSnapshot(reference="kryonsec/sandbox@sha256:" + "f" * 64, present=False)
    snapshot = _snapshot(cfg, image=image)
    monkeypatch.setattr(fix_module, "detect_system", lambda _cfg: snapshot)
    monkeypatch.setattr("kryonsec.doctor.run_doctor", lambda _cfg: 0)
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        return False, "no"

    monkeypatch.setattr(fix_module, "_stream_docker_pull", forbidden)

    fix_module.run_fix(cfg, input_fn=lambda _prompt: "no")

    assert called is False
    assert "skipped: no approval" in capsys.readouterr().out


def test_streaming_pull_refuses_a_mutable_or_non_docker_command():
    class Reporter:
        def line(self, *_args, **_kwargs):
            pass

    ok, detail = fix_module._stream_docker_pull(("bash", "-c", "curl evil"), Reporter())
    assert ok is False and "only `docker pull`" in detail

    ok, detail = fix_module._stream_docker_pull(
        ("docker", "pull", "kryonsec/sandbox:latest"), Reporter()
    )
    assert ok is False and "digest-pinned" in detail


def test_fix_refuses_to_run_as_root(cfg, monkeypatch):
    monkeypatch.setattr(fix_module.os, "geteuid", lambda: 0, raising=False)
    detected = False

    def record(_cfg):
        nonlocal detected
        detected = True
        return _snapshot(cfg)

    monkeypatch.setattr(fix_module, "detect_system", record)
    assert fix_module.run_fix(cfg, dry_run=True) == 2
    assert detected is False


def test_snapshot_detection_is_read_only(cfg, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(detect_module.sys, "platform", "linux")
    monkeypatch.setattr(detect_module, "_read_os_release", lambda: OsRelease(id="arch"))
    monkeypatch.setattr(detect_module, "_package_manager", lambda release: "pacman")
    monkeypatch.setattr(detect_module, "_docker", lambda: DockerSnapshot())
    monkeypatch.setattr(detect_module, "_gvisor", lambda: GvisorSnapshot())
    monkeypatch.setattr(
        detect_module,
        "_image",
        lambda _cfg, _docker: ImageSnapshot(reference=cfg.sandbox_image),
    )
    monkeypatch.setattr(detect_module, "_firewall", lambda: (None, "not checked"))
    monkeypatch.setattr(
        detect_module,
        "_disk",
        lambda _cfg: DiskSnapshot(path=str(cfg.home), free_gb=100, total_gb=500),
    )
    monkeypatch.setattr(
        detect_module,
        "_config_mode",
        lambda path: calls.append(str(path)) or 0,
    )

    snapshot = detect_module.detect_system(cfg)
    assert snapshot.supported is True
    assert cfg.home.exists() is False
    assert calls  # mode was queried, never changed
