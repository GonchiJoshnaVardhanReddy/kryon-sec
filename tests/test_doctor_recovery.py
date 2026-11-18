"""Sandbox-image mismatch diagnosis and recovery.

Every test here is offline.  Docker is replaced by hand-built metadata, so the
suite pins the rules that matter: the real source precedence, the full
metadata contract, loopback-only registry use, immutable digest selection, a
config backup, and fail-closed refusals.  Nothing pulls, tags, pushes, deletes,
or relabels a real image.
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.install import fix as fix_module
from kryonsec.install import recovery
from kryonsec.install.detect import (
    DiskSnapshot,
    DockerSnapshot,
    GvisorSnapshot,
    ImageSnapshot,
    OsRelease,
    SystemSnapshot,
)
from kryonsec.install.plan import APPROVAL, AUTO, MANUAL, build_plan
from kryonsec.purple import runtime_checks
from kryonsec.purple.runtime_checks import ImageCheck, ImageInfo

DIGEST = "kryonsec/sandbox@sha256:" + "a" * 64
LOCAL_DIGEST = "127.0.0.1:5000/kryonsec/sandbox@sha256:" + "b" * 64


def _info(
    *,
    version: str = "1.3.11",
    architecture: str = "amd64",
    operating_system: str = "linux",
    entrypoint: tuple[str, ...] = ("/entrypoint.sh",),
    user: str = "kryonsec-runner",
    digests: tuple[str, ...] = (),
    image_id: str = "sha256:" + "1" * 64,
    created: str = "2026-11-18T00:00:00Z",
) -> ImageInfo:
    return ImageInfo(
        image_id=image_id,
        architecture=architecture,
        operating_system=operating_system,
        entrypoint=entrypoint,
        user=user,
        repo_digests=digests,
        labels={"org.kryonsec.version": version} if version else {},
        created=created,
    )


@pytest.fixture()
def cfg(tmp_path: Path) -> KryonsecConfig:
    return KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")


# ---- source precedence ---------------------------------------------------


def test_image_source_prefers_env_then_config_then_default(cfg, monkeypatch):
    monkeypatch.delenv("KRYONSEC_SANDBOX_IMAGE", raising=False)
    assert recovery.configured_image_source(cfg) == (
        cfg.sandbox_image,
        recovery.SOURCE_DEFAULT,
    )

    cfg.home.mkdir(parents=True)
    (cfg.home / "config.toml").write_text(
        '[sandbox]\nimage = "kryonsec/sandbox:from-config"\n', encoding="utf-8"
    )
    assert recovery.configured_image_source(cfg) == (
        "kryonsec/sandbox:from-config",
        recovery.SOURCE_CONFIG,
    )

    monkeypatch.setenv("KRYONSEC_SANDBOX_IMAGE", "kryonsec/sandbox:from-env")
    assert recovery.configured_image_source(cfg) == (
        "kryonsec/sandbox:from-env",
        recovery.SOURCE_ENV,
    )


# ---- candidate contract --------------------------------------------------


def test_compatible_candidate_requires_every_sandbox_property(monkeypatch):
    monkeypatch.setattr(
        runtime_checks,
        "image_inspect",
        lambda _ref: _info(digests=(DIGEST,)),
    )
    candidate = recovery.inspect_candidate(
        "kryonsec/sandbox:ui-1.3.11",
        expected_version="1.3.11",
        server_architecture="amd64",
    )
    assert candidate.compatible is True
    assert candidate.digest_reference == DIGEST
    assert candidate.needs_registration is False


@pytest.mark.parametrize(
    ("info", "needle"),
    [
        (_info(version="1.3.10"), "does not match Kryonsec 1.3.11"),
        (_info(architecture="arm64"), "architecture arm64"),
        (_info(operating_system="windows"), "not Linux"),
        (_info(entrypoint=("/usr/bin/bash",)), "entrypoint"),
        (_info(user="root"), "runs as root"),
        (_info(version=""), "release-version label"),
        (_info(operating_system=""), "OS metadata"),
    ],
)
def test_candidate_rejects_unsafe_or_wrong_metadata(monkeypatch, info, needle):
    monkeypatch.setattr(runtime_checks, "image_inspect", lambda _ref: info)
    candidate = recovery.inspect_candidate(
        "kryonsec/sandbox:ui-1.3.11",
        expected_version="1.3.11",
        server_architecture="amd64",
    )
    assert candidate.compatible is False
    assert needle in candidate.reason


def test_missing_image_is_not_a_candidate(monkeypatch):
    monkeypatch.setattr(runtime_checks, "image_inspect", lambda _ref: None)
    candidate = recovery.inspect_candidate(
        "kryonsec/sandbox:missing", expected_version="1.3.11"
    )
    assert candidate.image_id == ""
    assert candidate.reason == "image is not present"


def test_best_digest_prefers_the_canonical_repository_and_never_invents():
    assert recovery.best_digest((LOCAL_DIGEST, DIGEST)) == DIGEST
    assert recovery.best_digest((LOCAL_DIGEST,)) == LOCAL_DIGEST
    assert recovery.best_digest(("kryonsec/sandbox:latest",)) == ""


def test_scan_prefers_the_newest_exact_release_build(monkeypatch):
    same_id = "sha256:" + "7" * 64
    newer = "kryonsec/sandbox:ui-1.3.11"
    older = "kryonsec/sandbox:v1.3.11-candidate"
    digests = {
        newer: _info(image_id=same_id, digests=(DIGEST,), created="2026-11-18T00:00:00Z"),
        older: _info(
            image_id=same_id,
            digests=("kryonsec/sandbox@sha256:" + "d" * 64,),
            created="2026-11-08T00:00:00Z",
        ),
    }
    monkeypatch.setattr(
        runtime_checks,
        "list_sandbox_image_refs",
        lambda: list(digests),
    )
    monkeypatch.setattr(
        runtime_checks, "image_inspect", lambda ref: digests.get(ref)
    )

    candidates = recovery.scan_candidates(
        expected_version="1.3.11", server_architecture="amd64"
    )

    assert [item.reference for item in candidates] == [newer]


def test_scan_prefers_a_canonical_digest_and_dedupes_the_image_id(monkeypatch):
    same_id = "sha256:" + "9" * 64
    digests = {
        "kryonsec/sandbox:ui-1.3.11": _info(image_id=same_id),
        DIGEST: _info(image_id=same_id, digests=(DIGEST,)),
        "localhost:5000/kryonsec/sandbox:1.3.11": _info(
            image_id=same_id, digests=(LOCAL_DIGEST,)
        ),
        "kryonsec/sandbox:old": _info(version="1.3.10", image_id="sha256:" + "8" * 64),
    }
    monkeypatch.setattr(
        runtime_checks,
        "list_sandbox_image_refs",
        lambda: list(digests),
    )
    monkeypatch.setattr(
        runtime_checks, "image_inspect", lambda ref: digests.get(ref)
    )

    candidates = recovery.scan_candidates(
        expected_version="1.3.11", server_architecture="amd64"
    )

    assert [item.reference for item in candidates] == [DIGEST, "kryonsec/sandbox:old"]
    assert candidates[0].compatible is True
    assert candidates[0].digest_reference == DIGEST
    assert candidates[1].compatible is False


# ---- developer registry --------------------------------------------------


def _registry_inspect(
    *,
    image: str = "registry:2",
    running: bool = True,
    network: str = "bridge",
    bindings: dict | None = None,
) -> dict:
    return {
        "State": {"Running": running},
        "Config": {"Image": image},
        "HostConfig": {
            "NetworkMode": network,
            "PortBindings": bindings
            if bindings is not None
            else {"5000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5000"}]},
        },
    }


def test_loopback_registry_is_verified_from_port_bindings(monkeypatch):
    monkeypatch.setattr(
        runtime_checks, "container_inspect", lambda _name: _registry_inspect()
    )
    status = recovery.registry_status()
    assert status.present is True
    assert status.running is True
    assert status.loopback is True
    assert status.address == "127.0.0.1:5000"
    assert status.reference("1.3.11") == "127.0.0.1:5000/kryonsec/sandbox:1.3.11"


@pytest.mark.parametrize(
    ("data", "needle"),
    [
        (_registry_inspect(image="alpine"), "not a Docker registry image"),
        (_registry_inspect(network="host"), "host networking"),
        (
            _registry_inspect(
                bindings={"5000/tcp": [{"HostIp": "", "HostPort": "5000"}]}
            ),
            "0.0.0.0:5000",
        ),
        (
            _registry_inspect(
                bindings={"5000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5000"}]}
            ),
            "only loopback bindings",
        ),
        (
            _registry_inspect(
                bindings={"5001/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5001"}]}
            ),
            "not the registry API port 5000",
        ),
        (_registry_inspect(bindings={}), "no published host port"),
    ],
)
def test_registry_must_be_a_loopback_registry_on_port_5000(monkeypatch, data, needle):
    monkeypatch.setattr(runtime_checks, "container_inspect", lambda _name: data)
    status = recovery.registry_status()
    assert status.loopback is False
    assert needle in status.reason


# ---- plan ----------------------------------------------------------------


def _snapshot(cfg: KryonsecConfig, image: ImageSnapshot) -> SystemSnapshot:
    return SystemSnapshot(
        platform="linux",
        is_linux=True,
        release=OsRelease(id="arch", like=("arch",), name="Arch Linux"),
        package_manager="pacman",
        python_version="3.12.0",
        python_executable="/usr/bin/python3",
        in_venv=True,
        venv_path=str(cfg.home / "venv"),
        home=str(cfg.home),
        config_file=str(cfg.home / "config.toml"),
        config_exists=True,
        config_mode=0o600,
        workspace=str(cfg.workspace),
        kryonsec_version="1.3.11",
        docker=DockerSnapshot(
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
        gvisor=GvisorSnapshot(
            binary="/usr/local/bin/runsc", version="release-1", registered=True
        ),
        image=image,
        firewall_ok=True,
        firewall_detail="ready",
        disk=DiskSnapshot(path=str(cfg.home), free_gb=100.0, total_gb=500.0),
    )


def _candidate(
    *,
    reference: str = "kryonsec/sandbox:ui-1.3.11",
    version: str = "1.3.11",
    digest: str = DIGEST,
    compatible: bool = True,
    created: str = "2026-11-18T00:00:00Z",
) -> recovery.ImageCandidate:
    return recovery.ImageCandidate(
        reference=reference,
        image_id="sha256:" + "2" * 64,
        version=version,
        architecture="amd64",
        operating_system="linux",
        entrypoint=("/entrypoint.sh",),
        user="kryonsec-runner",
        repo_digests=(digest,) if digest else (),
        digest_reference=digest,
        created=created,
        compatible=compatible,
        reason="" if compatible else "rejected",
    )


def _mismatch(
    *,
    source: str = recovery.SOURCE_CONFIG,
    candidates: tuple[recovery.ImageCandidate, ...] = (),
    registry: recovery.RegistryStatus | None = None,
) -> ImageSnapshot:
    return ImageSnapshot(
        reference="kryonsec/sandbox:latest",
        source=source,
        present=True,
        architecture="amd64",
        operating_system="linux",
        entrypoint=("/entrypoint.sh",),
        user="kryonsec-runner",
        validation_status="FAIL",
        validation_detail="image version 1.3.10 does not match Kryonsec 1.3.11",
        version="1.3.10",
        candidates=candidates,
        registry=registry,
    )


def test_matching_local_digest_is_selected_automatically(cfg):
    plan = build_plan(cfg, _snapshot(cfg, _mismatch(candidates=(_candidate(),))))
    action = next(
        action for action in plan.actions if action.key == "select-compatible-digest"
    )
    assert action.kind == AUTO
    assert action.new_image == DIGEST
    assert "no image or volume is touched" in action.detail
    assert "Selected via config.toml" in action.detail


def test_no_matching_image_fails_closed_and_never_relabels(cfg):
    plan = build_plan(cfg, _snapshot(cfg, _mismatch()))
    action = next(
        action for action in plan.actions if action.key == "image-incompatible"
    )
    assert action.kind == MANUAL
    assert "No compatible local sandbox image was found" in action.detail
    assert "will not relabel an old image" in action.detail
    assert not [
        action
        for action in plan.actions
        if action.key in {"select-compatible-digest", "register-local-image"}
    ]


def test_incompatible_candidates_are_not_selected(cfg):
    rejected = _candidate(
        reference="kryonsec/sandbox:old", version="1.3.10", digest="", compatible=False
    )
    plan = build_plan(cfg, _snapshot(cfg, _mismatch(candidates=(rejected,))))
    assert not [
        action for action in plan.actions if action.key == "select-compatible-digest"
    ]
    assert next(
        action for action in plan.actions if action.key == "image-incompatible"
    ).kind == MANUAL


def test_environment_override_is_never_edited_behind_the_operator(cfg, monkeypatch):
    monkeypatch.setenv("KRYONSEC_SANDBOX_IMAGE", "kryonsec/sandbox:latest")
    plan = build_plan(
        cfg,
        _snapshot(
            cfg,
            _mismatch(
                source=recovery.SOURCE_ENV, candidates=(_candidate(),)
            ),
        ),
    )
    action = next(
        action for action in plan.actions if action.key == "image-env-override"
    )
    assert action.kind == MANUAL
    assert action.shell_hint.startswith("export KRYONSEC_SANDBOX_IMAGE=")
    assert DIGEST in action.shell_hint
    assert not [
        action
        for action in plan.actions
        if action.kind == AUTO and action.new_image
    ]


def test_tag_only_local_build_needs_an_approved_loopback_registration(cfg):
    tag_only = _candidate(digest="")
    assert tag_only.needs_registration is True
    registry = recovery.RegistryStatus(
        present=True,
        running=False,
        loopback=True,
        host="127.0.0.1",
        port="5000",
        image="registry:2",
    )
    plan = build_plan(
        cfg,
        _snapshot(
            cfg, _mismatch(candidates=(tag_only,), registry=registry)
        ),
    )
    action = next(
        action for action in plan.actions if action.key == "register-local-image"
    )
    assert action.kind == APPROVAL
    assert action.registry_ref == "127.0.0.1:5000/kryonsec/sandbox:1.3.11"
    assert action.steps == (
        ("docker", "start", recovery.REGISTRY_CONTAINER),
        (
            "docker",
            "tag",
            "kryonsec/sandbox:ui-1.3.11",
            "127.0.0.1:5000/kryonsec/sandbox:1.3.11",
        ),
        ("docker", "push", "127.0.0.1:5000/kryonsec/sandbox:1.3.11"),
    )
    assert "&&" in action.exact_action
    assert "rm" not in action.exact_action


def test_a_running_registry_is_not_started_again(cfg):
    tag_only = _candidate(digest="")
    registry = recovery.RegistryStatus(
        present=True,
        running=True,
        loopback=True,
        host="127.0.0.1",
        port="5000",
        image="registry:2",
    )
    plan = build_plan(
        cfg, _snapshot(cfg, _mismatch(candidates=(tag_only,), registry=registry))
    )
    action = next(
        action for action in plan.actions if action.key == "register-local-image"
    )
    assert action.steps[0][1] == "tag"


def test_an_unsafe_registry_falls_back_to_manual_instructions(cfg):
    tag_only = _candidate(digest="")
    registry = recovery.RegistryStatus(
        present=True,
        running=True,
        loopback=False,
        host="0.0.0.0",
        port="5000",
        image="registry:2",
        reason="registry publishes on 0.0.0.0:5000; only loopback bindings are accepted",
    )
    plan = build_plan(
        cfg, _snapshot(cfg, _mismatch(candidates=(tag_only,), registry=registry))
    )
    assert not [
        action for action in plan.actions if action.key == "register-local-image"
    ]
    action = next(
        action for action in plan.actions if action.key == "image-incompatible"
    )
    assert action.kind == MANUAL
    assert "only loopback bindings are accepted" in action.detail


# ---- executors -----------------------------------------------------------


def test_registry_executor_refuses_anything_outside_the_allowlist():
    class Reporter:
        def line(self, *_args, **_kwargs):
            pass

    cfg = KryonsecConfig(home=Path("/nonexistent"), workspace=Path("/nonexistent"))
    action = fix_module.RepairAction(
        "VERIFYING SANDBOX",
        "register-local-image",
        "t",
        APPROVAL,
        steps=(("docker", "rm", "-f", "kryonsec"),),
        registry_ref="127.0.0.1:5000/kryonsec/sandbox:1.3.11",
    )
    ok, detail = fix_module._execute_registration(cfg, action, Reporter())
    assert ok is False
    assert "unexpected step" in detail

    outside = fix_module.RepairAction(
        "VERIFYING SANDBOX",
        "register-local-image",
        "t",
        APPROVAL,
        steps=(
            (
                "docker",
                "push",
                "evil.example.com/kryonsec/sandbox:1.3.11",
            ),
        ),
        registry_ref="evil.example.com/kryonsec/sandbox:1.3.11",
    )
    ok, detail = fix_module._execute_registration(cfg, outside, Reporter())
    assert ok is False and "loopback-bound" in detail


def test_registry_executor_records_only_the_digest_docker_publishes(
    cfg, monkeypatch
):
    cfg.home.mkdir(parents=True)
    (cfg.home / "config.toml").write_text(
        '[sandbox]\nimage = "kryonsec/sandbox:latest"\n', encoding="utf-8"
    )
    commands: list[tuple[str, ...]] = []

    def fake_run(command, **_kwargs):
        commands.append(tuple(command))
        return subprocess.CompletedProcess(list(command), 0, "ok", "")

    published = "127.0.0.1:5000/kryonsec/sandbox@sha256:" + "c" * 64
    monkeypatch.setattr(fix_module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        runtime_checks,
        "image_inspect",
        lambda _ref: _info(digests=(published,), image_id="sha256:" + "3" * 64),
    )
    written: list[str] = []
    monkeypatch.setattr(
        fix_module, "_write_image_reference", lambda _cfg, ref: written.append(ref) or "ok"
    )

    action = fix_module.RepairAction(
        "VERIFYING SANDBOX",
        "register-local-image",
        "t",
        APPROVAL,
        steps=(
            (
                "docker",
                "tag",
                "kryonsec/sandbox:ui-1.3.11",
                "127.0.0.1:5000/kryonsec/sandbox:1.3.11",
            ),
            ("docker", "push", "127.0.0.1:5000/kryonsec/sandbox:1.3.11"),
        ),
        registry_ref="127.0.0.1:5000/kryonsec/sandbox:1.3.11",
        local_ref="kryonsec/sandbox:ui-1.3.11",
        version="1.3.11",
    )

    class Reporter:
        def line(self, *_args, **_kwargs):
            pass

    ok, detail = fix_module._execute_registration(cfg, action, Reporter())
    assert ok is True
    assert commands == [
        (
            "docker",
            "tag",
            "kryonsec/sandbox:ui-1.3.11",
            "127.0.0.1:5000/kryonsec/sandbox:1.3.11",
        ),
        ("docker", "push", "127.0.0.1:5000/kryonsec/sandbox:1.3.11"),
    ]
    assert written == [published]
    assert "registry digest verified" in detail


def test_registry_executor_fails_when_no_digest_is_published(cfg, monkeypatch):
    monkeypatch.setattr(
        fix_module.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(list(command), 0, "", ""),
    )
    monkeypatch.setattr(
        runtime_checks, "image_inspect", lambda _ref: _info(digests=())
    )
    written: list[str] = []
    monkeypatch.setattr(
        fix_module, "_write_image_reference", lambda _cfg, ref: written.append(ref)
    )
    action = fix_module.RepairAction(
        "VERIFYING SANDBOX",
        "register-local-image",
        "t",
        APPROVAL,
        steps=(
            ("docker", "push", "127.0.0.1:5000/kryonsec/sandbox:1.3.11"),
        ),
        registry_ref="127.0.0.1:5000/kryonsec/sandbox:1.3.11",
    )

    class Reporter:
        def line(self, *_args, **_kwargs):
            pass

    ok, detail = fix_module._execute_registration(cfg, action, Reporter())
    assert ok is False
    assert "did not publish an immutable digest" in detail
    assert written == []


def test_digest_selection_is_validated_and_backed_up(cfg, monkeypatch):
    cfg.home.mkdir(parents=True)
    path = cfg.home / "config.toml"
    path.write_text('[sandbox]\nimage = "kryonsec/sandbox:latest"\n', encoding="utf-8")
    monkeypatch.setattr(
        runtime_checks,
        "docker_info",
        lambda: DockerSnapshot(architecture="amd64"),
    )
    monkeypatch.setattr(
        runtime_checks,
        "validate_image",
        lambda *_a, **_k: ImageCheck("PASS", "digest-pinned image is compatible"),
    )

    note = fix_module._write_image_reference(cfg, DIGEST)

    assert DIGEST in note
    assert list(cfg.home.glob("config.toml.bak-*"))
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    assert data["sandbox"]["image"] == DIGEST
    assert cfg.sandbox_image == DIGEST


def test_a_tag_is_never_written_as_a_digest(cfg, monkeypatch):
    cfg.home.mkdir(parents=True)
    path = cfg.home / "config.toml"
    path.write_text('[sandbox]\nimage = "kryonsec/sandbox:latest"\n', encoding="utf-8")
    before = path.read_text(encoding="utf-8")

    with pytest.raises(fix_module.RepairRefused, match="immutable digest"):
        fix_module._write_image_reference(cfg, "kryonsec/sandbox:ui-1.3.11")

    assert path.read_text(encoding="utf-8") == before
    assert not list(cfg.home.glob("config.toml.bak-*"))


def test_a_failing_validation_never_changes_config(cfg, monkeypatch):
    cfg.home.mkdir(parents=True)
    path = cfg.home / "config.toml"
    path.write_text('[sandbox]\nimage = "kryonsec/sandbox:latest"\n', encoding="utf-8")
    before = path.read_text(encoding="utf-8")
    monkeypatch.setattr(
        runtime_checks, "docker_info", lambda: DockerSnapshot(architecture="amd64")
    )
    monkeypatch.setattr(
        runtime_checks,
        "validate_image",
        lambda *_a, **_k: ImageCheck("FAIL", "image runs as root"),
    )

    with pytest.raises(fix_module.RepairRefused, match="runs as root"):
        fix_module._write_image_reference(cfg, DIGEST)

    assert path.read_text(encoding="utf-8") == before
    assert not list(cfg.home.glob("config.toml.bak-*"))


def test_explain_names_the_source_and_the_compatible_candidate():
    diagnosis = recovery.ImageDiagnosis(
        reference="kryonsec/sandbox:latest",
        source=recovery.SOURCE_CONFIG,
        version="1.3.10",
        reason="image version 1.3.10 does not match Kryonsec 1.3.11",
        candidates=(_candidate(),),
    )
    text = recovery.explain(diagnosis, "1.3.11")
    assert "version 1.3.10" in text
    assert "Selected via config.toml" in text
    assert DIGEST not in text
    assert "A locally built 1.3.11 candidate was found" in text
