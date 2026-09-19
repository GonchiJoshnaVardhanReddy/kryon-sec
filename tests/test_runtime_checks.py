"""Tests for the shared Docker / gVisor probes (purple/runtime_checks.py).

The interesting failure here is environmental, not logical: on WSL2 the
docker CLI is often talking to Docker Desktop's daemon, which lives outside
the distro and cannot be given a gVisor runtime from inside it. `runsc
install` then reports success, the runtime never appears, and every retry
fails the same way. The probe has to be able to tell that apart from a
genuinely missing gVisor install, because the fix is completely different.
"""

from kryonsec.purple import runtime_checks


def _fake_docker_info(monkeypatch, os_string, runtimes="runc"):
    """Answer `docker info` without a docker binary, keyed on the format
    string — the same call shape the real probe uses."""
    monkeypatch.setattr(runtime_checks.shutil, "which", lambda name: "/usr/bin/docker")

    class Result:
        returncode = 0

        def __init__(self, stdout):
            self.stdout = stdout

    def fake_run(argv, **kwargs):
        fmt = argv[-1]
        if "OperatingSystem" in fmt:
            return Result(os_string)
        if "Runtimes" in fmt:
            return Result(runtimes)
        return Result("")

    monkeypatch.setattr(runtime_checks.subprocess, "run", fake_run)


def test_docker_os_string_empty_without_a_docker_cli(monkeypatch):
    monkeypatch.setattr(runtime_checks.shutil, "which", lambda name: None)
    assert runtime_checks.docker_os_string() == ""
    assert runtime_checks.docker_desktop_in_use() is False


def test_docker_desktop_is_detected_from_dockers_own_os_string(monkeypatch):
    _fake_docker_info(monkeypatch, "Docker Desktop")
    assert runtime_checks.docker_desktop_in_use() is True


def test_distro_native_docker_is_not_docker_desktop(monkeypatch):
    _fake_docker_info(monkeypatch, "Ubuntu 24.04.3 LTS")
    assert runtime_checks.docker_desktop_in_use() is False


def test_gvisor_hint_names_docker_desktop_and_points_at_a_distro_daemon(monkeypatch):
    _fake_docker_info(monkeypatch, "Docker Desktop")
    hint = runtime_checks.gvisor_fix_hint()
    assert "Docker Desktop" in hint
    # the fix is installing docker inside the distro — not re-running runsc
    assert "docker.io" in hint
    assert "runsc install" in hint


def test_gvisor_hint_is_a_plain_install_otherwise(monkeypatch):
    _fake_docker_info(monkeypatch, "Ubuntu 24.04.3 LTS")
    hint = runtime_checks.gvisor_fix_hint()
    assert "Docker Desktop" not in hint
    assert "runsc install" in hint


def test_runsc_registered_reads_the_runtime_list(monkeypatch):
    _fake_docker_info(monkeypatch, "Ubuntu", runtimes="runc runsc ")
    assert runtime_checks.runsc_registered() is True

    _fake_docker_info(monkeypatch, "Ubuntu", runtimes="runc ")
    assert runtime_checks.runsc_registered() is False


def test_doctor_gvisor_row_carries_the_hint(monkeypatch):
    """doctor must not say 'gVisor missing' and stop — that sends the user
    back to an install that already claimed to succeed."""
    from kryonsec import doctor

    monkeypatch.setattr(runtime_checks, "runsc_registered", lambda: False)
    monkeypatch.setattr(runtime_checks, "gvisor_fix_hint", lambda: "FIXME-HINT")
    ok, message = doctor._check_gvisor()
    assert ok is False
    assert message == "FIXME-HINT"


def test_sandbox_available_points_at_doctor(monkeypatch):
    """The prompt's notice line is one line — the fix detail belongs in
    doctor, so the reason has to say where to look."""
    from kryonsec.purple import runner

    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runtime_checks, "docker_runtimes", lambda: "runc ")
    ok, reason = runner.sandbox_available()
    assert not ok
    assert "runsc" in reason
    assert "kryonsec doctor" in reason
