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
    assert "same host" in hint
    assert "will not switch contexts" in hint


def test_docker_desktop_hint_does_not_switch_context(monkeypatch):
    """A context is an operator choice, not an installer side effect."""
    _fake_docker_info(monkeypatch, "Docker Desktop")
    hint = runtime_checks.gvisor_fix_hint()
    assert "will not switch contexts" in hint
    assert "docker context use" not in hint


def test_gvisor_hint_is_self_contained(monkeypatch):
    """Neither branch may name `runsc install` on its own.

    runsc may not be installed at all yet, so `sudo runsc install` fails
    with "runsc: command not found" — the user is told to run a command
    that cannot work. Sending them back through the installer is the path
    that actually installs runsc first.
    """
    for os_string in ("Docker Desktop", "Ubuntu 24.04.3 LTS"):
        _fake_docker_info(monkeypatch, os_string)
        hint = runtime_checks.gvisor_fix_hint()
        assert "install" in hint.lower(), os_string
        assert "sudo runsc install" not in hint, os_string


def test_docker_desktop_hint_warns_that_the_switch_does_not_stick(monkeypatch):
    """The switch is reversible, and Docker Desktop is what reverses it.

    A hint that stops at `docker context use default` gives the user a
    working daemon until the next launch and then the same FAIL, with
    nothing explaining why they are back where they started. DOCKER_HOST
    overrides the context too, so both need naming.
    """
    _fake_docker_info(monkeypatch, "Docker Desktop")
    hint = runtime_checks.gvisor_fix_hint()
    assert "WSL Integration" in hint
    assert "DOCKER_HOST" in hint


def test_docker_desktop_hint_leads_with_the_selected_daemon(monkeypatch):
    """The fix must address the daemon actually being queried."""
    _fake_docker_info(monkeypatch, "Docker Desktop")
    hint = runtime_checks.gvisor_fix_hint()
    assert "selected Docker daemon" in hint
    assert "same host" in hint


def test_the_hint_does_not_embed_destructive_cleanup(monkeypatch):
    """Diagnostics must not remove apt sources or switch Docker contexts."""
    _fake_docker_info(monkeypatch, "Docker Desktop")
    hint = runtime_checks.gvisor_fix_hint()
    assert "rm -f" not in hint
    assert "docker context use" not in hint


def test_gvisor_hint_is_a_plain_install_otherwise(monkeypatch):
    _fake_docker_info(monkeypatch, "Ubuntu 24.04.3 LTS")
    hint = runtime_checks.gvisor_fix_hint()
    assert "Docker Desktop" not in hint
    assert "not registered" in hint


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


def test_permission_denied_socket_is_not_reported_as_a_dead_daemon(monkeypatch):
    """Right after installing Docker in a distro the socket is root-owned.

    "daemon not reachable" would send the user to restart a daemon that is
    running perfectly — the actual fix is group membership and a re-login.
    Docker Desktop's per-user socket is why this never came up before.
    """
    import subprocess

    def fake_run(*a, **kw):
        return subprocess.CompletedProcess(
            a, 1, "", "permission denied while trying to connect to the "
                      "Docker daemon socket at unix:///var/run/docker.sock")

    monkeypatch.setattr(runtime_checks.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_checks.subprocess, "run", fake_run)

    ok, detail = runtime_checks.docker_server_ok()
    assert ok is False
    assert "docker group" in detail
    assert "daemon not reachable" not in detail


def test_a_genuinely_dead_daemon_still_says_so(monkeypatch):
    import subprocess

    def fake_run(*a, **kw):
        return subprocess.CompletedProcess(
            a, 1, "", "Cannot connect to the Docker daemon at "
                      "unix:///var/run/docker.sock. Is the docker daemon running?")

    monkeypatch.setattr(runtime_checks.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_checks.subprocess, "run", fake_run)

    ok, detail = runtime_checks.docker_server_ok()
    assert ok is False
    assert detail == "daemon not reachable"


def test_safe_endpoint_does_not_print_userinfo():
    assert runtime_checks.safe_endpoint("ssh://alice:secret@example.test:2376/path") == "ssh://example.test:2376/path"


def test_validate_image_rejects_mutable_tags(monkeypatch):
    monkeypatch.setattr(
        runtime_checks,
        "image_inspect",
        lambda image: runtime_checks.ImageInfo(
            image_id="sha256:abc",
            architecture="amd64",
            operating_system="linux",
            entrypoint=("/entrypoint.sh",),
            user="kryonsec-runner",
            repo_digests=("ghcr.io/example/image@sha256:abc",),
            labels={"org.kryonsec.version": "1.3.7"},
        ),
    )
    check = runtime_checks.validate_image(
        "ghcr.io/example/image:1.3.7",
        expected_version="1.3.7",
        server_architecture="amd64",
    )
    assert check.status == "FAIL"
    assert "mutable tag" in check.detail


def test_validate_image_accepts_matching_digest_and_release(monkeypatch):
    monkeypatch.setattr(
        runtime_checks,
        "image_inspect",
        lambda image: runtime_checks.ImageInfo(
            image_id="sha256:abc",
            architecture="amd64",
            operating_system="linux",
            entrypoint=("/entrypoint.sh",),
            user="kryonsec-runner",
            repo_digests=("ghcr.io/example/image@sha256:abc",),
            labels={"org.kryonsec.version": "v1.3.7"},
        ),
    )
    check = runtime_checks.validate_image(
        "ghcr.io/example/image@sha256:abc",
        expected_version="1.3.7",
        server_architecture="x86_64",
    )
    assert check.status == "PASS"


def test_runtime_smoke_uses_runsc_entrypoint_and_cleans_up(monkeypatch):
    calls = []

    def fake(args):
        calls.append(args)
        if args[0] == "create":
            return type("Result", (), {"returncode": 0, "stdout": "name", "stderr": ""})()
        if args[0] == "inspect":
            return type("Result", (), {"returncode": 0, "stdout": "runsc\n", "stderr": ""})()
        if args[0] == "start":
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if args[0] == "rm":
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        raise AssertionError(args)

    monkeypatch.setattr(runtime_checks.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_checks, "_run_docker", fake)
    ok, detail = runtime_checks.runtime_smoke_test("image@sha256:abc")
    assert ok, detail
    create = calls[0]
    assert "--runtime" in create and create[create.index("--runtime") + 1] == "runsc"
    assert "--network" in create and create[create.index("--network") + 1] == "none"
    assert create[create.index("--entrypoint") + 1] == "/entrypoint.sh"
    assert calls[-1][0:2] == ["rm", "--force"]
