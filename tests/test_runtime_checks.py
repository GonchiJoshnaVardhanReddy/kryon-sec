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


def test_docker_desktop_hint_includes_the_context_switch(monkeypatch):
    """The step that looks unnecessary and is not.

    Docker Desktop leaves currentContext set to "desktop-linux" in
    ~/.docker/config.json, so a newly installed docker.io daemon is
    invisible to the CLI until the context is switched. Without this the
    user installs Docker in the distro, re-runs doctor, and gets the same
    FAIL — because every probe is still reading Docker Desktop.
    """
    _fake_docker_info(monkeypatch, "Docker Desktop")
    hint = runtime_checks.gvisor_fix_hint()
    assert "docker context use default" in hint
    # client-side config only: under sudo this would edit root's config and
    # change nothing for the user who is actually running kryonsec
    assert "sudo docker context use default" not in hint


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
        assert "installer" in hint, os_string
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


def test_docker_desktop_hint_leads_with_the_installer(monkeypatch):
    """The by-hand sequence fails on the state this hint is reached from.

    A user in this branch very likely has a malformed gvisor.list on disk —
    our own installer used to write one — and while it is there apt refuses
    every install, docker.io included. "Re-run the installer" does the whole
    thing in the working order, so it goes first rather than last.
    """
    _fake_docker_info(monkeypatch, "Docker Desktop")
    hint = runtime_checks.gvisor_fix_hint()
    assert hint.index("installer") < hint.index("docker.io")


def test_the_by_hand_fix_clears_the_bad_source_first(monkeypatch):
    """Without the rm, `apt-get install docker.io` is the command that
    fails — and it fails with a message about a gVisor repository, which is
    not a thing the user set up on purpose."""
    _fake_docker_info(monkeypatch, "Docker Desktop")
    hint = runtime_checks.gvisor_fix_hint()
    assert "rm -f /etc/apt/sources.list.d/gvisor.list" in hint
    assert hint.index("rm -f /etc/apt/sources.list.d/gvisor.list") < \
        hint.index("apt-get install -y docker.io")


def test_gvisor_hint_is_a_plain_install_otherwise(monkeypatch):
    _fake_docker_info(monkeypatch, "Ubuntu 24.04.3 LTS")
    hint = runtime_checks.gvisor_fix_hint()
    assert "Docker Desktop" not in hint
    assert "gVisor is missing" in hint


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
