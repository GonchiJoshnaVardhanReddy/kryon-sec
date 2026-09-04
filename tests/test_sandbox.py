"""Tests for the Kali sandbox spawn (spec §8.5)."""

import subprocess

from kryonsec.config import KryonsecConfig
from kryonsec.purple.sandbox import KaliSandbox


class Completed:
    """Minimal subprocess.CompletedProcess stand-in."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _sandbox(tmp_path, run_fn=None):
    cfg = KryonsecConfig(home=tmp_path)
    # no real seccomp profile in the tmp env -> flag just skipped
    return KaliSandbox(cfg=cfg, run_fn=run_fn,
                       seccomp_profile=tmp_path / "nope.json")


# ---- docker argv construction ------------------------------------------

def test_docker_argv_flags_and_image(tmp_path):
    s = _sandbox(tmp_path)
    argv = s._docker_argv(["nmap", "-sV", "target.com"])
    assert argv[0:3] == ["docker", "run", "--rm"]
    assert "--runtime" in argv and argv[argv.index("--runtime") + 1] == "runsc"
    assert argv[argv.index("--user") + 1] == "kryonsec-runner"
    assert "--read-only" in argv
    assert argv[argv.index("--memory") + 1] == "2g"
    assert argv[argv.index("--cpus") + 1] == "2"
    assert argv[argv.index("--pids-limit") + 1] == "100"
    # image, then tool argv as container args
    assert argv[-3:] == ["nmap", "-sV", "target.com"]
    # the image actually configured (tag, or pinned digest from env) is used
    assert s.image in argv


def test_docker_argv_never_builds_shell_string(tmp_path):
    s = _sandbox(tmp_path)
    argv = s._docker_argv(["sqlmap", "-u", "http://x/a?b=1 c"])
    # every element stays a separate argv token — no shell interpolation
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert "http://x/a?b=1 c" in argv


def test_docker_argv_seccomp_when_profile_exists(tmp_path):
    profile = tmp_path / "seccomp.json"
    profile.write_text("{}", encoding="utf-8")
    cfg = KryonsecConfig(home=tmp_path)
    s = KaliSandbox(cfg=cfg, seccomp_profile=profile)
    argv = s._docker_argv(["nmap", "x"])
    assert "--security-opt" in argv
    assert argv[argv.index("--security-opt") + 1] == f"seccomp={profile}"


def test_docker_argv_no_seccomp_when_missing(tmp_path):
    s = _sandbox(tmp_path)
    assert "--security-opt" not in s._docker_argv(["nmap", "x"])


# ---- spawn result parsing ----------------------------------------------

def test_spawn_parses_json_payload(tmp_path):
    def run_fn(argv, **kw):
        assert argv[0] == "docker"
        return Completed(stdout='{"exit_code": 3, "stdout": "scan output"}')

    res = _sandbox(tmp_path, run_fn).spawn(["nmap", "-sV", "t.com"])
    assert res.ok
    assert res.exit_code == 3
    assert res.stdout == "scan output"
    assert not res.truncated


def test_spawn_non_json_is_error(tmp_path):
    def run_fn(argv, **kw):
        return Completed(returncode=1, stdout="docker: daemon down",
                         stderr="Cannot connect to the Docker daemon")

    res = _sandbox(tmp_path, run_fn).spawn(["nmap", "x"])
    assert not res.ok
    assert "no JSON payload" in res.error
    assert "Docker daemon" in res.error


def test_spawn_entrance_allowlist_rejection(tmp_path):
    def run_fn(argv, **kw):
        return Completed(stdout='{"error": "tool_not_in_allowlist"}')

    res = _sandbox(tmp_path, run_fn).spawn(["eviltool", "x"])
    assert not res.ok
    assert res.error == "tool_not_in_allowlist"


def test_spawn_timeout(tmp_path):
    def run_fn(argv, **kw):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=330)

    res = _sandbox(tmp_path, run_fn).spawn(["nmap", "x"])
    assert not res.ok
    assert "sandbox timeout" in res.error
    assert res.exit_code == -1


def test_spawn_spawn_crash_is_error_not_exception(tmp_path):
    def run_fn(argv, **kw):
        raise OSError("docker binary missing")

    res = _sandbox(tmp_path, run_fn).spawn(["nmap", "x"])
    assert not res.ok
    assert "docker binary missing" in res.error


def test_spawn_bounds_output(tmp_path):
    def run_fn(argv, **kw):
        return Completed(stdout='{"exit_code": 0, "stdout": "%s"}' % ("A" * 10_000))

    cfg = KryonsecConfig(home=tmp_path)
    cfg.max_tool_output_chars = 100
    s = KaliSandbox(cfg=cfg, run_fn=run_fn, seccomp_profile=tmp_path / "n.json")
    res = s.spawn(["nmap", "x"])
    assert res.ok
    assert len(res.stdout) == 100
    assert res.truncated
