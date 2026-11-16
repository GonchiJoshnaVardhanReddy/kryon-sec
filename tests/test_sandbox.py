"""Tests for the Kali sandbox spawn (spec §8.5)."""

import subprocess
from pathlib import Path

import pytest

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
    # writable VOLATILE home tmpfs (nuclei et al. insist on writing their
    # configs into $HOME; a read-only home kills them at startup): same
    # mount class as /tmp — memory-backed, capped, no host path
    assert argv[argv.index("--tmpfs") + 1] == "/tmp:size=100m"
    home_idx = argv.index("--tmpfs", argv.index("--tmpfs") + 1)
    assert argv[home_idx + 1] == "/home/kryonsec-runner:size=100m"
    # image, then tool argv as container args
    assert argv[-3:] == ["nmap", "-sV", "target.com"]
    # the image actually configured (tag, or pinned digest from env) is used
    assert s.image in argv


def test_docker_argv_home_tmpfs_never_replaces_rw_host_mounts(tmp_path):
    """The home tmpfs grants NO host access: /evidence stays the only
    rw host mount, /code stays :ro, and the home mount itself is a bare
    tmpfs (no bind source)."""
    s = _sandbox(tmp_path)
    code = tmp_path / "code"
    code.mkdir()
    s2 = s.copy_with(code_dir=str(code))
    argv = s2._docker_argv(["bandit", "-r", "/code"])
    assert f"{code}:/code:ro" in argv
    # exactly two tmpfs mounts: /tmp and the runner home — no bind of
    # the host anywhere near $HOME
    tmpfs = [argv[i + 1] for i, a in enumerate(argv) if a == "--tmpfs"]
    assert tmpfs == ["/tmp:size=100m", "/home/kryonsec-runner:size=100m"]


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


# ---- code folder mount (tool expansion Phase 5) --------------------------

def test_docker_argv_mounts_code_dir_read_only(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    s = KaliSandbox(cfg=cfg, code_dir="/opt/victim-code",
                    seccomp_profile=tmp_path / "n.json")
    argv = s._docker_argv(["bandit", "-r", "/code"])
    # the host folder is mounted read-only at the FIXED /code path
    assert argv[argv.index("-v") + 1] == "/opt/victim-code:/code:ro"
    assert argv[argv.index("-w") + 1] == "/code"
    assert "--read-only" in argv  # rootfs still read-only too


def test_docker_argv_without_code_dir_has_no_mount(tmp_path):
    s = _sandbox(tmp_path)
    argv = s._docker_argv(["nmap", "x"])
    assert not any(a.endswith(":/code:ro") for a in argv)
    assert "-w" not in argv


def test_code_dir_must_be_absolute(tmp_path):
    """A relative path would silently resolve against the CWD — refuse
    it loudly instead (the CLI resolves to absolute before this)."""
    cfg = KryonsecConfig(home=tmp_path)
    with pytest.raises(ValueError):
        KaliSandbox(cfg=cfg, code_dir="victim-code",
                    seccomp_profile=tmp_path / "n.json")


# ---- evidence mount (tool expansion Phase 8) -------------------------------

def test_docker_argv_mounts_evidence_dir_read_write(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    s = KaliSandbox(cfg=cfg, evidence_dir="/opt/eng/evidence",
                    seccomp_profile=tmp_path / "n.json")
    argv = s._docker_argv(["gowitness", "scan", "website"])
    # the engagement evidence folder is the ONLY rw mount, at the FIXED
    # /evidence path (gowitness screenshots land there)
    assert argv[argv.index("-v") + 1] == "/opt/eng/evidence:/evidence:rw"
    assert "--read-only" in argv  # rootfs stays read-only
    assert not any(a.endswith(":/code:ro") for a in argv)  # no /code here


def test_docker_argv_without_evidence_dir_has_no_mount(tmp_path):
    s = _sandbox(tmp_path)
    argv = s._docker_argv(["nmap", "x"])
    assert not any(a.endswith(":/evidence:rw") for a in argv)


def test_evidence_dir_must_be_absolute(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    with pytest.raises(ValueError):
        KaliSandbox(cfg=cfg, evidence_dir="evidence",
                    seccomp_profile=tmp_path / "n.json")


def test_code_and_evidence_mounts_coexist(tmp_path):
    """Both mounts at once: /code stays read-only, /evidence rw — a
    scanner must never be able to write into the user's code folder."""
    cfg = KryonsecConfig(home=tmp_path)
    s = KaliSandbox(cfg=cfg, code_dir="/opt/victim-code",
                    evidence_dir="/opt/eng/evidence",
                    seccomp_profile=tmp_path / "n.json")
    argv = s._docker_argv(["bandit", "-r", "/code"])
    mounts = [a for a in argv if ":" in a and a.startswith(("/opt/", "/"))]
    assert "/opt/victim-code:/code:ro" in mounts
    assert "/opt/eng/evidence:/evidence:rw" in mounts


# ---- pinned-resolver resolv.conf mount (gVisor 127.0.0.11 gap) -----------

class _FakePolicy:
    """Minimal egress policy stand-in for argv construction tests."""

    def __init__(self, resolvers):
        self.network_name = "kryonsec-egress-test0"
        self.dns_resolvers = resolvers


def _sandbox_with_policy(tmp_path, resolvers):
    s = _sandbox(tmp_path)
    s.egress_policy = _FakePolicy(resolvers)
    return s


def test_docker_argv_mounts_pinned_resolv_conf_under_egress(tmp_path):
    """Docker's embedded resolver (127.0.0.11, which owns /etc/resolv.conf
    on user-defined networks) has no listener inside gVisor's netstack —
    every by-name lookup in the sandbox would die with "connection
    refused". The launch argv must therefore bind-mount a minimal
    resolv.conf carrying EXACTLY the policy's pinned resolvers, the same
    set --dns carries and the boundary already allows on dport 53."""
    s = _sandbox_with_policy(tmp_path, ["10.213.44.1", "10.213.44.2"])
    argv = s._docker_argv(["curl", "http://juice-shop.lab/"])
    assert argv[argv.index("--network") + 1] == "kryonsec-egress-test0"
    assert argv.count("--dns") == 2
    assert argv[argv.index("--dns") + 1] == "10.213.44.1"
    mounts = [a for a in argv if a.endswith(":/etc/resolv.conf:ro")]
    assert len(mounts) == 1, mounts
    src = mounts[0].split(":/etc/resolv.conf:ro")[0]
    assert Path(src).is_absolute(), src
    assert Path(src).read_text(encoding="utf-8") == (
        "nameserver 10.213.44.1\nnameserver 10.213.44.2\n")


def test_docker_argv_resolv_conf_mount_keeps_isolation_invariant(tmp_path):
    """The mount is additive: the launch argv still satisfies the hard
    isolation invariant (runsc, non-root, read-only rootfs, caps, ...)."""
    from kryonsec.purple.sandbox import missing_isolation_flags

    s = _sandbox_with_policy(tmp_path, ["10.213.44.1"])
    argv = s._docker_argv(["nmap", "-sV", "juice-shop.lab"])
    assert missing_isolation_flags(argv) == []


def test_docker_argv_no_resolv_conf_mount_for_network_none(tmp_path):
    """A network-none run touches no network at all — no --dns and no
    resolver mount may appear on its argv."""
    s = _sandbox_with_policy(tmp_path, ["10.213.44.1"])
    argv = s._docker_argv(["searchsploit", "apache"], network_mode="none")
    assert "--dns" not in argv
    assert not any("resolv.conf" in a for a in argv)
    assert argv[argv.index("--network") + 1] == "none"


def test_docker_argv_no_resolver_mount_without_pinned_resolvers(tmp_path):
    """No pinned resolver = no DNS (fail closed): no --dns, no mount —
    name resolution must fail loudly, never fall back to an unapproved
    resolver path."""
    s = _sandbox_with_policy(tmp_path, [])
    argv = s._docker_argv(["curl", "http://juice-shop.lab/"])
    assert "--dns" not in argv
    assert not any("resolv.conf" in a for a in argv)
    assert argv[argv.index("--network") + 1] == "kryonsec-egress-test0"


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


# --- container cleanup on interrupt (spec §8.5) -----------------------------

def _interrupt_sandbox(tmp_path, explode, monkeypatch):
    """A sandbox whose tool run raises `explode`, recording docker-kill calls.

    _kill_container() shells out through subprocess.run directly (not the
    injectable run_fn), so the kill has to be observed at that seam.
    """
    from kryonsec.purple import sandbox as sb_mod

    killed: list[str] = []

    def fake_run(argv, **kw):
        if list(argv[:2]) == ["docker", "kill"]:
            killed.append(argv[2])
            return Completed()          # the file's existing fake proc
        raise explode

    monkeypatch.setattr(sb_mod.subprocess, "run", fake_run)
    return _sandbox(tmp_path, run_fn=fake_run), killed


def test_interrupt_kills_the_running_container(tmp_path, monkeypatch):
    """Ctrl+C must not leave a container still sending packets at the target.

    Only TimeoutExpired triggered _kill_container. KeyboardInterrupt derives
    from BaseException, so it skipped the `except Exception` handler entirely:
    the docker CLI died and the container kept running in the daemon.
    """
    import pytest

    sb, killed = _interrupt_sandbox(tmp_path, KeyboardInterrupt(), monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        sb.spawn(["nmap", "-Pn", "-sT", "10.0.0.1"])
    assert len(killed) == 1, "the container must be killed before re-raising"


def test_interrupt_still_propagates(tmp_path, monkeypatch):
    """Cleanup must not swallow the interrupt — Ctrl+C has to stop the run."""
    import pytest

    sb, _ = _interrupt_sandbox(tmp_path, KeyboardInterrupt(), monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        sb.spawn(["nmap", "-Pn", "10.0.0.1"])


def test_system_exit_also_kills(tmp_path, monkeypatch):
    """A signal handler raising SystemExit is the same hazard."""
    import pytest

    sb, killed = _interrupt_sandbox(tmp_path, SystemExit(130), monkeypatch)
    with pytest.raises(SystemExit):
        sb.spawn(["nmap", "-Pn", "10.0.0.1"])
    assert len(killed) == 1


def test_normal_exception_does_not_kill(tmp_path, monkeypatch):
    """A docker-level failure that already exited must not fire a stray kill."""
    sb, killed = _interrupt_sandbox(
        tmp_path, RuntimeError("docker not found"), monkeypatch)
    result = sb.spawn(["nmap", "-Pn", "10.0.0.1"])
    assert result.ok is False
    assert "docker not found" in result.error
    assert killed == []


# ---- image source covers the production adapter executables (2B.5.1) -------

def test_image_source_covers_production_adapters():
    """Every production Mode B adapter's executable must be both built into
    the sandbox image source and entrypoint-allowlisted in it.

    WHY (Phase 2B.5.1): the released v1.3.8 image predates the 2B.3
    entrypoint change, so its ``httpx-toolkit`` binary sat behind a
    stale allowlist and every httpx-probe spawn got
    ``tool_not_in_allowlist`` (exit 125). The repo source was already
    right — nothing in CI verified THE IMAGE BUILD DESCRIPTION carries
    what the adapters can't live without. The generic
    test_entrypoint_allowlist_in_sync couples the HOST allowlist to the
    entrypoint; this test additionally couples the adapters (the
    consumers) to both source files by name, so the next image rebuild
    cannot ship an adapter-blocking image.
    """
    repo = Path(__file__).resolve().parents[1]
    entrypoint = (repo / "containers" / "sandbox" / "entrypoint.sh"
                  ).read_text(encoding="utf-8")
    dockerfile = (repo / "containers" / "sandbox" / "Dockerfile.kali"
                  ).read_text(encoding="utf-8")

    # entrypoint: every adapter executable allowlisted by its exact
    # quoted name (the entrypoint matches whole tokens, not substrings)
    for tool in ("httpx-toolkit", "whatweb", "searchsploit"):
        assert f'"{tool}"' in entrypoint, (
            f"{tool} missing from containers/sandbox/entrypoint.sh "
            "ALLOWED_TOOLS — adapter spawns would all be rejected "
            "with tool_not_in_allowlist")

    # build source: every adapter executable has a concrete install
    # statement (apt tool list; searchsploit ships with the exploitdb
    # package — the Dockerfile tokens below are the same eyeball-level
    # evidence test_allowlist.py already relies on for install-ness)
    build_tokens = {
        "httpx-toolkit": "httpx-toolkit" in dockerfile,
        "whatweb": "whatweb" in dockerfile,
        "searchsploit": "exploitdb" in dockerfile,
    }
    missing = [t for t, ok in build_tokens.items() if not ok]
    assert not missing, (
        f"containers/sandbox/Dockerfile.kali does not build: {missing}"
        " — a rebuilt image would lack the adapter executables")

