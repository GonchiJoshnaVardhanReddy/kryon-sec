"""Kali sandbox spawn (spec v2.1.1 §8.5/§8.6).

Runs one allowlisted tool inside the gVisor sandbox container:
argv as container args (never a shell string), pinned image, runsc
runtime, resource limits, non-root user, read-only rootfs, bounded
output. The entrypoint inside the image re-checks the tool allowlist
(defense-in-depth) and emits JSON: {"exit_code": N, "stdout": "..."}.

The docker invocation is injectable so tests run anywhere; only the
real run needs Linux + Docker + runsc + the pinned image.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..config import KryonsecConfig

log = logging.getLogger(__name__)

# Match the entrypoint's internal tool timeout (300s) + a small margin.
DEFAULT_TIMEOUT_S = 330

# Mode-B execution invariant (hard, permanent): every tool launch must be
# gVisor-isolated. These are the docker-run flags that make a spawn
# containerized execution rather than host-equivalent execution; `spawn`
# refuses to launch if any of them is missing from the built argv, so a
# future refactor of `_docker_argv` cannot silently drop isolation.
# (flag, required-next-token, "" for a bare flag)
_REQUIRED_ISOLATION_FLAGS: tuple[tuple[str, str, str], ...] = (
    ("--runtime", "runsc", "gVisor (runsc) runtime"),
    ("--user", "kryonsec-runner", "non-root user"),
    ("--read-only", "", "read-only root filesystem"),
    ("--memory", "2g", "memory limit"),
    ("--cpus", "2", "CPU limit"),
    ("--pids-limit", "100", "process limit"),
)


def missing_isolation_flags(docker_argv: list[str]) -> list[str]:
    """The isolation requirements the launch argv fails to carry.

    Pure check over the exact docker argv that would be executed. A bare
    flag only requires presence; a paired flag requires its token to
    follow with the required value.
    """
    missing: list[str] = []
    for flag, expected, meaning in _REQUIRED_ISOLATION_FLAGS:
        if flag not in docker_argv:
            missing.append(f"{flag} ({meaning})")
        elif expected and (
            len(docker_argv) <= docker_argv.index(flag) + 1
            or docker_argv[docker_argv.index(flag) + 1] != expected
        ):
            missing.append(f"{flag}={expected} ({meaning})")
    return missing


# Networks that would defeat the egress boundary outright — rejected
# REGARDLESS of network_name checks. Hard-coded: no config can re-enable
# them while an egress policy is set.
_FORBIDDEN_NETWORKS = ("bridge", "host", "none")


def missing_egress_flags(
    docker_argv: list[str], policy, image: str | None = None,
) -> list[str]:
    """The egress requirements the launch argv fails/defrauds to carry.

    Only meaningful when an EgressPolicy is set (every Zone B spawn now
    has one): the argv must run on THIS engagement's dedicated network
    (exact name), with DNS pinned to EXACTLY the policy's resolver set,
    and must never carry a forbidden network (bridge/host/none). Pure —
    argv cannot talk its way past this. Only tokens BEFORE the image
    position are docker flags (tool argv continues after it); a tool
    argument spelled "--dns" after the image is not a docker flag and
    cannot redirect the container's DNS anyway (the host firewall
    enforces the resolver scope regardless).
    """
    problems: list[str] = []
    docker_section = docker_argv
    if image is not None and image in docker_argv:
        docker_section = docker_argv[:docker_argv.index(image)]
    networks = []
    i = 0
    while i < len(docker_section):
        if docker_section[i] == "--network":
            if i + 1 < len(docker_section):
                networks.append(docker_section[i + 1])
            else:
                networks.append("<unterminated>")
            i += 2
            continue
        i += 1
    net = networks[0] if networks else None
    if net is None:
        problems.append(
            f"--network {policy.network_name} — the engagement "
            "egress boundary")
    else:
        if net.lower() in _FORBIDDEN_NETWORKS:
            problems.append(
                f"--network {net} is forbidden under an egress policy")
        elif net != policy.network_name:
            problems.append(
                f"--network {net} != engagement network {policy.network_name}")
    dns = []
    i = 0
    while i < len(docker_section):
        if docker_section[i] == "--dns":
            if i + 1 < len(docker_section):
                dns.append(docker_section[i + 1])
            else:
                dns.append("<unterminated>")
            i += 2
            continue
        i += 1
    expected_dns = sorted(str(r) for r in policy.dns_resolvers)
    if sorted(dns) != expected_dns:
        problems.append(
            f"--dns {dns or '(none)'} != pinned resolvers {expected_dns}")
    return problems


@dataclass
class SpawnResult:
    ok: bool                 # did the spawn itself work (docker + parse)
    exit_code: int           # the TOOL's exit code (from the JSON payload)
    stdout: str              # the tool's raw output
    error: str = ""          # spawn/parse failure reason
    truncated: bool = False  # output was bounded


class SandboxSpawnError(RuntimeError):
    pass


def _seccomp_default() -> Path:
    """Shipped inside the package so installed wheels find it too."""
    return Path(__file__).resolve().parents[1] / "containers" / "kryonsec-seccomp.json"


class KaliSandbox:
    """Spawns tools in the pinned Kali/gVisor container."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        run_fn: Callable[..., subprocess.CompletedProcess] | None = None,
        seccomp_profile: Path | None = None,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        code_dir: str | None = None,
        evidence_dir: str | None = None,
        egress_policy=None,
        egress_gate=None,
    ):
        self.cfg = cfg
        self.image = cfg.sandbox_image
        # Phase 1E: the engagement's egress boundary. When set, EVERY
        # spawn runs on the dedicated engagement bridge network with DNS
        # pinned to the policy resolvers, and the gate is re-verified
        # before each launch (fail closed — see spawn()).
        self.egress_policy = egress_policy
        self.egress_gate = egress_gate
        # Blue-team code scanning (Phase 5): an ABSOLUTE host path, mounted
        # READ-ONLY at the fixed /code inside the container. The path comes
        # from the CLI (--code), never the LLM; a relative path is refused
        # outright rather than silently resolved against an unknown cwd.
        if code_dir is not None:
            # absolute on EITHER platform: production is Linux (posixpath),
            # but Windows dev machines hand us "C:\\..." paths — both are
            # fine, only a relative path (which would silently resolve
            # against an unknown cwd) is refused
            import posixpath

            if not (Path(code_dir).is_absolute() or posixpath.isabs(code_dir)):
                raise ValueError(
                    f"code_dir must be an absolute path (got {code_dir!r})")
            # stored verbatim — str(Path(...)) would mangle forward slashes
            # to backslashes on Windows dev machines
            self.code_dir = code_dir
        else:
            self.code_dir = None
        # Evidence capture (Phase 8): gowitness screenshots etc. — an
        # ABSOLUTE host path mounted READ-WRITE at the fixed /evidence.
        # It is the ONLY read-write mount (rootfs and /code stay read-only);
        # the path comes from the runner (engagement folder), never the LLM.
        if evidence_dir is not None:
            import posixpath

            if not (Path(evidence_dir).is_absolute() or posixpath.isabs(evidence_dir)):
                raise ValueError(
                    f"evidence_dir must be an absolute path (got {evidence_dir!r})")
            self.evidence_dir = evidence_dir  # verbatim, same rule as code_dir
        else:
            self.evidence_dir = None
        if "@sha256:" not in self.image:
            # rule 7: the image should be digest-pinned — a tag is mutable.
            # Still runnable (install.sh builds a local :latest) but flagged.
            log.warning(
                "sandbox image %r is NOT digest-pinned — set "
                "KRYONSEC_SANDBOX_IMAGE to kryonsec/sandbox@sha256:<digest> "
                "(docker inspect --format '{{.Id}}' kryonsec/sandbox)",
                self.image,
            )
        # injectable for tests: signature matches subprocess.run
        self._run = run_fn or subprocess.run
        self.seccomp_profile = seccomp_profile or _seccomp_default()
        if self.seccomp_profile and not Path(self.seccomp_profile).is_file():
            # M4: a missing packaged profile used to silently drop the
            # seccomp flag — sandbox hardening (CLAUDE.md rule 9) must be loud
            log.warning(
                "seccomp profile %s not found — sandbox spawns will run "
                "WITHOUT a seccomp filter (broken install? reinstall the "
                "package or set KRYONSEC_SECCOMP_PROFILE)",
                self.seccomp_profile,
            )
        self.timeout_s = timeout_s

    def copy_with(
        self, code_dir: str | None = None, evidence_dir: str | None = None
    ) -> "KaliSandbox":
        """Shallow copy with replaced mounts (same validation as __init__).

        The runner constructs ONE sandbox per engagement and derives
        per-state variants here — one construction also means one
        image-pin warning, not one per state (M5).
        """
        import posixpath

        clone = object.__new__(KaliSandbox)
        clone.__dict__.update(self.__dict__)
        if code_dir is not None:
            if not (Path(code_dir).is_absolute() or posixpath.isabs(code_dir)):
                raise ValueError(
                    f"code_dir must be an absolute path (got {code_dir!r})")
            clone.code_dir = code_dir  # verbatim, same rule as __init__
        if evidence_dir is not None:
            if not (Path(evidence_dir).is_absolute() or posixpath.isabs(evidence_dir)):
                raise ValueError(
                    f"evidence_dir must be an absolute path (got {evidence_dir!r})")
            clone.evidence_dir = evidence_dir
        return clone

    def _docker_argv(self, tool_argv: list[str]) -> list[str]:
        """Build the docker run argv. Tool argv as container args (spec §8.5)."""
        argv = [
            "docker", "run", "--rm",
            "--name", self._container_name(),
            "--runtime", "runsc",
            "--user", "kryonsec-runner",
            "--read-only",
            "--tmpfs", "/tmp:size=100m",
            "--memory", "2g",
            "--cpus", "2",
            "--pids-limit", "100",
        ]
        if self.seccomp_profile and Path(self.seccomp_profile).is_file():
            argv += ["--security-opt", f"seccomp={self.seccomp_profile}"]
        # read-only code mount (blue-team scanners, Phase 5): :ro so no
        # scanner can write to the user's folder; -w /code so tools with a
        # default cwd still find the code
        if getattr(self, "code_dir", None):
            argv += ["-v", f"{self.code_dir}:/code:ro", "-w", "/code"]
        # read-write evidence mount (Phase 8): gowitness screenshots etc.
        # land in the engagement folder. The ONLY rw mount — rootfs and
        # /code stay read-only, so a tool can only write here.
        if getattr(self, "evidence_dir", None):
            argv += ["-v", f"{self.evidence_dir}:/evidence:rw"]
        # Zone B network egress (Phase 1E): when the engagement has an
        # egress policy, every spawn runs on the DEDICATED engagement
        # bridge (never the default bridge), with DNS pinned to the
        # policy's resolver set. The host DOCKER-USER firewall (built by
        # EgressGate) filters every packet leaving that bridge; `spawn`
        # re-verifies the boundary before each launch and refuses to run
        # when it is missing or drifted.
        if getattr(self, "egress_policy", None) is not None:
            argv += ["--network", self.egress_policy.network_name]
            for resolver in self.egress_policy.dns_resolvers:
                argv += ["--dns", str(resolver)]
        argv += [self.image]
        argv += list(tool_argv)
        return argv

    def _container_name(self) -> str:
        """Per-spawn unique name so a timed-out container can be killed."""
        import uuid

        return f"kryonsec-sbx-{uuid.uuid4().hex[:12]}"

    def _kill_container(self, name: str) -> None:
        """Best-effort: a timed-out container keeps running on the daemon
        after its docker CLI client is killed — stop the container itself."""
        try:
            subprocess.run(
                ["docker", "kill", name], capture_output=True, timeout=15,
            )
        except Exception as e:  # never let cleanup mask the timeout report
            log.warning("could not kill sandbox container %s: %s", name, e)

    def spawn(self, tool_argv: list[str]) -> SpawnResult:
        """Run one tool in the sandbox; parse the entrypoint's JSON payload.

        tool_argv[0] is the tool name (must be allowlisted — the host-side
        ToolAllowlist check happens BEFORE this is called; the image's
        entrypoint re-checks it as defense-in-depth).
        """
        docker_argv = self._docker_argv(tool_argv)
        container_name = docker_argv[docker_argv.index("--name") + 1]
        log.info("sandbox spawn: %s", " ".join(docker_argv[:6]) + " …")

        # Mode-B execution invariant: refuse to launch when the isolation
        # flags are missing. Fail closed with a diagnostic — a spawn that
        # would run unisolated on the Docker daemon is not "a worse sandbox",
        # it is host-equivalent execution and must never happen instead of a
        # sandboxed one. Audited by every caller as a failed spawn.
        missing = missing_isolation_flags(docker_argv)
        if missing:
            error = (
                "sandbox isolation invariant broken — refusing to launch "
                f"{tool_argv[0]!r}: missing {', '.join(missing)}"
            )
            log.error(error)
            return SpawnResult(ok=False, exit_code=-1, stdout="", error=error)

        # Egress invariant (Phase 1E): when this engagement carries an
        # egress policy, the launch argv must run on the dedicated
        # engagement network with the pinned resolvers, and the boundary
        # must STILL be live — re-verified here, fail closed. A spawn
        # without a verified boundary would be default-bridge execution
        # and must never happen instead of a bounded one. Audited by
        # every caller as a failed spawn.
        if getattr(self, "egress_policy", None) is not None:
            egress_problems = missing_egress_flags(
                docker_argv, self.egress_policy, image=self.image)
            if not egress_problems and self.egress_gate is not None:
                ok, reason = self.egress_gate.verify(self.egress_policy)
                if not ok:
                    egress_problems.append(
                        f"egress boundary not verified: {reason}")
            if egress_problems:
                error = (
                    "sandbox egress invariant broken — refusing to launch "
                    f"{tool_argv[0]!r}: "
                    + "; ".join(egress_problems)
                )
                log.error(error)
                return SpawnResult(
                    ok=False, exit_code=-1, stdout="", error=error)

        try:
            proc = self._run(
                docker_argv,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired:
            # killing the docker CLI leaves the container running on the
            # daemon (still sending packets) — kill the container itself
            self._kill_container(container_name)
            return SpawnResult(
                ok=False, exit_code=-1, stdout="",
                error=f"tool exceeded {self.timeout_s}s sandbox timeout",
            )
        except Exception as e:
            return SpawnResult(ok=False, exit_code=-1, stdout="", error=str(e))
        except BaseException:
            # Ctrl+C during a long scan, or a signal handler raising
            # SystemExit. KeyboardInterrupt/SystemExit derive from
            # BaseException, so `except Exception` above never saw them: the
            # docker CLI died while the container kept running in the daemon,
            # still sending packets at the target after the operator believed
            # the engagement had stopped. Kill it, then let the interrupt
            # propagate so Ctrl+C still stops the run.
            self._kill_container(container_name)
            raise

        # The entrypoint prints one JSON object on stdout (rejections too —
        # exit 125 with {"error": ...}); anything else (docker-level error)
        # goes to stderr.
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            # the entrypoint writes its rejection JSON to stderr in older
            # images — try that before giving up on a payload
            try:
                payload = json.loads(proc.stderr)
            except (json.JSONDecodeError, TypeError):
                err = (proc.stderr or proc.stdout or "")[:500]
                return SpawnResult(
                    ok=False, exit_code=proc.returncode, stdout="",
                    error=f"no JSON payload from sandbox: {err}",
                )

        if "error" in payload:
            # the entrypoint rejected the tool (not in image allowlist)
            return SpawnResult(
                ok=False, exit_code=proc.returncode, stdout="",
                error=str(payload["error"]),
            )

        stdout = str(payload.get("stdout", ""))
        truncated = False
        limit = self.cfg.max_tool_output_chars
        if len(stdout) > limit:
            stdout = stdout[:limit]
            truncated = True

        return SpawnResult(
            ok=True,
            exit_code=int(payload.get("exit_code", proc.returncode)),
            stdout=stdout,
            truncated=truncated,
        )
