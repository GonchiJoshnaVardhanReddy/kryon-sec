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
    ):
        self.cfg = cfg
        self.image = cfg.sandbox_image
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
        self.timeout_s = timeout_s

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
        # NOTE: full spec adds network_mode=container:kryonsec-proxy for
        # target-scope-only egress (§8.2). The proxy does not exist yet —
        # containers use the default bridge. Recorded in the audit chain
        # by the EXPLOIT subagent until the proxy lands.
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
