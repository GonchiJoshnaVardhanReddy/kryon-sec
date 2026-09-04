"""`kryonsec doctor` — preflight checks (spec v2.1.1 §11.1).

Checks, in order: storage, LLM providers, Purple Team prerequisites.
Prints a pass/fail report. Purple Team refuses to start on failure.
"""

from __future__ import annotations

import shutil
import sys

from rich.console import Console
from rich.table import Table

from .config import KryonsecConfig

console = Console()


def _check_storage(cfg: KryonsecConfig) -> tuple[bool, str]:
    try:
        cfg.ensure_dirs()
        from .storage import init_db

        init_db(cfg)
        kind = cfg.storage_kind
        return True, f"OK ({kind})"
    except Exception as e:  # pragma: no cover - environment-dependent
        return False, f"FAILED ({e})"


def _check_ollama(cfg: KryonsecConfig) -> tuple[bool, str]:
    from .llm import _normalize_ollama_host

    host = _normalize_ollama_host(cfg.ollama_host)
    try:
        import urllib.request

        with urllib.request.urlopen(f"{host}/api/tags", timeout=3) as r:
            if r.status == 200:
                return True, f"OK ({host})"
            return False, f"HTTP {r.status}"
    except Exception:
        return False, f"not reachable at {host} (local model unavailable)"


def _check_openai(cfg: KryonsecConfig) -> tuple[bool, str]:
    if cfg.openai_api_key:
        return True, "OK (OPENAI_API_KEY set)"
    return False, "OPENAI_API_KEY not set (third-party models unavailable)"


def _check_docker() -> tuple[bool, str]:
    docker = shutil.which("docker")
    if not docker:
        return False, "docker CLI not found"
    import subprocess

    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return True, f"OK (server {out.stdout.strip()})"
        return False, "daemon not reachable"
    except Exception as e:
        return False, str(e)


def _check_gvisor() -> tuple[bool, str]:
    import subprocess

    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{join .Runtimes \",\"}}"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0 and "runsc" in out.stdout:
            return True, "OK (runsc registered)"
        return False, "runsc runtime not registered — gVisor missing"
    except Exception as e:
        return False, str(e)


def run_doctor(cfg: KryonsecConfig | None = None) -> int:
    """Run all checks; return exit code (0 = all pass)."""
    cfg = cfg or KryonsecConfig()
    is_linux = sys.platform.startswith("linux")

    checks: list[tuple[str, str, bool, str]] = []

    ok, msg = _check_storage(cfg)
    checks.append(("Storage", "", ok, msg))
    ok, msg = _check_ollama(cfg)
    checks.append(("LLM: Ollama (local)", "compaction with secrets, local chat", ok, msg))
    ok, msg = _check_openai(cfg)
    checks.append(("LLM: OpenAI", "third-party chat/analysis", ok, msg))

    checks.append((
        "Purple Team: platform", "gVisor requires Linux",
        is_linux, "OK (Linux)" if is_linux else "NOT Linux — this machine cannot run Purple Team",
    ))
    if is_linux:
        ok, msg = _check_docker()
        checks.append(("Purple Team: Docker", "sandbox host", ok, msg))
        if ok:
            ok, msg = _check_gvisor()
            checks.append(("Purple Team: gVisor (runsc)", "sandbox runtime", ok, msg))
            if ok:
                from .purple.runner import _image_present

                image = cfg.sandbox_image
                if _image_present(image):
                    checks.append(("Purple Team: sandbox image", "Zone B tool container", True, f"OK ({image})"))
                else:
                    checks.append((
                        "Purple Team: sandbox image", "Zone B tool container", False,
                        f"missing: {image} — build with: docker build -t kryonsec/sandbox "
                        "-f containers/sandbox/Dockerfile.kali .",
                    ))
    else:
        checks.append((
            "Purple Team: Docker", "sandbox host", False,
            "skipped (non-Linux; use WSL2 or a Linux VM for Purple Team)",
        ))

    table = Table(title="kryonsec doctor")
    table.add_column("Check")
    table.add_column("Needed for")
    table.add_column("Result")
    for name, purpose, ok, msg in checks:
        table.add_row(
            name, purpose,
            f"[green]{'PASS' if ok else 'FAIL'}[/green] {msg}" if ok
            else f"[red]{'PASS' if ok else 'FAIL'}[/red] {msg}",
        )
    console.print(table)

    all_ok = all(ok for _, _, ok, _ in checks)
    if not all_ok:
        console.print(
            "\n[yellow]Profile 1 (Copilot) works if storage + at least one LLM provider pass.[/yellow]"
            "\n[yellow]Profile 2 (Purple Team) requires Linux + Docker + gVisor + PostgreSQL.[/yellow]"
        )
    return 0 if all_ok else 1
