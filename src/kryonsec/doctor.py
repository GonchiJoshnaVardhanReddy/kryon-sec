"""`kryonsec doctor` — preflight checks (spec v2.1.1 §11.1).

Checks, in order: storage, LLM providers, Purple Team prerequisites.
Prints a pass/fail report. Purple Team refuses to start on failure.
"""

from __future__ import annotations

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

        # 8 s: a cold `ollama serve` can take several seconds to answer the
        # first /api/tags — 3 s reported "down" on machines where it was
        # merely still starting
        with urllib.request.urlopen(f"{host}/api/tags", timeout=8) as r:
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
    from .purple import runtime_checks

    return runtime_checks.docker_server_ok()


def _check_gvisor() -> tuple[bool, str]:
    from .purple import runtime_checks

    if runtime_checks.runsc_registered():
        return True, "OK (runsc registered)"
    return False, "runsc runtime not registered — gVisor missing"


def run_doctor(cfg: KryonsecConfig | None = None) -> int:
    """Run all checks; return exit code (0 = all pass)."""
    cfg = cfg or KryonsecConfig()
    is_linux = sys.platform.startswith("linux")

    # ok is None for deliberate skips (non-Linux platform) — rendered as
    # yellow SKIP, never as a red FAIL that looks like something broke
    checks: list[tuple[str, str, bool | None, str]] = []

    ok, msg = _check_storage(cfg)
    checks.append(("Storage", "", ok, msg))
    ok, msg = _check_ollama(cfg)
    checks.append(("LLM: Ollama (local)", "compaction with secrets, local chat", ok, msg))
    ok, msg = _check_openai(cfg)
    checks.append(("LLM: OpenAI", "third-party chat/analysis", ok, msg))

    checks.append((
        "Purple Team: platform", "gVisor requires Linux",
        True if is_linux else None,
        "OK (Linux)" if is_linux else "NOT Linux — this machine cannot run Purple Team",
    ))
    if is_linux:
        ok, msg = _check_docker()
        checks.append(("Purple Team: Docker", "sandbox host", ok, msg))
        if ok:
            ok, msg = _check_gvisor()
            checks.append(("Purple Team: gVisor (runsc)", "sandbox runtime", ok, msg))
            if ok:
                from .purple import runtime_checks

                image = cfg.sandbox_image
                if runtime_checks.image_present(image):
                    checks.append(("Purple Team: sandbox image", "Zone B tool container", True, f"OK ({image})"))
                else:
                    checks.append((
                        "Purple Team: sandbox image", "Zone B tool container", False,
                        f"missing: {image} — build with: docker build -t kryonsec/sandbox "
                        "-f containers/sandbox/Dockerfile.kali .",
                    ))
    else:
        checks.append((
            "Purple Team: Docker", "sandbox host", None,
            "skipped (non-Linux; use WSL2 or a Linux VM for Purple Team)",
        ))

    table = Table(title="kryonsec doctor")
    table.add_column("Check")
    table.add_column("Needed for")
    table.add_column("Result")
    for name, purpose, ok, msg in checks:
        # ASCII markers, not ✔/✘: doctor must render in ANY console,
        # including legacy cp1252 ones (it's the tool you run when
        # things are already broken)
        if ok is None:
            mark = "[yellow]SKIP[/yellow]"
        else:
            mark = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(name, purpose, f"{mark} {msg}")
    console.print(table)

    # exit code reflects the profile this machine can actually run, not
    # "every optional check passed": an Ollama-only Copilot user (fully
    # supported, wizard-configured) must not get exit 1
    storage_ok = checks[0][2]
    any_llm = checks[1][2] or checks[2][2]
    copilot_ok = storage_ok and any_llm
    # skipped rows count as "not available here", not "failed"
    purple_ok = all(ok is True for _, _, ok, _ in checks)

    from rich.panel import Panel

    if purple_ok:
        console.print(Panel(
            "[green]PASS — Profile 1 (Copilot) and Profile 2 (Purple Team) "
            "are both ready.[/green]",
            border_style="green",
        ))
    elif copilot_ok:
        console.print(Panel(
            "[green]PASS — Profile 1 (Copilot) is fully working on this machine.[/green]\n"
            "[yellow]Profile 2 (Purple Team) needs Linux + Docker + gVisor "
            "+ a PostgreSQL DATABASE_URL.[/yellow]",
            title="What works here",
            border_style="green",
        ))
    else:
        console.print(Panel(
            "[red]FAIL — Profile 1 (Copilot) is NOT usable: storage and at "
            "least one LLM provider must pass (see above).[/red]\n"
            "[yellow]Profile 2 (Purple Team) needs Linux + Docker + gVisor "
            "+ a PostgreSQL DATABASE_URL.[/yellow]",
            title="What works here",
            border_style="red",
        ))
    return 0 if copilot_ok else 1
