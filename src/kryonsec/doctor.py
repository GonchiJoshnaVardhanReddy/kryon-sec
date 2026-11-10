"""`kryonsec doctor` — preflight checks (spec v2.1.1 §11.1).

Checks, in order: storage, LLM providers, Purple Team prerequisites.
Prints a pass/fail report. Purple Team refuses to start on failure.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.table import Table

from .config import KryonsecConfig
from . import __version__

console = Console()


def _check_storage(cfg: KryonsecConfig) -> tuple[bool, str]:
    """Check storage without creating directories or applying migrations.

    Doctor is a preflight command.  Startup and engagement execution remain
    responsible for schema creation; a diagnostic command must not mutate a
    user's home merely because it was run to understand a failure.
    """
    try:
        if cfg.database_url:
            from sqlalchemy import create_engine
            from .storage.db import _normalize_database_url

            engine = create_engine(_normalize_database_url(cfg.database_url), future=True)
            try:
                with engine.connect():
                    pass
            finally:
                engine.dispose()
            return True, f"reachable ({cfg.storage_kind}; schema not modified)"

        path = cfg.fallback_db_path
        if not path.exists():
            return True, f"SQLite fallback not initialized yet ({path}); first use will create it"
        import sqlite3

        uri = f"file:{path.as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            connection.execute("PRAGMA schema_version").fetchone()
        finally:
            connection.close()
        return True, f"reachable (SQLite fallback; schema not modified)"
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


def _check_bedrock(cfg: KryonsecConfig) -> tuple[bool, str]:
    # Deliberately offline: doctor must stay fast, and the setup wizard
    # already proved the key by probing every region (bedrock.probe_regions).
    # The region is echoed because a Bedrock call sent to the wrong region
    # is the most common failure and is otherwise invisible here.
    if cfg.bedrock_api_key:
        return True, f"OK (Bedrock API key set, region {cfg.bedrock_region})"
    return False, "no Bedrock API key (run `kryonsec setup`)"


def _check_openai_compatible(cfg: KryonsecConfig) -> tuple[bool, str]:
    # A live check, like the Ollama row and unlike the Bedrock one: an
    # endpoint that is simply not running is the failure this row exists to
    # catch, and GET /models is cheap. The key is passed straight through to
    # the request headers and never appears in the message.
    if not cfg.openai_compatible_base_url:
        return False, "no base URL configured (run `kryonsec setup`)"
    if not cfg.general_chat_model:
        # the endpoint may be perfectly reachable — the config is what is
        # incomplete, and saying "not reachable" here would send the user
        # to debug their server instead of running setup
        return False, "no model configured (run `kryonsec setup`)"

    from .llm import normalize_base_url
    from .openai_compatible import list_models

    base = normalize_base_url(cfg.openai_compatible_base_url)
    if list_models(base, cfg.openai_compatible_api_key) is None:
        return False, f"not reachable at {base} (endpoint down, or URL wrong)"
    return True, f"OK ({base})"


def _check_membership(cfg: KryonsecConfig) -> tuple[bool | None, str]:
    """The paid gate, reported honestly.

    Tri-state on purpose. No key is a SKIP, not a FAIL: a Copilot-only
    install is fully supported and free, and a red row would tell those
    users something is broken when nothing is.

    `verify()` phones home at most once a day, so this is normally a cache
    read — the one time it isn't is the one time the answer matters.
    """
    from .license import member_email, verify

    if not cfg.license_key:
        return None, "no membership key — Copilot mode only, which is free"

    result = verify(cfg)
    who = member_email(cfg)
    # Which machine, not just whether: the key being fine and this box not
    # being registered are different problems with different fixes.
    where = (
        f"machine connected as {who}" if who
        else "this machine is NOT connected — run `kryonsec connect`"
    )
    if result.purple_allowed:
        return True, f"OK ({result.status}; {where})"
    return False, f"{result.status} — {result.message}; {where}"


def _check_docker() -> tuple[bool, str]:
    from .purple import runtime_checks

    return runtime_checks.docker_server_ok()


def _check_gvisor() -> tuple[bool, str]:
    from .purple import runtime_checks

    if runtime_checks.runsc_registered():
        return True, "OK (runsc registered)"
    # a bare "gVisor missing" sends the user to re-run an install that may have
    # already "succeeded" — the hint carries the actual fix (and names Docker
    # Desktop, where the standard install can never take effect)
    return False, runtime_checks.gvisor_fix_hint()


def _egress_firewall_row() -> tuple[bool | None, str]:
    """Zone B network-boundary prerequisite (Phase 1E). None = skipped."""
    from .purple import runtime_checks

    if not sys.platform.startswith("linux"):
        return None, (
            "not checked on this host — the egress boundary is a "
            "Linux host firewall, and Purple Team is Linux-only"
        )
    ok, msg = runtime_checks.egress_firewall_ok()
    return ok, msg


def _check_config(cfg: KryonsecConfig) -> tuple[bool | None, str]:
    """Check an existing config without creating or rewriting it."""
    from .config import config_file_error, config_path

    path = config_path(cfg.home)
    if not path.exists():
        return None, f"not configured yet ({path}); run `kryonsec setup`"
    error = config_file_error(path)
    if error:
        return False, f"{error}; preserve a backup, repair TOML, then re-run setup"
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = 0
    permission_note = ""
    if sys.platform != "win32" and mode & 0o077:
        permission_note = (
            f"; permissions are {mode:o}, run `chmod 600 {path}`"
        )
    return True, f"valid TOML at {path}{permission_note}"


def _docker_context_row() -> tuple[str, str]:
    from .purple import runtime_checks

    context = runtime_checks.docker_context_info()
    if context.error:
        return "FAIL", (
            f"{context.error}; check Docker installation and the selected "
            "context before changing anything"
        )
    contexts = ", ".join(context.contexts) if context.contexts else "unknown"
    detail = (
        f"selected context {context.name}; endpoint {context.endpoint}; "
        f"available contexts: {contexts}"
    )
    if context.docker_host_override:
        return "WARNING", (
            f"{detail}; DOCKER_HOST overrides context selection — unset it "
            "only if this is not the intended daemon"
        )
    if len(context.contexts) > 1:
        return "WARNING", (
            f"{detail}; multiple contexts exist, and Kryonsec will not switch "
            "between them automatically"
        )
    return "PASS", detail


def _docker_versions_row() -> tuple[str, str]:
    from .purple import runtime_checks

    client, server = runtime_checks.docker_version()
    info = runtime_checks.docker_info()
    if not client and not server:
        return "WARNING", (
            "Docker version details unavailable; daemon connectivity may still "
            "be usable, but client/server compatibility is unverified"
        )
    if not server:
        return "WARNING", (
            f"client {client or 'unknown'}, server unavailable; the selected "
            "daemon cannot be validated"
        )
    suffix = ""
    if info:
        suffix = (
            f", daemon OS {info.operating_system or 'unknown'}, "
            f"architecture {info.architecture or 'unknown'}, "
            f"default runtime {info.default_runtime or 'unknown'}"
        )
    return "PASS", f"client {client or 'unknown'}, server {server}{suffix}"


def _runsc_local_row() -> tuple[str, str]:
    from .purple import runtime_checks

    context = runtime_checks.docker_context_info()
    path, version = runtime_checks.runsc_info()
    # A local binary is not evidence about an SSH/TCP daemon. Registration on
    # that daemon is checked separately from docker info.
    endpoint = context.endpoint.lower()
    remote = endpoint.startswith(("ssh://", "tcp://", "http://", "https://"))
    if remote and not path:
        return "PASS", (
            f"selected daemon is remote ({context.endpoint}); local runsc is "
            "not required; daemon registration is the authoritative check"
        )
    if not path:
        return "FAIL", (
            "runsc is not installed on this host; install the gVisor package "
            "on the selected daemon host (administrator change; no service "
            "restart is performed by Kryonsec)"
        )
    arch = runtime_checks._normalise_arch(__import__("platform").machine())
    return "PASS", f"runsc {version} at {path}; host architecture {arch}"


def _image_row(cfg: KryonsecConfig) -> tuple[str, str]:
    from .purple import runtime_checks

    info = runtime_checks.docker_info()
    check = runtime_checks.validate_image(
        cfg.sandbox_image,
        expected_version=__version__,
        server_architecture=info.architecture if info else None,
    )
    return check.status, check.detail


def _runtime_smoke_row(cfg: KryonsecConfig) -> tuple[str, str]:
    from .purple import runtime_checks

    ok, detail = runtime_checks.runtime_smoke_test(cfg.sandbox_image)
    if ok:
        return "PASS", detail
    return "FAIL", (
        f"{detail}; this proves the configured runsc runtime cannot start the "
        "sandbox. No fallback to runc is allowed"
    )


def run_doctor(
    cfg: KryonsecConfig | None = None,
    *,
    deep: bool = False,
    strict: bool = False,
) -> int:
    """Run the actual preflight checks; return 0 when Copilot is usable.

    ``deep`` adds a harmless, network-disabled container create/start/remove
    test. The normal command remains read-only with respect to the host and
    Docker daemon configuration.
    """
    cfg = cfg or KryonsecConfig()
    is_linux = sys.platform.startswith("linux")

    # status is one of PASS, FAIL, WARNING, SKIPPED. Keeping it as a string
    # avoids treating a warning as a successful Purple prerequisite.
    checks: list[tuple[str, str, str, str]] = []
    purple_names: list[str] = []

    def add(name: str, purpose: str, status: str, message: str, *, purple: bool = False):
        checks.append((name, purpose, status, message))
        if purple:
            purple_names.append(status)

    storage_ok, storage_msg = _check_storage(cfg)
    add("Storage", "Copilot memory", "PASS" if storage_ok else "FAIL", storage_msg)

    config_ok, config_msg = _check_config(cfg)
    add(
        "Configuration",
        "first run and provider selection",
        "SKIPPED" if config_ok is None else ("PASS" if config_ok else "FAIL"),
        config_msg,
    )

    # The selected provider is required. Other providers are optional and are
    # not contacted merely because they happen to have credentials in the
    # environment.
    provider_checks = (
        ("ollama", "LLM: Ollama (local)", "local chat / secret handling", _check_ollama),
        ("openai", "LLM: OpenAI", "third-party chat/analysis", _check_openai),
        ("bedrock", "LLM: AWS Bedrock", "third-party chat/analysis", _check_bedrock),
        ("openai_compatible", "LLM: OpenAI-compatible", "configured endpoint", _check_openai_compatible),
    )
    selected_llm_ok = False
    selected_provider_seen = False
    for provider, name, purpose, check in provider_checks:
        selected = cfg.provider == provider
        if selected:
            selected_provider_seen = True
            ok, msg = check(cfg)
            status = "PASS" if ok else "FAIL"
            selected_llm_ok = ok
        else:
            status = "SKIPPED"
            msg = "optional provider not selected"
        add(name, purpose, status, msg)

    if not selected_provider_seen:
        add(
            "LLM provider selection",
            "Copilot chat",
            "FAIL",
            f"unknown provider {cfg.provider!r}; run `kryonsec setup`",
        )

    membership_ok, membership_msg = _check_membership(cfg)
    add(
        "Membership",
        "Purple Team access",
        "SKIPPED" if membership_ok is None else ("PASS" if membership_ok else "FAIL"),
        membership_msg,
        purple=True,
    )

    if not is_linux:
        add(
            "Purple Team: platform",
            "Linux + gVisor",
            "SKIPPED",
            "this host is not Linux; use WSL2 with a Linux daemon or a Linux VM",
            purple=True,
        )
        add(
            "Purple Team: Docker",
            "selected sandbox daemon",
            "SKIPPED",
            "not checked on this host because Purple Team is Linux-only",
            purple=True,
        )
    else:
        add("Purple Team: platform", "Linux + gVisor", "PASS", "Linux host", purple=True)
        docker_ok, docker_msg = _check_docker()
        add(
            "Purple Team: Docker",
            "selected sandbox daemon",
            "PASS" if docker_ok else "FAIL",
            docker_msg,
            purple=True,
        )
        if docker_ok:
            context_status, context_msg = _docker_context_row()
            add("Docker context", "daemon selection", context_status, context_msg, purple=True)
            version_status, version_msg = _docker_versions_row()
            add("Docker versions", "client/server compatibility", version_status, version_msg, purple=True)

            runsc_status, runsc_msg = _runsc_local_row()
            add("gVisor binary", "local daemon host", runsc_status, runsc_msg, purple=True)
            registered, registered_msg = _check_gvisor()
            add(
                "gVisor registration",
                "the selected Docker daemon",
                "PASS" if registered else "FAIL",
                registered_msg,
                purple=True,
            )
            egress_ok, egress_msg = _egress_firewall_row()
            status = "SKIPPED" if egress_ok is None else (
                "PASS" if egress_ok else "FAIL")
            add(
                "Egress firewall",
                "Zone B network boundary (Phase 1E)",
                status,
                egress_msg,
                purple=True,
            )
            if registered:
                image_status, image_msg = _image_row(cfg)
                add(
                    "Sandbox image",
                    "architecture, entrypoint, version, digest",
                    image_status,
                    image_msg,
                    purple=True,
                )
                if deep and image_status in ("PASS", "WARNING"):
                    smoke_status, smoke_msg = _runtime_smoke_row(cfg)
                    add(
                        "gVisor runtime smoke",
                        "actual container lifecycle",
                        smoke_status,
                        smoke_msg,
                        purple=True,
                    )
                elif not deep:
                    add(
                        "gVisor runtime smoke",
                        "actual container lifecycle",
                        "SKIPPED",
                        "run `kryonsec doctor --deep` to create a harmless network-disabled test container",
                        purple=True,
                    )
        else:
            add(
                "Docker context",
                "daemon selection",
                "SKIPPED",
                "daemon is unavailable; context and image checks cannot be trusted",
                purple=True,
            )
            add(
                "gVisor registration",
                "the selected Docker daemon",
                "SKIPPED",
                "daemon is unavailable; local runsc alone is not sufficient",
                purple=True,
            )
            add(
                "Sandbox image",
                "architecture, entrypoint, version, digest",
                "SKIPPED",
                "daemon is unavailable; image presence cannot be verified",
                purple=True,
            )

    table = Table(title="kryonsec doctor")
    table.add_column("Check")
    table.add_column("Needed for")
    table.add_column("Result / detected state / next safe action")
    for name, purpose, status, msg in checks:
        colours = {
            "PASS": "green",
            "FAIL": "red",
            "WARNING": "yellow",
            "SKIPPED": "yellow",
        }
        mark = f"[{colours.get(status, 'white')}]{status}[/{colours.get(status, 'white')}]"
        table.add_row(name, purpose, f"{mark} {msg}")
    console.print(table)

    copilot_ok = bool(storage_ok and selected_llm_ok and config_ok is not False)
    purple_ok = bool(purple_names) and all(status == "PASS" for status in purple_names)

    from rich.panel import Panel

    if purple_ok and copilot_ok:
        console.print(Panel(
            "[green]PASS — Copilot and the verified Purple Team runtime are ready.[/green]",
            border_style="green",
        ))
    elif copilot_ok:
        console.print(Panel(
            "[green]PASS — Profile 1 (Copilot) is usable.[/green]\n"
            "[yellow]Purple Team is not ready. Review every FAIL/WARNING/SKIPPED "
            "row; it requires Linux, the selected Docker daemon, registered "
            "gVisor, a compatible sandbox image, and membership.[/yellow]",
            title="What works here",
            border_style="green",
        ))
    else:
        console.print(Panel(
            "[red]FAIL — Profile 1 (Copilot) is not usable: storage and the "
            "selected LLM provider must pass.[/red]\n"
            "[yellow]Purple Team is independently gated and will not fall back "
            "to an unisolated runtime.[/yellow]",
            title="What works here",
            border_style="red",
        ))
    if strict:
        return 0 if copilot_ok and purple_ok else 1
    return 0 if copilot_ok else 1
