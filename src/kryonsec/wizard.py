"""Interactive setup wizard (v1.1).

Two layers, deliberately separate:
- Pure functions (this file, top section): provider testing, model listing,
  selection rendering — no UI, fully unit-testable.
- Dialog layer (bottom): prompt_toolkit dialogs for a real terminal, with a
  numbered plain-input fallback for non-tty (same guard as tui.py).

The wizard is the ONLY writer of ~/.kryonsec/config.toml (see config.py).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .config import KryonsecConfig
from .llm import ollama_models

OPENAI_MODELS_URL = "https://api.openai.com/v1/models"
OPENAI_TIMEOUT_S = 15

# /v1/models returns everything ever created under the key; the wizard menu
# should show chat models. Excluded by id substring — err on showing fewer.
_NON_CHAT_SUBSTRINGS = (
    "embedding", "embed", "tts", "whisper", "moderation",
    "dall-e", "dalle", "realtime", "audio", "transcribe",
)


def check_openai_key(api_key: str) -> tuple[bool, str]:
    """Check an OpenAI key with a cheap authenticated GET.
    Returns (ok, message)."""
    if not api_key or not api_key.strip():
        return False, "empty key"
    req = urllib.request.Request(
        OPENAI_MODELS_URL,
        headers={"Authorization": f"Bearer {api_key.strip()}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT_S) as r:
            if r.status == 200:
                return True, "key works"
            return False, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, f"rejected (HTTP {e.code}) — wrong or revoked key"
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"network error: {e}"


def list_openai_models(api_key: str) -> list[dict[str, Any]] | None:
    """Chat-capable models for the key, most recent first.
    None = request failed (caller shows an error); [] = key fine but no
    models survived the filter."""
    req = urllib.request.Request(
        OPENAI_MODELS_URL,
        headers={"Authorization": f"Bearer {api_key.strip()}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT_S) as r:
            data = json.loads(r.read())
    except Exception:
        return None
    models = data.get("data", [])
    chat_models = [
        m for m in models
        if not any(s in m.get("id", "").lower() for s in _NON_CHAT_SUBSTRINGS)
    ]
    chat_models.sort(key=lambda m: m.get("created", 0), reverse=True)
    return chat_models


def ollama_model_names(host: str) -> list[str] | None:
    """Models pulled on the Ollama server (None = server down)."""
    return ollama_models(host)


# MCP servers offered in the wizard menu (preset list; users can add custom).
# command is what runs in a shell to start the stdio server.
# args marked "{ask}" are filled in by asking the user during setup.
MCP_PRESETS = [
    {
        "name": "fetch",
        "command": "uvx mcp-server-fetch",
        "args": [],
        "env": {},
        "description": "fetch web pages as clean text (no API key needed)",
    },
    {
        "name": "filesystem",
        "command": "npx -y @modelcontextprotocol/server-filesystem",
        "args": ["{ask}"],  # allowed directory — the server refuses to start without one
        "env": {},
        "description": "file access through the MCP standard (needs node)",
    },
]


# ===========================================================================
# Dialog layer — prompt_toolkit on a real terminal, numbered prompts when
# stdin is not a tty (same guard pattern as tui.py). Every interactive
# step has a pure "pick" function so the flow is unit-testable.
# ===========================================================================

from pathlib import Path
import sys


def _is_tty() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


BANNER = r"""
  ██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗███████╗███████╗ ██████╗
  ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔════╝
  █████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║███████╗█████╗  ██║
  ██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║╚════██║██╔══╝  ██║
  ██║  ██║██║  ██║   ██║   ╚██████╔╝██║ ╚████║███████║███████║╚██████╗
  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝
"""


def _pick_provider(answers: list[str] | None = None) -> str:
    """Provider choice. answers is the plain-input fallback queue (tests)."""
    if _is_tty() and not answers:
        from prompt_toolkit.shortcuts import radiolist_dialog

        result = radiolist_dialog(
            title="Kryonsec setup — LLM provider",
            text="Which LLM provider do you want to use?",
            values=[("openai", "OpenAI (needs an API key)"),
                    ("ollama", "Ollama (local, free)")],
        ).run()
        if result is None:
            raise KeyboardInterrupt
        return result
    answer = (answers or []).pop(0) if answers else input(
        "LLM provider?\n  1. OpenAI (needs an API key)\n  2. Ollama (local, free)\n> ")
    answer = answer.strip().lower()
    return "openai" if answer in ("1", "openai", "o") else "ollama"


def _ask_key(answers: list[str] | None = None) -> str:
    if _is_tty() and not answers:
        from prompt_toolkit.shortcuts import input_dialog

        result = input_dialog(
            title="OpenAI API key",
            text="Paste your OpenAI API key (sk-…):",
            password=True,
        ).run()
        if result is None:
            raise KeyboardInterrupt
        return result.strip()
    return (answers or []).pop(0).strip() if answers else input("OpenAI API key: ").strip()


def _pick_model(models: list[str], answers: list[str] | None = None) -> str:
    """Choose one model from a list, most-recent-first."""
    if _is_tty() and not answers:
        from prompt_toolkit.shortcuts import radiolist_dialog

        result = radiolist_dialog(
            title="Choose your model",
            text=f"{len(models)} models available (most recent first). Pick one:",
            values=[(m, m) for m in models],
        ).run()
        if result is None:
            raise KeyboardInterrupt
        return result
    print("Available models (most recent first):")
    for i, m in enumerate(models, 1):
        print(f"  {i}. {m}")
    raw = (answers or []).pop(0) if answers else input("model number: ")
    raw = raw.strip()
    if raw.isdigit() and 1 <= int(raw) <= len(models):
        return models[int(raw) - 1]
    # free text: accept if it matches an entry (or as a raw model id)
    for m in models:
        if m == raw:
            return raw
    return raw  # trust it — the provider test already ran / caller validates


def _pick_many(
    title: str,
    options: list[tuple[str, str]],  # (value, label)
    answers: list[str] | None = None,
) -> list[str]:
    """Multi-select: space toggles + enter accepts (dialog); comma numbers
    in plain mode (e.g. '1,3'). Blank = none selected."""
    if _is_tty() and not answers:
        from prompt_toolkit.shortcuts import checkboxlist_dialog

        result = checkboxlist_dialog(
            title=title,
            text="Space to select/deselect, Enter to continue",
            values=options,
        ).run()
        if result is None:
            return []
        return list(result)
    print(title)
    for i, (_, label) in enumerate(options, 1):
        print(f"  {i}. {label}")
    raw = (answers or []).pop(0) if answers else input("numbers (e.g. 1,3; blank = none): ")
    picked: list[str] = []
    for part in raw.replace(" ", "").split(","):
        if part.isdigit() and 1 <= int(part) <= len(options):
            picked.append(options[int(part) - 1][0])
    return picked


def run_setup(cfg: KryonsecConfig, answers: list[str] | None = None) -> KryonsecConfig:
    """The full wizard flow. Mutates and returns cfg; writes config.toml
    on success. answers: scripted plain-mode input (tests / pipes)."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    console.print(Panel.fit("[bold cyan]KRYONSEC SETUP[/bold cyan] — first-time configuration"))

    # ---- 1. provider + key + model --------------------------------------
    provider = _pick_provider(answers)
    cfg.provider = provider

    if provider == "openai":
        while True:
            key = _ask_key(answers)
            ok, msg = check_openai_key(key)
            if ok:
                break
            console.print(f"[red]key check failed:[/red] {msg}")
            retry = (answers or []).pop(0) if answers else input("try again? [Y/n]: ")
            if retry.strip().lower().startswith("n"):
                console.print("[yellow]setup aborted — no provider configured[/yellow]")
                return cfg
        cfg.openai_api_key = key
        models = list_openai_models(key)
        model_ids = [m["id"] for m in (models or [])]
        if not model_ids:
            # key works but listing failed/empty — fall back to typing it
            console.print("[yellow]could not list models — type the model id manually[/yellow]")
            model_ids = [((answers or []).pop(0) if answers else input("model id: ")).strip()]
        model = _pick_model(model_ids, answers)
        cfg.general_chat_model = model
        if not model.startswith("gpt"):
            # a custom id may need the openai/ prefix for litellm routing
            cfg.general_chat_model = f"openai/{model}"
        cfg.general_search_model = "gpt-4o-mini"
        cfg.compaction_model = "gpt-4o-mini"
        cfg.local_model = "ollama/llama3.1"  # local fallback stays available
    else:
        names = ollama_model_names(cfg.ollama_host)
        if not names:
            console.print(
                "[yellow]Ollama not answering at "
                f"{cfg.ollama_host}[/yellow]\n"
                "  start it (`ollama serve`) and pull a model "
                "(`ollama pull llama3.1`), then re-run `kryonsec setup`."
            )
            return cfg
        model = _pick_model(names, answers)
        base = model.split(":")[0]  # tag suffix (':latest') is not part of the id
        cfg.general_chat_model = f"ollama/{base}"
        cfg.local_model = f"ollama/{base}"
        # strict provider isolation: ollama config never calls a hosted API
        cfg.general_search_model = f"ollama/{base}"
        cfg.compaction_model = f"ollama/{base}"
        cfg.openai_api_key = cfg.openai_api_key or None

    # ---- 2. built-in tools ----------------------------------------------
    from .config import BUILTIN_TOOLS

    picked = _pick_many(
        "Built-in tools for the general agent",
        [(t, t) for t in BUILTIN_TOOLS],
        answers,
    )
    cfg.enabled_tools = picked or []

    # ---- 3. MCP servers ---------------------------------------------------
    mcp_options = [(p["name"], f"{p['name']} — {p['description']}") for p in MCP_PRESETS]
    mcp_options.append(("__custom__", "add a custom MCP server…"))
    picked_mcp = _pick_many("MCP servers (optional)", mcp_options, answers)

    servers: list[dict] = []
    for preset in MCP_PRESETS:
        if preset["name"] not in picked_mcp:
            continue
        args = list(preset["args"])
        if "{ask}" in args:
            # e.g. the filesystem server needs an allowed directory
            default_dir = str(Path.home())
            prompt = (
                f"{preset['name']}: allowed directory (Enter = {default_dir}, "
                "'none' to skip this tool): "
            )
            raw = (answers or []).pop(0) if answers else input(prompt)
            raw = raw.strip()
            if raw.lower() in ("none", "skip"):
                console.print(f"[yellow]{preset['name']} skipped[/yellow]")
                continue
            args = [raw or default_dir]
        servers.append({
            "name": preset["name"],
            "command": preset["command"],
            "args": args,
            "env": dict(preset["env"]),
        })
    if "__custom__" in picked_mcp:
        name = (answers or []).pop(0) if answers else input("server name: ")
        command = (answers or []).pop(0) if answers else input("command to start it: ")
        if name.strip() and command.strip():
            servers.append({"name": name.strip(), "command": command.strip(), "args": [], "env": {}})
    cfg.mcp_servers = servers

    # ---- 4. banner + summary + write --------------------------------------
    cfg.ensure_dirs()
    cfg.save()

    console.print(f"[bold white]{BANNER}[/bold white]")
    table = Table(title="KRYONSEC IS READY", show_header=False)
    table.add_column(style="dim")
    table.add_column(style="bold")
    table.add_row("provider", cfg.provider)
    table.add_row("chat model", cfg.general_chat_model)
    table.add_row("local model", cfg.local_model)
    table.add_row("tools", ", ".join(cfg.enabled_tools) or "none")
    table.add_row("mcp servers", ", ".join(s["name"] for s in cfg.mcp_servers) or "none")
    table.add_row("workspace", str(cfg.workspace))
    table.add_row("config", str(Path(cfg.home) / "config.toml"))
    console.print(table)
    console.print("[green]type `kryonsec` to start.[/green]")
    return cfg

