"""Kryonsec configuration (spec v2.1.1 §11).

Profile 1 (Copilot, any OS):
  - storage: PostgreSQL via DATABASE_URL, else embedded fallback (SQLite)
  - no Docker / gVisor / Redis / MinIO / Ollama required

Profile 2 (Purple Team, Linux only):
  - full stack: PostgreSQL, Redis, MinIO, Ollama, Docker + gVisor

Since v1.1 the primary config source is ~/.kryonsec/config.toml, written by
`kryonsec setup`. Environment variables still override TOML values (power
users, CI); the old .env loading is gone.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

CONFIG_FILENAME = "config.toml"

# built-in agent tools selectable in the setup wizard
BUILTIN_TOOLS = ["file_read", "file_write", "web_search", "cve_lookup"]


def config_path(home: Path | None = None) -> Path:
    home = home or Path(os.environ.get("KRYONSEC_HOME", str(Path.home() / ".kryonsec")))
    return home / CONFIG_FILENAME


def _default_home() -> Path:
    return Path(os.environ.get("KRYONSEC_HOME", str(Path.home() / ".kryonsec")))


def _default_workspace() -> Path:
    return Path(os.environ.get("KRYONSEC_WORKSPACE", str(Path.home() / "kryonsec" / "workspace")))


# ---- TOML (tiny hand-rolled writer — str/int/bool/list-of-str, plus
# array-of-tables for the MCP server entries) -------------------------------

def _toml_escape(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)
    if isinstance(value, str):
        return _toml_escape(value)
    if isinstance(value, list) and all(not isinstance(v, dict) for v in value):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    raise TypeError(f"cannot serialize {type(value).__name__} to TOML "
                    "(nested tables go through the array-of-tables path)")


def _flatten(prefix: str, table: dict, lines: list[str]) -> None:
    """One table's scalar/list values; dict-valued keys must be lists of
    tables handled by the caller (write_config)."""
    for key, value in table.items():
        if isinstance(value, dict):
            raise TypeError(
                f"nested table {prefix}{key} — only one level of tables "
                "plus [[array-of-tables]] is supported")
        lines.append(f"{key} = {_toml_value(value)}")


def write_config(path: Path, data: dict) -> Path:
    """Write a nested dict as TOML. Supported shapes: scalars, lists of
    scalars, one level of [tables], and [[array-of-tables]] (a table
    value that is a LIST of dicts, e.g. mcp.servers)."""
    lines: list[str] = []
    # scalar keys go before any [table] (TOML requirement)
    for key, value in data.items():
        if not isinstance(value, dict):
            lines.append(f"{key} = {_toml_value(value)}")
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        # split scalar values from array-of-tables entries
        scalars = {k: v for k, v in value.items()
                   if not (isinstance(v, list) and v
                           and all(isinstance(e, dict) for e in v))}
        arrays = {k: v for k, v in value.items()
                  if k not in scalars}
        lines.append("")
        lines.append(f"[{key}]")
        _flatten(key, scalars, lines)
        for arr_key, entries in arrays.items():
            for entry in entries:
                lines.append("")
                lines.append(f"[[{key}.{arr_key}]]")
                _flatten(f"{key}.{arr_key}", entry, lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:  # restrict to owner where the OS supports it (the file holds the API key)
        path.chmod(0o600)
    except OSError:  # pragma: no cover - Windows
        pass
    return path


def read_config(path: Path) -> dict:
    """Read TOML config; missing file -> empty dict."""
    import tomllib

    if not path.is_file():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def _server_from_row(row: dict) -> dict:
    """Normalize one MCP server row from TOML: env comes back as a JSON
    string (see to_toml_dict) — decode it; tolerate an already-decoded dict."""
    import json as _json

    server = dict(row)
    env = server.get("env", {})
    if isinstance(env, str):
        try:
            env = _json.loads(env or "{}")
        except ValueError:
            env = {}
    server["env"] = env if isinstance(env, dict) else {}
    return server


@dataclass
class KryonsecConfig:
    """Runtime configuration. TOML first, environment overrides."""

    home: Path = field(default_factory=_default_home)
    workspace: Path = field(default_factory=_default_workspace)

    database_url: str | None = field(
        default_factory=lambda: os.environ.get("DATABASE_URL")
    )
    ollama_host: str = field(
        default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    )
    openai_api_key: str | None = field(
        default_factory=lambda: os.environ.get("OPENAI_API_KEY")
    )

    # --- LLM routing (spec §7.1) ---
    provider: str = "openai"  # "openai" | "ollama"
    general_chat_model: str = "ollama/llama3.1"
    general_search_model: str = "gpt-4o-mini"
    compaction_model: str = "gpt-4o-mini"
    # Local fallback: used whenever secrets are detected (spec §6.4)
    # or when the preferred provider is unavailable.
    local_model: str = "ollama/llama3.1"

    # --- Agent tools (v1.1) ---
    enabled_tools: list[str] = field(default_factory=lambda: list(BUILTIN_TOOLS))

    # --- MCP servers (v1.1): [{name, command, args, env, enabled}] ---
    mcp_servers: list[dict] = field(default_factory=list)

    # --- Session STM limits (spec §3.4) ---
    max_session_tokens: int = 16000
    compaction_trigger_ratio: float = 0.8
    compaction_keep_tokens: int = 8000
    max_messages: int = 50

    # --- Output bounding (safety Layer 10) ---
    max_tool_output_chars: int = 20000

    # --- Zone B sandbox (spec §8.5/§8.6) ---
    # Tag until a digest is pinned (docker inspect after the smoke test);
    # KRYONSEC_SANDBOX_IMAGE may hold "kryonsec/sandbox@sha256:<digest>".
    sandbox_image: str = field(
        default_factory=lambda: os.environ.get(
            "KRYONSEC_SANDBOX_IMAGE", "kryonsec/sandbox:latest"
        )
    )

    # ---- TOML (de)serialization -----------------------------------------

    def to_toml_dict(self) -> dict:
        """The config as a plain dict for write_config(). MCP server env
        dicts are stored as JSON strings (the tiny TOML writer supports
        scalars, scalar lists, and [[array-of-tables]] — not nested dicts)."""
        import json as _json

        def server_row(s: dict) -> dict:
            row = dict(s)
            env = row.get("env") or {}
            row["env"] = _json.dumps(env) if env else "{}"
            return row

        return {
            "llm": {
                "provider": self.provider,
                "chat_model": self.general_chat_model,
                "search_model": self.general_search_model,
                "compaction_model": self.compaction_model,
                "local_model": self.local_model,
                "openai_api_key": self.openai_api_key or "",
                "ollama_host": self.ollama_host,
            },
            "tools": {
                "enabled": list(self.enabled_tools),
            },
            "mcp": {
                # [[mcp.servers]] array-of-tables entries
                "servers": [server_row(s) for s in self.mcp_servers],
            },
        }

    @classmethod
    def from_toml(cls, data: dict, **overrides) -> "KryonsecConfig":
        """Build a config from read_config() output. Environment variables
        still win over TOML for the credentials/connection fields."""
        llm = data.get("llm", {})
        tools = data.get("tools", {})
        mcp = data.get("mcp", {})

        cfg = cls(**overrides)
        cfg.provider = llm.get("provider", cfg.provider)
        if llm.get("chat_model"):
            cfg.general_chat_model = llm["chat_model"]
        if llm.get("search_model"):
            cfg.general_search_model = llm["search_model"]
        if llm.get("compaction_model"):
            cfg.compaction_model = llm["compaction_model"]
        if llm.get("local_model"):
            cfg.local_model = llm["local_model"]
        if llm.get("openai_api_key"):
            cfg.openai_api_key = llm["openai_api_key"]
        if llm.get("ollama_host"):
            cfg.ollama_host = llm["ollama_host"]
        if tools.get("enabled"):
            cfg.enabled_tools = list(tools["enabled"])
        cfg.mcp_servers = [_server_from_row(r) for r in mcp.get("servers", [])]

        # environment beats TOML (documented behavior for power users / CI)
        cfg.openai_api_key = os.environ.get("OPENAI_API_KEY") or cfg.openai_api_key
        cfg.database_url = os.environ.get("DATABASE_URL") or cfg.database_url
        cfg.ollama_host = os.environ.get("OLLAMA_HOST") or cfg.ollama_host
        return cfg

    # ---- lifecycle --------------------------------------------------------

    def ensure_dirs(self) -> None:
        """Create home and workspace directories."""
        self.home.mkdir(parents=True, exist_ok=True)
        self.workspace.mkdir(parents=True, exist_ok=True)

    def save(self) -> Path:
        """Write this config to ~/.kryonsec/config.toml."""
        return write_config(config_path(self.home), self.to_toml_dict())

    @property
    def storage_kind(self) -> str:
        """Human-readable storage backend description."""
        if self.database_url:
            if self.database_url.startswith("sqlite"):
                return "SQLite (explicit DATABASE_URL)"
            return "PostgreSQL"
        return "SQLite (embedded fallback — Copilot memory only)"

    @property
    def storage_is_postgres(self) -> bool:
        return bool(self.database_url) and not self.database_url.startswith("sqlite")

    @property
    def fallback_db_path(self) -> Path:
        return self.home / "kryonsec.db"


def load_config(**overrides) -> KryonsecConfig:
    """The app entry: read ~/.kryonsec/config.toml, apply environment
    overrides. Missing/corrupt file -> defaults (first run)."""
    return KryonsecConfig.from_toml(read_config(config_path()), **overrides)
