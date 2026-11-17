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
import tempfile
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
    # Write beside the destination and replace it only after the complete
    # document is on disk. A killed installer or a full filesystem must not
    # leave a half-written config that the next run silently treats as empty.
    temporary: Path | None = None
    try:
        fd, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        temporary = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:  # pragma: no cover - filesystems may not support it
                pass
        try:  # restrict to owner where the OS supports it (the file holds keys)
            temporary.chmod(0o600)
        except OSError:  # pragma: no cover - Windows
            pass
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
    try:  # keep the final path owner-only even when replacing an old file
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


def config_file_error(path: Path) -> str | None:
    """Return a safe parse/read error, or ``None`` for a valid/missing file.

    ``read_config`` intentionally keeps its historical "missing or corrupt is
    empty" contract for startup callers. Install and doctor need to tell a
    corrupt existing file apart from a first run so they do not overwrite a
    user's configuration while trying to recover.
    """
    import tomllib

    if not path.exists():
        return None
    try:
        if not path.is_file():
            return "configuration path is not a regular file"
        tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        return f"invalid TOML ({exc})"
    except OSError:
        return "configuration file could not be read"
    return None


def update_config_sections(path: Path, updates: dict[str, dict[str, object]]) -> Path:
    """Update selected TOML sections without inventing a fresh config.

    Installers use this for values learned after installation (the resolved
    sandbox digest, and a membership key if one was supplied — inert in this
    development build).  An existing malformed file is a
    hard error: silently treating it as an empty first-run config would erase
    the user's settings.  Parsed sections are round-tripped atomically by the
    same writer used by ``KryonsecConfig.save``.
    """
    error = config_file_error(path)
    if error:
        raise ValueError(error)
    data = read_config(path)
    if not isinstance(data, dict):
        data = {}
    for section, values in updates.items():
        current = data.get(section)
        if current is None:
            current = {}
            data[section] = current
        if not isinstance(current, dict):
            raise ValueError(f"configuration section [{section}] is not a table")
        current.update(values)
    return write_config(path, data)


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

    # --- Passive-recon API sources (tool expansion Phase 2) ---
    # Keyless sources (crt.sh, Wayback, OTX, RIPEstat) always run; these
    # keys only enable Shodan/Censys. Never logged, never audited.
    shodan_api_key: str | None = field(
        default_factory=lambda: os.environ.get("SHODAN_API_KEY")
    )
    censys_api_id: str | None = field(
        default_factory=lambda: os.environ.get("CENSYS_API_ID")
    )
    censys_api_secret: str | None = field(
        default_factory=lambda: os.environ.get("CENSYS_API_SECRET")
    )
    # GitHub recon (Phase 8): optional — code search needs a token; org/repo
    # search works without. Never logged, never audited.
    github_token: str | None = field(
        default_factory=lambda: os.environ.get("GITHUB_TOKEN")
    )

    # --- Membership (2026-09 plan) ---
    # Purple Team is the paid feature: the key gates engagements only.
    # Copilot mode is free and never requires one. Never logged.
    license_key: str | None = field(
        default_factory=lambda: os.environ.get("KRYONSEC_LICENSE_KEY")
    )

    # --- LLM routing (spec §7.1) ---
    # Built-in default BEFORE `kryonsec setup` has run — NOT a recommendation.
    # A fresh machine with no config file fails the OpenAI row in
    # `kryonsec doctor` on purpose; doctor now says the default is being
    # checked and points at `kryonsec setup` (local Ollama needs no key).
    # Do not silently switch this default to ollama instead: a machine
    # without Ollama installed would then fail a row it never chose, which
    # is exactly as confusing in the other direction.
    provider: str = "openai"  # "openai" | "ollama" | "bedrock" | "openai_compatible"
    general_chat_model: str = "ollama/llama3.1"
    general_search_model: str = "gpt-4o-mini"
    compaction_model: str = "gpt-4o-mini"
    # Local fallback: used whenever secrets are detected (spec §6.4)
    # or when the preferred provider is unavailable.
    local_model: str = "ollama/llama3.1"

    # --- AWS Bedrock (hosted, spec §7.1) ---
    # A Bedrock API key is an opaque bearer token (ABSK…) that carries no
    # region — AWS picks the region from the endpoint host. The wizard
    # discovers it by probing and stores it here; the region goes into the
    # runtime URL kryonsec calls (llm.bedrock_openai_base). Never logged,
    # never audited.
    bedrock_api_key: str | None = field(
        default_factory=lambda: os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
    )
    bedrock_region: str = field(
        default_factory=lambda: (
            os.environ.get("AWS_REGION_NAME")
            or os.environ.get("AWS_DEFAULT_REGION")
            or "us-east-1"
        )
    )

    # --- OpenAI-compatible endpoint (generic third-party, spec §7.1) ---
    # One provider for any server that speaks the OpenAI Chat Completions
    # protocol: LiteLLM, vLLM, llama.cpp, LM Studio, LocalAI, a gateway, or
    # something written after this comment. Nothing here names a vendor and
    # nothing is defaulted — the endpoint, the model and the key all come
    # from the user, because kryonsec knows nothing about their deployment
    # and should not guess. The key is optional: a local server usually has
    # none. Never logged, never audited.
    openai_compatible_base_url: str | None = field(
        default_factory=lambda: os.environ.get("KRYONSEC_OPENAI_COMPATIBLE_BASE_URL")
    )
    openai_compatible_api_key: str | None = field(
        default_factory=lambda: os.environ.get("KRYONSEC_OPENAI_COMPATIBLE_API_KEY")
    )

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
    # The source-tree default is intentionally a local tag so `kryonsec` can be
    # imported without release metadata.  It is never accepted by the Purple
    # runtime: the installer replaces it with the selected release's verified
    # registry digest, and doctor/runner fail closed if it remains a tag.
    # KRYONSEC_SANDBOX_IMAGE may hold a custom digest-pinned image.
    sandbox_image: str = field(
        default_factory=lambda: os.environ.get(
            "KRYONSEC_SANDBOX_IMAGE", "kryonsec/sandbox:latest"
        )
    )

    # --- Zone B network-egress boundary (Phase 1E, spec §8.2) ---
    # The sandbox run network: a DEDICATED bridge per engagement, with an
    # allow-only firewall in the Docker host's DOCKER-USER chain. The
    # target itself is derived from the validated engagement target; the
    # operator widens the set here (never narrow it — the boundary is
    # default-deny). DNS egress is permitted only to zone_b_dns_resolvers
    # (literal IPs). Dangerous ranges (loopback, link-local incl. cloud
    # metadata, multicast, unspec) are refused even if listed here.
    zone_b_subnet: str = "10.213.42.0/24"
    zone_b_allowed_cidrs: list[str] = field(default_factory=list)
    zone_b_allowed_domains: list[str] = field(default_factory=list)
    zone_b_dns_resolvers: list[str] = field(
        default_factory=lambda: ["1.1.1.1", "8.8.8.8"]
    )

    # --- Mode B tool planner (Phase 2B.6) ---
    # Conservative default OFF: with the flag unset, RECON_ACTIVE runs
    # the exact pre-2B.6 deterministic plan (bit-identical behavior).
    # When ON, a bounded ToolPlanner filters the RECON_ACTIVE adapter
    # lanes; eligibility, scope, argv, sandbox and egress rules are
    # unchanged — the planner only decides WHICH vetted checks run for
    # WHICH already-validated in-scope bases. Env:
    # KRYONSEC_TOOL_PLANNER_ENABLED=1|true|yes|on.
    tool_planner_enabled: bool = field(
        default_factory=lambda: os.environ.get(
            "KRYONSEC_TOOL_PLANNER_ENABLED", ""
        ).strip().lower() in ("1", "true", "yes", "on"),
    )

    # --- Adapter spawn retry budget (Phase 2B.7) ---
    # How many EXTRA attempts a RECON_ACTIVE adapter spawn gets when it
    # fails with the ``sandbox_infrastructure`` class — the sandbox or
    # daemon failed BEFORE the tool launched, so no target was contacted
    # and a retry touches no new target. Only that class is ever
    # retried: refusals are deterministic policy, and timeouts/tool
    # failures already reached the target. The engine hard-caps attempts
    # at two total regardless of this value; 0 disables retrying.
    # TOML only ([adapters] spawn_retries) — no env override, this is an
    # operator tuning knob, not a deployment switch.
    adapter_spawn_retries: int = field(default=1)

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
                "bedrock_api_key": self.bedrock_api_key or "",
                "bedrock_region": self.bedrock_region,
                # the OpenAI-compatible endpoint's own fields. `api_key` is
                # spelled plainly and lives beside openai_api_key on purpose:
                # it belongs to the provider named by [llm].provider, and the
                # spec asks for these two names.
                "base_url": self.openai_compatible_base_url or "",
                "api_key": self.openai_compatible_api_key or "",
            },
            "session": {
                # round-trip the tunables — previously env-only, silently
                # dropped on save (L23)
                "max_session_tokens": self.max_session_tokens,
                "compaction_trigger_ratio": self.compaction_trigger_ratio,
                "compaction_keep_tokens": self.compaction_keep_tokens,
                "max_messages": self.max_messages,
            },
            "limits": {
                "max_tool_output_chars": self.max_tool_output_chars,
            },
            "sandbox": {
                "image": self.sandbox_image,
                "zone_b_subnet": self.zone_b_subnet,
                "zone_b_allowed_cidrs": list(self.zone_b_allowed_cidrs),
                "zone_b_allowed_domains": list(self.zone_b_allowed_domains),
                "zone_b_dns_resolvers": list(self.zone_b_dns_resolvers),
            },
            "tool_planner": {
                "enabled": self.tool_planner_enabled,
            },
            "adapters": {
                "spawn_retries": self.adapter_spawn_retries,
            },
            "api": {
                "shodan_api_key": self.shodan_api_key or "",
                "censys_api_id": self.censys_api_id or "",
                "censys_api_secret": self.censys_api_secret or "",
                "github_token": self.github_token or "",
            },
            # No "license" section is written anymore: the development build
            # ignores membership keys. The reader still accepts one so old
            # config.toml files keep loading unchanged.
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
        session = data.get("session", {})
        limits = data.get("limits", {})
        sandbox = data.get("sandbox", {})
        planner = data.get("tool_planner", {})
        adapters_cfg = data.get("adapters", {})
        api = data.get("api", {})
        license_ = data.get("license", {})

        cfg = cls(**overrides)
        cfg.provider = llm.get("provider", cfg.provider)
        # `chat_model` is the canonical name and the one written back; `model`
        # is accepted as an alias because that is what the OpenAI-compatible
        # provider's config is documented as — one value, two spellings, not
        # a second place for it to live.
        if llm.get("chat_model") or llm.get("model"):
            cfg.general_chat_model = llm.get("chat_model") or llm["model"]
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
        if llm.get("bedrock_api_key"):
            cfg.bedrock_api_key = llm["bedrock_api_key"]
        if llm.get("bedrock_region"):
            cfg.bedrock_region = llm["bedrock_region"]
        if llm.get("base_url"):
            cfg.openai_compatible_base_url = llm["base_url"]
        if llm.get("api_key"):
            cfg.openai_compatible_api_key = llm["api_key"]
        if "enabled" in tools:
            # an explicitly empty list must round-trip as "no tools" —
            # a falsy check would resurrect the dataclass default
            # (all tools incl. file_write) on the next launch
            cfg.enabled_tools = list(tools["enabled"])
        # L23: the tunables round-trip too (env still wins where it exists)
        if session.get("max_session_tokens"):
            cfg.max_session_tokens = int(session["max_session_tokens"])
        if session.get("compaction_trigger_ratio"):
            cfg.compaction_trigger_ratio = float(session["compaction_trigger_ratio"])
        if session.get("compaction_keep_tokens"):
            cfg.compaction_keep_tokens = int(session["compaction_keep_tokens"])
        if session.get("max_messages"):
            cfg.max_messages = int(session["max_messages"])
        if limits.get("max_tool_output_chars"):
            cfg.max_tool_output_chars = int(limits["max_tool_output_chars"])
        if sandbox.get("image"):
            cfg.sandbox_image = str(sandbox["image"])
        # Phase 1E egress scope — explicitly-empty lists round-trip as
        # "wider scope removed", same rule as tools.enabled
        if sandbox.get("zone_b_subnet"):
            cfg.zone_b_subnet = str(sandbox["zone_b_subnet"])
        if "zone_b_allowed_cidrs" in sandbox:
            cfg.zone_b_allowed_cidrs = [
                str(c) for c in sandbox["zone_b_allowed_cidrs"]]
        if "zone_b_allowed_domains" in sandbox:
            cfg.zone_b_allowed_domains = [
                str(d) for d in sandbox["zone_b_allowed_domains"]]
        if "zone_b_dns_resolvers" in sandbox:
            cfg.zone_b_dns_resolvers = [
                str(r) for r in sandbox["zone_b_dns_resolvers"]]
        if "enabled" in planner:
            cfg.tool_planner_enabled = bool(planner["enabled"])
        # Phase 2B.7 adapter retry budget (stored raw except that a
        # negative value is nonsense; the engine still caps attempts at
        # two total, so a larger number stays a single retry)
        if "spawn_retries" in adapters_cfg:
            cfg.adapter_spawn_retries = max(
                0, int(adapters_cfg["spawn_retries"]))
        if api.get("shodan_api_key"):
            cfg.shodan_api_key = api["shodan_api_key"]
        if api.get("censys_api_id"):
            cfg.censys_api_id = api["censys_api_id"]
        if api.get("censys_api_secret"):
            cfg.censys_api_secret = api["censys_api_secret"]
        if api.get("github_token"):
            cfg.github_token = api["github_token"]
        if license_.get("key"):
            cfg.license_key = license_["key"]
        cfg.mcp_servers = [_server_from_row(r) for r in mcp.get("servers", [])]

        # The OpenAI-compatible seat has no default model, deliberately: the
        # dataclass defaults (`ollama/llama3.1`, `gpt-4o-mini`) belong to the
        # other providers, and inheriting one here would send chat to a
        # provider the user did not select while their configured endpoint sat
        # unused. Empty is the honest value for "never named", and build_call
        # refuses it with a message saying so.
        if cfg.provider == "openai_compatible" and not (llm.get("chat_model") or llm.get("model")):
            cfg.general_chat_model = ""

        # environment beats TOML (documented behavior for power users / CI)
        cfg.openai_api_key = os.environ.get("OPENAI_API_KEY") or cfg.openai_api_key
        # KRYONSEC_SANDBOX_IMAGE follows the same rule: an explicitly set env
        # image wins over TOML's [sandbox].image (which itself wins over the
        # source-tree default). Absent env keeps the TOML value. Whatever is
        # selected still has to pass the digest-pinned validation in
        # runtime_checks.validate_image — precedence never bypasses it.
        cfg.sandbox_image = (
            os.environ.get("KRYONSEC_SANDBOX_IMAGE") or cfg.sandbox_image
        )
        cfg.database_url = os.environ.get("DATABASE_URL") or cfg.database_url
        cfg.ollama_host = os.environ.get("OLLAMA_HOST") or cfg.ollama_host
        cfg.bedrock_api_key = (
            os.environ.get("AWS_BEARER_TOKEN_BEDROCK") or cfg.bedrock_api_key
        )
        cfg.bedrock_region = (
            os.environ.get("AWS_REGION_NAME")
            or os.environ.get("AWS_DEFAULT_REGION")
            or cfg.bedrock_region
        )
        cfg.openai_compatible_base_url = (
            os.environ.get("KRYONSEC_OPENAI_COMPATIBLE_BASE_URL")
            or cfg.openai_compatible_base_url
        )
        cfg.openai_compatible_api_key = (
            os.environ.get("KRYONSEC_OPENAI_COMPATIBLE_API_KEY")
            or cfg.openai_compatible_api_key
        )
        cfg.shodan_api_key = os.environ.get("SHODAN_API_KEY") or cfg.shodan_api_key
        cfg.censys_api_id = os.environ.get("CENSYS_API_ID") or cfg.censys_api_id
        cfg.censys_api_secret = (
            os.environ.get("CENSYS_API_SECRET") or cfg.censys_api_secret
        )
        cfg.github_token = os.environ.get("GITHUB_TOKEN") or cfg.github_token
        cfg.license_key = (
            os.environ.get("KRYONSEC_LICENSE_KEY") or cfg.license_key
        )
        # Phase 2B.6: the tool-planner gate — env beats TOML like every
        # other overridable; absent env keeps the TOML value.
        env_planner = os.environ.get(
            "KRYONSEC_TOOL_PLANNER_ENABLED", "").strip().lower()
        if env_planner:
            cfg.tool_planner_enabled = env_planner in (
                "1", "true", "yes", "on")
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

    @property
    def purple_db_path(self) -> Path:
        """Engagement storage for an install with no DATABASE_URL.

        A file of its own, not the Copilot fallback database: Copilot
        memory and engagement memory have different lifetimes and
        different backup needs, and ``init_db`` keeps the purple tables out
        of the fallback database on purpose. See ``storage.db``.
        """
        return self.home / "purple.db"

    @property
    def purple_storage_kind(self) -> str:
        """Human-readable description of where engagement data lives."""
        if self.database_url:
            return self.storage_kind
        return "SQLite (embedded engagement store)"


def load_config(**overrides) -> KryonsecConfig:
    """The app entry: read ~/.kryonsec/config.toml, apply environment
    overrides. Missing/corrupt file -> defaults (first run)."""
    return KryonsecConfig.from_toml(read_config(config_path()), **overrides)
