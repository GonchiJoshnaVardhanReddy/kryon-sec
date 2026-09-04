"""Kryonsec configuration (spec v2.1.1 §11).

Profile 1 (Copilot, any OS):
  - storage: PostgreSQL via DATABASE_URL, else embedded fallback (SQLite)
  - no Docker / gVisor / Redis / MinIO / Ollama required

Profile 2 (Purple Team, Linux only):
  - full stack: PostgreSQL, Redis, MinIO, Ollama, Docker + gVisor
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_home() -> Path:
    return Path(os.environ.get("KRYONSEC_HOME", str(Path.home() / ".kryonsec")))


def _default_workspace() -> Path:
    return Path(os.environ.get("KRYONSEC_WORKSPACE", str(Path.home() / "kryonsec" / "workspace")))


@dataclass
class KryonsecConfig:
    """Runtime configuration. Environment wins over defaults."""

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
    general_chat_model: str = "ollama/llama3.1"
    general_search_model: str = "gpt-4o-mini"
    compaction_model: str = "gpt-4o-mini"
    # Local fallback: used whenever secrets are detected (spec §6.4)
    # or when the preferred provider is unavailable.
    local_model: str = "ollama/llama3.1"

    # --- Session STM limits (spec §3.4) ---
    max_session_tokens: int = 16000
    compaction_trigger_ratio: float = 0.8
    compaction_keep_tokens: int = 8000
    max_messages: int = 50

    # --- Output bounding (safety Layer 10) ---
    max_tool_output_chars: int = 20000

    def ensure_dirs(self) -> None:
        """Create home and workspace directories."""
        self.home.mkdir(parents=True, exist_ok=True)
        self.workspace.mkdir(parents=True, exist_ok=True)

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
