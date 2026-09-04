"""Copilot file tools (spec v2.1.1 §3.7): scoped read/write with approval.

Rules:
- Reads inside the workspace: no approval. Outside: user must approve.
- Writes inside the workspace: no approval. Outside: BLOCKED entirely.
- Path traversal out of the workspace via ../ or symlinks is rejected.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from ..config import KryonsecConfig

MAX_READ_CHARS = 100_000  # output bounding (safety Layer 10)


class FileAccessDenied(Exception):
    pass


@dataclass
class ApprovalRequest:
    path: Path
    reason: str


class FileTools:
    def __init__(self, cfg: KryonsecConfig, approver=None):
        """approver: callable(ApprovalRequest) -> bool. None means interactive
        prompt (default) — tests inject a stub."""
        self.cfg = cfg
        self._approver = approver or self._prompt_approve
        self._always_approved: set[Path] = set()

    # ---- approval --------------------------------------------------------

    def _prompt_approve(self, req: ApprovalRequest) -> bool:
        answer = input(
            f"\n  Agent wants to read: {req.path}\n"
            f"  Reason: {req.reason}\n"
            f"  [A]pprove once / [Y] always for this path / [D]eny: "
        )
        a = answer.strip().lower()
        if a.startswith("y"):
            self._always_approved.add(req.path.resolve())
        return a.startswith(("a", "y"))

    def _needs_approval(self, path: Path) -> bool:
        """True when the read needs an approval prompt: outside the workspace
        AND not already approved (always-approved set)."""
        try:
            path.resolve().relative_to(self.cfg.workspace.resolve())
            return False  # inside workspace: no approval needed
        except ValueError:
            pass
        return path.resolve() not in self._always_approved

    # ---- reads -----------------------------------------------------------

    def read_file(self, path_str: str) -> str:
        path = Path(path_str).expanduser()
        if not path.exists() or not path.is_file():
            raise FileAccessDenied(f"not a readable file: {path}")
        if self._needs_approval(path):
            if not self._approver(ApprovalRequest(path=path, reason="Agent file read")):
                raise FileAccessDenied(f"user denied read: {path}")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise FileAccessDenied(f"cannot read {path}: {e}") from e
        return text[:MAX_READ_CHARS]

    def list_directory(self, path_str: str) -> list[str]:
        path = Path(path_str).expanduser()
        if not path.exists() or not path.is_dir():
            raise FileAccessDenied(f"not a readable directory: {path}")
        if self._needs_approval(path):
            if not self._approver(ApprovalRequest(path=path, reason="Agent directory listing")):
                raise FileAccessDenied(f"user denied listing: {path}")
        return sorted(p.name for p in path.iterdir())[:500]

    # ---- writes ----------------------------------------------------------

    def write_file(self, path_str: str, content: str) -> Path:
        path = Path(path_str).expanduser()
        try:
            resolved_parent = path.resolve().parent
            resolved_parent.relative_to(self.cfg.workspace.resolve())
        except ValueError:
            # Writes outside the workspace are BLOCKED entirely (spec §3.2)
            raise FileAccessDenied(f"write outside workspace is blocked: {path}")
        resolved_parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
