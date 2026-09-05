"""Copilot file tools (spec v2.1.1 §3.7, updated v1.1): scoped read/write
with approval.

Rules (v1.1 — user decision: "anywhere, with approval"):
- Reads inside the workspace: no approval. Outside: user must approve.
- Writes inside the workspace: no approval. Outside: user must approve
  (previously blocked outright).
- Path traversal out of the workspace via ../ or symlinks is still resolved
  before the approval decision, so an approved path is the real path.
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
    action: str = "read"  # "read" | "write"


class FileTools:
    def __init__(self, cfg: KryonsecConfig, approver=None):
        """approver: callable(ApprovalRequest) -> bool. None means interactive
        prompt (default) — tests inject a stub."""
        self.cfg = cfg
        self._approver = approver or self._prompt_approve
        self._always_approved: set[Path] = set()

    # ---- approval --------------------------------------------------------

    def _prompt_approve(self, req: ApprovalRequest) -> bool:
        verb = "read" if req.action == "read" else "write"
        answer = input(
            f"\n  Agent wants to {verb}: {req.path}\n"
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

    def read_file(self, path: str) -> str:
        target = Path(path).expanduser()
        if not target.exists() or not target.is_file():
            raise FileAccessDenied(f"not a readable file: {target}")
        if self._needs_approval(target):
            if not self._approver(ApprovalRequest(path=target, reason="Agent file read")):
                raise FileAccessDenied(f"user denied read: {target}")
        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise FileAccessDenied(f"cannot read {target}: {e}") from e
        return text[:MAX_READ_CHARS]

    def list_directory(self, path: str) -> list[str]:
        target = Path(path).expanduser()
        if not target.exists() or not target.is_dir():
            raise FileAccessDenied(f"not a readable directory: {target}")
        if self._needs_approval(target):
            if not self._approver(ApprovalRequest(path=target, reason="Agent directory listing")):
                raise FileAccessDenied(f"user denied listing: {target}")
        return sorted(p.name for p in target.iterdir())[:500]

    # ---- writes ----------------------------------------------------------

    def write_file(self, path: str, content: str) -> Path:
        target = Path(path).expanduser()
        try:
            target.resolve().parent.relative_to(self.cfg.workspace.resolve())
        except ValueError:
            # Writes outside the workspace need approval (v1.1) — same
            # gate as reads. Denial raises; approval proceeds.
            if self._needs_approval(target):
                if not self._approver(ApprovalRequest(
                        path=target, reason="Agent file write", action="write")):
                    raise FileAccessDenied(f"user denied write: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target
