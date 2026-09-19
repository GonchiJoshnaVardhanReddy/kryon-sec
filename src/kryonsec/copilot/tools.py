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
    action: str = "read"  # "read" | "list" | "write"
    # The path the agent literally named, when it differs from `path` (which
    # is always the resolved target). A symlink inside the workspace pointing
    # at /etc/shadow resolves outside it, so the approval gate correctly
    # fires — but the prompt used to show only the innocent-looking workspace
    # name, asking the user to approve a read of a file that wasn't the one
    # being read.
    requested_path: Path | None = None


class FileTools:
    def __init__(self, cfg: KryonsecConfig, approver=None):
        """approver: callable(ApprovalRequest) -> bool. None means interactive
        prompt (default) — tests inject a stub."""
        self.cfg = cfg
        self._approver = approver or self._prompt_approve
        self._always_approved: set[Path] = set()

    # ---- approval --------------------------------------------------------

    def _request(self, target: Path, reason: str, action: str) -> ApprovalRequest:
        """Build an ApprovalRequest describing the file the decision is
        actually about, plus the name the agent used when they differ."""
        import os

        resolved = target.resolve()
        requested = Path(os.path.abspath(target))
        return ApprovalRequest(
            path=resolved,
            reason=reason,
            action=action,
            requested_path=requested if requested != resolved else None,
        )

    def _prompt_approve(self, req: ApprovalRequest) -> bool:
        verb = {"read": "read", "list": "list", "write": "write"}.get(
            req.action, req.action)
        via = (
            f"  (requested as {req.requested_path})\n"
            if req.requested_path else ""
        )
        answer = input(
            f"\n  Agent wants to {verb}: {req.path}\n"
            f"{via}"
            f"  Reason: {req.reason}\n"
            f"  [A]pprove once / [Y] always for this path / [D]eny: "
        )
        a = answer.strip().lower()
        if a.startswith("y"):
            # resolved path, matching what _needs_approval() checks — keying
            # this on the unresolved name let a second symlink with the same
            # workspace name ride on the first approval
            self._always_approved.add(req.path)
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
            if not self._approver(self._request(
                    target, "Agent file read", "read")):
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
            if not self._approver(self._request(
                    target, "Agent directory listing", "list")):
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
                if not self._approver(self._request(
                        target, "Agent file write", "write")):
                    raise FileAccessDenied(f"user denied write: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target
