"""Visible stages and a redacted repair log for ``doctor --fix``.

The ten stage names are fixed by the installation contract.  A stage prints
once, with its own elapsed time, and a failure keeps the real error rather than
a generic "something went wrong".  Logs are redacted with the existing secrets
patterns before they touch disk.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from ..secrets import redact

STAGES: tuple[str, ...] = (
    "CHECKING SYSTEM",
    "CONFIGURING PYTHON",
    "INSTALLING KRYONSEC",
    "CHECKING DOCKER",
    "CONFIGURING GVISOR",
    "DOWNLOADING SANDBOX",
    "VERIFYING SANDBOX",
    "CHECKING FIREWALL",
    "FINAL VALIDATION",
    "READY",
)


class Stage:
    def __init__(self, reporter: "RepairReporter", index: int, name: str) -> None:
        self.reporter = reporter
        self.index = index
        self.name = name
        self.started = time.monotonic()
        self.status = "RUNNING"

    def __enter__(self) -> "Stage":
        self.reporter._stage_started(self.index, self.name)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        elapsed = time.monotonic() - self.started
        self.status = "FAILED" if exc is not None else "DONE"
        self.reporter._stage_finished(self.index, self.name, self.status, elapsed)
        return False  # let the orchestrator decide whether to continue


class RepairReporter:
    """Print the ten stages and keep a redacted log beside the config."""

    def __init__(
        self,
        *,
        home: Path,
        verbose: bool = False,
        quiet: bool = False,
        log_enabled: bool = True,
        stream=None,
    ) -> None:
        self.home = home
        self.verbose = verbose
        self.quiet = quiet
        self.stream = stream or sys.stdout
        self.log_path = (
            home / "logs" / f"doctor-fix-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.log"
            if log_enabled
            else None
        )
        self._log_handle = None
        self._log_broken = False
        if self.log_path is not None:
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                self._log_handle = self.log_path.open("a", encoding="utf-8")
                # Redacted, but still local state: owner-only like config.toml.
                os.chmod(self.log_path, 0o600)
            except OSError:
                # A read-only home must not take the repair down; the terminal
                # still carries every line.
                self._log_handle = None
                self._log_broken = True

    # ---- terminal -------------------------------------------------------

    def _emit(self, text: str) -> None:
        print(text, file=self.stream, flush=True)
        self._log(text)

    def _log(self, text: str) -> None:
        if self._log_handle is None:
            return
        safe_text, _mapping = redact(text)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self._log_handle.write(f"{stamp} {safe_text}\n")
            self._log_handle.flush()
        except OSError:
            self._log_handle = None

    def _stage_started(self, index: int, name: str) -> None:
        self._emit(f"[{index}/{len(STAGES)}] {name} ...")

    def _stage_finished(self, index: int, name: str, status: str, elapsed: float) -> None:
        if status == "FAILED":
            self._emit(f"[{index}/{len(STAGES)}] {name}  FAILED  {elapsed:.1f}s")
        elif self.quiet:
            self._emit(f"[{index}/{len(STAGES)}] {name}  done  {elapsed:.1f}s")

    def line(self, text: str, *, verbose_only: bool = False, error: bool = False) -> None:
        if verbose_only and not self.verbose:
            self._log(text)
            return
        if self.quiet and not error:
            self._log(text)
            return
        prefix = "  ! " if error else "  · "
        self._emit(f"{prefix}{text}")

    def action(self, title: str, detail: str = "") -> None:
        self.line(title)
        if detail:
            self.line(detail, verbose_only=True)

    def summary(self, text: str) -> None:
        """A line that survives quiet mode: final verdict and next actions."""
        self._emit(text)

    def stage(self, name: str) -> Stage:
        if name not in STAGES:
            raise ValueError(f"unknown installation stage {name!r}")
        return Stage(self, STAGES.index(name) + 1, name)

    def close(self) -> None:
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            finally:
                self._log_handle = None

    def __enter__(self) -> "RepairReporter":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False


__all__ = ["RepairReporter", "STAGES", "Stage"]
