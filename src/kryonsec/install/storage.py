"""Read-only storage summary and exact, confirmed cleanup.

Cleanup is deliberately narrow.  It can remove only Kryonsec-owned leftovers
directly inside the Kryonsec home:

* old ``config.toml.bak-*`` files (the newest backup is always kept),
* old ``logs/doctor-fix-*.log`` files,
* atomic-write ``*.tmp`` leftovers.

It never touches engagement/evidence directories, the workspace, the
database, Docker images, containers, volumes, build cache, or any path outside
``KryonsecConfig.home``.  Docker is summarised read-only; nothing is pruned.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..config import KryonsecConfig, config_path

RETENTION_DAYS = 30


@dataclass(frozen=True)
class StorageEntry:
    label: str
    path: Path
    bytes: int
    detail: str = ""

    @property
    def display_size(self) -> str:
        return _size(self.bytes)


@dataclass(frozen=True)
class DockerUsage:
    images_bytes: int = 0
    containers_bytes: int = 0
    volumes_bytes: int = 0
    cache_bytes: int = 0
    sandbox_bytes: int = 0
    sandbox_image: str = ""
    error: str = ""


@dataclass
class StorageReport:
    home: Path
    entries: list[StorageEntry] = field(default_factory=list)
    docker: DockerUsage = DockerUsage()
    candidates: list[StorageEntry] = field(default_factory=list)


def _size(value: int) -> str:
    value = max(0, int(value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024
    return f"{value:.1f} TiB"


def _tree_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for child in path.rglob("*"):
        try:
            if child.is_file():
                total += child.stat().st_size
        except OSError:
            continue
    return total


def _docker_usage(cfg: KryonsecConfig) -> DockerUsage:
    if not shutil.which("docker"):
        return DockerUsage(error="docker CLI not found")
    try:
        proc = subprocess.run(
            ["docker", "system", "df", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DockerUsage(error=type(exc).__name__)
    if proc.returncode != 0:
        return DockerUsage(error="docker system df unavailable")
    values: dict[str, int] = {}
    for line in (proc.stdout or "").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = str(row.get("Type") or "").lower()
        raw = str(row.get("Size") or "0B")
        values[kind] = _parse_docker_size(raw)
    sandbox = 0
    if cfg.sandbox_image:
        try:
            inspect = subprocess.run(
                ["docker", "image", "inspect", cfg.sandbox_image, "--format", "{{.Size}}"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if inspect.returncode == 0:
                sandbox = int((inspect.stdout or "0").strip() or 0)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            sandbox = 0
    return DockerUsage(
        images_bytes=values.get("images", 0),
        containers_bytes=values.get("containers", 0),
        volumes_bytes=values.get("local volumes", 0),
        cache_bytes=values.get("build cache", 0),
        sandbox_bytes=sandbox,
        sandbox_image=cfg.sandbox_image,
    )


def _parse_docker_size(value: str) -> int:
    text = value.strip().replace(" ", "")
    if not text:
        return 0
    units = {
        "B": 1,
        "KB": 1000,
        "MB": 1000 ** 2,
        "GB": 1000 ** 3,
        "TB": 1000 ** 4,
        "KIB": 1024,
        "MIB": 1024 ** 2,
        "GIB": 1024 ** 3,
        "TIB": 1024 ** 4,
    }
    for suffix in sorted(units, key=len, reverse=True):
        if text.upper().endswith(suffix):
            try:
                number = float(text[: -len(suffix)])
            except ValueError:
                return 0
            return int(number * units[suffix])
    try:
        return int(float(text))
    except ValueError:
        return 0


def _age_days(path: Path) -> float:
    try:
        return max(0.0, (time.time() - path.stat().st_mtime) / 86400.0)
    except OSError:
        return 0.0


def _cleanup_candidates(cfg: KryonsecConfig, retention_days: int) -> list[StorageEntry]:
    home = cfg.home
    if not home.is_dir():
        return []
    candidates: list[StorageEntry] = []

    backups = sorted(
        home.glob(f"{config_path(home).name}.bak-*"),
        key=lambda path: path.stat().st_mtime if path.exists() else 0,
        reverse=True,
    )
    for index, path in enumerate(backups):
        if index == 0:
            continue  # always keep the newest config backup
        if _age_days(path) < retention_days:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        candidates.append(
            StorageEntry(
                f"config backup ({_age_days(path):.0f}d old)",
                path,
                size,
                "newest backup is kept",
            )
        )

    logs = home / "logs"
    if logs.is_dir():
        for path in logs.glob("doctor-fix-*.log"):
            if _age_days(path) < retention_days:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            candidates.append(
                StorageEntry(f"repair log ({_age_days(path):.0f}d old)", path, size)
            )

    for path in home.glob(".*.tmp"):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        candidates.append(
            StorageEntry("interrupted atomic-write temp file", path, size)
        )
    return candidates


def summarize_storage(
    cfg: KryonsecConfig, *, retention_days: int = RETENTION_DAYS
) -> StorageReport:
    """Read-only summary; no directory or Docker state is modified."""
    report = StorageReport(home=cfg.home)
    db = cfg.fallback_db_path
    entries = [
        StorageEntry("Kryonsec home", cfg.home, _tree_size(cfg.home)),
        StorageEntry("workspace", cfg.workspace, _tree_size(cfg.workspace)),
        StorageEntry("sessions database", db, _tree_size(db)),
        StorageEntry(
            "engagements / evidence",
            cfg.home / "engagements",
            _tree_size(cfg.home / "engagements"),
            "never removed by cleanup",
        ),
        StorageEntry("logs", cfg.home / "logs", _tree_size(cfg.home / "logs")),
    ]
    report.entries = entries
    report.docker = _docker_usage(cfg)
    report.candidates = _cleanup_candidates(cfg, retention_days)
    return report


def _format_report(report: StorageReport) -> str:
    lines = ["STORAGE · READ-ONLY", ""]
    for entry in report.entries:
        if entry.bytes == 0 and not entry.path.exists():
            continue
        detail = f"  {entry.detail}" if entry.detail else ""
        lines.append(f"  {entry.display_size:>10}  {entry.label}{detail}")
        lines.append(f"              {entry.path}")
    docker = report.docker
    lines.append("")
    if docker.error:
        lines.append(f"  Docker: not inspected ({docker.error})")
    else:
        lines.append("  Docker (read-only; nothing is pruned):")
        lines.append(f"    images       {_size(docker.images_bytes)}")
        lines.append(f"    containers   {_size(docker.containers_bytes)}")
        lines.append(f"    volumes      {_size(docker.volumes_bytes)}")
        lines.append(f"    build cache  {_size(docker.cache_bytes)}")
        if docker.sandbox_image:
            lines.append(
                f"    sandbox      {_size(docker.sandbox_bytes)}  {docker.sandbox_image}"
            )
    lines.append("")
    if report.candidates:
        lines.append(f"CLEANUP CANDIDATES · {len(report.candidates)} exact file(s)")
        for entry in report.candidates:
            lines.append(f"  {entry.display_size:>10}  {entry.path}")
    else:
        lines.append("CLEANUP CANDIDATES · none")
    lines.append("")
    lines.append(
        "Cleanup never removes evidence, the workspace, the database, Docker "
        "images/containers/volumes, or the newest config backup."
    )
    return "\n".join(lines)


def run_storage(
    cfg: KryonsecConfig,
    *,
    cleanup: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
    retention_days: int = RETENTION_DAYS,
    input_fn: Callable[[str], str] = input,
) -> int:
    """Print the summary, and optionally delete confirmed exact files."""
    report = summarize_storage(cfg, retention_days=retention_days)
    print(_format_report(report))
    if not cleanup:
        return 0
    if not report.candidates:
        return 0
    if dry_run:
        print("\nDRY RUN: no file was removed.")
        return 0
    total = sum(entry.bytes for entry in report.candidates)
    prompt = (
        f"\nDelete these {len(report.candidates)} exact file(s), "
        f"freeing {_size(total)}? Type 'yes' to confirm: "
    )
    try:
        answer = input_fn(prompt)
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() != "yes":
        print("skipped: no confirmation; nothing was removed")
        return 0
    removed = 0
    for entry in report.candidates:
        try:
            entry.path.unlink()
        except OSError as exc:
            print(f"  failed: {entry.path}: {type(exc).__name__}: {exc}")
            continue
        removed += 1
        if verbose:
            print(f"  removed: {entry.path}")
    print(f"removed {removed} of {len(report.candidates)} file(s)")
    return 0


__all__ = [
    "DockerUsage",
    "RETENTION_DAYS",
    "StorageEntry",
    "StorageReport",
    "run_storage",
    "summarize_storage",
]
