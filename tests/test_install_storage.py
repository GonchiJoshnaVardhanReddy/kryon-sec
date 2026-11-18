"""Storage summary and exact-target cleanup.

No real Docker daemon is queried.  Cleanup is checked against a temporary
Kryonsec home containing decoys (a database, an evidence file, a workspace
file) that must survive.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.install import storage


@pytest.fixture()
def cfg(tmp_path: Path, monkeypatch) -> KryonsecConfig:
    value = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "workspace")
    value.home.mkdir(parents=True)
    value.workspace.mkdir(parents=True)
    monkeypatch.setattr(storage, "_docker_usage", lambda _cfg: storage.DockerUsage())
    return value


def _backup(cfg: KryonsecConfig, suffix: str, *, age_days: float = 0) -> Path:
    path = cfg.home / f"config.toml.bak-{suffix}"
    path.write_text("provider = 'ollama'\n", encoding="utf-8")
    if age_days:
        stamp = time.time() - age_days * 86400
        os.utime(path, (stamp, stamp))
    return path


def test_summary_lists_real_paths_and_never_prunes(cfg, monkeypatch):
    (cfg.home / "sessions.db").write_bytes(b"x" * 10)
    (cfg.home / "engagements").mkdir()
    (cfg.home / "engagements" / "audit.jsonl").write_text("{}\n", encoding="utf-8")
    called: list[list[str]] = []

    def forbidden(args, **kwargs):
        called.append(list(args))
        raise AssertionError("summary must not run Docker lifecycle commands")

    monkeypatch.setattr(storage.subprocess, "run", forbidden)
    report = storage.summarize_storage(cfg)

    labels = {entry.label for entry in report.entries}
    assert "Kryonsec home" in labels
    assert "engagements / evidence" in labels
    assert report.docker.error == ""  # _docker_usage is mocked at fixture level
    assert called == []
    assert (cfg.home / "engagements" / "audit.jsonl").is_file()


def test_cleanup_keeps_the_newest_backup_and_fresh_files(cfg):
    newest = _backup(cfg, "newest", age_days=1)
    old = _backup(cfg, "old", age_days=91)
    fresh = _backup(cfg, "fresh", age_days=2)
    log = cfg.home / "logs" / "doctor-fix-old.log"
    log.parent.mkdir()
    log.write_text("x", encoding="utf-8")
    old_stamp = time.time() - 90 * 86400
    os.utime(log, (old_stamp, old_stamp))

    candidates = storage._cleanup_candidates(cfg, 30)
    paths = {entry.path for entry in candidates}
    assert old in paths
    assert log in paths
    assert newest not in paths
    assert fresh not in paths


def test_cleanup_without_confirmation_removes_nothing(cfg, capsys):
    _backup(cfg, "newest", age_days=1)
    old = _backup(cfg, "old", age_days=91)
    result = storage.run_storage(cfg, cleanup=True, input_fn=lambda _prompt: "no")
    assert result == 0
    assert old.is_file()
    assert "nothing was removed" in capsys.readouterr().out


def test_cleanup_with_confirmation_removes_only_the_exact_candidates(cfg, tmp_path):
    old = _backup(cfg, "old", age_days=91)
    newest = _backup(cfg, "newest", age_days=1)
    db = cfg.home / "sessions.db"
    db.write_bytes(b"preserve")
    evidence = cfg.home / "engagements" / "audit.jsonl"
    evidence.parent.mkdir()
    evidence.write_text("{}\n", encoding="utf-8")
    workspace_file = cfg.workspace / "notes.txt"
    workspace_file.write_text("preserve", encoding="utf-8")

    result = storage.run_storage(cfg, cleanup=True, input_fn=lambda _prompt: "yes", verbose=True)

    assert result == 0
    assert not old.exists()
    assert newest.is_file()
    assert db.is_file()
    assert evidence.is_file()
    assert workspace_file.is_file()


def test_dry_run_never_removes(cfg, capsys):
    _backup(cfg, "newest", age_days=1)
    old = _backup(cfg, "old", age_days=91)
    storage.run_storage(cfg, cleanup=True, dry_run=True, input_fn=lambda _p: "yes")
    assert old.is_file()
    assert "DRY RUN" in capsys.readouterr().out


def test_cleanup_never_touches_the_workspace_even_if_it_is_old(cfg):
    (cfg.workspace / "old.txt").write_text("x", encoding="utf-8")
    stamp = time.time() - 500 * 86400
    os.utime(cfg.workspace / "old.txt", (stamp, stamp))
    candidates = storage._cleanup_candidates(cfg, 1)
    assert all(cfg.workspace not in entry.path.parents for entry in candidates)


def test_parse_docker_size_handles_decimal_and_binary_units():
    assert storage._parse_docker_size("1.5GB") == int(1.5 * 1000 ** 3)
    assert storage._parse_docker_size("2GiB") == 2 * 1024 ** 3
    assert storage._parse_docker_size("") == 0
    assert storage._parse_docker_size("nonsense") == 0
