"""Tests for `kryonsec doctor` (M2): non-Linux machines must show deliberate
skips as yellow SKIP, not red FAIL; exit code logic must stay intact."""

from kryonsec.config import KryonsecConfig
from kryonsec import doctor


def _fake_checks(monkeypatch):
    monkeypatch.setattr(doctor, "_check_storage", lambda c: (True, "OK (SQLite)"))
    monkeypatch.setattr(doctor, "_check_ollama", lambda c: (True, "OK"))
    monkeypatch.setattr(doctor, "_check_openai", lambda c: (False, "no key"))


def test_doctor_non_linux_renders_skip_not_fail(monkeypatch, tmp_path, capsys):
    _fake_checks(monkeypatch)
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    rc = doctor.run_doctor(KryonsecConfig(home=tmp_path))
    out = capsys.readouterr().out
    assert rc == 0  # copilot profile works
    assert "SKIP" in out
    # the deliberately skipped rows must not read as failures
    assert "FAIL — Profile 1" not in out


def test_doctor_linux_missing_docker_still_fail(monkeypatch, tmp_path, capsys):
    _fake_checks(monkeypatch)
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "_check_docker", lambda: (False, "docker CLI not found"))
    rc = doctor.run_doctor(KryonsecConfig(home=tmp_path))
    out = capsys.readouterr().out
    assert rc == 0  # copilot still fine
    assert "FAIL" in out  # a real gap on Linux stays a red FAIL
