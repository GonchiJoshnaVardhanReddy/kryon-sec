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


# ---- AWS Bedrock row --------------------------------------------------------

def test_check_bedrock_reports_key_and_region(tmp_path, monkeypatch):
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    cfg = KryonsecConfig(home=tmp_path)
    ok, msg = doctor._check_bedrock(cfg)
    assert not ok
    assert "setup" in msg  # points at the fix, not just the symptom

    cfg.bedrock_api_key = "ABSKtest"
    cfg.bedrock_region = "ap-south-1"
    ok, msg = doctor._check_bedrock(cfg)
    assert ok
    # the region is echoed: a call sent to the wrong region is the most
    # common Bedrock failure and is otherwise invisible here
    assert "ap-south-1" in msg


def test_doctor_shows_a_bedrock_row(monkeypatch, tmp_path, capsys):
    _fake_checks(monkeypatch)
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    doctor.run_doctor(KryonsecConfig(home=tmp_path))
    assert "AWS Bedrock" in capsys.readouterr().out


def test_doctor_bedrock_alone_is_enough_for_copilot(monkeypatch, tmp_path, capsys):
    """A Bedrock-only user is a fully supported Copilot configuration —
    the exit code must not depend on which provider row is which index."""
    monkeypatch.setattr(doctor, "_check_storage", lambda c: (True, "OK (SQLite)"))
    monkeypatch.setattr(doctor, "_check_ollama", lambda c: (False, "down"))
    monkeypatch.setattr(doctor, "_check_openai", lambda c: (False, "no key"))
    monkeypatch.setattr(doctor, "_check_bedrock", lambda c: (True, "OK"))
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    rc = doctor.run_doctor(KryonsecConfig(home=tmp_path))
    out = capsys.readouterr().out
    assert rc == 0
    assert "FAIL — Profile 1" not in out


def test_doctor_no_provider_at_all_is_a_failure(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(doctor, "_check_storage", lambda c: (True, "OK (SQLite)"))
    monkeypatch.setattr(doctor, "_check_ollama", lambda c: (False, "down"))
    monkeypatch.setattr(doctor, "_check_openai", lambda c: (False, "no key"))
    monkeypatch.setattr(doctor, "_check_bedrock", lambda c: (False, "no key"))
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    rc = doctor.run_doctor(KryonsecConfig(home=tmp_path))
    assert rc == 1
    assert "FAIL — Profile 1" in capsys.readouterr().out
