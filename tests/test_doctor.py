"""Tests for `kryonsec doctor` (M2): non-Linux machines must show deliberate
skips as yellow SKIP, not red FAIL; exit code logic must stay intact."""

import re

from kryonsec.config import KryonsecConfig
from kryonsec import doctor
from kryonsec.purple.runtime_checks import DockerContextInfo


def _fake_checks(monkeypatch):
    monkeypatch.setattr(doctor, "_check_storage", lambda c: (True, "OK (SQLite)"))
    monkeypatch.setattr(doctor, "_check_ollama", lambda c: (True, "OK"))
    monkeypatch.setattr(doctor, "_check_openai", lambda c: (False, "no key"))


# ---- Docker context row (Phase 5 regression) --------------------------------

def _context(info: DockerContextInfo, monkeypatch):
    monkeypatch.setattr(
        "kryonsec.purple.runtime_checks.docker_context_info", lambda: info)
    return doctor._docker_context_row()


def test_explicitly_pinned_context_passes_even_with_other_contexts(monkeypatch):
    """An explicit pin (`docker context use <name>` / DOCKER_CONTEXT env)
    shows up as a non-default current context: Docker resolves it
    deterministically, so an operator who pinned the native daemon gets
    a PASS, not a permanent WARNING. Regression: every multi-context
    host was warned regardless of the selection."""
    info = DockerContextInfo(
        name="kryonsec-native",
        endpoint="unix:///var/run/docker.sock",
        contexts=("default", "kryonsec-native"),
    )
    status, msg = _context(info, monkeypatch)
    assert status == "PASS"
    assert "kryonsec-native" in msg and "unix:///var/run/docker.sock" in msg


def test_ambient_default_with_multiple_contexts_stays_warning(monkeypatch):
    """Selecting nothing while other contexts exist is the ambiguous
    case: Kryonsec does not switch contexts itself, so this stays a
    WARNING that names the safe action."""
    info = DockerContextInfo(
        name="default",
        endpoint="unix:///var/run/docker.sock",
        contexts=("default", "kryonsec-native"),
    )
    status, msg = _context(info, monkeypatch)
    assert status == "WARNING"
    assert "docker context use" in msg


def test_single_context_default_passes(monkeypatch):
    info = DockerContextInfo(
        name="default", endpoint="unix:///var/run/docker.sock",
        contexts=("default",),
    )
    status, msg = _context(info, monkeypatch)
    assert status == "PASS"


def test_docker_host_override_stays_warning(monkeypatch):
    info = DockerContextInfo(
        name="kryonsec-native", endpoint="unix:///var/run/docker.sock",
        contexts=("default", "kryonsec-native"),
        docker_host_override=True,
    )
    status, msg = _context(info, monkeypatch)
    assert status == "WARNING"
    assert "DOCKER_HOST" in msg


def test_context_inspection_error_fails(monkeypatch):
    info = DockerContextInfo(error="docker CLI request failed")
    status, msg = _context(info, monkeypatch)
    assert status == "FAIL"


# ---- provider key vs configuration state (Phase 4 regression) ---------------

def _wide_console(monkeypatch) -> None:
    """Render on a console wide enough that no table cell wraps.

    The table's column widths depend on which rows exist, and those rows
    differ by host (Docker/gVisor present or absent). A 240-column console
    still wrapped the long provider diagnostic on CI even though it did not
    wrap locally. 1000 columns is wider than the whole table, so the
    diagnostic text is rendered as one string on every host.
    """
    from rich.console import Console

    monkeypatch.setattr(doctor, "console", Console(width=1000))


# Rich draws a vertical border between wrapped cell lines. A phrase split
# by a wrap therefore reads ``built-in │ default`` in captured output even
# though the message is correct — and the exact wrap point depends on the
# host's detected rows (Docker/gVisor present or absent). Strip the borders
# before collapsing whitespace so the assertion tests the diagnostic text,
# not the table's column geometry.
_BOX_DRAWING = str.maketrans("", "", "│┃║┆┊╎╏")


def _rendered_text(output: str) -> str:
    return re.sub(r"\s+", " ", output.translate(_BOX_DRAWING))


def test_missing_openai_key_fails_the_provider_row_not_configuration(
        monkeypatch, tmp_path, capsys):
    """A valid config with provider=openai but no key anywhere: the
    OpenAI row must report the missing key honestly while the
    Configuration row still PASSes — the two states are distinct."""
    from kryonsec.config import config_path, write_config

    write_config(config_path(tmp_path), {
        "llm": {"provider": "openai"},
    })
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    _wide_console(monkeypatch)
    rc = doctor.run_doctor(KryonsecConfig(home=tmp_path))
    out = _rendered_text(capsys.readouterr().out)
    assert "valid TOML" in out
    assert "OPENAI_API_KEY not set" in out


def test_invalid_toml_names_the_config_fault_and_reports_the_key_state(
        monkeypatch, tmp_path, capsys):
    """The real WSL2 failure sequence: a corrupted config file made the
    file-stored key invisible, so doctor showed BOTH 'invalid TOML' and
    'OPENAI_API_KEY not set'. The Configuration row must name the TOML
    fault as the cause; the provider row may only report the key state
    it can actually see (env), never claim readiness."""
    from kryonsec.config import config_path

    config_path(tmp_path).write_text(
        '[llm]\nprovider = "openai"\nopenai_api_key = "sk-file-only"\n'
        "max_tokens = 100tokens = 2\n",  # fused line, the observed damage
        encoding="utf-8",
    )
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    _wide_console(monkeypatch)
    rc = doctor.run_doctor(KryonsecConfig(home=tmp_path))
    out = _rendered_text(capsys.readouterr().out)
    assert "invalid TOML" in out
    assert "OPENAI_API_KEY not set" in out
    assert "sk-file-only" not in out  # never echo a key value


def test_doctor_non_linux_renders_skip_not_fail(monkeypatch, tmp_path, capsys):
    _fake_checks(monkeypatch)
    monkeypatch.setattr(doctor.sys, "platform", "win32")
    cfg = KryonsecConfig(home=tmp_path)
    cfg.provider = "ollama"
    rc = doctor.run_doctor(cfg)
    out = capsys.readouterr().out
    assert rc == 0  # copilot profile works
    assert "SKIP" in out
    # the deliberately skipped rows must not read as failures
    assert "FAIL — Profile 1" not in out


def test_doctor_linux_missing_docker_still_fail(monkeypatch, tmp_path, capsys):
    _fake_checks(monkeypatch)
    monkeypatch.setattr(doctor.sys, "platform", "linux")
    monkeypatch.setattr(doctor, "_check_docker", lambda: (False, "docker CLI not found"))
    cfg = KryonsecConfig(home=tmp_path)
    cfg.provider = "ollama"
    rc = doctor.run_doctor(cfg)
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
    cfg = KryonsecConfig(home=tmp_path)
    cfg.provider = "bedrock"
    rc = doctor.run_doctor(cfg)
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


# ---- fresh-machine default provider honesty (Phase 7) -----------------------

def test_fresh_machine_names_the_builtin_default_it_checked(monkeypatch, tmp_path, capsys):
    """No config file yet: doctor still checks the BUILT-IN default
    provider (openai), which fails with no key. A reader who never
    configured anything must not read that FAIL as a mistake they made —
    the row has to say the checked provider is the built-in default and
    point at `kryonsec setup`."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(doctor, "_check_storage", lambda c: (True, "OK (SQLite)"))
    _wide_console(monkeypatch)
    rc = doctor.run_doctor(KryonsecConfig(home=tmp_path))
    out = _rendered_text(capsys.readouterr().out)
    assert rc == 1  # an unconfigured fresh machine is not yet usable — honest
    assert "OPENAI_API_KEY not set" in out
    assert "built-in default" in out
    assert "kryonsec setup" in out


def test_configured_openai_failure_does_not_claim_builtin_default(monkeypatch, tmp_path, capsys):
    """When a config file actually selected openai, the failure is about
    the user's own key — the 'built-in default' note must not appear, or
    it would accuse the user of a choice they did not make."""
    from kryonsec.config import config_path, write_config

    write_config(config_path(tmp_path), {"llm": {"provider": "openai"}})
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    _wide_console(monkeypatch)
    rc = doctor.run_doctor(KryonsecConfig(home=tmp_path))
    out = capsys.readouterr().out
    assert rc == 1
    assert "built-in default" not in out
    assert "OPENAI_API_KEY not set" in out
