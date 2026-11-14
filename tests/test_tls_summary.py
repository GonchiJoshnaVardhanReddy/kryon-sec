"""TLS bounded-summary wrapper tests (Phase 2B.8, Task 4).

The Phase 2B.5 wrapper emitted every salvageable finding; a real run
produced ~24,932 chars of stdout, the sandbox's 20,000-char cap
honestly truncated it, and the payload was rejected — useful
observations lost. The corrected wrapper (containers/sandbox/scripts/
tls_probe.py) keeps the FULL tool output in the run's private /tmp
tmpfs, persists a redacted full-output artifact into the engagement
evidence dir when the run carries the mount, and prints a COMPACT,
SELF-BOUNDED summary (10,000 chars — far inside the host's UNCHANGED
20,000-char cap) whose counts and histogram always reflect ALL
salvaged findings.

These tests exercise the wrapper IN PROCESS (no subprocess, no
network): its pure functions directly, and main() end-to-end with
monkeypatched file paths and a fake testssl subprocess. The host
sandbox parser (adapter_tls.parse_tls_probe_payload) is tested against
the v2 payload shape for compatibility, including a v1-shaped payload.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kryonsec.purple.adapter_tls import parse_tls_probe_payload

_WRAPPER = Path("containers/sandbox/scripts/tls_probe.py")


def _load_script():
    spec = importlib.util.spec_from_file_location("tls_probe_v2", _WRAPPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def script(monkeypatch, tmp_path):
    """The wrapper with its file paths pointed at the test tmpfs."""
    mod = _load_script()
    monkeypatch.setattr(mod, "JSONFILE", str(tmp_path / "tls_findings.json"))
    monkeypatch.setattr(mod, "EVIDENCE_DIR", str(tmp_path / "evidence"))
    return mod


def _finding(fid: str, sev: str = "INFO", finding: str = "observed",
             port: str = "443") -> dict:
    return {"id": fid, "severity": sev, "finding": finding, "port": port}


def _write_findings(path: Path, findings: "list[dict]",
                    truncate_at: "int | None" = None) -> None:
    text = json.dumps(findings, indent=1)
    if truncate_at is not None:
        text = text[:truncate_at]
    path.write_text(text, encoding="utf-8")


def _fake_testssl(monkeypatch, script, exit_code: int = 0,
                  stdout: str = ""):
    """In-process invocation: the wrapper's argv is exactly one URL
    argument (as the entrypoint's baked contract requires), and a
    testssl subprocess that writes nothing and exits cleanly."""
    monkeypatch.setattr(script.sys, "argv",
                        ["tls_probe.py", "https://target-corp.com:8443/"])
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, exit_code, stdout, "")
    monkeypatch.setattr(script.subprocess, "run", run)

@pytest.fixture()
def capout(capsys):
    class Cap:
        @staticmethod
        def payload() -> dict:
            out = capsys.readouterr().out.strip()
            assert out, "the wrapper must print exactly one JSON payload"
            return json.loads(out)
    return Cap


# ---- small output ----------------------------------------------------------


def test_small_output_is_complete_and_fits(script, monkeypatch, capout,
                                           tmp_path):
    findings = [_finding("SSLv3", "LOW", "not offered"),
                _finding("cert_expirationStatus", "HIGH", "expires < 7d"),
                _finding("cipher_stuff", "OK", "fine")]
    _write_findings(Path(script.JSONFILE), findings)
    _fake_testssl(monkeypatch, script)
    rc = script.main()
    payload = capout.payload()
    assert rc == 0
    assert payload["kind"] == "kryonsec_tls_probe"
    assert payload["status"] == "complete"
    assert payload["finding_count_total"] == 3
    assert payload["severity_histogram"] == {"HIGH": 1, "LOW": 1, "OK": 1}
    assert payload["finding_count_emitted"] == 2   # the two weak findings
    assert len(json.dumps(payload)) <= script.OUTPUT_BOUND_CHARS
    assert payload["summary_truncated"] is False


# ---- output larger than the host bound --------------------------------------


def test_oversized_run_stays_under_the_host_cap(script, monkeypatch,
                                                capout, tmp_path):
    """A run producing ~25k chars of findings still yields a summary
    that fits: self-bound 10,000 chars, TRUE totals kept."""
    findings = [_finding(f"weak_cipher_{i}", "LOW", "x" * 280)
                for i in range(100)]
    _write_findings(Path(script.JSONFILE), findings)
    _fake_testssl(monkeypatch, script)
    rc = script.main()
    payload = capout.payload()
    assert rc == 0
    raw = json.dumps(payload)
    assert len(raw) <= script.OUTPUT_BOUND_CHARS < 20_000
    assert payload["finding_count_total"] == 100       # honest total
    assert payload["finding_count_emitted"] <= script.TOP_WEAK_FINDINGS
    assert payload["severity_histogram"] == {"LOW": 100}
    assert payload["truncated"] is True
    assert payload["summary_truncated"] is False   # bound was not hit


def test_bound_shrinks_sections_before_honesty(script, monkeypatch,
                                               capout, tmp_path):
    """When even the selection exceeds the self-bound, the wrapper
    drops list bodies first and sets summary_truncated — counts and
    the histogram NEVER drop."""
    findings = ([_finding(f"SSLv{i}", "LOW", "y" * 280)
                 for i in range(40)] +
                [_finding(f"weak_{i}", "HIGH", "z" * 280)
                 for i in range(40)])
    _write_findings(Path(script.JSONFILE), findings)
    _fake_testssl(monkeypatch, script)
    monkeypatch.setattr(script, "OUTPUT_BOUND_CHARS", 4_000)
    rc = script.main()
    payload = capout.payload()
    assert rc == 0
    raw = json.dumps(payload)
    assert len(raw) <= 4_000
    assert payload["summary_truncated"] is True
    assert payload["finding_count_total"] == 80
    assert payload["severity_histogram"] == {"HIGH": 40, "LOW": 40}
    assert "limitations" in payload and payload["limitations"]
    # the floor sections may be empty but the payload is valid JSON
    # with honest counts — the host parser still accepts it
    run, malformed = parse_tls_probe_payload(json.dumps(payload))
    assert malformed == 0 and run is not None
    assert run.finding_count_total == 80


# ---- malformed / partial ------------------------------------------------------


def test_malformed_json_is_salvaged_not_fabricated(script, monkeypatch,
                                                  capout, tmp_path):
    truncated = json.dumps([
        _finding("SSLv3", "LOW", "not offered"),
        _finding("cert_expirationStatus", "HIGH", "expired"),
    ], indent=1)[:-60]        # cut mid-object: the FIRST object survives
    Path(script.JSONFILE).write_text(truncated, encoding="utf-8")
    _fake_testssl(monkeypatch, script)
    rc = script.main()
    payload = capout.payload()
    assert rc == 0
    assert payload["finding_count_total"] == 1     # the complete one only
    assert [f["id"] for f in payload["findings"]] == ["SSLv3"]


def test_no_findings_file_is_an_honest_error(script, monkeypatch, capout):
    (Path(script.JSONFILE)).unlink(missing_ok=True)
    _fake_testssl(monkeypatch, script, exit_code=3)
    rc = script.main()
    payload = capout.payload()
    assert rc == 1
    assert payload["status"] == "error"
    assert payload["finding_count_total"] == 0
    assert payload["artifact"] is None


def test_partial_timeout_output(script, monkeypatch, capout, tmp_path):
    """A killed run keeps the partial findings it wrote and says so —
    never presented as complete."""
    findings = [_finding("weak_1", "HIGH", "partial run")]
    _write_findings(Path(script.JSONFILE), findings)
    _fake_testssl(monkeypatch, script)
    def slow_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 240)
    monkeypatch.setattr(script.subprocess, "run", slow_run)
    rc = script.main()
    payload = capout.payload()
    assert rc == 0
    assert payload["status"] == "partial"
    assert any("killed" in lim for lim in payload["limitations"])
    assert payload["finding_count_total"] == 1
    assert payload["findings"][0]["id"] == "weak_1"


# ---- excessive finding count --------------------------------------------------


def test_excessive_findings_top_n_selection(script, monkeypatch, capout,
                                            tmp_path):
    findings = ([_finding(f"weak_{i}", "LOW", f"weakness {i}")
                 for i in range(300)] +
                [_finding(f"info_{i}", "INFO", "f") for i in range(300)])
    _write_findings(Path(script.JSONFILE), findings)
    _fake_testssl(monkeypatch, script)
    rc = script.main()
    payload = capout.payload()
    assert rc == 0
    assert payload["finding_count_total"] == 600
    assert payload["severity_histogram"] == {"INFO": 300, "LOW": 300}
    assert payload["finding_count_emitted"] == script.TOP_WEAK_FINDINGS
    assert len(payload["findings"]) == script.TOP_WEAK_FINDINGS
    assert payload["truncated"] is True
    assert "top-20 weakest of 600" in payload["selection_note"]


# ---- artifact behavior ---------------------------------------------------------


def test_no_evidence_mount_means_no_artifact(script, monkeypatch, capout,
                                             tmp_path):
    _write_findings(Path(script.JSONFILE), [_finding("SSLv3", "LOW")])
    _fake_testssl(monkeypatch, script)
    script.main()
    payload = capout.payload()
    assert payload["artifact"] is None
    assert any("no evidence dir" in lim for lim in payload["limitations"])


def test_artifact_written_hashed_and_restricted(script, monkeypatch,
                                                capout, tmp_path):
    os.mkdir(Path(script.EVIDENCE_DIR))
    findings = [_finding("cert_expirationStatus", "HIGH", "expired"),
                _finding("SSLv3", "LOW", "no")]
    _write_findings(Path(script.JSONFILE), findings)
    _fake_testssl(monkeypatch, script)
    script.main()
    payload = capout.payload()
    art = payload["artifact"]
    assert art is not None and "omitted" not in art
    path = Path(script.EVIDENCE_DIR) / art["name"]
    assert path.is_file()
    data = path.read_bytes()
    assert art["bytes"] == len(data)
    assert art["sha256"] == __import__("hashlib").sha256(data).hexdigest()
    assert art["source_file"] == script.JSONFILE
    # restrictive permissions
    assert (os.stat(path).st_mode & 0o777) == 0o600
    # redaction note + zero redactions for this clean fixture
    assert art["redactions"] == 0
    assert "redacted copy" in art["note"]


def test_artifact_redacts_secrets(script, monkeypatch, capout, tmp_path):
    """Credential-bearing content is redacted from the PERSISTED copy —
    the pattern is counted, never silently passed through."""
    os.mkdir(Path(script.EVIDENCE_DIR))
    sensitive = ("password=hunter2 and api_key=sk-1234567890abcdef "
                 "-----BEGIN PRIVATE KEY-----\nMIIabc\n"
                 "-----END PRIVATE KEY----- AKIAIOSFODNN7EXAMPLE")
    findings = [_finding("cert_content", "INFO", sensitive)]
    Path(script.JSONFILE).write_text(json.dumps(findings), encoding="utf-8")
    _fake_testssl(monkeypatch, script)
    script.main()
    payload = capout.payload()
    art = payload["artifact"]
    assert art["redactions"] >= 3
    persisted = (Path(script.EVIDENCE_DIR) / art["name"]).read_text()
    assert "hunter2" not in persisted
    assert "sk-1234567890abcdef" not in persisted
    assert "BEGIN PRIVATE KEY" not in persisted
    assert "AKIAIOSFODNN7EXAMPLE" not in persisted
    assert "<redacted>" in persisted


def test_artifact_refuses_symlink_evidence_dir(script, monkeypatch,
                                               capout, tmp_path):
    """A symlinked evidence dir is refused — traversal by mount-point
    swap is one of the named attacks."""
    real = tmp_path / "real_evil"
    real.mkdir()
    os.symlink(real, Path(script.EVIDENCE_DIR))
    _write_findings(Path(script.JSONFILE), [_finding("SSLv3", "LOW")])
    _fake_testssl(monkeypatch, script)
    script.main()
    payload = capout.payload()
    assert payload["artifact"] is None
    assert not real.iterdir().__next__() if any(
        real.iterdir()) else True   # nothing written through the link


def test_artifact_refuses_symlink_target_and_never_clobbers(
        script, monkeypatch, capout, tmp_path):
    os.mkdir(Path(script.EVIDENCE_DIR))
    _write_findings(Path(script.JSONFILE), [_finding("SSLv3", "LOW")])
    _fake_testssl(monkeypatch, script)
    # first run writes the artifact
    script.main()
    first = capout.payload()["artifact"]
    # a SECOND run within the same second would collide — O_EXCL must
    # refuse to clobber and report honestly
    script.main()
    second = capout.payload()["artifact"]
    assert first is not None
    assert second is None     # omitted, never overwritten


def test_oversized_artifact_is_omitted_with_reason(script, monkeypatch,
                                                  capout, tmp_path):
    os.mkdir(Path(script.EVIDENCE_DIR))
    monkeypatch.setattr(script, "ARTIFACT_MAX_BYTES", 64)
    _write_findings(Path(script.JSONFILE), [_finding("SSLv3", "LOW", "x" * 300)])
    _fake_testssl(monkeypatch, script)
    script.main()
    payload = capout.payload()
    assert payload["artifact"] is None
    assert any("oversized" in lim for lim in payload["limitations"])


# ---- parser compatibility (v2 payload; v1 still parses) ------------------------


def test_parser_understands_v2_payload(script, monkeypatch, capout,
                                       tmp_path):
    os.mkdir(Path(script.EVIDENCE_DIR))
    findings = ([_finding("TLS1_0", "LOW", "offered")] * 3 +
                [_finding("cert_expirationStatus", "HIGH", "expired")])
    _write_findings(Path(script.JSONFILE), findings)
    _fake_testssl(monkeypatch, script)
    script.main()
    stdout = json.dumps(capout.payload())
    run, malformed = parse_tls_probe_payload(stdout)
    assert malformed == 0 and run is not None
    assert run.version == 2
    assert run.finding_count_total == 4
    assert run.finding_count_emitted == 4   # 3×TLS1_0 LOW + cert HIGH, all weak
    assert run.severity_histogram == {"HIGH": 1, "LOW": 3}
    assert run.artifact is not None
    assert len(run.artifact.sha256) == 64
    assert run.summary_bound_chars == script.OUTPUT_BOUND_CHARS
    # protocols/certs sections flow into the parsed model
    assert run.protocols_section[0].finding_id == "TLS1_0"
    assert run.certificates_section[0].finding_id == "cert_expirationStatus"


def test_v1_shaped_payload_still_parses():
    v1 = {
        "kind": "kryonsec_tls_probe",
        "url": "https://t:443/", "node": "t:443",
        "tool": "testssl", "tool_version": "3.2.4",
        "status": "complete", "exit_code": 0, "started_at": "x",
        "argv_reference": ["/usr/bin/testssl", "--quiet"],
        "findings": [{"id": "SSLv3", "severity_as_reported": "LOW",
                      "finding": "no", "cve": "", "port": "443"}],
        "finding_count": 1, "truncated": False,
    }
    run, malformed = parse_tls_probe_payload(json.dumps(v1))
    assert malformed == 0 and run is not None
    assert run.version == 1
    assert run.finding_count_total == 0     # v1 carried no total
    assert run.weak_findings[0].finding_id == "SSLv3"


def test_v2_node_properties_carry_counts_and_artifact(script, monkeypatch,
                                                      capout, tmp_path):
    os.mkdir(Path(script.EVIDENCE_DIR))
    findings = ([_finding("TLS1_0", "LOW", "offered")] * 30 +
                [_finding("cert_expirationStatus", "HIGH", "expired")])
    _write_findings(Path(script.JSONFILE), findings)
    _fake_testssl(monkeypatch, script)
    script.main()
    stdout = json.dumps(capout.payload())
    run, malformed = parse_tls_probe_payload(stdout)
    assert malformed == 0
    props = run.summary_properties(request_id="req-1")
    assert props["finding_count_total"] == 31
    assert props["finding_count_emitted"] == 20
    assert props["severity_histogram"] == {"HIGH": 1, "LOW": 30}
    assert props["summary_truncated"] is False
    assert props["artifact"]["sha256"]
    assert props["verification"] == "not_verified"
    assert props["classification"] == "tool_reported_observation"


# ---- honesty end-to-end --------------------------------------------------------


def test_full_result_is_never_claimed_partial(script, monkeypatch, capout,
                                              tmp_path):
    _write_findings(Path(script.JSONFILE), [_finding("SSLv3", "LOW")])
    _fake_testssl(monkeypatch, script)
    rc = script.main()
    payload = capout.payload()
    assert rc == 0 and payload["status"] == "complete"
    assert payload["summary_truncated"] is False
    assert payload["truncated"] is False
    assert payload["finding_count_total"] == payload["finding_count_emitted"]


def test_host_cap_untouched():
    """The sandbox stdout bound is NOT changed by the wrapper fix."""
    from kryonsec.config import KryonsecConfig
    assert KryonsecConfig().max_tool_output_chars == 20_000
