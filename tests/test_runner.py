"""Tests for the engagement runner (spec §4): two-tier gating.

On non-sandbox systems the engagement runs INIT + RECON_PASSIVE, then HALTs
at the first Zone B state with an audited reason — never runs un-sandboxed.
"""

from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.zonea import PassiveResult
from kryonsec.purple.runner import sandbox_available, start_engagement


def _fake_recon(domain):
    return PassiveResult(source="crt.sh", subdomains=["www." + domain])


@pytest.mark.parametrize(
    "runtimes,image_present,expected_reason",
    [
        (None, False, "docker CLI not found or daemon unreachable"),  # daemon down
        ("io.containerd.runc.v2,runc", False, "runsc"),  # no gVisor
        ("io.containerd.runc.v2,runc,runsc", False, "sandbox image not found"),  # no image
    ],
)
def test_sandbox_available_failure_paths(runtimes, image_present, expected_reason):
    with patch("kryonsec.purple.runner.platform.system", return_value="Linux"):
        with patch("kryonsec.purple.runner._docker_runtimes", return_value=runtimes):
            with patch("kryonsec.purple.runner._image_present", return_value=image_present):
                ok, reason = sandbox_available()
    assert not ok
    assert expected_reason in reason


def test_sandbox_available_ok_when_image_present():
    with patch("kryonsec.purple.runner.platform.system", return_value="Linux"):
        with patch(
            "kryonsec.purple.runner._docker_runtimes",
            return_value="io.containerd.runc.v2,runc,runsc",
        ):
            with patch("kryonsec.purple.runner._image_present", return_value=True):
                ok, reason = sandbox_available()
    assert ok, reason
    assert reason == "ok"


def test_sandbox_available_non_linux():
    with patch("kryonsec.purple.runner.platform.system", return_value="Windows"):
        ok, reason = sandbox_available()
    assert not ok
    assert "requires Linux" in reason


def test_engagement_halts_after_recon_without_sandbox(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    with patch("kryonsec.purple.runner.sandbox_available", return_value=(False, "not Linux")):
        with patch("kryonsec.purple.recon_passive.crt_sh_subdomains", side_effect=_fake_recon):
            orch, audit, graph = start_engagement(cfg, "e-run", target="target-corp.com")
            completed = orch.run()

    # INIT + RECON_PASSIVE ran; RECON_ACTIVE was blocked -> HALT
    assert completed[:3] == ["INIT", "RECON_PASSIVE", "RECON_ACTIVE"]
    assert orch.state == "HALT"
    assert "not Linux" in (orch.halt_reason or "")
    # Zone A results are present despite the halt
    assert [n["label"] for n in graph.by_type("subdomain")] == ["www.target-corp.com"]
    # the halt is audited
    import json
    with open(audit.path, encoding="utf-8") as f:
        events = [json.loads(line)["event"] for line in f if line.strip()]
    assert "zone_b_blocked" in events
    ok, reason = audit.verify()
    assert ok, reason


def test_engagement_runs_with_sandbox(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    with patch("kryonsec.purple.runner.sandbox_available", return_value=(True, "ok")):
        with patch("kryonsec.purple.recon_passive.crt_sh_subdomains", side_effect=_fake_recon):
            orch, audit, graph = start_engagement(cfg, "e-run2", target="target-corp.com")
            completed = orch.run()

    # Full loop: stubs report 'failed' but the state machine still walks on
    assert orch.state == "HALT"
    assert completed[0] == "INIT"
    assert "RECON_PASSIVE" in completed
    ok, reason = audit.verify()
    assert ok, reason
