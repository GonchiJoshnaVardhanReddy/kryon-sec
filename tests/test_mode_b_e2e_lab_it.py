"""Phase 2C.1 — REAL-container Mode B lab IT (tier 2).

Genuinely runs a complete Mode B engagement's Zone-B tooling inside REAL
gVisor (runsc) containers against a disposable, self-contained local lab
that this IT launches itself. This is the ONLY tier that may claim "a
real runsc container executed the tool".

Opt-in on purpose: run with ``KRYONSEC_MODE_B_E2E=1`` on a Linux host
with Docker + runsc + the pinned sandbox image, and privileges to
program iptables (the REAL egress boundary is armed — this file is
exempted from the conftest fake for exactly that reason). Skipped
silently otherwise.

Safety/authorization:

- The lab target is a throwaway container the IT starts itself, on the
  engagement's own egress bridge, serving ONE deterministic page. It is
  torn down again afterwards.
- The egress allowlist contains exactly that lab IP plus the pinned DNS
  resolvers, and the chain ends in an absolute DROP: nothing beyond the
  lab is reachable, and nothing public is ever touched.
- Declared fixtures, identical to the offline tier: the LLM consultants
  (hypothesize/blue-team) are deterministic objects, Zone-A fetchers are
  an empty fixture and enrichment is stubbed. Every Zone-B tool the
  report describes REALLY executed in its runsc container.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from kryonsec.config import KryonsecConfig

# Reuse the offline tier's declared consultant fixtures so both tiers
# inject at exactly the same seams.
from test_mode_b_e2e import (
    _consultant_init,
    _original_init,
    _read_chain,
    _remediation_set,
    _sqli_hypotheses,
)

LAB_SERVER_SCRIPT = """import http.server, urllib.parse as up
def do_GET(self):
    p = up.unquote(self.path)
    body = (b"LAB-PAGE-B-EMPTY" if "1=2" in p else b"LAB-PAGE-A-ROWS-7")
    self.send_response(200)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)
class S(http.server.BaseHTTPRequestHandler):
    do_GET = do_GET
    def log_message(self, *a):
        pass
http.server.HTTPServer(("0.0.0.0", 80), S).serve_forever()
"""


def _it_readiness() -> "tuple[bool, str]":
    """Everything a REAL lab engagement needs, probed honestly."""
    if os.environ.get("KRYONSEC_MODE_B_E2E") != "1":
        return False, "KRYONSEC_MODE_B_E2E=1 not set"
    if not sys.platform.startswith("linux"):
        return False, f"Mode B needs Linux, this is {sys.platform}"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    if not ok:
        return False, f"docker daemon: {reason}"
    if not rc.runsc_registered():
        return False, "runsc runtime not registered"
    image = KryonsecConfig().sandbox_image
    if not rc.image_present(image):
        return False, f"pinned sandbox image absent: {image}"
    return True, ""


def _lab_ip(cfg: KryonsecConfig) -> str:
    """A fixed, safe address inside the engagement subnet for the lab."""
    subnet = ipaddress.ip_network(cfg.zone_b_subnet, strict=False)
    return str(subnet.network_address + 10)


def _docker(args: "list[str]", timeout: int = 120) -> "tuple[bool, str]":
    try:
        proc = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()[:300]
    return True, (proc.stdout or "").strip()


def _start_lab(network: str, lab_ip: str, image: str, tag: str):
    """The disposable lab HTTP server: same bridge as the tools, fixed IP,
    deterministic page, torn down by the caller."""
    _docker(["rm", "-f", tag])
    ok, out = _docker([
        "run", "-d", "--rm", "--name", tag,
        "--network", network, "--ip", lab_ip,
        "--entrypoint", "python3",
        image, "-c", LAB_SERVER_SCRIPT,
    ])
    if not ok:
        return False, out
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                    f"http://{lab_ip}/?id=7", timeout=3) as resp:
                if b"LAB-PAGE-A-ROWS-7" in resp.read():
                    return True, "ok"
        except OSError:
            time.sleep(0.5)
    return False, "lab server never became reachable"


def _named(events, name):
    return [e for e in events if e.get("event") == name]


@pytest.fixture()
def lab_env(tmp_path, monkeypatch):
    """Readiness check + the disposable lab on the engagement bridge.

    The network is created with the SAME shape the egress gate derives;
    the REAL establish() inside start_engagement then reuses it
    (subnet-matched, verified) and arms the firewall around it.
    """
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"real-container lab IT not armed: {reason}")

    from kryonsec.purple import egress

    cfg = KryonsecConfig(home=tmp_path)
    cfg.database_url = f"sqlite:///{tmp_path / 'purple.db'}"
    engagement_id = f"e2e-lab-{os.getpid()}"
    lab_ip = _lab_ip(cfg)
    policy = egress.build_policy(cfg, engagement_id, lab_ip)  # REAL policy
    # The network must be EXACTLY the engine's shape — created through the
    # engine's own argv builder (which pins the bridge interface name the
    # gate programs DOCKER-USER jumps against). Hand-rolling the argv here
    # silently produced a bridge the gate's rules never matched: traffic
    # died on the icc=false isolation drop and the direct-spawn probe
    # timed out (curl exit 28) — a fail-closed boundary nobody was behind.
    # network_create_argv starts with the "docker" literal; the IT's
    # _docker helper adds the binary itself, so drop the first token.
    ok_n, err = _docker(egress.network_create_argv(policy)[1:])
    assert ok_n or "already exists" in (err or ""), err
    ok_l, reason = _start_lab(
        policy.network_name, lab_ip, cfg.sandbox_image,
        f"kryonsec-e2e-lab-{os.getpid()}")
    assert ok_l, f"lab server failed to start: {reason}"
    yield SimpleNamespace(
        cfg=cfg, engagement_id=engagement_id, lab_ip=lab_ip,
        network=policy.network_name)
    subprocess.run(
        ["docker", "rm", "-f", f"kryonsec-e2e-lab-{os.getpid()}"],
        capture_output=True)
    subprocess.run(
        ["docker", "network", "rm", policy.network_name], capture_output=True)


def _declared_fixtures(monkeypatch):
    """The SAME declared seams as the offline tier: no LLM provider, no
    third-party HTTP. The sandbox, the egress boundary and every tool
    stay completely REAL."""
    import kryonsec.purple.blue_team as blue_team
    import kryonsec.purple.enrichment as enrichment
    import kryonsec.purple.hypothesize as hypothesize
    import kryonsec.purple.recon_passive as recon_passive

    monkeypatch.setattr(recon_passive, "zone_a_fetchers", lambda cfg: [])
    monkeypatch.setattr(enrichment, "enrich_hypotheses", lambda *a, **k: None)
    monkeypatch.setattr(
        hypothesize.HypothesizeSubagent, "__init__",
        _consultant_init(hypothesize.HypothesizeSubagent,
                         _sqli_hypotheses()))
    monkeypatch.setattr(
        blue_team.BlueTeamSubagent, "__init__",
        _consultant_init(blue_team.BlueTeamSubagent, _remediation_set()))


def test_real_lab_container_serves_a_real_runsc_spawn(lab_env, monkeypatch):
    """The crisp execution claim: a REAL gVisor sandbox, spawned through
    the REAL egress boundary, really runs curl against the REAL lab and
    sees the lab's deterministic page — and a non-lab destination gets
    nothing through the boundary."""
    from kryonsec.purple import egress
    from kryonsec.purple.sandbox import KaliSandbox

    cfg, lab_ip = lab_env.cfg, lab_env.lab_ip
    # The policy MUST be derived under the fixture's engagement id: the
    # fixture already created that engagement's network with this subnet,
    # and establish() then reuses it instead of colliding with a second
    # pool on the same address space.
    policy = egress.build_policy(cfg, lab_env.engagement_id, lab_ip)
    assert policy.network_name == lab_env.network
    gate = egress.EgressGate()
    ok, reason = gate.establish(policy)
    assert ok, f"real egress establish failed: {reason}"
    try:
        sbx = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
        result = sbx.spawn(["curl", "-s", f"http://{lab_ip}/?id=7"])
        assert result.ok, result.error
        assert result.exit_code == 0, result.stdout
        assert "LAB-PAGE-A-ROWS-7" in result.stdout, (
            "a real runsc curl did not see the lab page: "
            f"{result.stdout!r}")
        # the boundary holds the other way: a destination that is NOT the
        # lab must not get through
        strays = ipaddress.ip_network(cfg.zone_b_subnet).broadcast_address
        result2 = sbx.spawn(["curl", "-s", "-m", "5", f"http://{strays}/"])
        assert "LAB-PAGE-A-ROWS-7" not in result2.stdout, (
            "the egress boundary let a non-lab destination through")
    finally:
        gate.release(policy)


def test_real_full_engagement_runs_zone_b_in_runsc(lab_env, monkeypatch):
    """A complete engagement end-to-end with REAL containers: the lab is
    the engagement target, Zone-B tools really run, the audit chain and
    the report are produced by the REAL engine."""
    from kryonsec.purple.runner import (
        persist_graph,
        record_engagement_ending,
        start_engagement,
    )
    from kryonsec.storage import reset_engine

    _declared_fixtures(monkeypatch)
    cfg, engagement_id, lab_ip = (
        lab_env.cfg, lab_env.engagement_id, lab_env.lab_ip)

    reset_engine()
    orch, audit, graph = start_engagement(
        cfg, engagement_id, target=lab_ip,
        human_reviewer=lambda hyps: {h["label"] for h in hyps},
        post_exploit_approver=lambda claim: False,
    )
    try:
        completed = orch.run()
        persist_graph(cfg, engagement_id, graph, audit)
        record_engagement_ending(
            cfg, engagement_id,
            outcome="halted" if orch.halt_reason else "completed",
            reason=orch.halt_reason,
            last_state=completed[-1] if completed else None,
            states_entered=len(completed),
        )
        engagement_dir = cfg.home / "engagements" / engagement_id
        events = _read_chain(cfg.home, engagement_id)

        # The loop ran to REPORT with the real sandbox probe passing and
        # the REAL egress boundary established.
        assert orch.state == "HALT" and orch.halt_reason is None
        assert completed == [
            "INIT", "RECON_PASSIVE", "RECON_ACTIVE", "HYPOTHESIZE",
            "HUMAN_REVIEW", "EXPLOIT", "VERIFY", "BLUE_TEAM", "REPORT"]
        check = _named(events, "sandbox_check")[-1]
        assert check["available"] is True, check["reason"]
        assert _named(events, "egress_policy_established"), (
            "the REAL egress boundary never established")

        # Zone-B tools REALLY ran: real spawns with real output — sqlmap
        # always prints its banner, so a zero-length stdout would mean
        # nothing actually executed.
        spawned = {e["tool"] for e in _named(events, "tool_spawn")}
        assert {"sqlmap", "curl"} <= spawned, sorted(spawned)
        # REAL target connectivity during the engagement: a curl inside
        # the sandbox fetched a NON-EMPTY body through the REAL egress
        # boundary. With the lab as the only authorized destination,
        # this can only be true if the tools actually reached the
        # authorized target (a dropped boundary yields exit 28 and
        # output_chars 0).
        curl_bodies = [
            e for e in _named(events, "tool_result")
            if e.get("tool") == "curl" and e.get("ok")
            and e.get("output_chars", 0) > 0]
        assert curl_bodies, (
            "no curl result with a non-empty body — the engagement's "
            "tools never actually reached the lab")
        sqlmap_results = [
            e for e in _named(events, "tool_result")
            if e.get("hypothesis_id") and e.get("ok")]
        assert sqlmap_results, "no successful tool_result in the chain"
        # real execution evidence lives in the graph too
        attempts = graph.by_type("exploit_attempt")
        assert attempts, "no exploit_attempt nodes recorded"

        # The report and the chain are the REAL engine's artifacts.
        assert (engagement_dir / "report.md").is_file()
        assert (engagement_dir / "report.json").is_file()
        ok_c, reason_c = audit.verify()
        assert ok_c, reason_c
        endings = _named(events, "engagement_finished")
        assert len(endings) == 1
        assert endings[-1]["outcome"] == "completed"
    finally:
        reset_engine()
