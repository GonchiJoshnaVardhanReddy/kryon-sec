"""GENUINE network-egress integration tests (Phase 1E) — mocked-test
counterpart living in test_egress.py.

These tests prove the real boundary end-to-end against a REAL Docker
daemon + host firewall: the engagement network is created, the
DOCKER-USER chains are programmed, and real gVisor-sandboxed processes
succeed against an ALLOWED destination and fail against a BLOCKED one.

Safety/authorization:
- The engagement "target" is 203.0.113.0/24 or 198.51.100.0/24
  (TEST-NET-3 / TEST-NET-2). Neither is routed on the public internet,
  so nothing out there is ever touched; connect attempts to them are
  negative controls that must FAIL.
- The allowed destination in the live checks is 1.1.1.1 (Cloudflare
  public DNS) over HTTPS/DNS — a plain public service every developer
  machine already reaches; no scanning, no exploitation.

Run explicitly:  KRYONSEC_EGRESS_INTEGRATION=1  on a Linux host with
Docker + gVisor + programming privileges for iptables/ip6tables (run
under a non-interactive-root-capable sudo, e.g. `sudo -E
env KRYONSEC_EGRESS_INTEGRATION=1 .venv/bin/python -m pytest ...`, since
the egress gate programs the host firewall the same way a live engagement
does). Skipped silently in the regular suite — this is the expected
default on dev machines; an unexercised boundary must never be reported
as production-verified.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import urllib.request

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.egress import (  # real bindings (import time)
    EgressGate,
    _fw_prefix,
    _input_jump_argv,
    build_policy,
    release_active,
)
from kryonsec.purple.sandbox import KaliSandbox

_env_gated = pytest.mark.skipif(
    not (
        sys.platform.startswith("linux")
        and shutil.which("docker") is not None
        and os.environ.get("KRYONSEC_EGRESS_INTEGRATION") == "1"
    ),
    reason=(
        "genuine boundary test: needs Linux + docker + runsc + "
        "KRYONSEC_EGRESS_INTEGRATION=1 (never runs in the regular suite)"
    ),
)


def _sudo_prefix() -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    return ["sudo", "-n"]


def _skip_unless_host_can_program_fw():
    """Skip cleanly when the host preflights fail (no sudo cache, no
    iptables): the boundary tests must not run half-capable."""
    from kryonsec.purple import runtime_checks

    ok, why = runtime_checks.egress_firewall_ok()
    if not ok:
        pytest.skip(f"host cannot program the firewall: {why}")


@_env_gated
def test_establish_programs_a_real_firewall_and_release_removes_it():
    _skip_unless_host_can_program_fw()
    prefix = _sudo_prefix()
    cfg = KryonsecConfig()
    policy = build_policy(
        cfg, "eng-integ-fake0", "203.0.113.10",
        resolver=lambda h: [(2, 1, 6, "", ("203.0.113.10", 0))])
    gate = EgressGate()
    try:
        ok, reason = gate.establish(policy)
        assert ok, f"boundary establishment failed: {reason}"
        # 1) the network exists on the REAL daemon with pinned options
        inspect = subprocess.run(
            ["docker", "network", "inspect", policy.network_name],
            capture_output=True, text=True, timeout=30)
        assert inspect.returncode == 0, inspect.stderr
        netinfo = json.loads(inspect.stdout)[0]
        assert netinfo["Options"].get(
            "com.docker.network.bridge.enable_icc") == "false"
        # 2) the rules exist in the REAL kernel: default-deny DROP, the
        # family's authorized destinations, and the INPUT jump that
        # guards host-LOCAL delivery
        for cmd, allowed in (("iptables", policy.v4_allowed),
                             ("ip6tables", policy.v6_allowed)):
            dump = subprocess.run(
                prefix + [cmd, "-S", policy.chain_name],
                capture_output=True, text=True, timeout=30)
            assert dump.returncode == 0, (cmd, dump.stderr)
            assert "-j DROP" in dump.stdout
            for net in [str(n) for n in allowed]:
                assert f"-d {net}" in dump.stdout
            indump = subprocess.run(
                prefix + [cmd, "-S", "INPUT"],
                capture_output=True, text=True, timeout=30)
            assert indump.returncode == 0, (cmd, indump.stderr)
            # -S prints "-A INPUT -i <bridge> -j <chain>" — no insert pos
            jump_body = " ".join(_input_jump_argv(policy)[3:])
            assert jump_body in indump.stdout, indump.stdout
    finally:
        gate.release(policy)
        # teardown removed everything of ours
        for cmd in ("iptables", "ip6tables"):
            dump = subprocess.run(
                prefix + [cmd, "-S", policy.chain_name],
                capture_output=True, text=True, timeout=30)
            assert dump.returncode != 0, (
                f"{cmd} chain survived teardown: {dump.stdout}")
            indump = subprocess.run(
                prefix + [cmd, "-S", "INPUT"],
                capture_output=True, text=True, timeout=30)
            assert " ".join(_input_jump_argv(policy)[3:]) not in indump.stdout, \
                f"{cmd} INPUT jump survived teardown"
        inspect = subprocess.run(
            ["docker", "network", "inspect", policy.network_name],
            capture_output=True, text=True, timeout=30)
        assert inspect.returncode != 0, "network survived teardown"


@_env_gated
def test_sandbox_packets_are_scoped_to_the_engineering_boundary():
    """The REAL proof: an allowed destination is reachable from the
    gVisor sandbox; a BLOCKED destination is not — same container, same
    tool, same argv shape. Uses KaliSandbox itself, exactly like a run.
    """
    _skip_unless_host_can_program_fw()

    cfg = KryonsecConfig()
    # target: TEST-NET-3 (unroutable); operator scope: 1.1.1.1 only.
    cfg.zone_b_allowed_cidrs = ["1.1.1.1/32"]
    cfg.zone_b_dns_resolvers = ["1.1.1.1"]
    policy = build_policy(
        cfg, "eng-integ-live0", "203.0.113.10",
        resolver=lambda h: [(2, 1, 6, "", ("203.0.113.10", 0))])
    gate = EgressGate()
    try:
        ok, reason = gate.establish(policy)
        assert ok, f"boundary establishment failed: {reason}"
        # and the boundary verifies back against the real host
        assert gate.verify(policy) == (True, "ok")

        sb = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)

        # ALLOWED: HTTPS to the Cloudflare resolver endpoint. The exact
        # status is 1.1.1.1's business (it answers 200; live checks show
        # 301 = redirect to one.one.one.one); what the boundary test
        # proves is that the connection COMPLETED.
        allowed = sb.spawn(
            ["curl", "-s", "--max-time", "15", "-o", "/dev/null",
             "-w", "%{http_code}", "https://1.1.1.1/"])
        assert allowed.ok, allowed.error
        assert allowed.exit_code == 0, allowed.stdout
        assert allowed.stdout.strip() in ("200", "301", "302"), \
            allowed.stdout

        # BLOCKED: another public resolver is NOT in the allowlist —
        # curl must time out (exit 28), i.e. the packets were dropped,
        # not refused by the far end
        blocked = sb.spawn(
            ["curl", "--max-time", "15", "-o", "/dev/null", "-sS",
             "https://8.8.8.8/"])
        assert blocked.exit_code == 28, (
            f"8.8.8.8 was reachable THROUGH the boundary "
            f"(exit {blocked.exit_code}) — the egress allowlist is not "
            "enforced at the network layer")

        # the authorized TARGET itself (TEST-NET-3, nothing out there)
        # also cannot be reached except through the pinned allowlist
        hostile = sb.spawn(
            ["curl", "--max-time", "15", "-o", "/dev/null", "-sS",
             "https://203.0.113.10/"])
        assert hostile.exit_code == 28, (
            "TEST-NET-3 destination was reachable THROUGH the boundary")
    finally:
        gate.release(policy)
        release_active("eng-integ-live0")


@_env_gated
def test_dns_outside_pinned_resolvers_is_blocked():
    """DNS egress is pinned: a resolver outside the policy set gets no
    packets (dig times out); the pinned one answers."""
    _skip_unless_host_can_program_fw()

    cfg = KryonsecConfig()
    cfg.zone_b_allowed_cidrs = ["198.51.100.0/24"]
    cfg.zone_b_dns_resolvers = ["1.1.1.1"]
    policy = build_policy(
        cfg, "eng-integ-dns0", "198.51.100.10",
        resolver=lambda h: [(2, 1, 6, "", ("198.51.100.10", 0))])
    gate = EgressGate()
    try:
        ok, reason = gate.establish(policy)
        assert ok, f"boundary establishment failed: {reason}"
        sb = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)

        pinned = sb.spawn(["dig", "@1.1.1.1", "example.com", "+time=5",
                           "+tries=2"])
        if not pinned.ok or pinned.exit_code not in (0,):
            pytest.skip(f"dig not usable in the sandbox image: {pinned.error}")
        assert "status: NOERROR" in pinned.stdout

        blocked = sb.spawn(["dig", "@8.8.8.8", "example.com", "+time=5",
                            "+tries=2"])
        if blocked.ok and blocked.exit_code == 0 and \
                "status: NOERROR" in blocked.stdout:
            pytest.fail(
                "8.8.8.8 answered DNS THROUGH the boundary — resolver "
                "pinning is not enforced at the network layer")
    finally:
        gate.release(policy)
        release_active("eng-integ-dns0")


def _chain_drop_counter(prefix: list[str], chain_name: str) -> int:
    """Total packets hitting the DROP rules of our REAL chain — the
    unforgeable evidence that out-of-policy packets were received and
    dropped (not merely unreachable for some other reason)."""
    dump = subprocess.run(
        prefix + ["iptables", "-v", "-n", "-L", chain_name, "-x"],
        capture_output=True, text=True, timeout=30)
    assert dump.returncode == 0, dump.stderr
    total = 0
    for line in dump.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == "DROP":
            total += int(fields[0])
    return total


def _host_primary_ip() -> str:
    """The host's own IPv4 on its default interface — WITHOUT sending
    any packet (UDP connect only picks the route/socket address)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("203.0.113.1", 80))  # TEST-NET-3: unroutable target
        return s.getsockname()[0]
    finally:
        s.close()


class _IntegrationHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        body = b"kryonsec-egress-integration-endpoint"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the test output clean
        pass


@_env_gated
def test_container_to_host_local_traffic_is_blocked():
    """The Phase 1E.1 bypass case, proven on a REAL kernel: traffic from
    the sandbox to the bridge GATEWAY IP and to the host's OWN IP is
    routed to the host's INPUT chain and never traverses
    FORWARD/DOCKER-USER. With the INPUT jump programmed, both endpoints
    must be dropped (curl exit 28) even though the host really listens
    there — and the chain's DROP counter must climb, proving the drops
    were made BY OUR RULES and not by an unreachable listener.
    Endpoints are disposable local listeners only."""
    _skip_unless_host_can_program_fw()
    prefix = _sudo_prefix()

    # environment fingerprint (recorded, not decisive): which firewall
    # backend this boundary was genuinely exercised against
    ver = subprocess.run(["iptables", "--version"], capture_output=True,
                         text=True, timeout=30)
    backend = (ver.stdout or "").strip()
    print(f"\nfirewall backend: {backend}")

    cfg = KryonsecConfig()
    cfg.zone_b_allowed_cidrs = ["203.0.113.0/24"]
    cfg.zone_b_dns_resolvers = ["1.1.1.1"]
    policy = build_policy(
        cfg, "eng-integ-local0", "203.0.113.10",
        resolver=lambda h: [(2, 1, 6, "", ("203.0.113.10", 0))])
    gate = EgressGate()

    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 0), _IntegrationHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    try:
        ok, reason = gate.establish(policy)
        assert ok, f"boundary establishment failed: {reason}"
        assert gate.verify(policy) == (True, "ok")

        # the REAL gateway IP of OUR engagement network
        gw = subprocess.run(
            ["docker", "network", "inspect", "-f",
             "{{(index .IPAM.Config 0).Gateway}}", policy.network_name],
            capture_output=True, text=True, timeout=30)
        assert gw.returncode == 0, gw.stderr
        gateway = gw.stdout.strip()
        assert gateway == str(policy.subnet.network_address + 1)
        host_ip = _host_primary_ip()

        # positive listener control: the endpoint itself really serves
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/", timeout=5) as resp:
            assert resp.status == 200

        before = _chain_drop_counter(prefix, policy.chain_name)

        sb = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)

        # 1) container -> bridge gateway IP (the Docker host) — INPUT path
        to_gateway = sb.spawn(
            ["curl", "--connect-timeout", "6", "--max-time", "8", "-o",
             "/dev/null", "-sS", f"http://{gateway}:{port}/"])
        assert to_gateway.exit_code == 28, (
            f"the sandbox reached a host-local endpoint THROUGH the "
            f"boundary (gateway {gateway}:{port}, exit "
            f"{to_gateway.exit_code}) — the INPUT path is not filtered")

        # 2) container -> the host's own IP (host services / proxies)
        to_host = sb.spawn(
            ["curl", "--connect-timeout", "6", "--max-time", "8", "-o",
             "/dev/null", "-sS", f"http://{host_ip}:{port}/"])
        assert to_host.exit_code == 28, (
            f"the sandbox reached the host's own service THROUGH the "
            f"boundary (host {host_ip}:{port}, exit "
            f"{to_host.exit_code}) — the INPUT path is not filtered")

        # packet-level evidence: our chain witnessed and dropped them
        after = _chain_drop_counter(prefix, policy.chain_name)
        assert after >= before + 2, (
            f"DROP counter did not climb ({before} -> {after}): the "
            "refusals were NOT produced by the egress chain — investigate")

        # the listener still works host-side after all of this
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/", timeout=5) as resp:
            assert resp.status == 200
    finally:
        srv.shutdown()
        srv.server_close()
        gate.release(policy)
        release_active("eng-integ-local0")
        # the INPUT jump must be gone: no lasting restriction on the host
        for cmd in ("iptables", "ip6tables"):
            dump = subprocess.run(
                prefix + [cmd, "-S", "INPUT"],
                capture_output=True, text=True, timeout=30)
            assert " ".join(_input_jump_argv(policy)[3:]) not in dump.stdout, \
                f"{cmd} INPUT jump survived teardown"
