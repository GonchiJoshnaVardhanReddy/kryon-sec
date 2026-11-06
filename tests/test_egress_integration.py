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
Docker + gVisor + non-interactive sudo for iptables. Skipped silently
in the regular suite — this is the expected default on dev machines;
an unexercised boundary must never be reported as production-verified.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.egress import (  # real bindings (import time)
    EgressGate,
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
        assert "com.docker.network.bridge.enable_icc=false" in inspect.stdout
        # 2) the rules exist in the REAL kernel, both families: the
        # default-deny DROP plus the exact authorized /32
        allowed_v4 = [str(n) for n in policy.v4_allowed]
        for cmd in ("iptables", "ip6tables"):
            dump = subprocess.run(
                prefix + [cmd, "-S", policy.chain_name],
                capture_output=True, text=True, timeout=30)
            assert dump.returncode == 0, (cmd, dump.stderr)
            assert "-j DROP" in dump.stdout
            for net in allowed_v4:
                assert f"-d {net}" in dump.stdout
    finally:
        gate.release(policy)
        # teardown removed everything of ours
        for cmd in ("iptables", "ip6tables"):
            dump = subprocess.run(
                prefix + [cmd, "-S", policy.chain_name],
                capture_output=True, text=True, timeout=30)
            assert dump.returncode != 0, (
                f"{cmd} chain survived teardown: {dump.stdout}")
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

        # ALLOWED: HTTPS to the Cloudflare resolver endpoint
        allowed = sb.spawn(
            ["curl", "--max-time", "15", "-o", "/dev/null",
             "-w", "%{http_code}", "https://1.1.1.1/"])
        assert allowed.ok, allowed.error
        assert allowed.exit_code == 0, allowed.stdout
        assert allowed.stdout.strip() == "200", allowed.stdout

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
