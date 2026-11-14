"""Ensure the package source is on sys.path for test runs (works even when
the package is not installed editable). The package lives at src/kryonsec —
inserting the repo root alone would not make `import kryonsec` work."""

import sys
from pathlib import Path

import pytest

src = Path(__file__).resolve().parents[1] / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))


@pytest.fixture(autouse=True)
def _member(request, monkeypatch):
    """Purple Team is a paid feature, and this suite drives it with no key.

    Every test that runs an engagement would otherwise stop at the membership
    gate and assert against a refusal instead of the behaviour it names. The
    gate is stood down for the suite and kept standing in test_license.py,
    which is the file that exists to prove it refuses — patching it there
    would leave those tests checking the stub.

    NB: patched on `kryonsec.license`, not `kryonsec.cli`. cli._run_purple
    imports the name inside the function body, so it looks it up on the
    module at call time — patching the module is what takes effect.
    """
    if Path(str(request.node.fspath)).name == "test_license.py":
        return
    from kryonsec import license

    monkeypatch.setattr(
        license, "ensure_purple_allowed",
        lambda cfg: license.VerifyResult(status=license.VALID, message="test member"),
    )


@pytest.fixture(autouse=True)
def _egress_boundary(request, monkeypatch):
    """The Zone B network-egress boundary is stood up and verified with the
    host's docker daemon and firewall — real work the test suite cannot do
    (and must not do). This fixture gives every runner-driven test a
    working boundary WITHOUT touching the host: `build_policy` returns a
    real EgressPolicy built from literal addresses (no DNS), and
    `EgressGate` is replaced by a recording fake whose establish/verify
    succeed.

    test_egress.py keeps the REAL classes for its gate-level tests via
    its own import-time bindings, and tests that need a failing boundary
    patch the module attributes themselves. The integration test files
    are skipped here too: the opt-in ITs (test_egress_integration.py,
    test_httpx_probe_adapter.py::test_real_httpx_probe_lab_it,
    test_whatweb_adapter.py::test_real_whatweb_probe_lab_it and
    test_nuclei_adapter.py::test_real_nuclei_probe_lab_it — Phase
    2B.4) must use the REAL boundary against a real daemon; arming one
    (`*_IT=1`) while the autouse fake silently substituted the
    boundary would prove a boundary that is not there.
    """
    _exempted = {
        "test_egress_integration.py",
        "test_httpx_probe_adapter.py",
        "test_whatweb_adapter.py",
        "test_nuclei_adapter.py",
        "test_tls_adapter.py",
        "test_api_adapter.py",
        # Phase 2C.1 tier-2: the REAL-container lab IT must prove the
        # REAL boundary end-to-end, exactly like the other ITs above.
        "test_mode_b_e2e_lab_it.py",
        # Phase 2B.8: the adapter lab IT validates ALL SIX adapters
        # through the REAL boundary — same rule as the e2e lab IT.
        "test_mode_b_adapter_lab_it.py",
        # Phase 2B.6: the planner lab IT arms the REAL boundary too —
        # a faked boundary would prove planning decisions that were
        # never really enforced.
        "test_tool_planner_lab_it.py",
    }
    if Path(str(request.node.fspath)).name in _exempted:
        return
    import ipaddress

    from kryonsec.purple import egress

    def _fake_build_policy(cfg, engagement_id, target, resolver=None):
        resolvers = tuple(
            ipaddress.ip_address(r) for r in cfg.zone_b_dns_resolvers)
        return egress.EgressPolicy(
            engagement_id=engagement_id,
            target=target,
            network_name="kryonsec-egress-test0",
            bridge_name="ksbtest000",
            chain_name="KRYONSEC-EGRESS-test",
            subnet=ipaddress.ip_network(cfg.zone_b_subnet, strict=False),
            v4_allowed=(ipaddress.ip_network("203.0.113.0/24"),),
            v6_allowed=(),
            dns_resolvers=resolvers,
        )

    class _FakeGate:
        def __init__(self, run_fn=None):
            self.run_fn = run_fn
            self.establish_calls: list = []
            self.verify_calls: list = []
            self.release_calls: list = []

        def establish(self, policy):
            self.establish_calls.append(policy.engagement_id)
            return True, "ok"

        def verify(self, policy):
            self.verify_calls.append(policy.engagement_id)
            return True, "ok"

        def release(self, policy):
            self.release_calls.append(policy.engagement_id)
            return True, "ok"

    monkeypatch.setattr(egress, "build_policy", _fake_build_policy)
    monkeypatch.setattr(egress, "EgressGate", _FakeGate)

