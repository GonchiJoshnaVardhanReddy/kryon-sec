"""Phase 1E mocked tests: the Zone B egress boundary.

Policy construction, exact firewall/docker argv, gate lifecycle
(establish → verify → release), the sandbox-side guards, and the
runner wiring. Every host interaction is scripted — NO docker daemon,
iptables or network is needed (and none is touched).

The REAL classes are bound at import time, so the conftest autouse
fixture's call-time patches of ``egress.build_policy`` /
``egress.EgressGate`` cannot affect these tests; gate-level tests here
use the real objects with a scripted ``run_fn``. The genuine-network
integration test lives in test_egress_integration.py and is
environment-gated (never runs here).
"""

from __future__ import annotations

import json
import types

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.egress import (  # real bindings (import time)
    _ACTIVE,
    EgressGate,
    _chain_rules,
    _fw_prefix,
    _has_rule,
    _input_jump_argv,
    _jump_argv,
    _jump_remove_argv,
    build_policy,
    network_create_argv,
    register_active,
    release_active,
)
from kryonsec.purple.sandbox import KaliSandbox, missing_egress_flags


def make_policy(cfg=None, engagement_id="eng-abcdef01", target="203.0.113.10",
                resolver=None):
    cfg = cfg or KryonsecConfig()
    return build_policy(cfg, engagement_id, target, resolver=resolver)


# ---- scripted host (docker + iptables state machine) ------------------------


class ScriptedHost:
    """A run_fn that simulates the docker daemon and the host firewall.

    Maintains real-ish state, PER FAMILY (iptables and ip6tables are two
    independent tables on a real host — the fake models that, so
    cross-family interactions are exercised honestly): networks
    (existence + subnet), per-family chains (existence, contents) and
    DOCKER-USER jumps. Every call is recorded so tests can assert the
    EXACT argv sequence and rollback scope.
    """

    def __init__(self, policy):
        self.policy = policy
        self.network_exists = False
        self.existing_subnet = None
        self.net_create_error = None
        # per-family iptables state: {"iptables": {...}, "ip6tables": {...}}
        self.fw = {
            fam: {"existing": set(), "rules": {},
                  "jumps": {"DOCKER-USER": [], "INPUT": []}}
            for fam in ("iptables", "ip6tables")
        }
        self.record = []

    # -- state helpers for tests --------------------------------------------

    def _fw_state(self, fam):
        return self.fw[fam]

    def all_jumps(self) -> list[str]:
        out = []
        for st in self.fw.values():
            for jumps in st["jumps"].values():
                out.extend(jumps)
        return out

    def clear_jumps(self) -> None:
        for st in self.fw.values():
            for name in st["jumps"]:
                st["jumps"][name] = []

    def clear_builtin_jumps(self, builtin: str) -> None:
        for st in self.fw.values():
            st["jumps"][builtin] = []

    def input_jumps(self, fam: str) -> list[str]:
        return self.fw[fam]["jumps"]["INPUT"]

    def remove_rule(self, fam: str, chain: str, body: str) -> None:
        st = self.fw[fam]
        st["rules"][chain] = [b for b in st["rules"].get(chain, [])
                              if b.replace(" ", "") != body.replace(" ", "")]

    def chain_dumps(self, fam: str, chain: str) -> list[str]:
        return [f"-A {chain} {b}"
                for b in self.fw[fam]["rules"].get(chain, [])]

    # -- plumbing -------------------------------------------------------------

    def _done(self, rc, out="", err=""):
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    def __call__(self, argv, capture_output=True, text=True, timeout=None,
                 **kw):
        self.record.append(list(argv))
        if argv[0] == "docker":
            return self._docker(argv)
        prefix = _fw_prefix()
        tokens = list(argv[len(prefix):]) if len(prefix) else list(argv)
        return self._fw(tokens)

    # -- docker daemon ------------------------------------------------------

    def _docker(self, argv):
        p = self.policy
        assert argv[0] == "docker" and argv[1] == "network", f"unexpected {argv}"
        rest = argv[1:3]
        if rest == ["network", "inspect"]:
            if self.network_exists:
                return self._done(0, json.dumps(
                    {"IPAM": {"Config": [{"Subnet": self.existing_subnet}]}}),
                    "")
            return self._done(1, "",
                              f"Error: No such network: {p.network_name}")
        if rest == ["network", "create"]:
            if self.net_create_error:
                return self._done(1, "", self.net_create_error)
            self.network_exists = True
            self.existing_subnet = str(p.subnet)
            return self._done(0, f"{p.network_name}\n")
        if rest == ["network", "rm"]:
            if self.network_exists:
                self.network_exists = False
                return self._done(0, f"{p.network_name}\n")
            return self._done(1, "", f"Error: No such network: {p.network_name}")
        return self._done(1, "", f"unexpected docker argv: {argv}")

    # -- firewall (per family!) ----------------------------------------------

    def _fw(self, tokens):
        p = self.policy
        fam, op = tokens[0], tokens[1]
        assert fam in ("iptables", "ip6tables"), f"unexpected {tokens}"
        st = self._fw_state(fam)
        if op == "-S":
            name = tokens[2]
            if name in ("DOCKER-USER", "INPUT"):
                lines = [f"-A {name} {j}" for j in st["jumps"].get(name, [])]
                return self._done(0, "\n".join(lines), "")
            if name not in st["existing"]:
                return self._done(1, "", f"Chain '{name}' does not exist")
            lines = [f"-A {name} {body}" for body in st["rules"].get(name, [])]
            return self._done(0, "\n".join(lines), "")
        if op == "-N":
            name = tokens[2]
            if name in st["existing"]:
                return self._done(1, "", f"Chain '{name}' already exists")
            st["existing"].add(name)
            st["rules"].setdefault(name, [])
            return self._done(0, "", "")
        if op in ("-A", "-I"):
            name, body_tok = tokens[2], tokens[3:]
            if name in ("DOCKER-USER", "INPUT"):
                # jump install: keep the direction-flagged body, like -S prints
                i = next(k for k, t in enumerate(body_tok)
                         if t in ("-i", "-o"))
                st["jumps"].setdefault(name, []).append(
                    " ".join(body_tok[i:]))
                return self._done(0, "", "")
            if name not in st["existing"]:
                return self._done(1, "", f"Chain '{name}' does not exist")
            st["rules"][name].append(" ".join(body_tok))
            return self._done(0, "", "")
        if op == "-F":
            name = tokens[2]
            st["rules"][name] = []
            return self._done(0, "", "")
        if op == "-X":
            name = tokens[2]
            st["existing"].discard(name)
            st["rules"].pop(name, None)
            return self._done(0, "", "")
        if op == "-D":
            name, body_tok = tokens[2], tokens[3:]
            if name in ("DOCKER-USER", "INPUT"):
                i = next(k for k, t in enumerate(body_tok)
                         if t in ("-i", "-o"))
                body = " ".join(body_tok[i:])
                jumps = st["jumps"].get(name, [])
                if body in jumps:
                    # real iptables deletes only the FIRST match
                    jumps.remove(body)
                return self._done(0, "", "")
            return self._done(1, "", f"unexpected -D on {name}")
        return self._done(1, "", f"unexpected fw op {tokens}")

    # -- assertions helpers ---------------------------------------------------

    def fw_ops(self, op):
        out = []
        prefix = _fw_prefix()
        for argv in self.record:
            if argv[0] == "docker":
                continue
            toks = list(argv[len(prefix):]) if len(prefix) else list(argv)
            if toks and toks[1] == op:
                out.append(toks)
        return out


# ---- policy construction -----------------------------------------------------


def test_policy_target_ip_exactly_authorized():
    p = make_policy()
    assert [str(n) for n in p.v4_allowed] == ["203.0.113.10/32"]
    assert p.v6_allowed == ()
    assert p.resolved_destinations == ()


def test_policy_names_are_deterministic_and_short():
    a = make_policy(engagement_id="eng-abcdefgh")
    b = make_policy(engagement_id="eng-abcdefgh")
    # deterministic per engagement id
    assert a.network_name == b.network_name == "kryonsec-egress-" + a.network_name.split("-")[-1]
    # linux ifnames cap at 15 chars ("ksb" + 8 hex)
    assert len(a.bridge_name) <= 15 and a.bridge_name.startswith("ksb")
    assert a.network_name != make_policy(engagement_id="other").network_name


def test_policy_resolves_names_via_injected_resolver():
    def resolver(host):
        if host == "target.example":
            return [
                (2, 1, 6, "", ("203.0.113.7", 0)),
                (10, 1, 6, "", ("2001:db8::7", 0)),
                (2, 1, 6, "", ("203.0.113.7", 0)),  # duplicate is collapsed
            ]
        raise OSError("unexpected host")

    p = make_policy(target="target.example", resolver=resolver)
    assert [str(n) for n in p.v4_allowed] == ["203.0.113.7/32"]
    assert [str(n) for n in p.v6_allowed] == ["2001:db8::7/128"]
    assert p.resolved_destinations == ("target.example",)


def test_resolution_failure_fails_closed():
    def resolver(host):
        raise OSError("temporary failure in name resolution")

    with pytest.raises(ValueError, match="resolution failed"):
        make_policy(target="target.example", resolver=resolver)


def test_dangerous_entries_stripped_regardless_of_operator():
    cfg = KryonsecConfig(
        zone_b_allowed_cidrs=["169.254.169.254/32", "198.51.100.0/24"],
        zone_b_allowed_domains=["resolver-loopback.example"],
    )
    p = make_policy(
        cfg=cfg, target="203.0.113.10",
        resolver=lambda h: [(2, 1, 6, "", ("127.0.0.1", 0))])
    # the metadata endpoint and the loopback answer are gone, the CIDR stays
    assert [str(n) for n in p.v4_allowed] == ["198.51.100.0/24", "203.0.113.10/32"]
    assert any("169.254" in s for s in p.stripped)
    assert any("127.0.0.0/8" in s for s in p.stripped)


def test_all_scope_stripped_fails_closed():
    cfg = KryonsecConfig(zone_b_allowed_cidrs=["127.0.0.0/8"])
    with pytest.raises(ValueError, match="no authorized network destinations"):
        make_policy(cfg=cfg, target="169.254.169.254")


def test_no_target_and_no_operator_scope_fails_closed():
    with pytest.raises(ValueError, match="no authorized network destinations"):
        make_policy(cfg=KryonsecConfig(), target="")


def test_dns_resolvers_must_be_literal_ips():
    cfg = KryonsecConfig(zone_b_dns_resolvers=["dns.corp.example"])
    with pytest.raises(ValueError, match="must be a literal IP"):
        make_policy(cfg=cfg)


def test_dns_resolver_inside_dangerous_range_refused():
    cfg = KryonsecConfig(zone_b_dns_resolvers=["169.254.169.254", "8.8.8.8"])
    with pytest.raises(ValueError, match="always-denied"):
        make_policy(cfg=cfg)


def test_bad_subnet_and_bad_cidr_fail_closed():
    with pytest.raises(ValueError, match="zone_b_subnet"):
        make_policy(cfg=KryonsecConfig(zone_b_subnet="not-a-network"))
    cfgr = KryonsecConfig(zone_b_allowed_cidrs=["198.51.300.0/24"])
    with pytest.raises(ValueError, match="zone_b scope entry"):
        make_policy(cfg=cfgr)


# ---- rule construction (exact argv) ------------------------------------------


def test_network_create_argv_exact():
    p = make_policy()
    assert network_create_argv(p) == [
        "docker", "network", "create",
        "--driver", "bridge",
        "--subnet", "10.213.42.0/24",
        "--opt", "com.docker.network.bridge.enable_icc=false",
        "--opt", "com.docker.network.bridge.name=" + p.bridge_name,
        "--label", "kryonsec.engagement=eng-abcdef01",
        p.network_name,
    ]


def test_chain_rules_v4_exact_order():
    p = make_policy()
    rules = _chain_rules(p, "iptables")
    assert rules[0] == ["-A", p.chain_name, "-m", "conntrack",
                        "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]
    # DNS udp+tcp, per pinned resolver, both families' resolvers skipped
    assert rules[1] == ["-A", p.chain_name, "-p", "udp",
                        "--dport", "53", "-d", "1.1.1.1", "-j", "ACCEPT"]
    assert rules[2] == ["-A", p.chain_name, "-p", "tcp",
                        "--dport", "53", "-d", "1.1.1.1", "-j", "ACCEPT"]
    assert rules[3] == ["-A", p.chain_name, "-p", "udp",
                        "--dport", "53", "-d", "8.8.8.8", "-j", "ACCEPT"]
    assert rules[4] == ["-A", p.chain_name, "-p", "tcp",
                        "--dport", "53", "-d", "8.8.8.8", "-j", "ACCEPT"]
    # the authorized destination
    assert rules[5] == ["-A", p.chain_name, "-d", "203.0.113.10/32",
                        "-j", "ACCEPT"]
    # ...and the absolute default-deny LAST
    assert rules[6] == ["-A", p.chain_name, "-j", "DROP"]
    assert len(rules) == 7


def test_chain_rules_v6_default_deny_only():
    p = make_policy()  # no v6 destinations, no v6 resolvers
    rules = _chain_rules(p, "ip6tables")
    assert rules[0][-2:] == ["-j", "ACCEPT"]  # established
    assert rules[-1] == ["-A", p.chain_name, "-j", "DROP"]
    assert len(rules) == 2


# ---- gate lifecycle -----------------------------------------------------------


def test_gate_establish_happy_path():
    p = make_policy()
    host = ScriptedHost(p)
    ok, reason = EgressGate(run_fn=host).establish(p)
    assert ok, reason
    # network really created, chains really programmed, jumps installed
    assert host.network_exists
    for fam in ("iptables", "ip6tables"):
        assert p.chain_name in host.fw[fam]["existing"]
        assert len(host.input_jumps(fam)) == 1
    assert len(host.all_jumps()) == 6  # 3 builtins x 2 families


def test_gate_establish_is_idempotent():
    p = make_policy()
    host = ScriptedHost(p)
    gate = EgressGate(run_fn=host)
    ok1, r1 = gate.establish(p)
    ok2, r2 = gate.establish(p)
    assert ok1 and ok2, (r1, r2)


def test_gate_establish_reuses_same_subnet_without_creating():
    p = make_policy()
    host = ScriptedHost(p)
    host.network_exists = True
    host.existing_subnet = str(p.subnet)
    ok, reason = EgressGate(run_fn=host).establish(p)
    assert ok, reason
    assert not any(
        a[:3] == ["docker", "network", "create"] for a in host.record)


def test_gate_establish_refuses_subnet_mismatch():
    p = make_policy()
    host = ScriptedHost(p)
    host.network_exists = True
    host.existing_subnet = "10.99.99.0/24"
    ok, reason = EgressGate(run_fn=host).establish(p)
    assert not ok
    assert "refusing" in reason and "mismatched" in reason
    # nothing was created (fail closed, no partial state)
    assert not any(a[:3] == ["docker", "network", "create"]
                   for a in host.record)


def test_gate_establish_fails_when_network_create_fails():
    p = make_policy()
    host = ScriptedHost(p)
    host.net_create_error = "could not find an available, non-overlapping pool"
    ok, reason = EgressGate(run_fn=host).establish(p)
    assert not ok and "creating egress network failed" in reason


def test_gate_establish_rolls_back_when_family_programming_fails():
    p = make_policy()
    host = ScriptedHost(p)
    # break rule ADDS only (a container could refuse -A with an error):
    original = host._fw

    def broken_add(tokens):
        if tokens[1] in ("-A", "-I") and tokens[2] == "INPUT":
            return host._done(1, "", "iptables: rule refused by host")
        return original(tokens)

    host._fw = broken_add
    ok, reason = EgressGate(run_fn=host).establish(p)
    assert not ok and "INPUT jump failed" in reason
    # rolled back: the network is gone again
    assert not host.network_exists


def test_gate_verify_fails_on_rule_drift():
    p = make_policy()
    host = ScriptedHost(p)
    gate = EgressGate(run_fn=host)
    ok, reason = gate.establish(p)
    assert ok, reason
    # an operator (or another process) deletes the default-deny DROP
    host.remove_rule("iptables", p.chain_name, "-j DROP")
    ok, reason = gate.verify(p)
    assert not ok and "missing" in reason and "-j DROP" in reason


def test_gate_verify_fails_on_missing_jump():
    p = make_policy()
    host = ScriptedHost(p)
    gate = EgressGate(run_fn=host)
    ok, reason = gate.establish(p)
    assert ok, reason
    host.clear_jumps()
    ok, reason = gate.verify(p)
    assert not ok and "DOCKER-USER missing jump" in reason


NFT_DEDUMP = (
    "-A CHAIN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
    "-A CHAIN -d 1.1.1.1/32 -p udp -m udp --dport 53 -j ACCEPT\n"
    "-A CHAIN -d 203.0.113.10/32 -j ACCEPT\n"
    "-A CHAIN -j DROP\n"
)


def test_has_rule_matches_nft_normalized_dump():
    """REAL nft dump text (captured live on nf_tables backend): rule
    presence is semantic — orders and masks and implicit -m differ —
    while the same rule written via our argv must still be FOUND."""
    # these exact argv bodies were programmed before the real dump:
    assert _has_rule(NFT_DEDUMP, ["-A", "CHAIN", "-m", "conntrack",
                                  "--ctstate", "ESTABLISHED,RELATED",
                                  "-j", "ACCEPT"])
    assert _has_rule(NFT_DEDUMP, ["-A", "CHAIN", "-p", "udp",
                                  "--dport", "53", "-d", "1.1.1.1",
                                  "-j", "ACCEPT"])
    assert _has_rule(NFT_DEDUMP, ["-A", "CHAIN", "-d", "203.0.113.10",
                                  "-j", "ACCEPT"])
    assert _has_rule(NFT_DEDUMP, ["-A", "CHAIN", "-j", "DROP"])
    # and a DIFFERENT rule must not certify the chain
    assert not _has_rule(NFT_DEDUMP, ["-A", "CHAIN", "-p", "udp",
                                      "--dport", "53", "-d", "8.8.8.8",
                                      "-j", "ACCEPT"])
    assert not _has_rule(NFT_DEDUMP, ["-A", "CHAIN", "-j", "ACCEPT"])


def test_input_jump_argv_is_exact_and_scoped():
    p = make_policy()
    jump = _input_jump_argv(p)
    assert jump == ["-I", "INPUT", "1", "-i", p.bridge_name,
                    "-j", p.chain_name]
    # the removal is the rule-spec ONLY: real iptables refuses the
    # mixed `-D INPUT 1 -i ...` form and silently leaves the rule
    assert _jump_remove_argv(jump) == ["-D", "INPUT", "-i",
                                       p.bridge_name, "-j", p.chain_name]


def test_jump_remove_argv_drops_position_for_docker_user():
    """Same spec-only delete rule for the DOCKER-USER jumps — the
    genuine-kernel run caught stale jumps there too (Phase 1E's
    position+spec form never deleted anything)."""
    p = make_policy()
    jump = _jump_argv(p, "-i")
    assert jump[:3] == ["-I", "DOCKER-USER", "1"]
    assert _jump_remove_argv(jump) == ["-D", "DOCKER-USER", "-i",
                                       p.bridge_name, "-j", p.chain_name]


def test_gate_release_removes_duplicate_jumps():
    """Real `-D` removes only the FIRST match: a duplicate jump left by
    an older broken release must not survive the release. The removal
    loops delete-and-recheck until `-S` shows the jump gone."""
    p = make_policy()
    host = ScriptedHost(p)
    gate = EgressGate(run_fn=host)
    ok, reason = gate.establish(p)
    assert ok, reason
    # simulate an old leftover: the v4 INPUT jump exists TWICE
    body = host.fw["iptables"]["jumps"]["INPUT"][0]
    host.fw["iptables"]["jumps"]["INPUT"].append(body)
    ok, reason = gate.release(p)
    assert ok, reason
    for st in host.fw.values():
        for jumps in st["jumps"].values():
            assert not jumps
    assert not host.network_exists


def test_gate_verify_fails_on_missing_input_jump():
    """The host-local deliverability path (INPUT) is part of the
    boundary: without it, container -> host services / gateway IP would
    bypass the DOCKER-USER filter. Per-family INPUT drift (while the
    DOCKER-USER jumps are present) must fail the boundary."""
    p = make_policy()
    host = ScriptedHost(p)
    gate = EgressGate(run_fn=host)
    ok, reason = gate.establish(p)
    assert ok, reason
    # family-scoped drift: ip6tables loses its INPUT jump while its
    # DOCKER-USER jumps stay — only the INPUT check can catch this
    host.fw["ip6tables"]["jumps"]["INPUT"] = []
    ok, reason = gate.verify(p)
    assert not ok and "ip6tables INPUT missing jump" in reason


def test_gate_release_is_scoped_to_our_rules_only():
    p = make_policy()
    host = ScriptedHost(p)
    gate = EgressGate(run_fn=host)
    assert gate.establish(p)[0]
    host.record = []
    ok, reason = gate.release(p)
    assert ok, reason
    # ONLY our chain was flushed/deleted, ONLY our jumps removed,
    # ONLY our network removed
    flushed = {t[2] for t in host.fw_ops("-F")}
    deleted = {t[2] for t in host.fw_ops("-X")}
    assert flushed == deleted == {p.chain_name}
    # the removals are our jumps only: INPUT + DOCKER-USER, our chain
    d_ops = host.fw_ops("-D")
    assert {t[2] for t in d_ops} == {"INPUT", "DOCKER-USER"}
    assert all(p.chain_name in " ".join(t[3:]) for t in d_ops)
    rmed = [a for a in host.record if a[:3] == ["docker", "network", "rm"]]
    assert rmed == [["docker", "network", "rm", p.network_name]]
    assert not host.network_exists


def test_gate_release_is_idempotent():
    p = make_policy()
    host = ScriptedHost(p)
    gate = EgressGate(run_fn=host)
    assert gate.establish(p)[0]
    assert gate.release(p)[0]
    ok, reason = gate.release(p)
    assert ok, reason  # second release must not invent failures


def test_registry_roundtrip():
    p = make_policy(engagement_id="eng-registry-test")
    gate = EgressGate(run_fn=ScriptedHost(p))
    register_active(p, gate)
    assert "eng-registry-test" in _ACTIVE
    release_active("eng-registry-test")
    assert "eng-registry-test" not in _ACTIVE
    release_active("eng-registry-test")  # silent no-op


# ---- sandbox wiring -----------------------------------------------------------


@pytest.fixture
def sandbox_with_boundary():
    cfg = KryonsecConfig()
    policy = make_policy(cfg=cfg, target="203.0.113.10")
    gate = EgressGate(run_fn=ScriptedHost(policy))
    gate.establish(policy)
    sb = KaliSandbox(cfg=cfg, seccomp_profile=None,
                     egress_policy=policy, egress_gate=gate)
    return sb, policy, gate


def test_docker_argv_carries_network_and_dns(sandbox_with_boundary):
    sb, policy, _ = sandbox_with_boundary
    argv = sb._docker_argv(["nmap", "--top-ports", "5"])
    image_at = argv.index(sb.image)
    head = argv[:image_at]
    assert head[head.index("--network") + 1] == policy.network_name
    dns = head[head.index("--dns") + 1]
    assert dns == "1.1.1.1"
    assert head.count("--dns") == 2  # both pinned resolvers


def test_docker_argv_without_policy_has_no_network_flag():
    cfg = KryonsecConfig()
    sb = KaliSandbox(cfg=cfg, seccomp_profile=None)  # direct construction: no conftest fake involved
    argv = sb._docker_argv(["nmap"])
    assert "--network" not in argv[:argv.index(sb.image)]
    assert "--dns" not in argv[:argv.index(sb.image)]


def test_egress_guard_accepts_correct_argv(sandbox_with_boundary):
    sb, policy, _ = sandbox_with_boundary
    argv = sb._docker_argv(["curl", "https://203.0.113.10/"])
    assert missing_egress_flags(argv, policy, image=sb.image) == []


def test_egress_guard_rejects_forbidden_networks(sandbox_with_boundary):
    sb, policy, _ = sandbox_with_boundary
    for bad in ("bridge", "host", "none"):
        argv = sb._docker_argv(["curl", "x"])
        at = argv.index("--network")
        argv[at + 1] = bad
        problems = missing_egress_flags(argv, policy, image=sb.image)
        assert problems and "forbidden" in problems[0], bad


def test_egress_guard_rejects_foreign_network_and_dns(sandbox_with_boundary):
    sb, policy, _ = sandbox_with_boundary
    argv = sb._docker_argv(["curl", "x"])
    at = argv.index("--network")
    argv[at + 1] = "some-other-net"
    problems = missing_egress_flags(argv, policy, image=sb.image)
    assert any("!= engagement network" in p for p in problems)
    argv2 = sb._docker_argv(["curl", "x"])
    d = argv2.index("--dns")
    argv2[d + 1] = "9.9.9.9"
    problems = missing_egress_flags(argv2, policy, image=sb.image)
    assert any("--dns" in p for p in problems)


def test_tool_argv_cannot_override_egress_policy(sandbox_with_boundary):
    """An approved tool's argv is container content, not docker flags: a
    value like 'host' after the image neither changes the docker section
    nor trips the guard into scanning tool args."""
    sb, policy, _ = sandbox_with_boundary
    argv = sb._docker_argv(
        ["nmap", "--network=host", "--dns=9.9.9.9", "203.0.113.10"])
    image_at = argv.index(sb.image)
    head = argv[:image_at]
    # the docker flags are still exactly the engagement's
    assert head[head.index("--network") + 1] == policy.network_name
    assert missing_egress_flags(argv, policy, image=sb.image) == []
    # and even IF docker had honored such tokens, the host firewall's
    # allowlist has no rule for other resolvers — the boundary is not argv
    resolver_daddrs = [str(r) for r in policy.dns_resolvers]
    assert "9.9.9.9" not in resolver_daddrs


def test_spawn_refuses_when_boundary_not_verified(sandbox_with_boundary):
    sb, policy, gate = sandbox_with_boundary
    gate.verify = lambda policy: (False, "iptables chain unreadable")
    res = sb.spawn(["curl", "https://203.0.113.10/"])
    assert not res.ok
    assert res.exit_code == -1
    assert "egress invariant broken" in res.error
    assert "not verified" in res.error


def test_spawn_refuses_tampered_docker_flags(sandbox_with_boundary):
    sb, policy, _ = sandbox_with_boundary
    original = sb._docker_argv

    def tampered(tool_argv, network_mode=None):
        argv = original(tool_argv, network_mode=network_mode)
        at = argv.index("--network")
        argv[at + 1] = "bridge"  # e.g. a corrupted config path
        return argv

    sb._docker_argv = tampered
    res = sb.spawn(["curl", "https://203.0.113.10/"])
    assert not res.ok
    assert "forbidden" in res.error


def test_spawn_preflight_runs_before_any_container(sandbox_with_boundary):
    """With a healthy gate the spawn preflight passes through to the
    (fake) docker run; the preflight never spawns on its own when the
    boundary fails."""
    sb, policy, gate = sandbox_with_boundary
    calls = []

    def run(argv, **kw):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout='{"exit_code": 0, "stdout": "ok"}',
                                     stderr="")

    sb._run = run
    res = sb.spawn(["curl", "https://203.0.113.10/"])
    assert res.ok
    assert len(calls) == 1
    assert "--network" in calls[0]


# ---- config roundtrip ---------------------------------------------------------

def test_zone_b_config_defaults_and_toml_roundtrip():
    original = KryonsecConfig(
        zone_b_subnet="10.250.0.0/24",
        zone_b_allowed_cidrs=["198.51.100.0/24"],
        zone_b_allowed_domains=["db.example.com"],
        zone_b_dns_resolvers=["9.9.9.9"],
    )
    data = original.to_toml_dict()["sandbox"]
    assert data["zone_b_subnet"] == "10.250.0.0/24"
    assert data["zone_b_allowed_cidrs"] == ["198.51.100.0/24"]
    assert data["zone_b_allowed_domains"] == ["db.example.com"]
    assert data["zone_b_dns_resolvers"] == ["9.9.9.9"]

    restored = KryonsecConfig.from_toml({"sandbox": data})
    assert restored.zone_b_subnet == "10.250.0.0/24"
    assert restored.zone_b_allowed_cidrs == ["198.51.100.0/24"]
    assert restored.zone_b_allowed_domains == ["db.example.com"]
    assert restored.zone_b_dns_resolvers == ["9.9.9.9"]


def test_zone_b_explicit_empty_scope_roundtrips():
    original = KryonsecConfig(zone_b_allowed_cidrs=["1.2.3.4/32"])
    restored = KryonsecConfig.from_toml(
        {"sandbox": original.to_toml_dict()["sandbox"]
         | {"zone_b_allowed_cidrs": []}})
    # an explicitly empty list must stay empty (same rule as tools.enabled)
    assert restored.zone_b_allowed_cidrs == []


def test_zone_b_defaults_survive_configs_without_keys():
    restored = KryonsecConfig.from_toml({"sandbox": {"image": "whatever"}})
    assert restored.zone_b_subnet == "10.213.42.0/24"
    assert restored.zone_b_dns_resolvers == ["1.1.1.1", "8.8.8.8"]
    assert restored.zone_b_allowed_cidrs == []


# ---- runner wiring -------------------------------------------------------------


def _run_tiny_engagement(tmp_path, monkeypatch, engagement_id,
                         sandbox_ok=True, sandbox_reason="ok"):
    """A minimal engagement run with the Zone A fetcher faked and the
    sandbox probes patched; returns (orch, audit, graph, completed)."""
    from kryonsec.purple import recon_passive
    from kryonsec.purple.runner import start_engagement

    cfg = KryonsecConfig(home=tmp_path)

    def fake_recon(domain):
        from kryonsec.purple.recon_passive import PassiveResult

        return PassiveResult(source="crt.sh", subdomains=["www." + domain])

    with monkeypatch.context() as m:
        m.setattr("kryonsec.purple.runner.sandbox_available",
                  lambda image=None: (sandbox_ok, sandbox_reason),
                  raising=True)
        m.setattr(recon_passive, "zone_a_fetchers",
                  lambda cfg: [fake_recon])
        orch, audit, graph = start_engagement(
            cfg, engagement_id, target="203.0.113.10")
        completed = orch.run()
    return orch, audit, graph, completed


def _audit_events(audit):
    import json as _json

    with open(audit.path, encoding="utf-8") as f:
        return [_json.loads(line) for line in f if line.strip()]


def test_runner_establishes_boundary_and_audits_it(tmp_path, monkeypatch):
    """Healthy boundary: the run proceeds into RECON_ACTIVE, the
    established policy is audited, and the boundary is registered for
    teardown."""
    from kryonsec.purple import egress, sandbox as sandbox_module

    real_ks = sandbox_module.KaliSandbox
    made: list = []

    def ks_factory(*a, **kw):
        sb = real_ks(*a, **kw)
        made.append(sb)
        return sb

    monkeypatch.setattr(sandbox_module, "KaliSandbox", ks_factory)

    orch, audit, graph, completed = _run_tiny_engagement(
        tmp_path, monkeypatch, "eng-e1")
    try:
        events = _audit_events(audit)
        established = [e for e in events
                       if e["event"] == "egress_policy_established"]
        assert len(established) == 1
        assert established[0]["policy"]["enforcement"] == \
            "host_docker_user_chain"
        assert established[0]["policy"]["allowed_networks"] == \
            ["203.0.113.0/24"]
        assert not any(e["event"] == "egress_policy_failed" for e in events)
        # the sandbox the runner built carries the boundary
        assert len(made) == 1
        assert made[0].egress_policy is not None
        assert made[0].egress_policy.network_name.startswith(
            "kryonsec-egress-")
        assert made[0].egress_gate is not None
        # the run got past RECON_ACTIVE (not blocked)
        assert "RECON_ACTIVE" in completed
        # and the boundary is registered for the engagement-ending release
        assert "eng-e1" in egress._ACTIVE
    finally:
        egress.release_active("eng-e1")
    assert "eng-e1" not in egress._ACTIVE


def test_runner_fails_closed_when_boundary_cannot_be_established(
        tmp_path, monkeypatch):
    """A boundary that cannot be established halts Zone B with an audited
    reason — no sandbox object is ever constructed."""
    from kryonsec.purple import egress, sandbox as sandbox_module

    real_ks = sandbox_module.KaliSandbox
    made: list = []

    def ks_factory(*a, **kw):
        sb = real_ks(*a, **kw)
        made.append(sb)
        return sb

    monkeypatch.setattr(sandbox_module, "KaliSandbox", ks_factory)

    class FailGate:
        def __init__(self, run_fn=None):
            pass

        def establish(self, policy):
            return False, "iptables (ipv4): no route to firewall"

        def verify(self, policy):
            return True, "ok"

        def release(self, policy):
            return True, "ok"

    monkeypatch.setattr(egress, "EgressGate", FailGate)

    orch, audit, graph, completed = _run_tiny_engagement(
        tmp_path, monkeypatch, "eng-e2")
    events = _audit_events(audit)
    assert any(e["event"] == "egress_policy_failed" and
               e["phase"] == "establish" for e in events)
    # Zone B blocked (fail closed), NOT run un-sandboxed on the host
    blocked = [e for e in events if e["event"] == "zone_b_blocked"]
    assert blocked and "network egress boundary unavailable" in \
        blocked[0]["reason"]
    assert "RECON_ACTIVE" in completed  # entered, then halted via blocked()
    assert orch.state == "HALT"
    assert made == []  # no sandbox without a verified boundary


def test_runner_fails_closed_on_policy_build_error(tmp_path, monkeypatch):
    """An invalid/empty egress configuration halts Zone B rather than
    falling back to the default bridge."""
    from kryonsec.purple import egress

    def broken_policy(cfg, engagement_id, target, resolver=None):
        raise ValueError("no authorized network destinations")

    monkeypatch.setattr(egress, "build_policy", broken_policy)
    orch, audit, graph, completed = _run_tiny_engagement(
        tmp_path, monkeypatch, "eng-e3")
    events = _audit_events(audit)
    fails = [e for e in events if e["event"] == "egress_policy_failed"]
    assert fails and fails[0]["phase"] == "build"
    assert "no authorized network destinations" in fails[0]["reason"]
    blocked = [e for e in events if e["event"] == "zone_b_blocked"]
    assert blocked and "egress policy build failed" in blocked[0]["reason"]
    assert orch.state == "HALT"


def test_engagement_ending_releases_the_boundary(tmp_path, monkeypatch):
    """record_engagement_ending (the CLI finally hook) tears the boundary
    down: registry emptied, gate.release called, exactly once, silently
    for engagements that never registered one."""
    from kryonsec.purple import egress
    from kryonsec.purple.audit import AuditLog
    from kryonsec.purple.runner import record_engagement_ending

    released: list = []

    class Gate:
        def release(self, policy):
            released.append(policy.engagement_id)
            return True, "ok"

    cfg = KryonsecConfig(home=tmp_path)
    audit_path = cfg.home / "engagements" / "eng-e4" / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    AuditLog(audit_path).write({"event": "engagement_created"})

    policy = make_policy(cfg=cfg, engagement_id="eng-e4")
    register_active(policy, Gate())

    assert record_engagement_ending(cfg, "eng-e4", outcome="completed")
    assert released == ["eng-e4"]
    assert "eng-e4" not in egress._ACTIVE

    # a second ending (idempotency path) does not double-release
    assert not record_engagement_ending(cfg, "eng-e4", outcome="completed")
    assert released == ["eng-e4"]
    # never-registered engagement: silent no-op, still returns an ending
    e5_path = cfg.home / "engagements" / "eng-e5" / "audit.jsonl"
    e5_path.parent.mkdir(parents=True, exist_ok=True)
    AuditLog(e5_path).write({"event": "engagement_created"})
    assert record_engagement_ending(cfg, "eng-e5", outcome="completed")
    assert released == ["eng-e4"]
