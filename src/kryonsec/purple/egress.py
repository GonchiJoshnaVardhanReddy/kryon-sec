"""Zone B network-egress boundary (spec v2.1.1 §8.2, Phase 1E).

Closes the standing default-bridge gap: every security-tool container
now runs on a DEDICATED Docker bridge network for its engagement, and an
allow-only firewall in the Docker host's DOCKER-USER chain scopes every
packet that leaves that network to the engagement's authorized
destinations. The enforcement is at the host network layer:

- independent of LLM instructions, tool argv, and tool behavior
  (nmap SYN scans, curl, direct DNS probes — everything crosses one
  bridge, everything hits the same rules);
- independent of the container runtime (runc or runsc — once a packet
  has left the sandbox across the bridge it is ordinary host-netns
  filtered traffic; gVisor's netstack does not implement netfilter, so
  in-container iptables was never an option, and netns-sharing
  topologies such as ``network_mode=container:...`` are the recorded
  WSL2/gVisor incompatibility — not repeated here);
- scoped: rules match ONLY the engagement bridge in/out (FORWARD via the
  host's DOCKER-USER chain, and host-LOCAL delivery via the INPUT chain —
  the gateway IP and any service the host listens on would otherwise be
  reachable without ever traversing DOCKER-USER), so unrelated
  containers and host traffic pass untouched;
- always default-deny: no allow rule means the packet is dropped; DNS
  egress is permitted only to the configured resolver set; and the
  always-dangerous ranges (loopback, link-local incl. cloud metadata,
  multicast, unspec) are stripped from the allowlist even when an
  operator lists them explicitly.

Fail closed: if the network cannot be created, the firewall cannot be
programmed (no iptables, no DOCKER-USER chain, sudo unavailable), or the
post-install verification does not reproduce the intended ruleset, the
engagement's Zone B is blocked with an audited reason — tools never run
on an unrestricted bridge as a fallback.

Residual limitations, stated honestly in every report:
- DNS queries to the configured public resolvers can still encode
  exfiltration in query names; the L3 boundary pins the resolver set,
  it cannot inspect DNS payloads.
- An authorized destination's DNS record rotating after policy
  creation resolves out of the allowlist and is dropped (fail-closed)
  until the operator widens the scope or starts a new engagement.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import socket
import subprocess
from dataclasses import dataclass

from ..config import KryonsecConfig

log = logging.getLogger(__name__)

# Bridge interface names are limited to 15 chars on Linux: "ksb" + 8 hex.
_BRIDGE_PREFIX = "ksb"
_CHAIN_PREFIX = "KRYONSEC-EGRESS"
_NETWORK_PREFIX = "kryonsec-egress-"

FW_TIMEOUT_S = 30


# ---- policy construction (pure, injectably resolvable) ----------------------

def _dangerous_overlap(
    net: "ipaddress.IPv4Network | ipaddress.IPv6Network",
) -> str:
    """The always-dangerous range this network overlaps ('' when clean).

    Stripped from the allowlist regardless of who configured it — an
    operator-allowed or DNS-resolved loopback/link-local/multicast/
    unspec entry can never become an authorized destination.
    """
    checks: "tuple[tuple[str, str], ...]" = (
        ("0.0.0.0/8", "::/128"),          # unspecified / "this host"
        ("127.0.0.0/8", "::1/128"),       # loopback (never leaves the netns)
        ("169.254.0.0/16", "fe80::/10"),  # link-local <: includes CLOUD METADATA
        ("224.0.0.0/4", "ff00::/8"),      # multicast
        ("255.255.255.255/32", ""),       # limited broadcast
    )
    for v4, v6 in checks:
        if net.version == 4:
            candidate = ipaddress.ip_network(v4)
        else:
            if not v6:
                continue
            candidate = ipaddress.ip_network(v6)
        if candidate.version != net.version:
            continue
        if net.overlaps(candidate):
            return str(candidate)
    return ""


def hash8(value: str) -> str:
    """Stable 8-hex identifier: network/bridge/chain names per engagement."""
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]


def _as_host_networks(name: str, resolver) -> "tuple[list, list]":
    """One scope entry -> its exact /32-/128 networks (v4, v6).

    A CIDR is taken verbatim (strict=False so 10.0.0.5/24 normalizes);
    a bare IP is authorized as exactly that host; a NAME is resolved
    host-side via the injectable resolver (getaddrinfo, AF_UNSPEC).
    """
    if "/" in name:
        try:
            net = ipaddress.ip_network(name, strict=False)
        except ValueError as e:
            raise ValueError(f"zone_b scope entry {name!r}: {e}") from e
        nets = [net]
    else:
        try:
            addr = ipaddress.ip_address(name)
        except ValueError:
            addr = None
        if addr is not None:
            nets = [ipaddress.ip_network(
                f"{addr}/{'32' if addr.version == 4 else '128'}")]
        else:
            # a NAME — resolve host-side (recorded in the policy's
            # resolved_destinations by the caller)
            try:
                infos = (socket.getaddrinfo(name, None,
                                            proto=socket.IPPROTO_TCP)
                         if resolver is None else resolver(name))
            except OSError as e:
                raise ValueError(
                    f"authorizing {name!r}: resolution failed ({e})") from e
            v4_hosts: dict = {}
            v6_hosts: dict = {}
            for info in infos:
                host_ip = str(info[4][0])
                try:
                    parsed = ipaddress.ip_address(host_ip)
                except ValueError:
                    continue
                if parsed.version == 4:
                    v4_hosts[host_ip] = ipaddress.ip_network(f"{host_ip}/32")
                else:
                    v6_hosts[host_ip] = ipaddress.ip_network(f"{host_ip}/128")
            return list(v4_hosts.values()), list(v6_hosts.values())
    if nets and nets[0].version == 4:
        return nets, []
    return [], nets


def _compact(networks: list) -> tuple:
    """Unique, sorted, subnet-merged destination set."""
    if not networks:
        return ()
    families: dict = {}
    for n in networks:
        families.setdefault(n.version, []).append(n)
    merged = []
    for version in sorted(families):
        merged.extend(ipaddress.collapse_addresses(sorted(families[version])))
    return tuple(sorted(merged, key=str))


@dataclass(frozen=True)
class EgressPolicy:
    """The allow-only destination set for ONE engagement's sandbox net."""

    engagement_id: str
    target: str
    network_name: str
    bridge_name: str
    chain_name: str
    subnet: ipaddress.IPv4Network
    v4_allowed: tuple = ()
    v6_allowed: tuple = ()
    dns_resolvers: tuple = ()
    stripped: tuple = ()
    resolved_destinations: tuple = ()

    def summary(self) -> dict:
        """Audit-safe, host-detail-free summary of the live boundary."""
        return {
            "network": self.network_name,
            "subnet": str(self.subnet),
            "allowed_networks": sorted(
                [str(n) for n in self.v4_allowed]
                + [str(n) for n in self.v6_allowed]),
            "dns_resolvers": sorted(str(r) for r in self.dns_resolvers),
            "stripped": list(self.stripped),
            "enforcement": "host_docker_user_chain",
        }


def build_policy(
    cfg: KryonsecConfig,
    engagement_id: str,
    target: str,
    resolver=None,
) -> EgressPolicy:
    """Derive the engagement's allow-only destination set. Raises
    ValueError (fail closed) when nothing authorized survives the
    dangerous-range strip — an engagement with NO authorized
    destination gets NO network, and Zone B is blocked rather than run
    on an unrestricted bridge.

    ``target`` is the validated engagement target (host, domain or IP);
    the operator widens the set via cfg.zone_b_allowed_cidrs and
    cfg.zone_b_allowed_domains (e.g. the vulnerability-DB endpoints the
    blue-team scanners need).
    """
    stripped: list[str] = []
    v4: list = []
    v6: list = []
    resolved: list[str] = []

    def _add(name: str) -> None:
        nets_v4, nets_v6 = _as_host_networks(name, resolver)
        for net in (*nets_v4, *nets_v6):
            danger = _dangerous_overlap(net)
            if danger:
                stripped.append(f"{name!r} overlaps {danger}")
                continue
            (v4 if net.version == 4 else v6).append(net)

    if target:
        if "/" not in target:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                resolved.append(target)
        _add(target)
    for cidr in cfg.zone_b_allowed_cidrs:
        _add(str(cidr))
    for domain in cfg.zone_b_allowed_domains:
        entry = str(domain)
        if "/" not in entry:
            try:
                ipaddress.ip_address(entry)
            except ValueError:
                resolved.append(entry)
        _add(entry)

    v4_set = _compact(v4)
    v6_set = _compact(v6)
    if not v4_set and not v6_set:
        raise ValueError(
            "no authorized network destinations for the Zone B egress "
            "boundary — configure zone_b_allowed_cidrs / "
            "zone_b_allowed_domains or use an in-scope target"
        )

    resolvers: list = []
    for raw in cfg.zone_b_dns_resolvers:
        try:
            parsed = ipaddress.ip_address(str(raw))
        except ValueError as e:
            raise ValueError(
                f"zone_b_dns_resolver {raw!r} must be a literal IP: {e}"
            ) from e
        danger = _dangerous_overlap(
            ipaddress.ip_network(
                f"{parsed}/{'32' if parsed.version == 4 else '128'}"))
        if danger:
            raise ValueError(
                f"zone_b_dns_resolver {parsed} is inside the always-denied "
                f"range {danger} — refusing a loopback/link-local resolver"
            )
        resolvers.append(parsed)

    try:
        subnet = ipaddress.ip_network(cfg.zone_b_subnet, strict=False)
    except ValueError as e:
        raise ValueError(f"zone_b_subnet {cfg.zone_b_subnet!r}: {e}") from e
    if subnet.version != 4 or subnet.prefixlen > 30:
        raise ValueError(
            f"zone_b_subnet {cfg.zone_b_subnet!r} must be an IPv4 network "
            "with /30 or shorter prefix"
        )

    tag = hash8(engagement_id)
    return EgressPolicy(
        engagement_id=engagement_id,
        target=target,
        network_name=f"{_NETWORK_PREFIX}{tag}",
        bridge_name=f"{_BRIDGE_PREFIX}{tag}",
        chain_name=f"{_CHAIN_PREFIX}-{tag}",
        subnet=subnet,
        v4_allowed=v4_set,
        v6_allowed=v6_set,
        dns_resolvers=tuple(resolvers),
        stripped=tuple(sorted(set(stripped))),
        resolved_destinations=tuple(sorted(set(resolved))),
    )


# ---- rule construction (pure — every argv is testable) ----------------------

def _fw_prefix() -> list[str]:
    """Root runs iptables directly; non-root needs a NON-interactive
    sudo (fails loudly, never prompts) — the host firewall is a
    deployment prerequisite, surfaced by `kryonsec doctor`."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    return ["sudo", "-n"]


def _jump_argv(policy: EgressPolicy, direction_flag: str) -> list[str]:
    return [
        "-I", "DOCKER-USER",
        "1" if direction_flag == "-i" else "2",
        direction_flag, policy.bridge_name, "-j", policy.chain_name,
    ]


def _input_jump_argv(policy: EgressPolicy) -> list[str]:
    """Host-LOCAL deliverability (INPUT) is a separate netfilter reach:
    a packet to the bridge gateway IP or any other host-owned address
    (host services, published ports behind a host proxy) is routed to
    the host's INPUT chain and NEVER traverses FORWARD/DOCKER-USER.
    Without this jump a container could reach whatever the host listens
    on. Scoped exactly like the others: only OUR bridge interface.
    """
    return [
        "-I", "INPUT", "1",
        "-i", policy.bridge_name, "-j", policy.chain_name,
    ]


def _jump_remove_argv(jump: list[str]) -> list[str]:
    """The delete is the rule-SPEC of the insert, WITHOUT the numeric
    insert position: real iptables refuses a mixed `-D CHAIN 1 -i ...`
    form ('Bad rule'), and the release path is best-effort, so the
    failure was silent — a genuine-kernel defect caught by the Phase
    1E.1 integration run (jumps survived teardown on both built-ins).
    Only the spec-only form actually deletes."""
    out = list(jump)
    out[0] = "-D"
    i = next(k for k, t in enumerate(out) if t in ("-i", "-o"))
    return [out[0], out[1]] + out[i:]


def _chain_rules(policy: EgressPolicy, cmd: str) -> "list[list[str]]":
    """The allow-only ruleset for one family (iptable or ip6table).

    Order matters: established flows first, the pinned DNS resolvers
    (same family only), then every authorized destination, then an
    absolute DROP — the default-deny.
    """
    family_v6 = cmd == "ip6tables"
    rules: list[list[str]] = [
        ["-A", policy.chain_name,
         "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
         "-j", "ACCEPT"],
    ]
    for resolver in policy.dns_resolvers:
        if (resolver.version == 6) != family_v6:
            continue
        for proto in ("udp", "tcp"):
            rules.append([
                "-A", policy.chain_name, "-p", proto, "--dport", "53",
                "-d", str(resolver), "-j", "ACCEPT",
            ])
    for net in (policy.v6_allowed if family_v6 else policy.v4_allowed):
        rules.append(["-A", policy.chain_name, "-d", str(net),
                      "-j", "ACCEPT"])
    rules.append(["-A", policy.chain_name, "-j", "DROP"])
    return rules


def network_create_argv(policy: EgressPolicy) -> list[str]:
    """The dedicated bridge for this engagement: inter-container
    communication disabled, explicit bridge interface name, labeled."""
    return [
        "docker", "network", "create",
        "--driver", "bridge",
        "--subnet", str(policy.subnet),
        "--opt", "com.docker.network.bridge.enable_icc=false",
        "--opt", f"com.docker.network.bridge.name={policy.bridge_name}",
        "--label", f"kryonsec.engagement={policy.engagement_id}",
        policy.network_name,
    ]


def _rule_body(argv: list[str]) -> str:
    """The identifying tail of a rule: what iptables -S prints AFTER the
    '-A <chain>' prefix. Works for our argv forms too, whether the rule
    starts with -A or is a DOCKER-USER jump (whose numeric insert
    position the dumps never carry)."""
    if argv[1] in ("DOCKER-USER", "INPUT"):
        i = next(k for k, t in enumerate(argv) if t in ("-i", "-o"))
        return " ".join(argv[i:])
    return " ".join(argv[2:])


def _dumped_body(line: str) -> str:
    """The rule body of one '-A <chain> ...' line from iptables -S."""
    tokens = line.split()
    if len(tokens) > 2 and tokens[0] == "-A":
        return " ".join(tokens[2:])
    return ""


def _has_rule(dump: str, argv: list[str]) -> bool:
    """Whether a ruleset dump contains this rule — presence verified,
    never assumed. The comparison is SEMANTIC, not textual: a real
    nf_tables backend prints rules normalised (ctstate members in
    canonical order, implicit masks spelled out, implicit match
    modules added, match options reordered) so a literal string match
    always fails on a real host while the rule is actually there."""
    want = _rule_canon(_rule_body(argv).split())
    if not want:
        return False
    for line in dump.splitlines():
        got = _rule_canon(_dumped_body(line).split())
        if got and got == want:
            return True
    return False


def _rule_canon(tokens: "list[str]") -> "frozenset[str]":
    """One rule's option tokens, normalised to an order-insensitive,
    mask/module-agnostic form of (flag, value) pairs.

    - `--ctstate A,B` -> members sorted (nft canon order is arbitrary)
    - bare `-d/-s` addresses get their implicit /32 or /128
    - a redundant `-m X` right beside `-p X` is dropped (nft prints it)
    Pairs compare as an unordered set: rule sameness is its option
    set, not the print order."""
    if not tokens:
        return frozenset()
    # the -p value, so we can drop the redundant -m p value nft prints
    p_val = None
    for k, t in enumerate(tokens):
        if t == "-p" and k + 1 < len(tokens):
            p_val = tokens[k + 1]
    canon: list = []
    k = 0
    while k < len(tokens):
        t = tokens[k]
        val = tokens[k + 1] if k + 1 < len(tokens) else ""
        if t in ("--ctstate",):
            canon.append(f"{t} {','.join(sorted(val.split(',')))}")
            k += 2
            continue
        if t in ("-d", "-s") and "/" not in val:
            val += "/32" if "." in val else "/128"
        if t == "-m" and val and val == p_val:
            k += 2
            continue
        canon.append(f"{t} {val}")
        k += 2
    return frozenset(canon)


class EgressGate:
    """Builds, verifies and releases the network boundary.

    The runner establishes it ONCE per engagement (fail closed on any
    failure), the sandbox re-verifies it before every spawn, and the
    engagement-ending hook releases it. run_fn is injectable like
    KaliSandbox's (tests run anywhere; the real run needs Linux+Docker).
    """

    def __init__(self, run_fn=None):
        self._run = run_fn or subprocess.run

    # -- docker / firewall helpers ----------------------------------------

    def _docker(self, args: list[str]) -> "tuple[bool, str, str]":
        try:
            proc = self._run(args, capture_output=True, text=True,
                             timeout=FW_TIMEOUT_S)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, "", str(e)
        return (proc.returncode == 0,
                str(getattr(proc, "stdout", "") or ""),
                str(getattr(proc, "stderr", "") or ""))

    def _fw(self, args: list[str]) -> "tuple[bool, str]":
        try:
            proc = self._run(args, capture_output=True, text=True,
                             timeout=FW_TIMEOUT_S)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, str(e)
        return (proc.returncode == 0,
                str(getattr(proc, "stdout", "") or ""))

    def _network_subnet_matches(self, policy: EgressPolicy) -> "tuple[bool, str]":
        ok, out, err = self._docker([
            "docker", "network", "inspect", "--format", "{{json .}}",
            policy.network_name])
        if not ok:
            return False, f"egress network missing: {(err or out)[:200]}"
        try:
            netspec = json.loads(out)
            subnet = (netspec.get("IPAM", {}).get("Config", [{}])[0]
                      .get("Subnet", ""))
        except (ValueError, KeyError, IndexError):
            return False, "egress network IPAM spec unreadable"
        if subnet != str(policy.subnet):
            return False, (
                f"egress network exists with subnet {subnet!r}, policy "
                f"requires {policy.subnet} — refusing a mismatched "
                "boundary (remove it or align zone_b_subnet)")
        return True, "ok"

    # -- lifecycle ---------------------------------------------------------

    def establish(self, policy: EgressPolicy) -> "tuple[bool, str]":
        """Create the network and program its firewall; the post-state
        must VERIFY back — a failed verification rolls the boundary back
        and reports failure. Never a 'best effort' commitment."""
        ok, reason = self._network_subnet_matches(policy)
        if not ok:
            # a PRE-EXISTING network with a DIFFERENT subnet is a conflict
            # worth surfacing verbatim; a MISSING network is normal first use
            if reason.startswith("egress network missing:"):
                ok_c, out, err = self._docker(network_create_argv(policy))
                if not ok_c:
                    return False, (
                        "creating egress network failed: "
                        f"{(err or out or '').strip()[:300]}")
            else:
                return False, reason

        for cmd in ("iptables", "ip6tables"):
            ok_f, err = self._program_family(policy, cmd)
            if not ok_f:
                self.release(policy)
                return False, (
                    f"{cmd}: {err} — refusing to run Zone B without the "
                    "network boundary (fail closed)")

        ok, reason = self.verify(policy)
        if not ok:
            self.release(policy)
            return False, f"post-program verification failed: {reason}"
        return True, "ok"

    def _program_family(
        self, policy: EgressPolicy, cmd: str,
    ) -> "tuple[bool, str]":
        """Idempotently (re)create OUR chain + jumps for one family.

        Only our exact chain name and our two jump rules are touched —
        flushing/deleting an absent chain is a no-op, so an unrelated
        firewall state cannot be damaged.
        """
        argv = _fw_prefix()
        ok, out = self._fw(argv + [cmd, "-S", policy.chain_name])
        # remove OUR jumps first, from BOTH built-ins (INPUT and
        # DOCKER-USER): deleting (-X) a chain that is still referenced
        # would fail on a real host
        for base in (_jump_argv(policy, "-i"), _jump_argv(policy, "-o"),
                     _input_jump_argv(policy)):
            self._delete_jump(cmd, argv, base)
        if ok:
            # recreate cleanly — the chain exists but its content may be
            # from an earlier run with a different policy
            self._fw(argv + [cmd, "-F", policy.chain_name])
            self._fw(argv + [cmd, "-X", policy.chain_name])
        ok_n, err_n = self._fw(argv + [cmd, "-N", policy.chain_name])
        if not ok_n and "already exists" not in err_n:
            return False, f"cannot create chain {policy.chain_name}: {err_n}"
        for jump in (
                _input_jump_argv(policy),
                _jump_argv(policy, "-i"),
                _jump_argv(policy, "-o"),
        ):
            ok_j, err = self._fw(argv + [cmd] + jump)
            if not ok_j:
                return False, (
                    f"{jump[1]} jump failed: {err.strip()[:200]}")
        for rule in _chain_rules(policy, cmd):
            ok_r, err = self._fw(argv + [cmd] + rule)
            if not ok_r:
                return False, (
                    f"rule add failed ({' '.join(rule[:3])}…): "
                    f"{err.strip()[:200]}")
        return True, "ok"

    def _delete_jump(
            self, cmd: str, argv: list[str], jump: list[str],
    ) -> "tuple[bool, str]":
        """A real `-D` deletes only the FIRST matching rule; a jump can
        exist twice (e.g. a previous release whose deletion form was
        silently refused). Delete, re-check via `-S`, repeat — bounded;
        reporting (gone, why) so release can surface a stubborn jump."""
        builtin = jump[1]
        for _ in range(4):
            self._fw(argv + [cmd] + _jump_remove_argv(jump))
            ok_s, out = self._fw(argv + [cmd, "-S", builtin])
            if not ok_s or not _has_rule(out, jump):
                return True, "ok"
        return False, (
            f"{cmd} {builtin} jump still present after delete: "
            f"{_rule_body(jump)}")

    def verify(self, policy: EgressPolicy) -> "tuple[bool, str]":
        """The post-state must reproduce the policy: network present at
        the policy subnet, our chain ends in an absolute DROP, every
        allow/DNS rule present, both DOCKER-USER jumps AND the INPUT
        jump in place — in BOTH families. Any drift fails the boundary."""
        ok, reason = self._network_subnet_matches(policy)
        if not ok:
            return False, reason
        for cmd in ("iptables", "ip6tables"):
            argv = _fw_prefix()
            ok_s, out = self._fw(argv + [cmd, "-S", policy.chain_name])
            if not ok_s:
                return False, f"{cmd} chain {policy.chain_name} unreadable"
            for rule in _chain_rules(policy, cmd):
                if not _has_rule(out, rule):
                    return False, (
                        f"{cmd} chain missing: {' '.join(rule)}")
            ok_l, out = self._fw(argv + [cmd, "-S", "DOCKER-USER"])
            if not ok_l:
                return False, f"{cmd} DOCKER-USER chain unreadable"
            for jump in (_jump_argv(policy, "-i"), _jump_argv(policy, "-o")):
                if not _has_rule(out, jump):
                    return False, (
                        f"{cmd} DOCKER-USER missing jump: "
                        f"{_rule_body(jump)}")
            ok_i, out = self._fw(argv + [cmd, "-S", "INPUT"])
            if not ok_i:
                return False, f"{cmd} INPUT chain unreadable"
            if not _has_rule(out, _input_jump_argv(policy)):
                return False, (
                    f"{cmd} INPUT missing jump: "
                    f"{_rule_body(_input_jump_argv(policy))}")
        return True, "ok"

    def release(self, policy: EgressPolicy) -> "tuple[bool, str]":
        """Best-effort teardown of OUR rules + network; idempotent.

        Removes only our exact chain, our DOCKER-USER jumps and our INPUT
        jump, then the network. Other chains, other networks and host
        rules are untouched.
        """
        problems: list[str] = []
        for cmd in ("iptables", "ip6tables"):
            argv = _fw_prefix()
            for jump in (_jump_argv(policy, "-i"), _jump_argv(policy, "-o"),
                         _input_jump_argv(policy)):
                gone, why = self._delete_jump(cmd, argv, jump)
                if not gone:
                    problems.append(why)
            self._fw(argv + [cmd, "-F", policy.chain_name])
            self._fw(argv + [cmd, "-X", policy.chain_name])
        ok, _, err = self._docker([
            "docker", "network", "rm", policy.network_name])
        if not ok and not any(
                gone in str(err or "").lower()
                for gone in ("not found", "no such network")):
            problems.append((err or "network rm failed").strip()[:200])
        if problems:
            return False, "; ".join(problems)
        return True, "ok"


# Registry so the engagement-ending hook can release the boundary without
# threading the gate through every call site — keyed by engagement id.
_ACTIVE: "dict[str, tuple[EgressGate, EgressPolicy]]" = {}


def register_active(policy: EgressPolicy, gate: EgressGate) -> None:
    _ACTIVE[policy.engagement_id] = (gate, policy)


def release_active(engagement_id: str) -> None:
    """Best-effort teardown at engagement end. Silent when nothing was
    registered (tests, non-Linux runs with no Zone B at all)."""
    entry = _ACTIVE.pop(engagement_id, None)
    if entry is not None:
        gate, policy = entry
        ok, reason = gate.release(policy)
        if not ok:
            log.warning(
                "egress teardown incomplete for %s: %s",
                engagement_id, reason)
