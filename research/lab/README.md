# Kryonsec IEEE-research lab — isolated OWASP Juice Shop

Disposable, operator-owned Docker lab for the Phase 2–6 experiments.
Infrastructure only lives here; security-tool runs happen only against
the operator-approved scope below.

## Status (2026-11-16)

- Scope: **APPROVED** by the operator (with the Nuclei template hosts).
- Plumbing: **GREEN — 9/9 REAL checks** (`plumbing_check.py`, results in
  `plumbing-results.json`): the approved target is reachable through
  Kryonsec's REAL path (EgressGate → KaliSandbox runsc spawn), the
  pinned resolver serves the lab record, unrelated destinations are
  dropped at the network layer, and the boundary verifies before and
  after spawns and releases cleanly.
- WebGoat: **PREPARED, scope pending** (second lab IP + DNS record; no
  tool may touch it until its scope is separately approved).

## Approved scope (as applied to `/home/dev/.kryonsec-selftest/config.toml`)

- Target: `juice-shop.lab` → `10.213.43.10`, HTTP port 80 only
  (`zone_b_allowed_cidrs = ["10.213.43.10/32"]`).
- Nuclei template hosts: `github.com`, `codeload.github.com`,
  `raw.githubusercontent.com` (`zone_b_allowed_domains`) — resolved
  host-side at engagement start and pinned to the exact IPs; rotation
  fails closed.
- Resolver: `10.213.44.1` — the lab dnsmasq (lab-local only).
- Everything else: default-deny at the host firewall (DOCKER-USER +
  INPUT allow-only chains). Never bypassed.

## Topology (as verified 2026-11-16)

```
WSL2 host (docker 29.1.3, runsc release-20261109.0)
├─ kryonsec-lab        INTERNAL bridge, 10.213.43.0/24, icc=false
│   ├─ juice-shop-lab   10.213.43.10  alias juice-shop.lab  http/80 (no published ports)
│   └─ webgoat-lab      10.213.43.11  alias webgoat.lab     http/8080 webgoat, http/9090 webwolf
├─ kryonsec-dns        bridge, 10.213.44.0/24 (gateway 10.213.44.1)
│   └─ kryonsec-lab-dns HOST-network dnsmasq bound ONLY to 10.213.44.1:53
└─ (per-engagement non-internal bridges kryonsec-egress-<hash8> created
    by Kryonsec's EgressGate on 10.213.42.0/24; sandbox traffic to the
    lab and the resolver passes the allow-only gate chains or nothing)
```

- The lab network is `--internal` (icc off): no published ports, no
  upstream route for the target; nothing outside this WSL2 VM can
  reach it.
- The resolver is **host-owned** (see the Docker 28/29 note below): the
  dnsmasq container shares the host netns and binds only the dns-bridge
  gateway IP — it is NOT listening on eth0/WSL NAT, and DNS answers
  never create connectivity (the L3 egress boundary decides everything).
- The target serves HTTP on **port 80**: the deterministic recon
  pipeline scans a pinned port list (no 3000) and composes port-less
  URLs; `PORT=80` + `net.ipv4.ip_unprivileged_port_start=80` (image
  runs as uid 65532).
- Host prerequisite: `/etc/hosts` maps `juice-shop.lab` → `10.213.43.10`
  and `webgoat.lab` → `10.213.43.11` (Kryonsec resolves the engagement
  target host-side to pin the egress /32). `/etc/wsl.conf` got
  `[network] generateHosts = false` so the entries survive WSL boots.
  Remove the entries + the wsl.conf section to fully uninstall the lab.

## Two environment discoveries (recorded 2026-11-16, they shaped the lab)

1. **Docker 28/29 protect container IPs with a stateless raw-table
   drop.** Every container IP on a NON-internal network gets
   `-t raw -A PREROUTING -d <container-ip>/32 ! -i <its-bridge> -j DROP`,
   which silently kills cross-bridge packets to it (verified
   empirically: explicit or auto-assigned IP on a non-internal net →
   guard; any container on an `--internal` net → no guard). A
   containerized resolver on a normal bridge is therefore unreachable
   from the engagement bridge no matter what the egress gate allows.
   The lab answer: the resolver has NO container IP — dnsmasq runs with
   `--network host` bound to `10.213.44.1` (the dns-bridge gateway),
   reached via the gate's INPUT path. The official opt-out
   (`dockerd --allow-direct-routing`) would relax protection for ALL
   container IPs machine-wide — deliberately not used.
2. **gVisor has no listener for Docker's embedded DNS (127.0.0.11).**
   On user-defined networks Docker points `/etc/resolv.conf` at
   `127.0.0.11` and demotes `--dns` to upstream forwarders — but that
   listener does not exist under runsc, so every by-name lookup in the
   sandbox died with "connection refused" (only an explicit
   `dig @server` worked). Fixed in the product:
   `KaliSandbox._docker_argv` now bind-mounts a minimal resolv.conf
   carrying EXACTLY the policy's pinned resolvers (same set `--dns`
   carries and the boundary allows on dport 53). Covered by
   `tests/test_sandbox.py` (mount present under egress policy; absent
   for network-none runs and for policies with no pinned resolvers —
   fail closed).

## Immutable pins (recorded at pull/build time 2026-11-16)

| Artifact | Reference | Digest |
|---|---|---|
| Target image (Docker Hub tag `v20.4.0`) | `bkimminich/juice-shop@sha256:9bbaecc4…` | `9bbaecc41791f00b002bc65931cc5ff355fbdb941fa72b06558c18dace43197b` |
| WebGoat image (tag `v2026.5`, PREPARED only) | `webgoat/webgoat@sha256:95c23e70…` | `95c23e70502d0e0e11a826a73889e2ca93f965171202c17c0c59353ba67be86a` |
| DNS base image | `alpine:3.22` | `49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f` |
| DNS image (built from `dnsmasq/Dockerfile`) | `kryonsec-lab-dns:1` | `9d3e8c3e6f613d1fc3bcd2fd54915447997bc8876abfb793f0ce36f960e13d8e` |

The digest-pinned references used by `lab-up.sh` live in `images/`.

## Target identity + version ground truth

- Container `juice-shop-lab`: started and owned by the operator on the
  operator's machine (no external management plane, no cloud, no
  published ports). uid 65532, entrypoint
  `/nodejs/bin/node /juice-shop/build/app.js`, env `PORT=80`.
- App-reported version (fetched through the REAL sandbox path during
  the approved plumbing check, from
  `http://juice-shop.lab/rest/application-version`):
  **`{"version":"20.4.0-SNAPSHOT"}`** — consistent with image tag
  `v20.4.0`.
- Known-vulnerability ground truth:
  `ground-truth/juice-shop-v20.4.0-challenges.yml`, fetched from
  `raw.githubusercontent.com/juice-shop/juice-shop` at the exact
  `v20.4.0` tag. **118 challenges**: Sensitive Data Exposure 17,
  Injection 14, Broken Access Control 13, Improper Input Validation
  12, Broken Authentication 10, XSS 9, Vulnerable Components 9,
  Miscellaneous 6, Security Misconfiguration 5, Cryptographic Issues
  5, Observability Failures 4, Broken Anti Automation 4, Security
  through Obscurity 3, Insecure Deserialization 3, Unvalidated
  Redirects 2, XXE 2; difficulties 1–6. Phase 6 missed/FP analysis is
  scored against this file, never against memory.
- WebGoat notes (prepared, unapproved): WebGoat serves 8080
  (`/WebGoat`, verified 200 from the host), WebWolf serves **9090**
  (`/WebWolf`, per app logs — 9090 is NOT in Kryonsec's pinned recon
  port list). The upstream image's Docker healthcheck calls `curl`,
  which the image lacks, so the container always shows "unhealthy" —
  readiness is judged by the app log line and a manual GET instead.

## Reproducible reset procedure

```bash
./lab-down.sh           # remove lab containers + networks
./lab-up.sh             # recreate from the pinned digests (target state = fresh)
```

- The targets keep no volumes: container recreation is the reset.
- Engagement-side state lives in
  `/home/dev/.kryonsec-selftest/engagements/<id>/` (audit chain, graph,
  evidence) and is never shared between runs.
- Full teardown incl. images: `docker rmi` the pinned references above.
- Re-verify after any change: `KRYONSEC_HOME=/home/dev/.kryonsec-selftest
  ~/venvs/kryonsec-batch1/bin/python plumbing_check.py` → must be 9/9.
