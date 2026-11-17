# Kryonsec IEEE-research lab — isolated OWASP Juice Shop

Disposable, operator-owned Docker lab for the Phase 2–6 experiments.
Infrastructure only lives here; security-tool runs happen only against
the operator-approved scope below.

## Status (2026-11-17 — Phases 5–6 complete)

- Scope: **APPROVED** by the operator (with the Nuclei template hosts).
- Plumbing: **GREEN — all REAL checks** (`plumbing_check.py`, results in
  `plumbing-results.json`; 10 checks as of 2026-11-17): the approved
  target is reachable through Kryonsec's REAL path (EgressGate →
  KaliSandbox runsc spawn), the pinned resolver serves the lab record,
  unrelated destinations are dropped at the network layer, and the
  boundary verifies before and after spawns and releases cleanly.
- Phases 5–6 (real engagements + missed/FP scoring): **COMPLETE** —
  one full engagement + one LLM-off baseline through the REAL product
  path (`_run_purple`), both audit-chain-verified, plus deterministic
  scoring against the 118-challenge ground truth. Headline: full run
  **2 OBSERVED / 0 CONFIRMED / 0 false positives / 78 in-scope MISSED**,
  baseline **1 / 0 / 0 / 79**; REAL provider-billed LLM usage recorded
  (2 calls, 4,832 tokens, $0.13353). Full detail, method, egress-gate
  and sudoers implications, and honest interpretation:
  **`PHASE5-6-REPORT.md`** in this directory.
- Phase 4 (per-tool REAL-path runs): **COMPLETE — 11 REAL runs all
  exit 0 + 1 SKIPPED, 0 harness failures** in the final recorded run
  `results/20261117T095324Z/phase4-tool-runs.json` (naabu, nmap, dnsx,
  httpx, whatweb, katana, feroxbuster, gowitness, api-probe,
  openapi_probe, nuclei; tls-probe SKIPPED — the approved target serves
  plain HTTP only). These are RUNNABILITY records only: detection
  performance is NOT measured here (that is Phase 5–6, scored against
  ground truth).
- Phase 4 also produced four REAL product fixes + one lab-harness
  hardening, all verified live against the real binaries (details in
  the tool-drift section below):
  dnsx `-r {resolver}` + output shape, naabu `-r {resolver}` + `-duc`,
  gowitness `scan single` (v3 CLI) + `--chrome-path` (image chromium),
  katana `-duc`; harness records FAILED rows instead of crashing and
  verifies the DNS pin step after SIGHUP.
- WebGoat: **PREPARED, scope pending** (second lab IP + DNS record; no
  tool may touch it until its scope is separately approved).
- Phase 4b (9 NEW tool integrations, REAL-path runs): **COMPLETE —
  three recorded runs in `results/*-p4b-verify/`** via
  `phase4b_tool_verify.py`. Final recon run (`20261117T163332`):
  wafw00f/dirsearch/smbmap/enum4linux-ng exit 0, **nbtscan exit 0**
  with the target's RESOLVED IP (10.213.43.10), dirsearch parsed 20
  real paths; dnsenum/fierce exit 255 on THIS lab zone — dnsmasq's
  hosts-file zone has no NS/SOA records (dig-verified), a zone
  artifact, not a template bug. Blue-team run (`20261117T161222`):
  checksec + exiftool through the REAL `run_code_scanners` path,
  once each, against a real ELF fixture. Five REAL-output fixes:
  nbtscan `-w`→`-t` (ms) + hostname rejection → resolved-IP rule,
  smbmap spinner survives `--no-update` → tail excerpt, wafw00f
  banner head → tail excerpt, dirsearch real row shape → regex
  rewrite (guessed shape parsed 0 real rows), ANSI-clean excerpts
  (`clean_excerpt`) for dnsenum/enum4linux-ng (no no-color flags).
  Detail: `docs/TOOL-EXPANSION-BATCH5.md` working notes.

## Phase 4 tool-drift findings (all found LIVE through the real path)

Every fix below was driven by a REAL run failing (or phoning home)
under the gate, then verified by a REAL run succeeding:

1. **dnsx 1.3.1** — `-d` is now a brute-force flag needing `-w`; the
   legacy shape died at startup. Also ignores resolv.conf and queries
   a HARDCODED public-resolver list without `-r` (queries the gate
   drops; proved by the empty dnsmasq delta), and its output flags
   changed shape (`-resp-only -nc` for bare-IP lines). Template now:
   `-l {target} -r {resolver} -resp-only -silent -duc -nc`.
2. **naabu 2.x** — same hardcoded-resolver behavior as dnsx: a domain
   target died with "no valid ipv4 or ipv6 targets were found" (IP
   target worked; zero lab-resolver queries without `-r`). Also
   phones `api.pdtm.sh` without `-duc`. Template now carries
   `-r {resolver}` + `-duc`; verified live (domain target resolves
   through the pinned resolver, port 80 found, zero pdtm queries).
3. **gowitness 3.2.2** — the v2-era `scan website` subcommand and the
   `--no-console` / `--disable-db` flags no longer exist (Usage banner
   at startup). v3 writes no result DB unless `--write-*` is passed.
   It DOWNLOADS a Chrome binary at runtime by default — the gate drops
   that — so the template pins the image's own chromium
   (`--chrome-path /usr/bin/chromium`, verified present in the pinned
   image). Verified live: exit 0, real 1280×577 JPEG in `/evidence`.
4. **katana** — no `-duc` meant one `api.pdtm.sh` DNS query per run
   (the gate dropped the connect). Template now carries `-duc`;
   verified live (zero pdtm queries).
5. **Not fixable in argv (recorded, connects dropped by the gate):**
   feroxbuster checks `api.github.com` for a newer release (one DNS
   query + one dropped connect per run); gowitness's chromium attempts
   a handful of Google lookups (`update/fonts/accounts.*.google*`) at
   launch (all non-target connects dropped; the screenshot is
   unaffected).

Lab-harness notes (same date): a WSL DNS flake made the host-side
template-host rotation check fail mid-run — the product refused to
authorize (correct, fail-closed) and the harness now records a FAILED
row instead of crashing; the DNS-pin step verifies its records took
effect after SIGHUP; the lab DNS container was recreated twice from
the outside (09:40:24, 09:58:21 — `lab-up.sh`-style recreate, pinned
template-host records reset each time; recorded runs were NOT affected
— the pin runs at sequence start).

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
  ~/venvs/kryonsec-batch1/bin/python plumbing_check.py` → every check
  REAL (the check list grows between phases; the invariant is "all
  REAL", not a fixed count — 10/10 as of 2026-11-17).
