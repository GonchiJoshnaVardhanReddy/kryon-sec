# Phase 5–6 report — real-product engagement runs, then missed/false-positive scoring

Date: 2026-11-17 (UTC stamps). Branch: `feature/tool-expansion-batch1`.
Commits: `baa28aa` (product change), `1e64ce6` (runs + scorer + this report's inputs).

Plain-English summary: we ran the **real product** (the Purple Team state
machine via `_run_purple`, not a test harness mock) against the approved lab
target twice — once with the LLM enabled, once with it disabled — recorded
what it actually did, then scored both runs against the 118-challenge Juice
Shop ground truth with a deterministic, curated scorer.

The one-line result: **the pipeline works end to end, and it detected almost
nothing.** Full run: 2 of 118 challenges OBSERVED (an observation, not a
solve), 0 CONFIRMED, 0 false positives, 78 in-scope MISSED. LLM-off
baseline: 1 OBSERVED, 0 CONFIRMED, 79 MISSED. This is exactly the kind of
honest number the research question needs.

---

## 1. What shipped in the product (commit `baa28aa`)

- `llm.py`: real usage capture — provider-reported token usage and, where
  the provider's cost map can price the call, a real USD cost. Unpriced
  calls are recorded as *unknown*, never guessed. Added `chat_with_usage`.
- The `KRYONSEC_DISABLE_LLM` gate: a single switch that makes every LLM
  state fail audited (used for the baseline run).
- Purple-team LLM calls now accrue usage with `estimate=False` and write
  `llm_usage` audit events into the chain.
- 17 new tests (`tests/test_llm_usage.py`). Full suite at commit time:
  2,759 passed / 61 skipped.

## 2. Method — what "real" means here

The harness (`phase5_engagement_runs.py`) drives the product's own
engagement path (`_run_purple`). Per run it:

1. Resets the lab (teardown + rebuild), so every run starts from the same
   image and state.
2. Runs the plumbing preflight (10 checks — egress boundary up/down,
   target reachability, app version, pinned resolver, deny checks). All
   checks must be REAL; the invariant is "all REAL", not a fixed count.
3. Pins the nuclei-template hosts (`github.com`,
   `codeload.github.com`, `raw.githubusercontent.com`) host-side with
   rotation verification. The pin **fails closed**: if DNS rotates
   between resolution and pin, the attempt is refused and retried
   (hardened during this phase for both the observed GitHub GeoDNS
   rotation and a transient WSL host-DNS outage; 4 attempts / 15 s).
4. Runs the engagement through the product with:
   - Gate 2 (hypothesis approval) answered by automation — labeled in
     every artifact as **"automation-injected (non-human)"**. No human
     reviewed anything; treat approvals accordingly.
   - Gate 3 (post-exploit) always refused — no post-exploitation, ever.
   - Scope: `juice-shop.lab` → `10.213.43.10`, HTTP port 80 only, plus
     the pinned template hosts for nuclei downloads. No brute force, no
     DoS, no destructive exploitation (the scorer's OUT_OF_SCOPE table
     below mirrors these rules).
5. Dumps the run manifest, audit chain, graph, and product report into
   `results/<stamp>/run-<mode>/`, and verifies the audit chain.

Every artifact carries the honest labels: REAL / MOCKED / SKIPPED /
FAILED / NOT RUN, and "automation-injected (non-human)" for approvals.
**Infrastructure success is not detection performance** — the manifest
says so in `honest_note`, and Phase 6 does the actual scoring.

## 3. Run 1 — full engagement (LLM on)

`lab-p5-full-20261117T110737Z` → `results/20261117T110737Z/run-full/`

| Fact | Value | Label |
|---|---|---|
| Outcome | `completed`, all 8 states entered | REAL |
| Wall time | 912.6 s | — |
| Audit chain | 227 events, verified, head `d0513193…` | REAL |
| Lab reset + plumbing | 10/10 checks, all REAL | REAL |
| Template-host pin | ok, 1 attempt | REAL |
| LLM provider/model | openai / `gpt-6-astra` via LiteLLM | REAL |
| LLM calls audited | 2 (HYPOTHESIZE + BLUE_TEAM) | REAL |
| Tokens | 4,832 provider-reported (3,016 + 1,816) | REAL |
| Cost | **$0.13353** known; 0 unpriced calls | REAL |
| Hypotheses | 4 proposed, 4 approved | **automation-injected (non-human)** |
| Gate 3 | refused (no post-exploitation) | enforced |
| ToolRunner spawns | 10 (6 non-zero exits, kept) | REAL |
| Recon adapter spawns | 10 (audited separately, see below) | REAL |
| Findings confirmed / verified | **0 / 0** | — |

The four hypotheses (proposed by the LLM from recon evidence, then
auto-approved):

| ID | Target | Idea | Confidence | Tools |
|---|---|---|---|---|
| H1 | `/metrics` | unauthenticated Prometheus metrics disclosure | 0.72 | curl, nuclei |
| H2 | `/ftp` | public directory listing / unintended file disclosure | 0.55 | curl, wget |
| H3 | `/main.js` | sensitive info in the client bundle | 0.28 | curl, wget |
| H4 | `/` | overly permissive CORS | 0.25 | curl |

Tool execution, honestly:

- **Exploit-phase ToolRunner spawns (7):** curl `/metrics` exit 0; nuclei
  `/metrics` exit 137 (killed — most likely the sandbox resource cap;
  exit recorded, output partial); curl `/ftp` exit 0 **but the marker did
  not confirm disclosure**; wget `/ftp` exit 0; curl `/main.js` exit 18
  (partial transfer — some content retrieved, not the full bundle);
  wget `/main.js` exit 4; curl `/` exit 0.
- **Recon adapter spawns (10):** the deterministic recon pipeline's
  adapters (nmap, naabu, httpx, whatweb, nuclei, katana, dnsx,
  feroxbuster, gowitness, api-probe), audited as `adapter_spawn` /
  `adapter_result`. The recon nuclei adapter found the
  `prometheus-metrics @ /metrics` vuln candidate (detection only).
- **OSINT sandbox spawns (3):** subfinder exit 2, amass exit 1,
  assetfinder exit 2 — all failed (the lab target has no public
  subdomains; the failures are recorded, not hidden).

Nothing was confirmed by the exploit phase: each probe either did not
retrieve what the hypothesis needed, or retrieved something the marker
check did not accept. Graph: 50 nodes / 29 edges (4 hypotheses,
7 exploit attempts, 4 remediations, recon evidence).

## 4. Run 2 — LLM-off baseline

`lab-p5-llm-off-20261117T112949Z` → `results/20261117T112949Z/run-llm-off/`

Same lab reset, plumbing (10/10 all REAL), and pin (1 attempt). The only
difference: `KRYONSEC_DISABLE_LLM=1`.

| Fact | Value | Label |
|---|---|---|
| Outcome | `completed`, 6 states entered (EXPLOIT/VERIFY skipped — nothing to exploit) | REAL |
| Wall time | 339.9 s | — |
| Audit chain | 132 events, verified, head `51c234f0…` | REAL |
| LLM calls / tokens / cost | **0 / 0 / $0** — the gate worked | REAL |
| HYPOTHESIZE, BLUE_TEAM | failed, audited: "LLM disabled by KRYONSEC_DISABLE_LLM" | REAL failure |
| Hypotheses | 0 proposed, 0 approved | — |
| ToolRunner spawns | 3 (subfinder/amass/assetfinder, all failed) | REAL |
| Findings | 0 confirmed / 0 verified | — |
| Graph | 35 nodes / 22 edges | — |

The baseline is the "pipeline without its creative brain" control: recon
and bookkeeping still run deterministically; nothing LLM-shaped happens.

## 5. Failed attempts kept on the record

Never dropped — each has its own results directory:

- `results/20261117T110414Z/` — harness plumbing bug (caught by the
  preflight itself; fixed before the good runs).
- `results/20261117T110558Z/` — GitHub GeoDNS rotation refused the pin
  (fail-closed working as designed; committed earlier).
- `results/20261117T112712Z/` — rotation refusal **plus** a transient
  WSL host-DNS outage (`Temporary failure in name resolution`). The
  retry loop was hardened to catch both; the next attempt pinned on the
  first try.

## 6. The egress gate and what it demands from the host

Zone B tool execution is fenced by a host-layer allow-only firewall
(`src/kryonsec/purple/egress.py`), which is why these runs are meaningful:

- Every tool container runs on a **dedicated, per-engagement Docker
  bridge** (`kryonsec-egress-<id8>`, icc off) — never the default
  bridge — and the host's `DOCKER-USER` chain (plus the host `INPUT`
  chain for host-owned addresses) is programmed with a per-engagement
  chain allowing only: ESTABLISHED/RELATED, DNS to the pinned resolver
  set, and the engagement's authorized destinations. Everything else
  drops.
- Enforcement is at the host network layer: independent of LLM
  instructions, tool argv, tool behavior, and the container runtime
  (gVisor's netstack has no netfilter, so the fence lives outside the
  guest on purpose). `spawn()` re-verifies the boundary before every
  launch and rejects wrong networks or wrong DNS pinning.
- **Fail closed everywhere:** empty/dangerous scope raises; failed
  establishment, verification drift, or sudo unavailability halts Zone B
  with an audited `zone_b_blocked` — tools never run on an unrestricted
  bridge as a fallback.

**Sudoers implication (said plainly):** the product programs the host
firewall. As root it runs `iptables` directly; as a normal user it runs
`sudo -n iptables …` — **non-interactive**, failing loudly rather than
prompting. That means a Mode-B deployment needs a *deliberate* sudoers
grant for firewall programming (on this lab host: `/etc/sudoers.d/kryonsec-egress`;
its exact contents are root-readable only, by design). This is a real
host privilege and it must be scoped on purpose: it exists so the
default-deny fence can exist at all, it is surfaced by `kryonsec doctor`
as a deployment prerequisite, and without it the system refuses to run
tools rather than run them unfenced. The trade is explicit: a narrow,
audited firewall-administration grant in exchange for a network fence
that no tool, prompt, or LLM decision can talk its way around.

**Known residual (stated in every report):** the L3 boundary pins the
DNS resolver set but cannot inspect DNS payloads — a tool could park
exfiltration data in query names to allowed resolvers. Recorded, not
solved.

## 7. Phase 6 — deterministic missed/FP scoring

`phase6_scoring.py` scores a run against
`ground-truth/juice-shop-v20.4.0-challenges.yml` (118 challenges, Juice
Shop v20.4.0). Rules curated **once** and applied identically to every
run:

- **Curation: 118/118, exactly three tables.** 38 challenges are
  OUT_OF_SCOPE with a named class and reason (see below); 70 have a
  distinctive SURFACE regex; 10 are explicitly "in scope, no curated
  surface" (structurally capped at MISSED, each with a reason — listed,
  never hidden). The loader refuses to run if a challenge is missing
  from all tables, if a table names a challenge the YAML doesn't have,
  or if tables overlap.
- **Evidence-only matching.** Surface regexes match only EVIDENCE node
  types (endpoints, paths, exploit attempts, findings, scanner results,
  …). Hypothesis, vuln_candidate, remediation, and engagement_note nodes
  are excluded on purpose: **an LLM proposing an attack is not evidence
  of one.** (Validated live: the same "UNION SELECT" string was ignored
  in a remediation node and credited in a finding node.)
- **Verdicts:** CONFIRMED (a confirmed/verified finding whose evidence
  matches the surface) / OBSERVED (an evidence node matches the surface)
  / OUT_OF_SCOPE / MISSED. Every verdict cites node ids from the
  persisted graph. **OBSERVED ≠ SOLVED** — only CONFIRMED is a
  solved-shaped claim, and the run had none.
- **False positives:** confirmed findings matching no challenge surface.
- OUT_OF_SCOPE classes (38 total): `disabledEnv-Docker` (11 — the
  challenge itself declares it unsolvable in Docker), DoS-shaped without
  the Docker tag (1 — forbidden), brute-force/race (2 — forbidden),
  OSINT on external persons (7 — outside the target), data-egress to
  external services (2 — forbidden), client-side/browser-required (13),
  visual judgment (2). Zero OOS rows carried any evidence hits
  (integrity-checked).

**Two over-claims caught and fixed live** (under-crediting is fine;
over-crediting is not):

- `supplyChainAttackChallenge` matched our own tooling's OSINT note
  ("…needs a GITHUB_TOKEN (kryonsec setup)") — regex tightened to real
  token shapes (`ghp_…`, `github_pat_`, `cve-\d{4}`).
- `redirectChallenge` matched the root endpoint's CORS-probe properties
  — tightened to `/redirect\b`.

Re-scored after the fix; integrity re-verified (0 OOS rows with hits;
the no-surface list is exactly the 10 curated keys).

## 8. Results vs ground truth

| Verdict (of 118) | Full run | LLM-off baseline |
|---|---|---|
| CONFIRMED | **0** | **0** |
| OBSERVED | **2** | **1** |
| OUT_OF_SCOPE | 38 | 38 |
| MISSED | 78 | 79 |
| False positives | 0 | 0 |

Which surfaces were observed, with citations:

| Challenge | Full run | Baseline | Cited evidence |
|---|---|---|---|
| directoryListingChallenge (`/ftp`) | OBSERVED | OBSERVED | recon crawl path node `/ftp`; full run also cites the H2 curl/wget exploit attempts |
| exposedMetricsChallenge (`/metrics`) | OBSERVED | MISSED | H1 curl + nuclei exploit attempts (full run only) |

Reading it honestly:

- The **difference between the runs is exactly the LLM's surface
  contribution**: recon alone observes `/ftp`; the HYPOTHESIZE →
  approve → probe loop adds the `/metrics` probe. That is a real,
  measurable effect of the creative component.
- **2 OBSERVED is not 2 SOLVED.** Both are observations consistent with
  the challenge surfaces (a 200 on `/ftp`, probes that reached
  `/metrics`). No finding was confirmed; nothing was exploited.
- **78 MISSED in scope is the headline.** Out of the 80 in-scope
  challenges, the full pipeline observed 2 surfaces and solved 0. The
  recon-only baseline observed 1. On a one-shot, non-brute-force,
  port-80-only, no-browser run of a v20.4.0 Juice Shop, that is the
  true capability number for this pipeline today.
- **0 false positives** matters as much: the exploit phase confirmed
  nothing, so the scorer had nothing to over-credit — the two regex
  fixes above were caught before they could manufacture false hits.
- **Limitations, all structural:** one run per mode (no variance
  estimate); curated surfaces could miss observations a richer curation
  would credit (the 10 no-surface keys are capped at MISSED by design);
  the agent has no browser (which the OOS table prices in honestly);
  Gate-3 refusal and the no-DoS/no-brute-force rules rule out several
  families by design — those sit in OUT_OF_SCOPE, not MISSED, and must
  never be counted as capability gaps.
- **Cost of the measured capability:** $0.13353 of real provider-billed
  tokens (2 calls). That is the honest denominator for "what did the
  LLM's 2 observed-surface delta buy".

## 9. Reproduce

```bash
# full engagement + LLM-off baseline (WSL, user dev)
cd /mnt/d/project/kryon-sec/research/lab
KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase5_engagement_runs.py both

# scoring (deterministic; re-runs are byte-identical for the same graph)
KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase6_scoring.py \
  results/20261117T110737Z/run-full
KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase6_scoring.py \
  results/20261117T112949Z/run-llm-off
```

The graph is read back from storage (SQLite purple fallback at
`~/.kryonsec-selftest/purple.db`) so citations are node ids from the
persisted engagement, not a rebuilt one; `graph.json` in the run dir is
a fallback only.

## 10. Owed Phase-7 design notes (recorded here, not left in someone's head)

**Constrained-helper proposal** (the sudoers grant today is broader than
the need it serves):

- Today: `/etc/sudoers.d/kryonsec-egress` gives user `dev` NOPASSWD on
  `iptables` / `ip6tables` / `xtables-nft-multi` — exactly the binaries
  the egress gate needs, but those binaries can rewrite ANY firewall
  rule on the host (flush chains, insert rules anywhere, change
  policies). The product's actual need is far narrower: manage ONLY its
  own `KRYONSEC-EGRESS-<id8>` chain on its own `ksb<id8>` bridge.
- Proposal: replace the raw-binary grant with a tiny root-owned helper
  (e.g. `/usr/local/sbin/kryonsec-egress-helper`) whose entire argv
  grammar is `establish <chain> <bridge> <rules-file>` / `release
  <chain>`; it validates the chain prefix and bridge shape itself,
  applies rules only from a root-owned validated file, refuses
  everything else, re-verifies the post-install ruleset, and prints it.
  sudoers then grants NOPASSWD on that one helper — `dev` can no longer
  run arbitrary iptables at all.
- Honest trade-offs, stated: a helper binary is itself attack surface
  (argv/file parsing bugs), so the narrowest *safe* grant today remains
  the two-binary NOPASSWD + `visudo -c` validation; the helper only
  ships after its own review and tests. Root-running deployments need
  neither (the product runs iptables directly as root). This is a
  design note, NOT an implementation commitment.

**Environment discoveries recap** (fully documented in
`research/lab/README.md`; listed so the report stands alone):

1. Docker 28/29 protects container IPs on non-internal networks with a
   stateless raw-table drop → the lab resolver is host-owned dnsmasq on
   the dns-bridge gateway IP (an opt-out flag that would relax
   protection machine-wide was deliberately not used).
2. gVisor has no listener for Docker's embedded resolver 127.0.0.11 →
   `KaliSandbox` bind-mounts a minimal resolv.conf carrying exactly the
   pinned resolvers (fail-closed otherwise).
3. ProjectDiscovery tools (dnsx/naabu) query hardcoded public resolvers
   unless `-r {resolver}` is passed → both lanes fail closed without
   pinned resolvers; the same tool family gets `-duc` to stop
   update-check phone-homes (katana, nuclei, httpx likewise).
4. gowitness 3.x downloads a browser at runtime by default → the
   template pins the image's own chromium path; feroxbuster's GitHub
   release check and chromium's Google lookups remain unfixable in argv
   and are dropped by the gate (recorded, not hidden).

## 11. Artifact index

| Artifact | What it is |
|---|---|
| `results/20261117T110737Z/run-full/phase5-run-manifest.json` | full-run manifest (honest labels, REAL usage/cost) |
| `results/20261117T110737Z/run-full/audit.jsonl` | 227-event SHA256-chained audit trail (verified) |
| `results/20261117T110737Z/run-full/graph.json` | 50-node engagement graph |
| `results/20261117T110737Z/run-full/phase6-scored.{json,csv}` | per-challenge verdicts with node-id citations |
| `results/20261117T112949Z/run-llm-off/…` | same set for the baseline |
| `results/20261117T110414Z, 110558Z, 112712Z/` | recorded FAILED attempts |
| `phase5_engagement_runs.py` | the harness |
| `phase6_scoring.py` | the scorer (curation tables are in it, in one place) |
| `ground-truth/juice-shop-v20.4.0-challenges.yml` | the 118-challenge ground truth |

Phase 7 status: the full pytest suite re-ran on the final code:
**2,781 passed / 62 skipped, 0 failed** (the long-documented
`test_install_sh` ensurepip environmental failure is now a designed
SKIP — the helper's unguarded import contradicted its own fallback
design; fixed in `ef61383`, environment untouched). Vault bookkeeping
completed alongside this report.
