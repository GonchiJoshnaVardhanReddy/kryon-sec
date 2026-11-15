# Changelog

## Unreleased — Tool Expansion Batches 1–2 (feature branch, not released)

Six new vetted RECON_ACTIVE adapters — `naabu-probe`, `dnsx-probe`,
`katana-probe` (Batch 1), then `nmap-probe`, `feroxbuster-probe`,
`gowitness-probe` (Batch 2) — built on the existing Phase 2B adapter
framework. Branch `feature/tool-expansion-batch1`; nothing below is
published yet.

### New vetted adapters (Batch 2)

- **nmap-probe** (the authoritative stage-1 service scan) runs nmap with the
  SAME fixed argv the legacy discovery entry uses (`-Pn -sT -sV -sC
  --max-rate 100 -p RECON_PORTS` — `-sT` because gVisor grants no raw
  sockets; the bounded 18-port list, never a full-range scan). It REUSES the
  legacy TEXT parser (`parse_nmap_services` — no second regex to drift) and
  emits the SAME legacy-shape `service` nodes, now with adapter provenance
  (`target:port/proto` labels, first-wins dedupe). Replaces the legacy nmap
  entry deterministically; NOT planner-gated (pre-plan discovery lane,
  reported `covered` post-hoc like naabu/dnsx).
- **feroxbuster-probe** (content discovery) runs feroxbuster with the legacy
  `-u {urlfuzz} -w <baked seclists> -t 5 --timeout 30` shape. The FUZZ-marker
  URL is composed DETERMINISTICALLY by the adapter framework from the
  scope-validated base (`base.rstrip('/') + '/FUZZ'` — the same composition
  the legacy entry applies); the lane can never point the fuzzing at a
  different origin than the base it was given, and a params dict carrying
  `urlfuzz` is refused as unexpected. Reuses the legacy result-line regex
  (`_FEROX_RE`/`_FEROX_STATUS` — lockstep by construction); emits legacy
  shape `path` nodes with adapter provenance, first-wins dedupe by label
  (cross-source: a path katana or a passive source already placed is
  skipped). Replaces the legacy feroxbuster entry; planner-gated like every
  other web lane.
- **gowitness-probe** (screenshots) runs gowitness with the legacy
  `scan website --url {base} --screenshot-path /evidence --no-console
  --disable-db` shape — the PNG lands in the rw `/evidence` mount (the
  engagement folder), NOT in tool output. There is NO text contract to
  parse: the run's exit code is the truth. ONE legacy-shape `screenshot`
  node per successful run (label = the base URL, `dir=/evidence` plus
  adapter provenance); a refused/failed run records NO node. Replaces the
  legacy gowitness entry; planner-gated like every other web lane.
- **TEXT output contracts, not `-json/-oX`**: the shipped Layer-2 templates
  stay in lockstep, and XML/JSON field shapes could not be verified against
  the real binaries from the development environment.
- **No allowlist or image change**: all three binaries were already
  allowlisted and baked into the pinned sandbox image.

### New vetted adapters (Batch 1)

- **naabu-probe** (TCP port discovery) runs the image's real naabu with the
  SAME fixed argv the legacy discovery entry uses — the lane pins
  `ports=RECON_PORTS` (the bounded 18-port list, never a full-range scan) and
  `rate=100`. Legacy parity preserved: the parsed ports merge into the shared
  `open_ports` set and the adapter adds **no graph nodes of its own** — the
  run's `adapter_attempt` node is the evidence. Replaces the legacy naabu
  entry deterministically (one probe per check, never both).
- **dnsx-probe** (DNS resolution) runs dnsx with the legacy `-d {target}
  -silent` shape and emits ONE legacy-shape `dns_resolution` node (all IPs,
  adapter provenance, first-wins dedupe). A clean run that resolves nothing
  is an honest INCONCLUSIVE — no node, no negative claim. Replaces the legacy
  dnsx entry.
- **katana-probe** (web crawl) runs katana with the legacy `-u {url} -d 2
  -silent` shape, the crawl depth pinned to `2` via a named constant (a
  deeper crawl would be a conscious code change, never caller input).
  Emits legacy-shape `path` nodes with adapter provenance, first-wins dedupe
  by label (cross-source: a path another source already placed is skipped).
  Replaces the legacy katana entry; planner-gated like every other web lane.
- **TEXT output contracts, not `-json`**: the shipped Layer-2 templates must
  stay in lockstep, and the JSON field shapes could not be verified against
  the real binaries from the development environment. `-silent` text lines
  (`host:port`, IPs, bare URLs) parse deterministically with bounded,
  defensive parsers.
- **No allowlist or image change**: all three binaries were already
  allowlisted and baked into the pinned sandbox image.

### Planner (2B.6) — domain-target pairing

- `ToolPlanner.plan()` gained a `domain_targets` parameter: domain-kind
  adapters (nmap-probe, naabu-probe, dnsx-probe) are paired ONLY with the
  engagement target, never with URL bases; URL-kind adapters pair only with
  bases. The three discovery lanes run BEFORE the plan (they produce the
  ports it plans from) and are reported as `covered` post-hoc; a FAILED lane
  stays selected and is honestly listed as planned-but-not-executed. The
  planner remains **OFF by default**; with it off, behavior is identical to
  the fixed plan plus the six adapter lanes. Planner metadata now covers all
  eleven registered adapters (priority, cost, requires/produces evidence).

### Tests and honest status

- Batch 1 mocked suites: `tests/test_dnsx_adapter.py` (24),
  `tests/test_naabu_adapter.py` (22), `tests/test_katana_adapter.py` (26).
- Batch 2 mocked suites: `tests/test_nmap_adapter.py` (28),
  `tests/test_feroxbuster_adapter.py` (27), `tests/test_gowitness_adapter.py`
  (25) — argv lockstep against the shipped Layer-2 templates (byte-identical,
  including the framework-composed `{urlfuzz}`), scope/option-injection
  refusals, unexpected-params refusals (the FUZZ URL and the screenshot dir
  are never caller input), gate/sandbox/egress refusals, honest failure
  classification, bounded output, `not_verified` invariants, either/or
  integration (one probe per check, never both), planner gating, and
  no-subprocess scans. Plus one opt-in real-gVisor lab IT per adapter
  (`KRYONSEC_NAABU_IT=1`, `KRYONSEC_DNSX_IT=1`, `KRYONSEC_KATANA_IT=1`,
  `KRYONSEC_NMAP_IT=1`, `KRYONSEC_FEROX_IT=1`, `KRYONSEC_GOWITNESS_IT=1`) —
  **armed but NOT RUN on the Windows dev host**; run them in the Linux lab.
- Full suite on the branch after Batch 2: 2,481 passed / 61 skipped (WSL2,
  Python 3.14); the 2 failures are environmental (no `ensurepip` in that
  Python; no docker group access), not regressions.

## v1.3.11 — the reviewed Nuclei manifest, TLS/API adapters, and honest failures

Eleven commits since v1.3.10, all in the Purple Team engine. The headline: the
Nuclei template policy is now an enforced, hash-pinned manifest instead of a
directory allowlist — and a packaging bug that would have made wheel installs
fail closed is caught and fixed before release.

### Packaging fix: the Nuclei manifest now ships in the wheel (v1.3.10 bug)

- **v1.3.10's wheel omitted `nuclei_manifest.json`.** pyproject.toml declared
  it under the wrong package-data key, so the pattern matched nothing: the
  file silently stayed out of the wheel. A wheel-installed RECON_ACTIVE then
  raised `NucleiPolicyError` at registry build — fail-closed, but Mode B was
  dead on arrival for wheel installs. Tests never saw it because the source
  tree kept the real file on disk. Caught in the v1.3.11 release preflight by
  building and inspecting the actual wheel.
- **The fix plus a class guard**: the manifest is declared with its directory
  (`purple/nuclei_manifest.json`), and `tests/test_packaging.py` now fails the
  suite if ANY declared package-data glob matches no real file — the mistake
  can never again ship silently.

### Mode B: the Nuclei template policy is an enforced manifest (2B.8)

- **1,605 reviewed templates, pinned by sha256 at upstream commit `1cb2d50b`.**
  The manifest replaces the four-directory allowlist as the RECON_ACTIVE
  probe's policy. `token-spray/` and `misconfiguration/` carry zero entries
  and are not execution-eligible.
- **Enforced at three layers**: the adapter's argv is built FROM the manifest
  (no caller input); adapter registration refuses a policy-violating
  configuration; and a sandbox-side gate refuses unapproved `-t` values at
  execution time (exit 125, fail-closed even if the gate itself cannot run).
- **The image bakes the policy**: the template tree is pinned at the reviewed
  commit and the build fails if any manifest entry is missing or drifted, or
  if an unsafe subtree appears in the manifest.
- **The legacy EXPLOIT-stage path keeps its spec semantics unchanged** — the
  exact template-tree root stays its one allowed directory, and every EXPLOIT
  nuclei run still requires explicit Gate-2 human approval per hypothesis
  (non-TTY approves nothing; every decision audited). **These approved
  whole-tree runs are genuinely state-changing**: nuclei probes can exercise
  potentially exploitable behavior against the authorized target, including
  effects on target systems and data. That is precisely why they sit behind
  Gate 2 per-hypothesis approval and are unreachable from RECON_ACTIVE or
  model-generated arguments — but they are not "detection-only", and the
  release notes state that plainly.

### New vetted adapters: tls-probe and api-probe (2B.5)

- **tls-probe** runs the image's real testssl binary through a baked wrapper
  with a frozen flag set — no phone-out, no authenticated testing, one
  approved https host:port, a 240s internal kill with honest partial-JSON
  salvage. **2B.8 adds the bounded summary**: a 10,000-character self-bound
  (inside the unchanged 20,000-character host cap), totals and severity
  histogram that reflect every salvaged finding, and the full redacted
  artifact written to the engagement evidence directory (O_EXCL|O_NOFOLLOW,
  0600, sha256 recorded).
- **api-probe** is read-only: GET/OPTIONS only, redirects recorded and never
  followed, one fixed inert CORS test origin, no credentials, at most 7
  requests, 512 KiB reads, `$ref` counted and never resolved.
- **One probe per check**: the either/or wiring keeps the legacy
  sslscan/testssl.sh and openapi_probe entries out exactly while the vetted
  adapters are registered. RECON_ACTIVE now carries five vetted web adapters
  (httpx-probe, whatweb-probe, searchsploit-term, tls-probe, api-probe) plus
  the nuclei-probe adapter from this range.

### Zone B boundary: Docker bridge integrity (2C.2)

- The egress gate now verifies the WHOLE network shape before adopting it —
  exact name, bridge driver, explicit bridge name (auto-named refused),
  inter-container communication disabled, ownership label, the policy subnet,
  and the bridge interface actually present in the host kernel right now. A
  foreign or stale network can no longer be adopted while the iptables chains
  match a name that binds to no traffic; the same check re-runs at every
  verify, so post-establishment drift fails the boundary before any spawn.

### Deterministic tool planning (2B.6) — OFF by default

- A bounded, evidence-backed execution planner for RECON_ACTIVE: eligibility
  gates, conservative dedupe, explicit priority ordering, a wall-clock budget
  with audited deferral. It is a VIEW over the vetted adapter registry and
  advisory-only — it can never supply executables, argv, targets or
  templates. Feature-gated: OFF unless `KRYONSEC_TOOL_PLANNER_ENABLED` or
  `[tool_planner] enabled = true` is set, and a planner crash falls back to
  the exact pre-2B.6 deterministic path with an audited notice.

### Honest failures and bounded retries (2B.7)

- Adapter failures are classified (policy, tool, infra, timeout…) instead of
  flattened, infrastructure errors get a bounded retry, and every adapter
  start/outcome reaches the operator as one redacted progress line.

### Image build integrity

- **A required-tool check now FAILS the sandbox image build** when any of the
  six Mode B adapter executables, the entrypoint helpers (jq, timeout,
  python3), the EXPLOIT/verify lane's core tools, or the frozen-argv
  wordlists is missing. Optional tools (checkov, graphql-cop, semgrep,
  hadolint, kube-bench) stay best-effort: their absence is an audited spawn
  failure, never a silent hole.
- apt installs retry per package with bounded timeouts, so one mirror hiccup
  cannot silently drop a tool (the whatweb lesson, measured live).

### Release engineering: two-stage publication

- **The one-stage tag-push release path is gone.** The old `release-wheel.yml`
  and `sandbox-image.yml` published a wheel, created the GitHub Release and
  moved the GHCR `latest` pointer straight off a `v*` tag push — a single
  unreviewed tag could expose unvalidated code to members and re-point
  production installs. They are replaced by `release-candidate.yml` (Stage A:
  builds wheel + image from one frozen commit as restricted artifacts — no
  tag, no release, no `latest`), `release-promote.yml` (Stage B: promotes the
  already-validated image by digest — no rebuild — publishes the release with
  the hash-verified wheel, and moves `latest` only after the release exists
  and only on explicit request, behind the `release-production` environment),
  and `release-guard.yml` (fails loudly on manually pushed `v*` tags).
- **No `--clobber`, no tag rewriting, no overwrite of published releases** —
  recovery is fixing forward with a new version; see RELEASING.md.
- RELEASING.md's stale "the repo is private" claims are corrected (the repo
  is public since the docs commit; distribution is gated by the membership
  key, not by repository visibility).

### Known limitations

- semgrep, hadolint and kube-bench are absent from the 2026-11 Kali snapshot;
  checkov and graphql-cop install best-effort from PyPI/GitHub. Spawns for
  those tools fail closed with an audited `tool_failure` — they are optional
  capabilities, not release requirements.
- Adapters remain network-none or target-scope-only; RECON_PASSIVE still
  sends zero packets to any target.

Test suite: **2331 passed, 55 skipped** (local full run, Python 3.11, on the
release-prep commit; the 55 skips are env-gated Docker/gVisor lab tests; CI
covers 3.11/3.12/3.13). Real Docker + gVisor verification: 12/12 adapter lab
ITs and 2/2 full-engagement e2e lab ITs against the digest-pinned image
`sha256:d759cef7d0b364bcb3f0182388797cbc3c0d9de980278b9f04bdf584400a8f85`.

## v1.3.10 — authorized MCP, the full-screen workspace, and version integrity

Everything merged since the v1.3.8 release ships together here, including the
full-screen workspace and the security fix that closed the window its merge
opened. The version string is now consistent across the wheel, the package
metadata, this changelog, and the README badge.

### Accurate release history: where v1.3.9 stands

The published v1.3.9 artifacts (the GitHub Release wheel and the GHCR sandbox
image tagged `:v1.3.9` and `:latest`) were built from commit `ccaf635`, a
pre-merge state: the full-screen Textual workspace had not yet been merged at
that point. Those artifacts therefore contain neither the workspace nor the
MCP agent-route regression described below — and neither do they include the
merged registry, UI, and the PR #3 fix that v1.3.10 ships. The v1.3.9 tag,
release, and image are intentionally left untouched; v1.3.10, once published,
supersedes them as the release to install.

### Mode B sandbox and security hardening

- **Spawn-time isolation is verified before anything runs.** A launch guard
  refuses every Purple security-tool execution that is not Docker-only
  (`runsc`, non-root, read-only rootfs, resource caps, exactly one
  network-none flag); a missing guard fails closed to an audited `zone_b_blocked`
  halt, never a host execution.
- **Zone B egress is policed at the Docker host boundary**, so a process inside
  the sandbox cannot reach outside the engagement scope.
- **EXPLOIT records and hands off on evidence**: structured, evidence-derived
  attempt records, and an evidence-driven EXPLOIT → POST_EXPLOIT capability
  handoff instead of a schedule.

### MCP registry authorization and audit

- **One execution choke point.** Every real MCP tool call goes through
  `McpRegistry.call_mcp_tool`: trust policy → tool allowance → human approval →
  schema validation → concurrency bound → redaction, each decision audited and
  fail closed.
- **Connection-level startup policy** decides which MCP server process may
  launch at all; blocked servers stay visible but never start, and the block is
  audited.
- **A vetted read-only DocSafe provider** with path-scope confinement
  (traversal, absolute-path, and symlink escapes refused before dispatch).
- **A ship-aware wiring scan** in CI asserts the shipped code cannot execute an
  MCP tool or feed a raw catalog outside the registry.

### Mode B adapters (sandbox-contained, entrypoint-allowlisted)

- **httpx-probe**, **searchsploit-term**, **whatweb-probe**: the first three
  production Mode B adapters, each with allowlisted executables, in-scope-only
  arguments, verified network-none isolation, and audited inputs/outputs.

### Verification and evidence improvements

- **Capability verification separated from approval**, with verification
  statuses derived from concrete recorded evidence, a lineage graph over that
  evidence, and a deterministic `report.json`.
- **Independent capability verification** via static producer contracts, plus
  doctor's sandbox-image validation pre-flight.

### The full-screen Textual workspace

- Live session tabs with persisted history, a Mode B engagement console with
  live state/evidence views, inline approvals, the memory-browser launch point,
  and the mode-driven workspace palette.

### Fixed: the workspace goes through the MCP registry too (PR #3)

- The merge sequence landed the workspace against a pre-registry base, which
  opened a temporary authorization gap on `main`: its agent loop wired the
  legacy toolbox catalog without policy or audit, and its launcher started MCP
  server processes without the startup-policy gate. v1.3.10 carries the fix:
  the workspace sees MCP exactly like the approved chat path (registry-derived
  discovery only, `connect_all` gated by `startup_allowance()`), fail-closed
  without a registry, pinned by dedicated regression tests.

### Installation, config, and license

- Installer profiles with dry run, repair, and strict pre-flight; the Windows
  install is approved in the browser, not in the URL; the license endpoint
  names the identity a beta key needs; site-call transport failures are named
  without printing credentials; config writes are atomic and section-scoped.

Test suite: **2128 passed, 8 skipped** on Python 3.11, 3.12, and 3.13 (CI on
`388821a`); Docker + gVisor integration runs green on Linux.

## v1.3.8 — reliable installation and runtime validation

The release now fails closed when the required Purple Team runtime is not ready,
while keeping Copilot installation independent of Docker and gVisor.

- **Installers are repeatable.** Linux and Windows installers support dry runs,
  repair paths, explicit approval for host changes, wheel-hash verification, and
  preserved configuration.
- **Purple readiness is strict.** Docker context and daemon mismatches, missing
  `runsc`, mutable or mismatched images, and unsafe fallback runtimes are
  reported before execution. `kryonsec doctor --deep --strict` includes the
  network-disabled smoke test.
- **Site failures are explained safely.** Login, connection, logout, and license
  checks distinguish HTTP, DNS, TLS, timeout, and malformed-response failures
  without printing credentials or transport internals.

Test suite: **1747 passed, 4 skipped** (1751 collected across 55 test files).

## v1.3.7 — a crash the licence cache could reach

One fix. Test suite: **1676 tests green**.

- **A date-only expiry crashed the offline path.** The endpoint's documented
  `expires` shape is a date, not a datetime, and `fromisoformat` returns a
  naive one — subtracting it from an aware `now` is a `TypeError`, which the
  `ValueError` guard around it did not catch. So `verify()` could raise out of
  a function whose whole contract is that it never does, on the cached path a
  member hits on every launch for a day after a successful check. It now uses
  the `_parse_ts` helper that already existed for exactly this. Not reachable
  today, because the endpoint answers `expires: ""` — it becomes reachable the
  day expiry is added, which is the reason to fix it now rather than then.

## v1.3.6 — the membership gate, and `kryonsec connect`

The security engine is untouched: no state transition, tool allowlist,
sandbox behaviour, exploit or verify logic, or authorization gate was
modified. Test suite: **1675 tests green** (was 1667).

v1.3.5 shipped a licence check that nothing called. The key gated the
download and stopped there, so a Purple Team engagement ran for anyone who
had the code. This release wires it in and adds the one-time step that makes
it know *who*, not just *whether*.

- **`kryonsec connect` registers this machine.** It prints a link, opens a
  browser once, and waits for you to confirm your email. After that the
  machine is known and never asks again. Nothing types a password into a
  terminal, and the key is never pasted into a web page.
- **Purple Team now needs a connected machine, not just a valid key.** A key
  proves a membership exists; it does not say whose machine this is. Copilot
  mode is free and calls nothing.
- **The key travels in a header, not the URL.** A query string lands in access
  logs, proxy logs and Referer headers, and a membership key is a credential.
  Older installs still work — the endpoint accepts `?key=` as well.
- **Cloudflare no longer refuses the app's own requests.** urllib's default
  User-Agent is on the zone's banned-signature list, so every activation was
  answered 403 and silently interpreted as "offline", which the grace period
  then covered. What looked like working offline tolerance was a wall.
- **`kryonsec doctor` reports the membership and the machine.** A new row says
  whether the key is good *and* whether this box is connected, because those
  are different problems with different fixes.

## v1.3.5 — closed source, key-gated install

Kryonsec is commercial software now. The security engine is untouched: no
state transition, tool allowlist, sandbox behaviour, exploit or verify logic,
authorization gate, or provider code was modified.

- **The licence is proprietary and the repository is private.** Nothing had
  ever granted reuse rights, but a public repo fronting a one-command install
  read as open source.
- **Installing needs a membership key.** `install.sh` / `install.ps1` fetch the
  built wheel from `kryonsec.in` instead of cloning a repo, and save the key to
  `~/.kryonsec/config.toml` so Purple Team does not ask for it twice. Building
  the sandbox image locally is no longer a fallback — it is a pull, or nothing.
- **Purple Team asks `kryonsec.in` whether the key is still good**, at most once
  a day per machine, with a multi-day offline grace period. Copilot mode stays
  free and needs no key.
- **`zstd` is installed first.** Ollama's installer cannot unpack its own
  archive without it.

## v1.3.2 — Purple Team operations console

Presentation-only change. The security engine is untouched: no state
transition, tool allowlist, sandbox behaviour, exploit or verify logic,
authorization gate, or provider code was modified. Test suite: **861 tests
green** (was 854).

Purple Team output used to be raw developer logs — a spinner printing
`purple 20%` over a one-line inventory of every tool in the state, full
tracebacks from free public APIs answering 429/403/404, and a final summary
in plain text. It is now a single live console.

- **One live region** (`purple/ui.py`, new) replaces the scrolling log. The
  console learns everything from two existing streams — the orchestrator's
  state callback and the audit chain via a new read-only `AuditLog.add_observer`
  — so no subagent knows a UI exists.
- **Honest progress.** The old `20%` was the fraction of *states entered*,
  which reads as work completed. The bar is now labelled `Stage 3 of 10`.
- **Tool activity.** Every tool shows its operator-facing name (`crt.sh`,
  not `crt_sh_subdomains`), what it does, how long it took, and its result.
  Completed tools stay as history; only tools that actually ran appear.
  Columns are dropped, not crushed, as the terminal narrows.
- **Tracebacks are split, not shown.** `PurpleLogHandler` renders one line
  per warning to the console; the untouched record, `exc_info` intact, goes
  to `engagements/<id>/debug.log`. The stderr handler `basicConfig()`
  installs is silenced while the console owns the screen (it sat at WARNING
  already, so pinning it there left the raw line — and its traceback —
  printing beside the notice) and restored on exit.
- **Consistent dashboard.** `Panel(expand=False)` measures content and only
  caps at `width`, so panels boxed themselves at wildly different widths.
  All panels now share one width, capped at 100 columns.
- **ASCII fallback completed.** The glyph set alone was not enough: rich
  still drew Unicode borders unless it detected a legacy Windows console.
  The box style now travels with the glyph set, and the hardcoded `●` in the
  RUNNING/STOPPED indicator was added to it.
- **Piped and CI runs stay observable.** With no TTY there is no live region
  and the run was previously silent; it now prints one line per state.
- **Human review** is an approval panel (`A`/`R`, with `y`/`n` still
  accepted) instead of a bare `y/N` prompt; the live region pauses so the
  prompt owns the terminal.
- **Final summary** is a complete/halted panel carrying duration, verified
  findings, hypotheses, tool executions and evidence count, with paths
  written relative to the kryonsec home.

Loading a state no longer prints its full tool inventory — the inventory is
shown per tool, as each one actually runs.

## v1.3.0 — Purple Team tool expansion Phase 8 (user tool map)

Test suite: **559 tests green** (was 496).

The user supplied a complete tool map for every state; Phase 8 closes the
gaps against the ~40 tools already present. Every addition keeps the hard
invariants: argv templates (never shell strings), fixed plans (no LLM-driven
tool choice), every spawn audited, sandbox hardening unchanged.

- **Passive recon** (8A): RDAP WHOIS (IANA bootstrap-derived registry hosts),
  GitHub recon (free API, optional `GITHUB_TOKEN`), HackerTarget DNS history,
  cloud asset discovery (local pass, zero fetch), certificate issuer/validity
  enrichment. Zone A is now 10 sources.
- **Active recon** (8B): gowitness screenshots (new read-write `/evidence`
  mount — the only one; screenshots land under
  `engagements/<id>/evidence/`), massdns (allowlisted, not in the default
  plan), and a baked `openapi_probe.py` that finds OpenAPI/Swagger/GraphQL
  endpoints per web port (found paths become graph nodes).
- **Hypothesis enrichment** (8C): OSV and GitHub Advisory lookups, CWE ids
  from the NVD record, and nuclei template metadata (front-matter scan of the
  baked templates) — all rendered in the report's known-risk block.
- **Post-exploit** (8D): controlled impacket subset + bloodhound-python
  allowlisted and in the image but **dormant** (excluded from the plan — they
  need shell/domain context that does not exist today); cloud metadata
  enumeration script added to the plan (probes the sandbox's own metadata
  service, which is none).
- **Blue-team scanners** (8E): syft (SBOM), osv-scanner, grype join the scan
  plan as pinned binaries — syft offline, the other two need vuln-DB egress
  (same caveat as trivy). The report gained a "Code scanning results" section
  with an SBOM summary line.
- **Report** (8F): audit entries now carry an ISO-8601 UTC `ts` (informational
  — the hash chain remains the ordering guarantee, old chains still verify),
  a Timeline table built from the chain, and an `owasp_api` suggestion field
  (e.g. API1:2023-BOLA) in the fixes section.
- **Docs & version** (8G): expansion doc Phase 8 section, README tool tables,
  version 1.3.0.

**Deferred / skipped** (reasons in the expansion doc): Playwright (breaks the
argv-only rule; gowitness covers screenshots), Interactsh + Burp Community
(need listening services / callback traffic — revisit with the egress proxy),
kube-bench (audits live nodes, not code folders).

**Sandbox image changed** — rebuild required in WSL2:
`docker build -t kryonsec/sandbox -f containers/sandbox/Dockerfile.kali .`

**Known limitations**: gowitness 3.x flags could not be live-verified during
development (drift would surface as an audited spawn failure); sandbox egress
still uses the default docker bridge (proxy pending); POST_EXPLOIT dormant.

## v1.2.0 — Purple Team tool expansion (7 phases)

Test suite: **496 tests green** (was 321).

The Purple Team tool inventory grew from ~10 to **~40 sandboxed tools**,
every spawn allowlisted (argv templates, never shell strings), audited
(SHA256-chained), and run inside the gVisor sandbox. Highlights:

- **Zone B tool inventory** (Phase 1): passive subdomain tools (subfinder /
  amass / assetfinder, forced `-passive`), active recon (naabu, rustscan,
  whatweb, katana, hakrawler, sslscan, testssl.sh, dnsx), exploit
  specialists (dalfox, commix, ssrfmap, arjun, tplmap, jwt_tool, wfuzz,
  kiterunner, graphql-cop), verify tools (http, dig, nc, ncat), and a
  per-subagent template split so each state validates against its own set.
- **Passive recon expansion** (Phase 2): OTX passive DNS, RIPEstat
  whois/ASN, Shodan + Censys (API keys via config/wizard, never logged),
  all through the bounded, redirect-rechecked Zone A fetcher.
- **Hypothesis enrichment** (Phase 3): NVD/CPE, CISA KEV, EPSS, and
  sandboxed searchsploit per hypothesis — free public APIs, cached 24h,
  failures are audited skips, unknown ≠ absent.
- **POST_EXPLOIT** (Phase 4): wired-but-dormant (no current tool yields a
  shell). Fixed evidence-collection plan behind a separate terminal
  approval gate; the EXPLOIT boundary decides via shell detection +
  Gate 3.
- **Blue-team code scanners** (Phase 5): `purple --code FOLDER` mounts
  the folder read-only at `/code`; semgrep, bandit, gitleaks, trivy,
  checkov, hadolint run before the LLM, whose remediations are grounded
  in real scanner evidence. Remediations may carry suggested
  CWE/OWASP/ATT&CK mappings.
- **Report enrichment** (Phase 6): known-risk block per hypothesis (KEV /
  EPSS / exploit availability / CPE), pure-Python CVSS 3.1 base-score
  calculator (verified against FIRST examples), evidence normalizer
  (ANSI/whitespace/uniform truncation), duplicate-hypothesis merging with
  pointer remapping, and validate_report checks for dropped enrichment,
  unmerged duplicates, and ANSI leaks.
- **Docs & version** (Phase 7): this changelog, README tool tables,
  version 1.2.0.

**Known limitations** (recorded in the expansion doc): sandbox egress
still uses the default docker bridge (the target-scope-only proxy is not
built yet); POST_EXPLOIT is dormant pending a shell-yielding tool;
semgrep `--config=auto` and trivy DB need sandbox internet egress;
`--code` is CLI-only (not reachable from the chat loop).

## v1.1.2 — code-review fixes (10 findings + 1 bonus bug)

All fixes verified against the review of commit `f286273` (v1.1.1).
Test suite: **321 tests green** (was 216 — 40+ new tests cover every fix).

### Secret leaks (CLAUDE.md rule 4)

1. **Copilot agent tool loop leaked secrets to hosted LLMs**
   (`src/kryonsec/copilot/agent.py`)
   The secrets gate ran once, *before* the tool loop. If a tool result
   (e.g. `file_read` on `.env`) introduced a secret in round 1, round 2
   sent it verbatim to the third-party provider. The gate now re-runs
   before **every** LLM round: secrets in the conversation route to the
   local Ollama model; when no local model is up, the outbound messages
   are redacted (`«SECRET_n»` placeholders, mapping never leaves the
   machine) instead of leaking. The chat never crashes either way.

2. **Blue-team instructor path bypassed the secrets gate**
   (`src/kryonsec/purple/blue_team.py`)
   The instructor (structured-output) call went to the provider directly,
   skipping `chat()`'s gate. It now uses the same gate as HYPOTHESIZE.

3. **Report redaction used a private, drifting pattern list**
   (`src/kryonsec/purple/report.py`)
   The report's own `_SECRET_PATTERNS` list had already diverged from
   `secrets.py` and missed AWS keys, GitHub tokens, bearer tokens, and
   connection strings — in the one artifact meant to be shared. The
   private list is deleted; redaction delegates to the shared detector.
   Password/key labels are kept, only the value is replaced.

New shared helper: `kryonsec.llm.secrets_safe_prompt()` — the
single-prompt form of the §6.4 gate for the purple-team LLM states.
Routes to the local model when one is up, redacts when not, and never
raises.

### Purple-team logic regressions

4. **VERIFY baseline stripped the entire query string**
   (`src/kryonsec/purple/verify.py`)
   The baseline fetch for the boolean check dropped `?id=1`, fetching a
   different page (missing-param error), so `true_out == base_out` could
   almost never hold — genuine boolean-SQLi findings systematically
   "failed" verification. The baseline is now the original URL with its
   original query string.

5. **Over-strict hypothesis-id pattern zeroed hypothesis sets**
   (`src/kryonsec/purple/hypothesize.py`)
   The v1.1.1 pattern `^[A-Za-z][A-Za-z0-9_-]{0,19}$` rejected ids LLMs
   naturally emit (`1`, 21+ chars), and validation is all-or-nothing —
   one bad id ended the engagement with zero hypotheses. The pattern now
   only rejects what actually breaks things: `:` (it corrupts the
   `H1:sqlmap` label joins), plus whitespace/wild characters.

6. **Secrets gate could crash the HYPOTHESIZE state**
   (`src/kryonsec/purple/hypothesize.py`)
   `secrets_safe_model` was called outside the try block, so a
   false-positive secret pattern in recon data (e.g. a Wayback path
   `/login?password=forgot123`) raised `SecretsMustStayLocal` and the
   state failed with zero hypotheses. The gate (now
   `secrets_safe_prompt`) never raises — it routes or redacts.

7. **Negative `skipped` count written into the chained audit log**
   (`src/kryonsec/purple/exploit.py`)
   `skipped` was computed as `len(approved) - executed`, which went
   negative once multi-tool hypotheses began executing every listed tool
   (one approved hypothesis, tools `[nmap, sqlmap]` → `skipped: -1`).
   It now counts planned tool runs that never spawned.

### Smaller but real

8. **`/cve` output showed a Rich object repr instead of the table**
   (`src/kryonsec/cli.py`)
   The Rich Table was f-string-interpolated into a Panel title body, so
   every `/cve` lookup printed `<rich.table.Table object at 0x…>`. The
   Table is now a proper Panel child via `Group`.

9. **MCP servers slower than 10s were silently dropped for the session**
   (`src/kryonsec/copilot/mcp_tools.py`)
   A server whose tool list arrived after the 10s connect timeout (cold
   `npx` cache) was dropped with only a log line, and its tools were
   never registered. Now: a visible console notice, the server keeps
   booting in the background, and its tools merge into the live toolbox
   when they arrive (picked up on the next chat turn via a thread-safe
   `snapshot()`). A server that never becomes ready is dropped *with* a
   notice.

   **Bonus bug found while fixing this:** `_ServerConnection.ready` was
   initialized to `None` and never turned into a `threading.Event`, so
   every *real* MCP connect crashed into the "failed to start" path.
   Fixed — the Event is created in `__init__`.

10. **Token/cost budgets were never enforced**
    (`src/kryonsec/purple/orchestrator.py`, `hypothesize.py`,
    `blue_team.py`, `runner.py`)
    `BudgetTracker.record_usage()` existed but had zero call sites, so
    `used_tokens`/`used_cost_usd` stayed 0 forever and the guard could
    only trip on wall-clock time. The HYPOTHESIZE and BLUE_TEAM
    subagents now accrue their (approximate) prompt+response token
    usage; the runner passes the engagement's tracker to both.

### Tests added/updated

- Agent loop: secrets entering via tool results — local routing and
  redaction paths (2 tests)
- `secrets_safe_prompt`: routes / redacts / passes through / local
  model (4 tests)
- HYPOTHESIZE: natural id formats accepted, `:` rejected, secret
  prompt is redacted not fatal, budget usage recorded (4 tests)
- BLUE_TEAM: instructor-path gate, budget usage recorded (2 tests)
- VERIFY: baseline keeps the query string (regression test); existing
  sandbox fakes updated to identify the baseline by "no injection"
  instead of "no `?`"
- EXPLOIT: `skipped` never negative; skipped tool runs counted (2 tests)
- REPORT: AWS keys / GitHub tokens / connection strings redacted;
  password label survives (updated parametrize + 1 test)
- MCP: slow-server tools merge late with notices; dead server noticed
  (2 tests + updated disabled-server test)
- Runner: fake subagent `__init__` accepts the new `budget` kwarg

## v1.1.1

Audit fixes + detailed README with logo (see commit `f286273`).

## v1.1.0

Installer (bash + PowerShell), setup wizard, agent tool loop, MCP
tools, status line (see commit `ce8a442`).
