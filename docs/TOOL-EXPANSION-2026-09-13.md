# Tool Expansion Record — 2026-09-13

Session log for the Purple Team tool-inventory expansion. Per-phase: what was
added, files touched, and decisions made. This file is updated as each phase
lands (it is the record requested alongside the work).

Approved plan: `~/.claude/plans/cozy-swinging-squid.md` (phases 1–7).

User decisions locked before implementation:
- Blue-team static analyzers scan a **user-provided code folder** (`--code`).
- **RAG deferred** — hypothesis enrichment uses free public APIs only
  (NVD/CPE/KEV/EPSS/ExploitDB) this round.
- subfinder / amass-passive / assetfinder run **in the gVisor sandbox**
  (passive flags), never on the host.
- Shodan + Censys **API keys** added to config.toml + setup wizard.

Hard invariants kept throughout (CLAUDE.md):
RECON_PASSIVE sends zero packets to the target; allowlist templates + argv
lists only; sandbox hardening (gVisor, seccomp, non-root, read-only rootfs,
limits, output bounding); every spawn audited; secrets gate on all LLM calls.

---

## Phase 1 — Zone B tool inventory (ACTIVE RECON + EXPLOIT + VERIFY)

**Status: COMPLETE — full suite green (378 passed, `py -3.13 -m pytest -q`,
2026-09-13).**

Completed this phase (across sessions 2026-09-13):
- 1a: allowlist template rewrite + template/sync tests in
  `tests/test_allowlist.py`
- 1b: `containers/sandbox/Dockerfile.kali` extended (extended apt block with
  per-package fallback, GitHub tools best-effort, nuclei templates moved to
  world-readable `/opt/nuclei-templates`, baked scripts
  `containers/sandbox/scripts/` → `/opt/kryonsec/`); entrypoint
  `ALLOWED_TOOLS` covers every host-allowlisted tool
- 1c: states wired — `recon_active.py` (fixed multi-tool plan, see below),
  `exploit.py` `build_argv` (nuclei/dalfox/commix/ssrfmap/arjun/tplmap/
  graphql-cop/wfuzz), `verify.py` (secondary probes), `runner.py`
  STATE_INFO, `templates/hypothesize.jinja` tool list

### 1a. Allowlist templates (`src/kryonsec/purple/allowlist.py`)

- Templates split by state: `ACTIVE_RECON_TEMPLATES`, `EXPLOIT_TEMPLATES`,
  `VERIFY_TEMPLATES` (plus `PASSIVE_TOOL_TEMPLATES` in Phase 2);
  `EXPLOIT_ALLOWLIST_TEMPLATES` kept as the union for compatibility.
- New template placeholders:
  - `{depth}` — crawl depth, small int (1–3)
  - `{hostport}` — `host:port` for openssl s_client
  - `{port}` — single TCP port (1–65535)
  - `{token}` — JWT-shaped token (base64url segments)
  - `{term}` — searchsploit search term (alnum/space/dash/dot, no shell
    metacharacters — argv is exec'd directly anyway, this is belt-and-braces)
- Active recon tools added: `naabu`, `httpx`, `rustscan`, `whatweb`, `katana`,
  `hakrawler`, `feroxbuster`, `sslscan`, `testssl.sh`, `dnsx`
  (dnsx deliberately lives in ACTIVE — it resolves target DNS = packets).
- Exploit tools added: `dalfox`, `commix`, `ssrfmap`, `jwt_tool`, `wfuzz`,
  `arjun`, `tplmap`, `kr`, `graphql-cop`
- Verify tools added: `http` (httpie), `openssl`, `dig`, `nc`, `ncat`,
  `python3` (fixed baked probe script only — no free-form file args)
- `jq` / `grep` / `diff` are NOT exposed as tools: they only ever run inside
  the baked probe script. Free-form file arguments would break the strict
  template rule.

### Decisions made during Phase 1

- **nuclei entrypoint mismatch fixed** (pre-existing bug found during the
  project walkthrough): `nuclei` was in the host allowlist but missing from
  the sandbox entrypoint `ALLOWED_TOOLS`, so every nuclei spawn would have
  been rejected inside the image. Both lists are now generated to match and a
  sync test (`test_allowlist.py::test_entrypoint_allowlist_in_sync`) keeps
  them from drifting again.
- **nuclei templates moved to `/opt/nuclei-templates`** in the image:
  `nuclei -update-templates` runs at build time as root (templates land in
  `/root/nuclei-templates`), but tools run as `kryonsec-runner` — without
  the move every nuclei spawn would die on file permissions. `build_argv`
  points `-t` at the new path.
- **dnsx moved to ACTIVE recon** — it resolves the target's DNS names,
  which sends packets; it cannot sit in the zero-packet passive phase.
- **RECON_ACTIVE runs a fixed two-stage plan** (no LLM input): discovery
  (nmap → naabu → dnsx) then web probes per discovered web port (httpx →
  whatweb → katana → feroxbuster; sslscan + testssl.sh on TLS ports; port
  80 probed as the default when nothing web-ish is found). rustscan and
  hakrawler are allowlisted but not in the default plan (nmap+naabu and
  katana already cover them — runtime cost without new evidence).
- **VERIFY secondary probes run only when boolean probing is impossible**
  (no numeric query parameter): httpie/nc/dig (+ openssl for https) gather
  reachability evidence into `verify_attempt.properties.secondary_evidence`.
  They never mark a finding "verified" — that stays the boolean probe's
  call.
- **jwt_tool and kr are allowlisted but dormant**: no tool in the graph
  produces a captured JWT or a .kx route wordlist, so `build_argv` returns
  None → audited skip. Templates exist for when that lands.
- **searchsploit is for Phase 3** (hypothesis enrichment), not EXPLOIT.
- POST_EXPLOIT tools (linpeas, pspy, linux-exploit-suggester, baked enum
  scripts) get wired with the subagent in Phase 4; the scripts are already
  baked (`containers/sandbox/scripts/`).

---

## Phase 2 — Passive recon expansion (Zone A + sandboxed passive)

**Status: COMPLETE — full suite green (396 passed, `py -3.13 -m pytest -q`,
2026-09-13).**

### New Zone A sources (`src/kryonsec/purple/zonea.py`)

All third-party APIs — zero packets to the target by construction. Hosts
added to `ZONE_A_ALLOWED_HOSTS`: `api.shodan.io`, `search.censys.io`,
`stat.ripe.net` (redirect re-check unchanged).

- `otx_passive_dns(domain)` — AlienVault OTX passive DNS hostnames
  (keyless).
- `ripestat_whois(domain)` — registrar, registration dates, nameservers.
  **Notes-only source** (no subdomains).
- `ripestat_asn(domain)` — resolved IPs (per RIPEstat's server-side DNS
  chain) → AS number / prefix / holder.
- `shodan_subdomains(domain, api_key)` — `api.shodan.io/dns/domain/<d>`;
  labels expanded to full names. Returns a **skipped** result when no key
  is configured — a visible audit notice, never a failure.
- `censys_subdomains(domain, api_id, api_secret)` — Search v2 hosts API
  (POST, Basic auth); `names:` query.

`PassiveResult` gained two fields:

- `notes: list[str]` — free-form evidence lines (whois/ASN) that become
  `osint_note` graph nodes; `render_hypothesize_prompt` flattens them into
  an "Other OSINT evidence" prompt section (capped at 20 lines).
- `skipped: str | None` — set when a source did not run (no API key);
  `ReconPassiveSubagent.run` audits it as `passive_source_skipped` and
  continues. `passive_source_ok` now also records a `notes` count.

### Sandboxed passive enumeration (`src/kryonsec/purple/recon_passive.py`)

- `sandbox_passive_fetcher(sandbox, audit)` — subfinder / amass / assetfinder
  spawned **inside the gVisor sandbox** with `-passive` flags. Same safety
  pattern as every Zone B spawn: allowlist + blocklist validation, argv
  lists, audited `tool_spawn`/`tool_result` with state `RECON_PASSIVE`.
  Output lines are scope-filtered to hosts strictly under the target
  (`host.endswith("." + domain)` — the apex is the target node, not a
  subdomain). Wired in `runner.py` only when the sandbox exists; elsewhere
  the engagement simply runs without it.
- `zone_a_fetchers(cfg)` — the Zone A source list for a config: crt.sh,
  Wayback, OTX, RIPEstat ×2 always; shodan/censys closures read
  `cfg.shodan_api_key` / `cfg.censys_api_id` / `cfg.censys_api_secret`.
  The dataclass default fetchers stay `[crt_sh, wayback]` (tests inject).

### Config + wizard

- `src/kryonsec/config.py`: `shodan_api_key`, `censys_api_id`,
  `censys_api_secret` fields (env defaults `SHODAN_API_KEY`,
  `CENSYS_API_ID`, `CENSYS_API_SECRET`), `[api]` TOML table, env-beats-TOML
  on load (same policy as the OpenAI key).
- `src/kryonsec/wizard.py`: new step 4 (after MCP) — optional Shodan key +
  Censys ID/secret. Censys needs BOTH id and secret or it is skipped with
  a clear message. Summary table row "passive-recon keys". Blank = skip;
  keyless sources always run either way.

### Decisions made during Phase 2

- **rdap.org → RIPEstat (deviation from plan).** The plan called for
  WHOIS via rdap.org; in practice it 302-redirects to arbitrary per-TLD
  registry hosts (rdap.verisign.com, rdap.nic.uk, …) which cannot be
  safely allowlisted ahead of time. RIPEstat's whois data call serves the
  same data from one fixed host (`stat.ripe.net`), so the Zone A egress
  allowlist stays small and enumerable.
- **RIPEstat resolves the domain server-side.** `ripestat_asn` asks
  RIPEstat's dns-chain endpoint for the target's addresses — WE never
  query the target's DNS ourselves, so the zero-packets invariant holds.
- **Keyless sources ship first-class.** A missing Shodan/Censys key is a
  skip notice in the audit log (the operator sees exactly what did not run
  and why), not a failure — one missing key can never fail the state.
- **Sandbox passive tools run with `-passive` flags only.** subfinder and
  amass both have active modes; the allowlist templates
  (`PASSIVE_TOOL_TEMPLATES`) hard-require the flag and a test
  (`test_passive_templates_require_passive_flag`) enforces it.
- **Runner tests patch `zone_a_fetchers`** instead of `crt_sh_subdomains`:
  the fetcher list grew from 2 to 7 sources, and the old patch target
  would have sent the other 5 to the real network during tests.
- **Wizard scripted answers grew by one.** The new step consumes one
  answer; every scripted wizard test gained a trailing `"n"` so the queue
  never falls back to blocking `input()` under pytest.

### Tests (`tests/test_zonea.py`, `tests/test_config_toml.py`)

New: `_in_scope_subdomains` filtering (lookalikes/wildcards/other TLDs),
shodan keyless-skip + label parsing, censys keyless-skip + POST body +
scoping, OTX parsing + scoping, RIPEstat whois notes, RIPEstat ASN notes
(chain + network-info), `zone_a_fetchers` list/keys-through (fully
offline — every source patched), skipped-source audit notice,
notes→osint_note nodes, prompt includes notes, sandbox passive fetcher
(argv shapes, allowlist validation, scoping, failed tool continues).
Config: `[api]` round-trip + env overrides (fixture extended with the
three new env vars).

---

## Phase 3 — Hypothesis enrichment (free APIs, RAG deferred)

**Status: COMPLETE — full suite green (419 passed, `py -3.13 -m pytest -q`,
2026-09-13).**

New `src/kryonsec/purple/enrichment.py`. After the LLM proposes
hypotheses, each one that names a CVE gets public-risk context:

- **NVD/CPE** — reuses `copilot/cve.py:lookup_cve` (cache-first, NVD
  fallback; NVD is an approved search API per spec §3.2). `_from_nvd` now
  also extracts the affected-product CPEs (bounded, deduped) into
  `record["cpes"]`.
- **KEV** — CISA known-exploited catalog JSON
  (`www.cisa.gov/.../known_exploited_vulnerabilities.json`), cached in
  `system_knowledge` (24h TTL, same pattern as the websearch cache).
  Fetched at most once per run. Fetch failure returns None = "unknown" —
  never treated as "not in KEV".
- **EPSS** — `api.first.org/data/v1/epss?cve=…` (same cache pattern).
- **ExploitDB** — `searchsploit --colorless {term}` in the sandbox (local
  database, no egress). Term = the CVE id; the `{term}` allowlist pattern
  (alnum/space/dash/dot) is enforced by the template and the term is
  *stripped* to that charset, never escaped (argv is exec'd directly).
  Without a sandbox (e.g. Windows) it is an audited skip.

Enrichment lands in `hypothesis.properties["enrichment"]` =
`{cve, cvss_score, severity, cpes, kev, epss, epss_percentile, exploits,
exploit_available}` (fields present only when the lookup succeeded).

### Wiring

- `Hypothesis` model + JSON prompt gained an optional `cve` field (the
  LLM may name the CVE directly; regex extraction from
  title/rationale is the fallback — `extract_cve_ids`).
- `HypothesizeSubagent` gained `sandbox=None`; enrichment runs after the
  dedup pass, wrapped so any crash is an `enrichment_failed` audit event —
  it can never fail the state (same policy as a flaky passive source).
- `runner.py` passes a `KaliSandbox` to HYPOTHESIZE when the sandbox
  exists; STATE_INFO updated.
- `zonea._zone_a_fetch` gained a keyword-only `allowed_hosts` override so
  enrichment reuses the same bounded, redirect-re-checked fetch with its
  own host set (`www.cisa.gov`, `api.first.org`). The target is never in
  any of these sets.

### Decisions made during Phase 3

- **Enrichment = third parties only.** NVD, CISA, FIRST, and the
  sandbox-local ExploitDB copy — the target is never contacted, so
  HYPOTHESIZE keeps its Zone A character even with enrichment on.
- **Unknown ≠ absent.** A failed KEV/EPSS/NVD lookup leaves the field
  out entirely; `kev: False` is reserved for "checked and definitively
  not in the catalog". This distinction flows into the report (Phase 6).
- **searchsploit searches by CVE id, not free text.** Hypothesis titles
  are prose ("SQLi on login") — searching ExploitDB with them returns
  noise; a CVE id is a precise query.
- **`_zone_a_fetch` parameterized instead of duplicated.** One bounded
  fetch + redirect re-check implementation, two allowlists (recon
  sources, enrichment sources) — the safety-critical code stays single.
- **Existing hypothesize tests stayed offline by construction**: their
  fake hypotheses contain no CVE ids, so enrichment's no-CVE path does
  zero lookups. The one test that wires the new `sandbox` kwarg
  (`test_runner.py::test_full_loop_through_exploit`) forces `None`.

### Tests (`tests/test_enrichment.py` — new)

CVE extraction/dedup, term sanitization (metacharacters stripped, length
cap), KEV fetch/parse/cache/stale-refetch/failure-is-None, EPSS
fetch/cache/unknown/failure, searchsploit allowlist validation +
audit events + spawn-failure and rejected-term paths, `enrich_hypotheses`
(properties written, CVE-less hypothesis skipped, all-APIs-down = audited
skips with `kev` absent not False, ExploitDB hits mark
`exploit_available`, KEV catalog fetched once for many hypotheses, empty
graph noop), NVD CPE extraction, and two HYPOTHESIZE integrations
(enrichment after proposing; enrichment crash never fails the state).

---

## Phase 4 — POST_EXPLOIT subagent (evidence collection only)

**Status: COMPLETE — full suite green (431 passed, `py -3.13 -m pytest -q`,
2026-09-13). Wired-but-dormant: no current tool yields a shell (see the
honest limitation below).**

New `src/kryonsec/purple/post_exploit.py`:

- **Fixed, deterministic plan** (no LLM input): linpeas.sh `-a`, pspy64,
  linux-exploit-suggester.sh, and the four baked scripts
  (`/opt/kryonsec/enum_processes.py`, `enum_fs.py`, `enum_network.py`,
  `find_secrets.py`, each with `{target}` as a context label). Every spawn
  is allowlist-validated (POST_EXPLOIT_TEMPLATES from Phase 1) + blocklist
  checked + audited with state POST_EXPLOIT; a rejected tool fails closed
  (audited, never spawned).
- **Evidence nodes**: each run adds a `post_exploit_evidence` node with
  `{tool, ok, exit_code, stdout_chars}` plus either a bounded JSON
  `summary` (the baked scripts print JSON; lists capped at 50 items) or a
  2000-char `excerpt` for text tools like linpeas. The subagent never
  claims a finding or a shell — collection only.
- **Separate approval gate (Gate 3)** — `terminal_post_exploit_approver`:
  distinct from HUMAN_REVIEW (approving a hypothesis is not approving
  post-exploitation of a shell it might yield). Non-TTY stdin approves
  nothing — silence is never consent, same rule as `terminal_reviewer`.

### EXPLOIT boundary wiring (`purple/exploit.py`)

- `ExploitSubagent._detect_shell()` is the single shell detection point.
  It returns False today — nothing in the inventory (sqlmap, nuclei,
  dalfox…) hands over an interactive session; they confirm vulnerabilities.
- When a shell IS detected, the approval gate runs at the EXPLOIT/POST_EXPLOIT
  boundary and the result carries `post_exploit_approved` (the orchestrator
  transition was already in place from v1: `shell_obtained AND
  post_exploit_approved → POST_EXPLOIT`, otherwise `→ VERIFY`). The gate
  decision is audited as `post_exploit_gate`.
- Runner: POST_EXPLOIT now wires the real subagent when a sandbox exists
  (was a stub); STATE_INFO updated.

### Honest limitation (recorded per plan)

No tool in the current inventory produces a shell, so `shell_obtained`
stays False and engagements route EXPLOIT → VERIFY directly. The state is
complete and fully tested; when a shell-yielding tool lands, the one-line
change is `_detect_shell()`.

### Tests (`tests/test_post_exploit.py` — new)

Plan argv shapes validate against the real allowlist; `{target}`
substitution is element-wise (never spliced into a string); plan covers
every POST_EXPLOIT template (no dead tools in the image); full-plan run
with a fake sandbox (evidence nodes, bounded excerpt/summary, audit
spawn/result/done events, chain verifies); failed tool still records its
node and never fails the state; empty allowlist rejects everything
(fail-closed, zero spawns); gate non-TTY/default/yes behavior; EXPLOIT
boundary (no shell today → VERIFY and gate never consulted; patched
shell detection → gate decides, denied → VERIFY, approved → POST_EXPLOIT).

## Phase 5 — Blue-team code scanners (`--code` folder)

**Status: COMPLETE — full suite green (465 passed, `py -3.13 -m pytest -q`,
2026-09-13).**

BLUE_TEAM gained a pre-LLM tool phase: when the operator passes
`kryonsec purple --target t --code FOLDER`, six static analyzers scan the
folder through a read-only sandbox mount before the LLM writes
remediations, so fixes are grounded in real scanner evidence instead of
guesses.

### What runs (`src/kryonsec/purple/blue_team.py`)

- **Fixed plan** (no LLM input): semgrep `--config=auto`, bandit `-r`,
  gitleaks `detect --source`, trivy `fs --scanners vuln`, checkov `-d` —
  all against the fixed `/code` mount; hadolint runs only when a
  `Dockerfile` exists in the folder. Every spawn is allowlist-validated
  (new `BLUE_TEAM_TEMPLATES`, unioned into `EXPLOIT_ALLOWLIST_TEMPLATES`)
  + blocklist checked + audited with state BLUE_TEAM; a rejection fails
  closed (audited `scanner_rejected_by_allowlist`, never spawned).
- **Scanner evidence nodes** (`scanner_result`): `{tool, exit_code,
  stdout_chars, excerpt (2000-char cap), findings_count?}`. `_count_findings`
  parses JSON first (trivy `Results[].Vulnerabilities`, checkov
  `failed_checks`), then per-tool text regexes; unknown output shape →
  no count, never a guess presented as one.
- **Remediation model** gained optional `cwe` / `owasp` / `attack`
  (MITRE ATT&CK) fields — LLM-suggested mappings shown as suggestions to
  verify, never established fact. The prompt instructs the LLM to leave
  them empty rather than guess, and it may write remediations for scanner
  findings using the tool name as `hypothesis_id` (e.g. "semgrep").

### Sandbox mount (`src/kryonsec/purple/sandbox.py`)

`KaliSandbox(code_dir=...)` adds `-v <abs>:/code:ro -w /code` to the
docker argv: read-only (no scanner can write to the user's folder), fixed
`/code` literal inside the templates (a different path never validates),
absolute paths only (relative is refused — it would silently resolve
against an unknown cwd). Absolute is accepted on either platform:
production is Linux, but Windows dev machines hand `C:\...` paths in
tests. The rootfs stays `--read-only` too.

### CLI (`src/kryonsec/cli.py`)

`kryonsec purple --target t --code FOLDER` — the path is expanded and
resolved; a non-folder is a hard error (exit 2), never a silent wrong
scan. Without a sandbox the run prints that `--code` is ignored
(scanners need the sandbox) and continues. `engagement_created` audits
`code_scan: true/false`.

### Decisions made during Phase 5

1. **kube-bench is deliberately NOT in the scan plan.** It audits a live
   node's kubelet configuration, not a code folder — inside this sandbox
   it would test the sandbox itself. Its entrypoint registration and
   allowlist template remain for future node-audit work.
2. **bandit and gitleaks EXIT 1 when they FIND something** — that is a
   finding, not a tool failure. Evidence nodes are written for ok spawns
   regardless of exit code; the count regexes read the output, not the
   exit code. The prompt tells the LLM this explicitly.
3. **`--code` is CLI-only.** The `/mode` chat-loop invocation stays
   target-only — a chat message is not a trustworthy path source.
4. **Failing scanner = audited skip, never fatal** — same semantics as a
   flaky passive source; the LLM phase runs regardless, and a scanner
   phase crash is caught (`scanners_failed`) with the LLM phase still
   running.
5. **Sandbox egress note:** semgrep `--config=auto` (registry fetch) and
   trivy (vuln DB download) need outbound internet from the sandbox.
   Containers currently use the default docker bridge (the
   target-scope-only proxy does not exist yet, same caveat as EXPLOIT);
   on the default bridge both have egress, but when the proxy lands an
   allowlist entry for registry/database hosts will be required.
6. **Findings counts are approximate** (regex over text output) — they
   are labelled `~N` in the prompt and meant for grounding, not for
   exact reporting.

### Tests

`tests/test_sandbox.py` (mount flags, no-mount default, relative-path
refusal), `tests/test_blue_team_report.py` (`_count_findings` unit
cases, plan-vs-allowlist drift guard, full-run evidence + audit chain,
hadolint gating, failing-scanner skip, exit-1-is-findings, empty
allowlist fail-closed, prompt scanner-evidence section, mapping fields
optional, scanners-before-LLM ordering, scanner crash resilience, pure
LLM without sandbox), `tests/test_runner.py` (code-folder wiring: only
the BLUE_TEAM sandbox gets the mount, audit `code_scan` flag, missing
folder rejected), `tests/test_allowlist.py` (6 valid argv cases + other
paths rejected).

## Phase 6 — Report enrichment

**Status: COMPLETE — full suite green (496 passed, `py -3.13 -m pytest -q`,
2026-09-13).**

The report now shows the public-risk context Phase 3 gathered, computes a
numeric CVSS score from the hypothesis vector, merges duplicate
hypotheses, and normalizes tool evidence — all in `purple/report.py` +
`templates/report.jinja`.

### Enrichment rows (per hypothesis)

When a hypothesis carries `enrichment` (from Phase 3), the report renders
a "Known risk data for CVE-…" block: CISA KEV status (YES — fix first /
no / unknown-lookup-failed — unknown is never rendered as "no"), EPSS
score (unknown when the lookup failed), public exploit availability, and
CPE software list. Failed lookups leave keys absent;
`_normalize_enrichment` gives the template a fixed shape so
StrictUndefined can never crash REPORT.

### CVSS 3.1 base-score calculator

`cvss_base_score(vector)` — pure Python (~80 lines), no new dependency.
Full v3.1 math: scope-changed impact formula, the official Appendix A
`Roundup` (5-decimal intermediate, ceiling to 1 decimal), metric tables.
Missing/unknown metric → None, never a guessed score. `cvss_severity`
buckets to none/low/medium/high/critical. The report shows the LLM's
vector, the calculated score, and the bucket; when the vector is
unparseable it falls back to NVD's own score, and when neither exists it
says "score could not be calculated".

### Evidence normalizer

`normalize_evidence(text)` — ANSI escape codes stripped, whitespace
collapsed to single spaces, uniform truncation (200 chars + ellipsis).
Applied to `exploit_attempt.output_excerpt` in the repeatable-steps
section; raw output stays in the audit chain (this is only the report's
view). `validate_report` now also rejects any ANSI codes in the rendered
report.

### Hypothesis dedup

`dedup_hypotheses(graph, audit)` runs at the top of REPORT (before
rendering): hypotheses with the same (sorted tool set, target asset) are
merged into the first occurrence — keeping the max confidence and the
first non-empty cve / cvss_vector / enrichment — with `merged_from`
recording the absorbed ids. Every node pointing at a merged id
(remediation, finding, verify_attempt, exploit_attempt "H2:tool" labels)
is remapped so report joins stay correct. The merge count lands on the
audit chain as `hypotheses_merged`. Dedup runs in the REPORT state, not
HYPOTHESIZE: the hypothesis-time id dedup (same id twice) stays where it
was; this one catches the same *idea* proposed twice with different ids,
which only matters once the report renders.

### Mapping tags

The fixes section shows CWE / OWASP / ATT&CK when BLUE_TEAM suggested
them, labelled "suggested, not verified". Old remediation nodes without
the fields render fine (defaults, not StrictUndefined crashes).

### validate_report extensions

(1) every enriched hypothesis's CVE must appear in the report; (2) an
unmerged duplicate (same tools/asset) is a problem; (3) ANSI escape
codes anywhere in the output are a problem.

### Decisions made during Phase 6

1. **Score source is labeled.** A calculated score is shown as
   "calculated base score"; NVD's own score is only used when the vector
   is missing/unparseable. The reader can always tell what was computed
   vs looked up.
2. **Dedup merges in the graph, not just at render time** — so the
   remediation joins, the report's tested/confirmed sets, and any future
   consumer all see the merged view. The audit chain keeps the full
   pre-merge history.
3. **`hypotheses_merged` audit event carries the alias map** — a
   verifier can reconstruct exactly which suggestions were absorbed into
   which.
4. **KEV "unknown" ≠ "no".** Same semantics as Phase 3: a failed lookup
   must never read as "not exploited".

### Tests (`tests/test_blue_team_report.py`)

normalize_evidence (ANSI/whitespace/truncation/empty), cvss_base_score
parametrized over official FIRST examples + malformed vectors,
cvss_severity buckets, enrichment rendering (full + partial data with
unknown-not-no semantics), dedup (merge + pointer remapping + audit
event + noop), subagent merges before rendering, validate_report catches
unmerged duplicates / dropped enrichment / ANSI in output, normalized
attempt excerpts, mapping tags render with the "suggested" label.

## Phase 7 — Record, tests, docs (final)

**Status: COMPLETE — full suite green (496 passed, `py -3.13 -m pytest -q`,
2026-09-13). Version bumped to 1.2.0.**

- **CHANGELOG.md**: v1.2.0 entry summarizing all seven phases, with the
  known limitations (default-bridge egress, dormant POST_EXPLOIT,
  semgrep/trivy sandbox-egress needs, CLI-only --code).
- **README.md**: version/test badges (1.2.0, 496 tests), the 10-state
  table rewritten with the real per-state tool inventories, Zone A/B
  descriptions updated (OTX/RIPEstat/Shodan/Censys + enrichment APIs,
  read-only /code mount), a new "Enrichment and the report" section, a
  sandbox smoke-test recipe (WSL2: `kryonsec doctor` then `purple --target
  … --code …`), the roadmap table gains the expansion rows (POST_EXPLOIT
  now "wired but dormant", egress proxy listed as pending), test counts
  fixed, and the safety layer 6 claim corrected — the egress proxy is
  NOT built yet, the sandbox uses the default docker bridge today.
- **Version**: `__version__` + pyproject 1.1.0 → 1.2.0 (they had been
  left at 1.1.0 through the whole expansion; no test asserts the value).
- **Final verification**: full suite 496 passed; `kryonsec doctor`
  behaves unchanged (expected Profile-2 failures on the Windows dev
  machine, Purple Team is WSL2-only).

### The full expansion in one line each

1. Zone B tool inventory (~30 templates, per-state splits)
2. Passive recon sources (OTX, RIPEstat, Shodan, Censys)
3. Hypothesis enrichment (NVD/CPE, KEV, EPSS, searchsploit)
4. POST_EXPLOIT (wired, dormant behind Gate 3)
5. Blue-team code scanners (--code, read-only /code mount)
6. Report enrichment (CVSS 3.1 calculator, dedup, normalizer)
7. CHANGELOG, README tool tables, version 1.2.0

---

# Phase 8 — User tool map (2026-09-14)

Approved plan: `~/.claude/plans/shiny-singing-hanrahan.md`. The user supplied a
complete tool map for every state; comparing it to the codebase, ~40 tools were
already present (v1.2.0). Phase 8 closes the gaps. Commits:
`v1.3.0-1` (8A+8B) → `v1.3.0-2` (8C+8D) → `v1.3.0-3` (8E+8F) → `v1.3.0` (8G).
Suite: **496 → 559 tests**.

User decisions locked before implementation:
- Browser tool → **gowitness only** (Playwright skipped — needs driver code,
  breaks the argv-only rule).
- **Interactsh + Burp Community deferred** — they need listening services /
  external callback traffic; revisit when the egress proxy exists.
- GitHub recon → **free API only**, optional `github_token` in config (same
  pattern as Shodan/Censys keys).
- BloodHound CE / impacket → **allowlist + image now, dormant** (no shell
  exists; same status as the rest of POST_EXPLOIT).

## Phase 8A — Passive recon (Zone A) additions

**Status: COMPLETE — commit 6f2ee8c (v1.3.0-1), suite 530.**

New sources in `zonea.py` + `recon_passive.py::zone_a_fetchers` (now 10):

- **RDAP WHOIS** (`rdap_whois`) — fetches the IANA RDAP bootstrap
  (`data.iana.org/rdap/dns.json`), finds the registry RDAP server for the TLD,
  queries it via `_zone_a_fetch` with the IANA-derived host added to the
  allowlist (the host comes from IANA's official bootstrap file, never from a
  redirect). Notes: registrar, dates, nameservers, status.
- **GitHub recon** (`github_recon`) — `api.github.com` (free tier): org + repo
  search named after the domain; with `github_token` configured, code search
  for the domain (leaked-config references → notes only, never fetched).
  Repo-name subdomain-like hostnames become subdomains.
- **DNS history** (`hackertarget_hostsearch`) — keyless, heavily rate-limited;
  a failure is an audited skip like every source. Host,IP pairs → subdomains.
- **Cloud asset discovery** (`cloud_asset_notes`) — **zero fetch**: a local
  pass over already-collected subdomains matching cloud provider suffixes
  (`.amazonaws.com`, `.cloudfront.net`, `.azurewebsites.net`,
  `.blob.core.windows.net`, `.herokuapp.com`, `.netlify.app`, `.fastly.net`,
  `.appspot.com`) → one `osint_note` listing cloud-hosted assets. Runs last.
- **Certificate enrichment** — `crt_sh_subdomains` now parses issuer/validity
  into bounded notes.

Config/wizard: `github_token` (`[api]`, env `GITHUB_TOKEN`), wizard step with
the Shodan/Censys keys. Token never logged or audited.

## Phase 8B — Active recon additions

**Status: COMPLETE — commit 6f2ee8c (v1.3.0-1).**

- **gowitness** (screenshots) — `KaliSandbox` gained `evidence_dir`:
  `-v <abs>:/evidence:rw`, the **only read-write mount** in the system
  (`/code` stays `:ro`, rootfs stays `--read-only`). Runner wires
  `cfg.home/engagements/<id>/evidence` for RECON_ACTIVE/EXPLOIT/POST_EXPLOIT/
  VERIFY sandboxes. One gowitness run per web port in `_web_plan`; screenshot
  node label = the `--url` argument, `dir=/evidence`.
  **Known caveat:** gowitness 3.x flags could not be live-verified during
  development (documented usage: `scan website --url X --screenshot-path Y
  --no-console --disable-db`); flag drift would surface as an audited spawn
  failure, never a safety issue.
- **massdns** — apt package; allowlist template with fixed literal wordlist +
  resolver paths (seclists). NOT in the default plan (dnsx covers resolution);
  allowlisted for future plan use.
- **OpenAPI/API discovery** — baked script `containers/sandbox/scripts/
  openapi_probe.py` (argv `{url}` only): probes `/openapi.json`,
  `/swagger.json`, `/api-docs`, `/graphql`, prints a JSON summary of found
  endpoints (bounded 50 endpoints, 120-char labels). Added to `_web_plan`
  stage 2 per web port; found paths become `path` nodes (source
  `openapi_probe`).

## Phase 8C — Hypothesis enrichment additions

**Status: COMPLETE — commit 2a4d66c (v1.3.0-2), suite 549.**

`enrichment.py`, after the Phase 3 lookups:

- **OSV** (`osv_record`) — `api.osv.dev/v1/vulns/{cve}` (keyless):
  `osv_aliases`, `osv_severity`, `affected_packages` (bounded). Audited as
  kind "osv".
- **GitHub Advisory Database** (`ghsa_record`) — `api.github.com/advisories?
  cve_id=…` (keyless): `ghsa_id`, `ghsa_severity`, `patched_versions`.
- **CWE** — `copilot/cve.py::_from_nvd` extracts CWE ids from the record's
  `weaknesses` list → `enrichment["cwes"]` (bounded, deduped).
- **Nuclei template metadata** — baked script `containers/sandbox/scripts/
  nuclei_meta.py` (argv `{term}`): front-matter scan of the baked
  `/opt/nuclei-templates` for the CVE/term, prints `{matches: [{id, severity,
  tags}]}` (bounded 10). Called from `enrich_hypotheses` exactly like
  searchsploit; matches → `enrichment["nuclei_templates"]` and
  `exploit_available=True`.

Report: `_normalize_enrichment` + `report.jinja` gained the OSV / GHSA / CWE /
nuclei rows (same "unknown ≠ absent" semantics as Phase 3).

## Phase 8D — Post-exploit (dormant) additions

**Status: COMPLETE — commit 2a4d66c (v1.3.0-2).**

- **Impacket (controlled subset)** — apt `impacket-scripts`; allowlist
  templates for `GetNPUsers.py`, `GetUserSPNs.py`, `GetADUsers.py`,
  `findDelegation.py` (each `["{term}", "-dc-ip", "{target}"]` shaped).
  Deliberately NOT in `POST_EXPLOIT_PLAN` — they need operator-provided
  domain/credential context that does not exist without a shell. The
  dangerous remainder (secretsdump, atexec/wmiexec/smbexec/psexec, GetST,
  ticketer) is NOT allowlisted and a test pins that.
- **bloodhound-python** — already in image + entrypoint; added the missing
  host template `["--collection", "All", "--domain", "{term}", "--dc-ip",
  "{target}"]`, dormant.
- **POST_EXPLOIT_DORMANT_TOOLS** set in `post_exploit.py` — the plan-coverage
  test excludes it, and a dedicated test asserts none of them is ever in the
  plan.
- **Cloud metadata enumeration** — baked script
  `containers/sandbox/scripts/cloud_meta.py` (argv `{target}` label): probes
  `169.254.169.254` / `metadata.google.internal` etc. from inside the
  sandbox, JSON out (bounded 2000 chars). IS in `POST_EXPLOIT_PLAN` —
  harmless, it probes the sandbox's own (nonexistent) metadata service.

## Phase 8E — Blue-team scanner additions

**Status: COMPLETE — commit (v1.3.0-3), suite 559.**

`BLUE_TEAM_SCAN_PLAN` grew from 6 to 9 (+ conditional hadolint):

- **syft v1.26.0** (SBOM) — `["scan", "/code", "-o", "json"]`, offline.
- **osv-scanner v2.0.2** — `["-r", "/code", "--format", "json"]`; needs
  egress to api.osv.dev (default bridge works today — same caveat as trivy;
  fails as an audited skip offline).
- **grype v0.95.0** — `["dir:/code", "-o", "json"]`; needs vuln-DB download
  (same egress caveat).

All three are pinned GitHub release binaries in `Dockerfile.kali` (same wget
pattern, WARN fallbacks). `_count_findings` gained JSON parsers: syft
`artifacts` (a **package count, not vulns** — rendered as the SBOM line),
osv-scanner `results→packages→vulnerabilities`, grype `matches`. The report
gained a "Code scanning results (blue team)" section with an SBOM summary
line ("SBOM: N packages identified (syft)") and one row per scanner.

## Phase 8F — Report additions

**Status: COMPLETE — commit (v1.3.0-3).**

- **Timeline** — `audit.py::write()` stamps every entry with an ISO-8601 UTC
  `ts` field (informational; the hash chain, not wall clock, remains the
  ordering guarantee — old chains still verify since `verify()` hashes
  whatever fields exist). `report.py::build_timeline()` reads
  `engagement_created` / `state_enter` / `report_written` milestones (bounded
  100 rows); `report.jinja` renders the Timeline table after the halt reason.
- **OWASP API mapping** — `Remediation` gained optional `owasp_api` (e.g.
  `API1:2023-BOLA`), prompted in `blue_team.jinja`, rendered in the same
  "suggested, not verified" mapping line.

## Phase 8G — Docs, version, final verification

**Status: COMPLETE — v1.3.0.**

- This Phase 8 section; README tool tables + badges; CHANGELOG v1.3.0;
  version 1.2.0 → 1.3.0 (`__init__.py` + `pyproject.toml`).
- Sandbox image changed (gowitness, massdns, syft, grype, osv-scanner,
  impacket-scripts, baked scripts) → **rebuild required in WSL2**:
  `docker build -t kryonsec/sandbox -f containers/sandbox/Dockerfile.kali .`

### Covered by existing tools (documented, not re-added)

- **Wappalyzer** — whatweb `-a 3` + httpx `-tech-detect` cover tech
  fingerprinting.
- **OWASP/ATT&CK "knowledge"** — the blue-team LLM suggestion fields from
  Phase 5 (+ `owasp_api` in 8F).
- **Custom HTTP/DNS probes** — baked `probe.py` + `dig`.
- **Response comparison** — VERIFY's boolean baseline probe.
- **Container/K8s analyzers** — trivy FS + checkov + hadolint cover images /
  manifests / Dockerfiles; kube-bench deliberately excluded (audits live
  nodes, not code folders — it would test the sandbox itself).

### Deferred / skipped (with reasons)

| Tool | Decision | Reason |
|---|---|---|
| Playwright | skipped | Needs driver code in the sandbox; breaks the argv-only rule. gowitness covers screenshots. |
| Interactsh | deferred | Needs a listening client server / external callback traffic; revisit with the egress proxy. |
| Burp Community | deferred | Needs a listening proxy service and operator-driven traffic; same egress-proxy prerequisite. |
| kube-bench | excluded | Audits live kubelet config, not a code folder. |
| massdns | allowlisted, not planned | dnsx covers resolution in the default plan. |
| impacket / bloodhound-python | allowlisted + image, dormant | Need shell + operator domain/cred context that does not exist today. |
