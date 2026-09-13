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
