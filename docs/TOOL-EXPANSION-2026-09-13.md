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

_(updated as phases land)_
