# Session Notes — 2026-09-13

Complete record of this session, start to finish: what was asked, what was
found, questions and answers, the plan that was approved, and exactly where
implementation stopped. Read this first when resuming.

---

## 1. What happened in this session (summary)

1. The user asked for a **full walkthrough of the project**. I read every
   source file and gave a complete report (section 2).
2. The user asked **which tools Purple Team can use and what the agent system
   prompts are** (section 3).
3. The user provided a **big tool list (~70 tools across all Purple Team
   states)** and asked to add them all, plus keep a record of the work.
4. I entered plan mode, asked 4 decision questions (section 4), wrote a
   7-phase plan, and it was **approved** (section 5).
5. Implementation of **Phase 1 started** — 3 files were changed — then the
   user stopped it to close the session (section 6: exact state of the code).

---

## 2. Full project walkthrough (findings)

### What was reviewed
Every source file under `src/kryonsec/` (core, copilot, purple, storage,
templates), `containers/sandbox/` (Dockerfile + entrypoint), the test
directory, README/CHANGELOG. (~8,000 lines of source + ~3,700 lines of tests.)

### Architecture as found (v1.1.3)
- **Core:** `cli.py` (chat loop, slash commands, Shift+Tab mode toggle),
  `config.py` (`~/.kryonsec/config.toml`, env overrides), `llm.py` (LiteLLM
  routing, provider isolation, §6.4 secrets gate), `secrets.py` (10 detection
  patterns + redaction/restore), `doctor.py` (preflight, Linux-gated
  Docker/gVisor checks), `storage/` (SQLAlchemy, PostgreSQL system-of-record,
  SQLite fallback).
- **Copilot (Mode A):** agent tool loop (max 8 rounds, per-round secrets
  re-gating), approval-gated file tools, CVE lookup (NVD + cache), web search
  (5 fallback sources + 1-day cache), live MCP toolbox, Strix-style session
  compaction, LTM fact extraction.
- **Purple Team (Mode B):** deterministic 10-state loop + HALT (rejection
  routes through BLUE_TEAM per v2.1.1), SHA256-chained JSONL audit log with
  canonical JSON, argv-template allowlist (Layer 2) + blocklist (Layer 8),
  gVisor sandbox (seccomp, non-root, read-only rootfs, resource limits,
  output bounding, kill-on-timeout), scope enforced by construction in
  `compose_url`, human review where non-TTY approves nothing, VERIFY with
  baseline-corrected boolean probes.

### Assessment
The codebase is well-built and matches the v2.1.1 spec and the CLAUDE.md core
rules closely. Tests: 26 files, ~321 tests per CHANGELOG, covering every
safety layer. (I could not re-run the suite this session — the command
classifier was temporarily unavailable and the PATH `python` (3.14) has no
pytest; the suite last ran under Python 3.12.)

### Known gaps found during the walkthrough
1. **nuclei allowlist mismatch (real bug):** `nuclei` was in the host
   allowlist but missing from the sandbox entrypoint `ALLOWED_TOOLS` — every
   nuclei spawn would be rejected inside the image. *(Fixed in this session —
   see section 6.)*
2. Sandbox egress is the default Docker bridge — the spec §8.2 target-scope
   traffic proxy does not exist yet; scope enforced by argv only (audited).
3. Sandbox image is tag-pinned (`:latest`), not digest-pinned (warned at
   runtime).
4. POST_EXPLOIT was a stub (no subagent implemented).
5. `EngagementGraph` stays in memory; `stm_nodes`/`checkpoints` tables exist
   but are unused.
6. Redis/MinIO from the spec are not used at all.
7. Minor: `GeneralUserLtm.value` is a JSON column but receives plain strings.

---

## 3. Question: Purple Team tools + agent prompts (answered)

**Tools, by layer (as found before this session's changes):**
- Host allowlist (authoritative, 8 tools): `nmap, sqlmap, nuclei, curl,
  nikto, ffuf, gobuster, wget` — each with a strict argv template.
  `masscan` deliberately excluded (spec §9.1).
- Sandbox entrypoint (defense-in-depth): `nmap, dnsx, subfinder, sqlmap,
  nikto, gobuster, ffuf, curl, wget, nc, ncat, openssl, python3,
  linpeas.sh, bloodhound-python`.
- Zone A passive sources (APIs, not tools): crt.sh, Wayback.

**Agents:** 10 states + HALT; only 2 are LLM agents:
- **HYPOTHESIZE** system prompt: "You are the hypothesis engine of a
  purple-team engagement. You propose vulnerability hypotheses from recon
  data. You NEVER claim to have tested anything. Output JSON only." +
  `templates/hypothesize.jinja` (8 rules, max 10 hypotheses, tools restricted
  to the allowlist, 0.0–1.0 confidence).
- **BLUE_TEAM** system prompt: "You are the blue-team engine of a purple-team
  engagement. You write defensive recommendations: concrete fixes and
  detection signatures. Output JSON only." + `templates/blue_team.jinja`.
- All other states are plain Python / terminal-interactive (INIT,
  RECON_PASSIVE, RECON_ACTIVE, HUMAN_REVIEW, EXPLOIT, POST_EXPLOIT stub,
  VERIFY, REPORT) — by design ("creative LLM, rigid system").
- Copilot mode has its own system prompt in `templates/system_prompt.jinja`.

---

## 4. The tool-expansion request and the 4 decisions

The user provided a full professional tool inventory to add:

- PASSIVE RECON: subfinder, amass-passive, assetfinder, dnsx, crt.sh,
  Wayback, Shodan, Censys, OTX, WHOIS/RDAP, ASN/BGP
- ACTIVE RECON: nmap, naabu, httpx, rustscan, whatweb, katana, hakrawler,
  feroxbuster, gobuster, sslscan, testssl.sh
- HYPOTHESIS: NVD/CVE, CPE, KEV, EPSS, ExploitDB, Nuclei metadata, RAG
- EXPLOIT/TEST: nuclei, sqlmap, dalfox, commix, ssrfmap, jwt_tool, ffuf,
  wfuzz, arjun, tplmap, GraphQL tooling, kiterunner, API testing
- POST-EXPLOIT: linpeas, pspy, linux-exploit-suggester, process/filesystem/
  network enumeration, secret discovery, controlled impact/evidence
- VERIFY: curl, httpie, openssl, dig, nc/ncat, python, jq, grep, diff,
  custom probes
- BLUE TEAM: semgrep, bandit, gitleaks, trivy, checkov, hadolint,
  kube-bench, config/code analyzers
- REPORT: CVSS, CWE, OWASP, ATT&CK, evidence normalizer, dedup, generator

**Questions I asked (AskUserQuestion) and the user's answers:**

| # | Question | Answer |
|---|----------|--------|
| 1 | Blue-team scanners scan what? (pure LLM today) | **Scan a code folder** — user provides a path via `--code`; scanners run in the sandbox read-only, LLM writes fixes grounded in results |
| 2 | Build RAG now or later? | **Defer RAG** — this round uses free APIs only (NVD/CPE/KEV/EPSS/ExploitDB) |
| 3 | subfinder/amass/assetfinder run where? | **In the sandbox** with `-passive` flags (zero packets to target, nothing to install on the host) |
| 4 | Add Shodan/Censys API keys? | **Yes** — keys in config.toml + setup wizard; keyless sources skipped with a notice |

Decision I made myself (stated in the plan): **dnsx moves to ACTIVE recon** —
it resolves target DNS, which sends packets, so it cannot sit in the
zero-packet passive phase.

---

## 5. Approved plan (7 phases) — `~/.claude/plans/cozy-swinging-squid.md`

1. **Zone B tool inventory** — new allowlist templates for all ACTIVE RECON /
   EXPLOIT / VERIFY tools; Dockerfile + entrypoint extension (fix nuclei
   mismatch); wire recon_active (multi-tool plan), exploit build_argv,
   verify probes; new placeholders `{depth} {port} {hostport} {token} {term}`;
   entrypoint↔host sync test.
2. **Passive recon expansion** — host-side API sources (Shodan, Censys, OTX,
   RDAP/WHOIS, RIPEstat ASN/BGP) through the Zone-A bounded fetch; sandbox
   passive tools (subfinder/amass/assetfinder) when the sandbox exists;
   API keys in config + wizard.
3. **Hypothesis enrichment** — `purple/enrichment.py`: NVD (reuse
   `copilot/cve.py`), CPE, KEV (CISA catalog), EPSS (FIRST API), ExploitDB
   (searchsploit in sandbox); cached in `system_knowledge`; enrichment
   failures never fail the state.
4. **POST_EXPLOIT subagent** — linpeas, pspy, linux-exploit-suggester + baked
   enum scripts; evidence collection only (no destructive "controlled
   impact"); separate approval gate. Honest limitation: no current tool
   yields a shell, so this state is wired-but-dormant.
5. **Blue team scanners** — `kryonsec purple --code <path>`; read-only bind
   mount `/code` in the sandbox; semgrep/bandit/gitleaks/trivy/checkov/
   hadolint/kube-bench run pre-LLM; results fed into the blue-team prompt;
   Pydantic schema gains cwe/owasp/attack fields.
6. **Report enrichment** — CVE/KEV/EPSS/CPE table, CWE/OWASP/ATT&CK tags,
   evidence normalizer (strip ANSI, dedupe findings), pure-Python CVSS 3.1
   base-score calculator.
7. **Record, tests, docs** — `docs/TOOL-EXPANSION-2026-09-13.md` (the record
   doc, created), CHANGELOG, README tool tables, tests for every new layer.

---

## 6. Implementation status when the session stopped

**The user stopped implementation mid-Phase-1 to close the session.**
Files changed (3):

| File | Change |
|------|--------|
| `src/kryonsec/purple/allowlist.py` | **Fully rewritten** (Phase 1a). Templates split into `PASSIVE_TOOL_TEMPLATES`, `ACTIVE_RECON_TEMPLATES`, `EXPLOIT_TEMPLATES`, `VERIFY_TEMPLATES`, `POST_EXPLOIT_TEMPLATES`; `EXPLOIT_ALLOWLIST_TEMPLATES` kept as the union (back-compat). New placeholders `{depth} {port} {hostport} {token} {term}`. Generalized template compiler (embedded `{…}` segments in literals). All original 8 exploit templates unchanged. |
| `containers/sandbox/entrypoint.sh` | **Rewritten** (Phase 1b, partial): full `ALLOWED_TOOLS` covering every host-allowlisted tool incl. baked `/opt/kryonsec/*.py` scripts and blue-team analyzers. Fixes the nuclei mismatch. |
| `docs/TOOL-EXPANSION-2026-09-13.md` | **Created** (the record doc; Phase 1 status says "in progress" — it is now stopped, see below). |

**NOT done (the rest of Phase 1 and all later phases):**
- `containers/sandbox/Dockerfile.kali` — not yet extended (new packages,
  GitHub tools, baked `/opt/kryonsec/` scripts not yet written).
- `purple/recon_active.py`, `purple/exploit.py` (`build_argv`), `purple/verify.py`
  — not yet wired to the new tools; they still use the old tool set only.
- `purple/runner.py` STATE_INFO and `templates/hypothesize.jinja` tool list —
  not yet updated.
- Phases 2–7 — untouched.
- **Tests were never run after the allowlist rewrite.** The rewrite is
  designed to be backward compatible (all old templates identical, union
  under the old name), but that is unverified. Run `pytest` first thing.

**To resume:** start from the approved plan (`~/.claude/plans/
cozy-swinging-squid.md`), Phase 1b (Dockerfile + scripts), then 1c (wire the
states), then Phases 2–7 in order. Update `docs/TOOL-EXPANSION-2026-09-13.md`
as each phase lands, and run the full test suite before committing.

---

## 7. Other session facts

- Git state at start: branch `main`, only untracked `.claude/`. Nothing was
  committed this session.
- Environment notes: dev machine is Windows 11; PATH `python` is 3.14 without
  pytest; the project's tests run under Python 3.12 (per `.pyc` files). A
  working interpreter with pytest + deps: `C:\Users\gonch\AppData\Local\
Programs\Python\Python313\python.exe` (pytest availability unverified).
- The command-safety classifier was temporarily unavailable near the end,
  which is one reason the test suite was not run.
