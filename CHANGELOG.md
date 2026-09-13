# Changelog

## v1.2.0 — Purple Team tool expansion (7 phases)

Full record per phase: `docs/TOOL-EXPANSION-2026-09-13.md`. Test suite:
**496 tests green** (was 321).

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
