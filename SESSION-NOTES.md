# Kryonsec — Session Handoff Notes
**Date:** 2026-09-05 (end of session 10)
**Repo:** https://github.com/GonchiJoshnaVardhanReddy/kryon-sec (branch: main)
**Status: v1.1.0 — installer + setup wizard + tool-using agent + MCP.
241 tests green. Working tree: v1.1 changes committed? check `git status`.**

## FIRST THING NEXT SESSION: live-test v1.1 (all built, unit-tested, not live-run)
1. **Wizard live** (WSL, real terminal): `kryonsec setup` — pick OpenAI,
   paste key, see the model list, pick one, tool checkboxes, MCP menu,
   banner, config.toml written to ~/.kryonsec/config.toml
2. **Agent live**: start `kryonsec`, ask "read <some file> and summarize" —
   the agent should call file_read (approval prompt if outside workspace),
   print the `> using file_read(...)` line, then answer using the content
3. **LTM live**: tell it something durable ("I work mainly with PHP apps"),
   restart, ask "what do you remember about me" — the fact should be recalled
4. **Installer live**: in a FRESH WSL home (or after moving ~/.kryonsec),
   run the curl one-liner from the README

## Session 10 (v1.1) additions
- **Config (config.py):** ~/.kryonsec/config.toml is THE config source
  (hand-rolled TOML writer + tomllib reader; [[mcp.servers]] array-of-tables,
  env dicts stored as JSON strings). .env loading REMOVED — env vars still
  override TOML. `load_config()` is the app entry; `kryonsec setup` /
  first-run auto-launch writes it (chmod 600 where supported).
- **Setup wizard (wizard.py):** provider → API key (live-tested, retry/abort)
  → model list (OpenAI /v1/models filtered to chat models, sorted newest
  first; Ollama /api/tags) → tool checkboxes → MCP presets + custom →
  banner + Rich summary table. prompt_toolkit dialogs on a tty, numbered
  plain-input fallback otherwise (fully scriptable in tests).
- **Agent loop (copilot/agent.py):** real LLM function-calling for the
  copilot. litellm.completion(tools=...), dispatch table (only registered
  tools exist — unknown names return an error message to the LLM),
  8-round cap with forced text wrap-up, required-arg validation, output
  bounding. Chat falls back to plain chat() if the model can't do tools.
- **FileTools (copilot/tools.py):** writes outside the workspace are now
  APPROVAL-GATED (was: blocked). ApprovalRequest gained action read/write.
  Params renamed path/content to match tool schemas.
- **MCP (copilot/mcp_tools.py):** stdio servers from config; tools become
  `mcp_*` agent tools; lazy `mcp` import; dead server = skipped, never
  blocks chat. mcp>=1.0 is now a hard dependency.
- **LTM:** fact recall into the system prompt (GeneralUserLtm category
  "fact") + best-effort extraction after each exchange (silent failures).
- **Installer (install.sh):** py3.11+ check → ~/.kryonsec/venv → pip install
  git+repo → idempotent PATH in .bashrc → runs wizard. curl one-liner in
  README.
- **System prompt rewritten** for the tool-using agent (no more "you have
  NO shell access" — now it HAS file tools and must handle denials).

## Gotchas found while building (fixed)
- pytest collects `test_*` functions from SRC modules too — the wizard's
  key check is named check_openai_key, not test_openai_key
- litellm fetches a remote model cost map on import (SSL timeout adds ~60s
  to the suite when offline) — harmless, known slowness
- .env removal broke test_llm_routing (key now set explicitly in fixture)

## Session 9: TUI live-tested (all pass)
The checklist from session 8 is done — all four checks passed live in WSL:
1. `exit` quits cleanly ✅
2. Shift+Tab flips `[COPILOT]>` <-> `[PURPLE]>` ✅ (prompt repaints with notice)
3. Ctrl+C = clean bye, no traceback ✅
4. Up-arrow history + chat + /search all work ✅

Session 9 fixes:
- **Non-tty fallback (tui.py):** piped stdin/stdout (e.g. `wsl -e bash -c`) now
  falls back to plain input() instead of prompt_toolkit warning + instant EOF.
- **LLM skip log (llm.py):** "LLM (skipped) failed" read like a model named
  "skipped" — now says "local model unavailable; using hosted fallback X".
- **Wikipedia snippets (websearch.py):** the API prefixes each snippet with
  the (bolded) article title, so results displayed the title twice — stripped.

## Session 8 additions
- **TUI (spec §5.1):** `src/kryonsec/tui.py` — prompt_toolkit input
  (already a dependency). Shift+Tab toggles copilot <-> purple (prompt
  repaints, typed text survives); /mode shares the same set_mode logic;
  input history saved to ~/.kryonsec/chat_history (up-arrow, Ctrl+R
  prefix search); Ctrl+C now exits cleanly (CancelledError was escaping
  the handler and printing a traceback). 7 tests in tests/test_tui.py.
- **Web search FIXED (live-verified in WSL):** the root cause was that
  DDG's html + lite endpoints AND Mojeek all serve bot-challenge pages
  to this network. Fix: search now tries 5 sources in order until one
  answers — DDG html, DDG lite (POST), Mojeek, **DDG Instant Answer
  JSON API** (api.duckduckgo.com — works here), **Wikipedia search API**
  (keyless JSON, covers any query). DDG topic redirect URLs
  (duckduckgo.com/<Topic>) expand to Wikipedia article URLs.
- **`exit` / `quit` (plain words) now leave the chat** — previously they
  went to the LLM.
- README polished for v1.0 (both modes, commands, safety rules, status).
- Chat loop now calls `init_db(cfg, include_purple=False)` at startup —
  no more "no such table" warnings on first run.

## The complete engine (live-verified, engagement d8107d02)
Every state runs for real: passive recon (crt.sh+Wayback) -> active recon
(nmap in sandbox, services feed the LLM prompt) -> LLM hypotheses ->
HUMAN_REVIEW (y/n) -> EXPLOIT (sqlmap+curl in sandbox) -> VERIFY
(independent curl boolean probes: AND 1=1 vs AND 1=2) -> BLUE_TEAM ->
REPORT. Final result: H3/H4 confirmed by sqlmap AND verified by the
independent probe; 5 other runs honestly "not confirmed".

## Session 7 additions
- **RECON_ACTIVE**: ReconActiveSubagent — one allowlisted nmap -sV scan
  in the sandbox; open ports -> service graph nodes -> hypothesize.jinja
  now shows live services (LLM sees the real tech stack).
- **VERIFY**: VerifySubagent — for each confirmed finding, curl probes
  `?id=1 AND 1=1` vs `?id=1 AND 1=2`; finding gets `verified: true`
  only when responses differ. Report shows "Double-checked: yes — a
  second tool re-tested it and agreed" (or the honest warning).
- **RetURL unwrap** in compose_url: LLMs wrap everything as
  `/Login.asp?RetURL=%2Freal%2Fpage` — the wrapper is deterministically
  unwrapped (double-unquoted) to test the real inner page. This fixed a
  full false-negative run (engagement 688364d0).
- **Verdict excerpt**: report's "tool's own words" now shows the actual
  "is vulnerable" line, not the sqlmap banner (first 500 chars was the
  banner).

## The evidence ladder (only claimed when the audit proves it)
suggestion (LLM) -> tested (exploit_attempt node) -> confirmed (tool's
own words contain a marker) -> verified (independent second tool agrees).

## REMAINING WORK
None of the planned features. Optional ideas for a future session:
- docker socket proxy (spec §8.2 — sandbox currently uses default
  bridge, noted in audit)
- POST_EXPLOIT stays stubbed by design (needs separate approval flow)
- PostgreSQL as system of record (currently SQLite — spec allows it as
  Profile-1 fallback)

## Environment facts
- Dev on Windows 11; engagement runs in WSL2 Ubuntu (`wsl`).
- WSL: Docker + gVisor runsc release-20260817.0 + kryonsec/sandbox image.
  GOTCHA: `runsc install` and hand-editing /etc/docker/daemon.json
  overwrite each other — re-run `sudo /usr/local/bin/runsc install` then
  restart docker if runsc vanishes.
- WSL python: `~/ksvenv` venv, `pip install -e .` from
  /mnt/c/Users/gonch/Desktop/kryonsec.
- OpenAI is the working provider (.env, git-ignored). Ollama wedged.
- crt.sh flaky (404/502 at times); Wayback reliable but slow (~15s).
- Known test-target facts: testasp.vulnweb.com SQLi lives in
  showthread.asp?id / showforum.asp?id (NOT ListProducts.asp — that's
  the testphp clone; Login.asp RetURL is a true negative).
- User's authorized targets: pakheartjournal.com + client sites
  (they said they have permission — don't re-flag).
- Bash tool on Windows often gets "classifier unavailable" errors;
  user runs commands via `! <command>` prefix in the session instead.

## LLM handoff lessons (all fixed deterministically in code)
1. LLM drops query strings -> seed `=1` when value empty.
2. LLM wraps real pages in RetURL=... -> unwrap (double-decode).
3. LLM proposes archive payloads as URLs -> prompt asks for clean URLs.
4. `quote()` double-encodes %-paths -> `%` in safe set.
Rule #1 of the spec proved itself: every LLM quirk got a rigid code
fix, never a prompt-only hope.
