# Kryonsec — Session Handoff Notes
**Date:** 2026-09-05 (end of session 7)
**Repo:** https://github.com/GonchiJoshnaVardhanReddy/kryon-sec (branch: main)
**Status: ~98% complete. ALL 10 STATES HAVE REAL SUBAGENTS. Evidence
ladder complete: suggestion -> tested -> confirmed -> verified
(independent second tool). 172 tests green, live-verified.**
**Check `git status` first next session — commit + push if anything is pending.**

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

## REMAINING WORK (~2%)
1. **TUI** (~1%): Shift+Tab mode toggle (Copilot <-> Purple).
2. **Web search tool** (~1%): spec §3.7 (Copilot mode).
3. Optional polish: docker socket proxy (spec §8.2 — sandbox currently
   uses default bridge, noted in audit); POST_EXPLOIT stays stubbed by
   design (needs separate approval flow).

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
