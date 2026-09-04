# Kryonsec — Session Handoff Notes
**Date:** 2026-09-05 (end of session 6)
**Repo:** https://github.com/GonchiJoshnaVardhanReddy/kryon-sec (branch: main)
**Status: ~95% complete. EXPLOIT IS LIVE — the engine found 2 confirmed
SQL injection vulnerabilities on testasp.vulnweb.com by itself. 154 tests
green, pushed through a57471b.**
**Check `git status` first next session — commit + push if anything is pending.**

## The milestone (live-verified, engagement 5aceb7a9)
Full automated loop: passive recon → LLM hypotheses → HUMAN_REVIEW
(y/n) → sqlmap actually running in the gVisor sandbox → 2 CONFIRMED
findings (showforum.asp?id, showthread.asp?id, MSSQL backend) →
honest report with repeatable test steps + blue-team advice + audit chain.
CLI now prints "tool runs executed: N" with per-run confirmed verdicts
and "confirmed findings" at the end.

## The three bugs that mattered (all LLM→tool handoff, all fixed in code)
1. LLM dropped query strings → prompt demands full path WITH params +
   `compose_url` seeds `=1` when the value is empty (the big one — two
   false negatives were empty `id=`).
2. LLM proposed archive payloads as URLs → prompt asks for clean base
   URL, prefers DB-ish params (id, artist, cat) over redirect params
   (RetURL, next, url).
3. `quote()` double-encoded %-encoded archive paths → `%` in safe set.

## What works end-to-end
Run in WSL: `kryonsec purple --target testasp.vulnweb.com`
- Sandbox spawn: docker run --runtime=runsc (non-root, read-only rootfs,
  2g/2cpu, seccomp, 330s timeout) → entrypoint JSON → bounded output.
- EXPLOIT: approved-only, fixed argv templates (sqlmap/nmap/curl), host
  allowlist validated before every spawn, exploit_attempt + finding
  nodes, conservative confirmation markers ("is vulnerable", "injection
  point", "back-end DBMS") — never exit codes.
- Report: "How the testing was done" section — exact command, plain
  explanation, tool's own verdict words, safety reminder.
- crt.sh + Wayback recon, HUMAN_REVIEW, BLUE_TEAM all still solid.

## REMAINING WORK (~5%)
1. **RECON_ACTIVE**: nmap in sandbox (spawn machinery exists — build
   argv templates + wire a subagent, model on ExploitSubagent).
2. **VERIFY**: re-run confirmed findings with an independent tool
   (e.g. curl probe) — only then mark "verified" in report.
3. **TUI** (~2%): Shift+Tab mode toggle.
4. **Web search tool** (~2%): spec §3.7 (Copilot mode).

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

## Session 6 history (for context)
EXPLOIT built (KaliSandbox + ExploitSubagent + report/CLI wiring),
live-ran it, debugged the LLM→tool handoff (empty param values, archive
payloads, double-encoding), added curl template + repeatable-steps
report section. 4 commits. First confirmed findings in project history.
