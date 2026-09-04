# Kryonsec — Session Handoff Notes
**Date:** 2026-09-04 (end of session 5)
**Repo:** https://github.com/GonchiJoshnaVardhanReddy/kryon-sec (branch: main)
**Status: ~80% complete. Full loop live in WSL2: recon → hypotheses →
HUMAN_REVIEW (y/n) → blue-team advice → simple-English report file.
128 tests green, all pushed through 5e50f5c.**
**Check `git status` first next session — commit + push if anything is pending.**

## What works end-to-end (live-verified on testasp.vulnweb.com in WSL)
Run: `kryonsec purple --target testasp.vulnweb.com`
- RECON_PASSIVE: crt.sh + Wayback (two sources; each is flaky sometimes,
  together reliable). Zero packets to target. Retry/backoff built in.
- HYPOTHESIZE: real OpenAI call → 10 structured hypotheses (Pydantic;
  Instructor when installed, JSON-fallback otherwise).
- HUMAN_REVIEW: interactive y/n per hypothesis, decisions audited,
  strict parsing (anything but y/yes = no), silence = never consent.
- BLUE_TEAM: remediations + detection rules per hypothesis.
- REPORT: `~/.kryonsec/engagements/<id>/report.md` — simple English,
  truthful "no testing was done" until tools actually run.
- Progress display: every state prints agent + tools + zone.
- WSL venv for running: `source ~/ksvenv/bin/activate` (created session 5).

## REMAINING WORK (~20%)
1. **EXPLOIT execution — THE BIG ONE** (next step):
   - `KaliSandbox.spawn()` per spec §8.5: docker run --runtime=runsc
     <pinned-image> <tool argv>, resource limits, seccomp profile
     (containers/sandbox/kryonsec-seccomp.json), output bounded.
   - EXPLOIT subagent: for each APPROVED hypothesis, build argv from
     hypothesis tools (validated against purple/allowlist.py templates!),
     spawn, parse JSON output from entrypoint, store exploit_attempt
     + finding nodes in graph. Audit every spawn.
   - Sandbox exists and works: image pinned digest
     sha256:d91c139c33492f6c09ba41a48bb9c2f93d16efa9a43db37225f24e2661346246
     (in .env as KRYONSEC_SANDBOX_IMAGE).
   - Note: argv templates in allowlist.py are strict (exact arg counts);
     sqlmap template needs a URL — hypothesis target_asset is a PATH like
     /Login.asp, so compose full URL from the engagement target.
2. **RECON_ACTIVE**: nmap etc. in sandbox (same spawn machinery).
3. **VERIFY**: re-run findings independently (curl etc.).
4. **TUI** (~3%): Shift+Tab mode toggle.
5. **Web search tool** (~2%): spec §3.7.

## Environment facts
- Dev on Windows 11; engagement runs in WSL2 Ubuntu (`wsl`).
- WSL: Docker + gVisor runsc release-20260817.0 + kryonsec/sandbox image.
  GOTCHA: `runsc install` and hand-editing /etc/docker/daemon.json
  overwrite each other — re-run `sudo /usr/local/bin/runsc install` then
  restart docker if runsc vanishes. registry-mirrors + runsc both live
  in that file now.
- WSL python: `~/ksvenv` venv, `pip install -e .` from
  /mnt/c/Users/gonch/Desktop/kryonsec.
- OpenAI is the working provider (.env, git-ignored). Ollama wedged.
- crt.sh API is flaky (404 / non-JSON / slow at different times);
  Wayback CDX is slow (~15s) but reliable. Both have retries.
- User's authorized targets: pakheartjournal.com + client sites
  (they said they have permission — don't re-flag).
- Bash tool on Windows often gets "classifier unavailable" errors;
  user runs commands via `! <command>` prefix in the session instead.

## Session 5 history (for context)
Fixed WSL gVisor (2023 apt runsc was the bug — direct binary download
fixed it), built+pinned the Kali image, HUMAN_REVIEW, BLUE_TEAM, REPORT,
crt.sh query fix (no % wildcard — crt.sh rejects it), Wayback as second
passive source + paths as LLM evidence, live progress display,
simple-English report. 9 commits today, 128 tests.
