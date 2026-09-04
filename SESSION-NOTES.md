# Kryonsec — Session Handoff Notes
**Date:** 2026-09-04
**Repo:** https://github.com/GonchiJoshnaVardhanReddy/kryon-sec (branch: main)
**Status:** ALL 5 TASKS DONE. Chat verified working end-to-end. 48 tests green.

## What this project is
Single-user CLI cybersecurity platform, two modes:
- **Mode A — Copilot:** chat assistant, CVE lookup, file tools. Works on Windows. ✅ WORKING
- **Mode B — Purple Team:** deterministic pentest engine. Needs Linux (WSL2/VM) + Docker + gVisor.

Design-of-record spec: `kryonsec-v2.1.1-dual-mode-architecture.md` (in repo, pushed).
Also read `CLAUDE.md` in the repo — it has the design rules and build order.

## Current state: ~60% done

### DONE (all committed and pushed — commit 22395d3 is latest)
- v2.1.1 merged spec (all errata fixes applied)
- Project scaffold: `pip install -e .`, `kryonsec --version`, `kryonsec doctor`
- Storage layer (SQLAlchemy; SQLite fallback locally, PostgreSQL when DATABASE_URL set)
- Copilot chat loop — VERIFIED WORKING (answers questions via OpenAI)
- Strix-style compaction with secret redaction/restore; secrets path is
  local-only by design (CompactionMustStayLocal error, spec §6.4)
- LLM routing: skips dead/wedged Ollama AND unpulled models (no 30s hangs)
- File tools with approval gates + workspace enforcement
- CVE lookup (local cache + NVD API)
- Purple Team state machine (11 states, deterministic), audit chain,
  tool allowlist (masscan excluded)
- `kryonsec purple --target X` (Profile-2 gated, blocked message on Windows)
- 48 tests passing
- Old broken OPENAI_API_KEY env var deleted; good key lives in `.env`
  (git-ignored, never pushed)

### REMAINING WORK (~40%)
1. **Purple Team subagents** (biggest piece, ~20%): passive recon (Zone A,
   host-side, zero packets to target), HYPOTHESIZE via Instructor/Pydantic,
   BLUE_TEAM, REPORT (Jinja2) — stubs in `src/kryonsec/purple/runner.py`
2. **Kali sandbox** (~15%): Dockerfile + gVisor per spec §8.5 — Linux/WSL2 only
3. **TUI** (~3%): Shift+Tab mode toggle (prompt_toolkit); currently slash commands
4. **Web search tool** (~2%): specced §3.7, not built

## How the user and I work together
- User is on Windows 11, Python 3.12. Prefers SIMPLE English, short questions.
- Push to GitHub after every update (user asked explicitly).
- Ollama is installed but WEDGED on this machine (listens on 11434, never
  answers). OpenAI via `.env` is the working provider.
- When the sandbox classifier blocks my shell (happened a lot this session),
  the user runs commands themselves and pastes output — that works well.

## Next session: start here
1. Read this file + CLAUDE.md + spec §4 (Purple Team).
2. Pick from REMAINING WORK above — subagents first is the natural order.
3. RECON_PASSIVE Zone A first (pure Python, no Docker needed — can run on
   Windows): crt.sh / waybackurls-style fetchers via urllib, results into
   stm_nodes, audit-logged. Then HYPOTHESIZE (needs Instructor + Pydantic).
4. Sandbox/Docker work requires WSL2 — ask the user to set that up when needed.
