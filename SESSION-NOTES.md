# Kryonsec — Session Handoff Notes
**Date:** 2026-09-04
**Repo:** https://github.com/GonchiJoshnaVardhanReddy/kryon-sec (branch: main)

## What this project is
Single-user CLI cybersecurity platform, two modes:
- **Mode A — Copilot:** chat assistant, CVE lookup, file tools. Works on Windows.
- **Mode B — Purple Team:** deterministic pentest engine. Needs Linux (WSL2/VM) + Docker + gVisor.

Design-of-record spec: `kryonsec-v2.1.1-dual-mode-architecture.md` (in repo, pushed).
Also read `CLAUDE.md` in the repo — it has the design rules and build order.

## Current state: ~60% done

### DONE (all pushed to GitHub)
- v2.1.1 merged spec (all errata fixes applied)
- Project scaffold: `pip install -e .` works, `kryonsec --version`, `kryonsec doctor`
- Storage layer (SQLAlchemy; SQLite fallback locally, PostgreSQL when DATABASE_URL set)
- Copilot chat loop, Strix-style compaction with secret redaction/restore
- File tools with approval gates + workspace enforcement
- CVE lookup (local cache + NVD API)
- Purple Team state machine (11 states, deterministic, HUMAN_REVIEW fix), audit chain,
  tool allowlist (masscan excluded)
- `kryonsec purple --target X` command (Profile-2 gated, prints blocked message on Windows)
- 45 tests passing (was 43, +2 LLM routing tests)

### IN PROGRESS — the "no response" bug (2 parts)
1. **API key problem (USER ACTION NEEDED):** Windows has the OLD broken
   `OPENAI_API_KEY` saved as a permanent environment variable (ends in `fxoA`).
   The NEW key is in `C:\Users\gonch\Desktop\kryonsec\.env` (correct, ends in `...wA`).
   The env var beats .env, so the old broken key is used. FIX: run in PowerShell:
   ```
   [Environment]::SetEnvironmentVariable("OPENAI_API_KEY", $null, "User")
   ```
   Then restart PowerShell. Or set it to the new key from .env instead of deleting.

2. **LLM routing bug (CODE FIX — HALF DONE):** `src/kryonsec/llm.py` `chat()` was
   fixed to skip a dead/hanging Ollama before calling it, BUT the fallback chain
   still retried Ollama (the failed test `test_ollama_probed_once_and_skipped_when_dead`
   shows `['ollama/llama3.1', 'gpt-4o-mini']` instead of `['gpt-4o-mini']`).
   The newest edit (uncommitted) reworks `chat()` with a `skip_local` flag and a
   planned `_ollama_model_ok()` helper that checks the model is actually pulled.
   **NOT FINISHED:** `_ollama_model_ok()` is referenced in the new `chat()` but
   DOES NOT EXIST YET. It must be written next. Design:
   - probe `GET {host}/api/tags` (timeout 2s), cache result per-process
   - `_ollama_model_ok(cfg, model)` = server up AND `model.split("/",1)[1]` in tags
   - Also: the last user log shows even `gpt-4o-mini` timed out at 30s then auth-failed;
     with the key fixed, `_complete` already sets `timeout=30, num_retries=0`.

### REMAINING WORK (after bug is fixed)
- Run tests, commit, push (user runs commands when my shell is blocked — the
  sandbox classifier had an outage all session; ask user to run
  `python -m pytest tests/ -q` and `git add -A; git commit; git push`)
- Purple Team subagents (passive recon Zone A, HYPOTHESIZE via Instructor/Pydantic,
  BLUE_TEAM, REPORT Jinja2) — currently stubs in `src/kryonsec/purple/runner.py`
- Kali sandbox Dockerfile + gVisor (Linux/WSL2 only) per spec §8.5
- TUI: Shift+Tab mode toggle (prompt_toolkit), currently slash commands only
- Web search tool (specced §3.7, not built)

## How the user and I work together
- User is on Windows 11, Python 3.12. Prefers SIMPLE English, short questions.
- Push to GitHub after every update (user asked explicitly).
- Ollama is installed but WEDGED on this machine (listens on 11434, doesn't
  answer). OpenAI is the practical provider. `OPENAI_API_KEY` in `.env` (new key).
- When my shell is blocked by the classifier outage, the user runs commands
  themselves and pastes output — that workflow works well.
- Tests currently: 1 failed (`test_ollama_probed_once_and_skipped_when_dead`
  — expected, it's testing the not-yet-finished fix), 45 passed.

## Next session: start here
1. Read this file + CLAUDE.md + the spec §6.4/§7.1.
2. Write `_ollama_model_ok()` in `src/kryonsec/llm.py`.
3. Fix the test (it patches `_ollama_ok`; may need updating to the new helper).
4. Ask user to run `python -m pytest tests/ -q` — all green → commit+push.
5. Ask user to delete the old env var (command above), then `kryonsec` → type
   a question → confirm the chat answers.
