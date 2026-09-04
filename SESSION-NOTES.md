# Kryonsec — Session Handoff Notes
**Date:** 2026-09-04 (end of session 4)
**Repo:** https://github.com/GonchiJoshnaVardhanReddy/kryon-sec (branch: main)
**Status:** WSL2 sandbox stack WORKING (Docker + gVisor verified with a real
gVisor container run). Zone B container files + image probe written.
**Check `git status` first next session — commit + push if anything is pending.**

## Session 4 summary (what happened)
- User's WSL2 Ubuntu: runsc registered but `docker run --runtime=runsc` failed
  with "cannot run with network enabled in root network namespace".
- Root cause: Ubuntu's apt runsc package is from **2023** (0.0~20230807) — old.
  The gVisor apt repo URL in these notes also 404s (old releases are deleted).
- **FIX that worked:** direct download of the latest runsc binary:
  ```bash
  ARCH=$(uname -m)
  curl -o runsc https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}/runsc
  chmod +x runsc && sudo mv runsc /usr/local/bin/runsc
  sudo /usr/local/bin/runsc install && sudo systemctl restart docker
  ```
  → runsc **release-20260817.0**, and `docker run --rm --runtime=runsc
  hello-world` prints "Hello from Docker!" ✅ (works with network and --network=none).
- GOTCHA: `runsc install` and manually writing `/etc/docker/daemon.json`
  OVERWRITE each other. If runsc vanishes from `docker info`, re-run
  `sudo /usr/local/bin/runsc install` and restart docker. Keep registry-mirrors
  and runsc in the same file — current daemon.json has both.
- New this session (code):
  - `containers/sandbox/Dockerfile.kali` + `entrypoint.sh` +
    `kryonsec-seccomp.json` (spec §8.5, exact content from the spec)
  - `runner.sandbox_available()` now probes: Linux → docker daemon → runsc →
    **pinned image present** (image via `cfg.sandbox_image`, env override
    `KRYONSEC_SANDBOX_IMAGE`). New helper `_image_present()`.
  - `kryonsec doctor` now also checks the sandbox image on Linux.
  - Tests for all failure paths in test_runner.py.
- **NOTE for HYPOTHESIZE:** session notes previously said next step is
  HYPOTHESIZE subagent — still true, it's sandbox-free and runs on Windows.

## NEXT STEPS (in order)
1. **Commit + push everything** (Zone A + sandbox stack work from sessions 3–4).
2. **Build the sandbox image in WSL2** (user runs this, from repo root in WSL):
   ```bash
   docker build -t kryonsec/sandbox -f containers/sandbox/Dockerfile.kali .
   docker run --rm --runtime=runsc kryonsec/sandbox nmap --version
   # then pin by digest:
   docker inspect --format '{{index .RepoDigests 0}}' kryonsec/sandbox
   # → set KRYONSEC_SANDBOX_IMAGE=kryonsec/sandbox@sha256:<digest> in .env
   ```
   (Kali apt may be slow/flaky from India — retry if needed; mirror.gcr.io
   is already set as Docker registry mirror.)
3. **HYPOTHESIZE subagent** (~8%): LLM proposes hypotheses, Pydantic schema via
   Instructor, orchestrator stays deterministic. Prompt in `templates/`.
   Needs `instructor` package added to pyproject.
4. **BLUE_TEAM + REPORT subagents** (~8%).
5. **RECON_ACTIVE / EXPLOIT / POST_EXPLOIT / VERIFY logic** — Zone B states
   can now actually execute once the image is built (KaliSandbox.spawn in spec
   §8.5: argv as container args, runsc runtime, resource limits, seccomp).
6. **TUI** (~3%): Shift+Tab mode toggle.
7. **Web search tool** (~2%): spec §3.7.

## What this project is
Single-user CLI cybersecurity platform, two modes:
- **Mode A — Copilot:** chat assistant, CVE lookup, file tools. Works on Windows. ✅ WORKING
- **Mode B — Purple Team:** deterministic pentest engine. Needs Linux (WSL2/VM) + Docker + gVisor.

Design-of-record spec: `kryonsec-v2.1.1-dual-mode-architecture.md` (in repo, pushed).
Also read `CLAUDE.md` in the repo — it has the design rules and build order.

## Current state: ~65% done

### DONE (committed through ced9ec8, plus new uncommitted Zone A work)
- v2.1.1 merged spec; scaffold (`pip install -e .`, `kryonsec doctor`)
- Storage layer (SQLAlchemy; SQLite fallback, PostgreSQL when DATABASE_URL set)
- Copilot chat working end-to-end via OpenAI; compaction + secret redaction;
  LLM routing that skips dead/wedged Ollama; file tools with approval gates;
  CVE lookup (NVD + cache)
- Purple Team state machine (11 states), audit chain (SHA256-chained JSONL),
  tool allowlist (argv templates, masscan excluded)
- **NEW this session — RECON_PASSIVE Zone A (all 75 tests green):**
  - `src/kryonsec/purple/zonea.py` — crt.sh subdomain discovery (certificate
    transparency, zero packets to target), Wayback paths, Zone A egress
    allowlist (ZoneAViolation on anything else), `normalize_target` /
    `validate_target` (rejects garbage, numeric TLDs like 999.999, URLs ok)
  - `src/kryonsec/purple/recon_passive.py` — EngagementGraph (in-memory STM,
    app-layer size_bytes per spec §4.5) + ReconPassiveSubagent (injectable
    fetchers, failed source never kills the state, every call audited)
  - `src/kryonsec/purple/runner.py` — REWRITTEN: two-tier gating. SANDBOX_FREE
    states {INIT, RECON_PASSIVE, HYPOTHESIZE, HUMAN_REVIEW} run on any OS;
    Zone B states return a HALT result with audited reason when no sandbox.
    `sandbox_available()` replaces profile2_available().
  - `kryonsec purple --target http://testasp.vulnweb.com/` live-verified on
    Windows: runs INIT → RECON_PASSIVE, halts at RECON_ACTIVE with audited
    "Zone B requires Linux" reason. Exactly per spec.

### REMAINING WORK (~35%)
1. **HYPOTHESIZE subagent** (~8%): LLM proposes hypotheses, Pydantic schema via
   Instructor, orchestrator stays deterministic. Prompt in `templates/`.
2. **BLUE_TEAM + REPORT subagents** (~8%): BLUE_TEAM reviews findings;
   REPORT renders via Jinja2 template, writes to engagements dir.
3. **RECON_ACTIVE / EXPLOIT / POST_EXPLOIT / VERIFY** (~5% on Windows):
   logic + allowlist entries; real execution needs the sandbox. Zone B states
   already HALT cleanly without it.
4. **Kali sandbox** (~10%): Dockerfile + gVisor (runsc) per spec §8.5 — WSL2.
   User HAS WSL. Setup steps are at the bottom of this file.
5. **TUI** (~3%): Shift+Tab mode toggle (prompt_toolkit); slash commands now.
6. **Web search tool** (~2%): spec §3.7.

## How the user and I work together
- Windows 11, Python 3.12. SIMPLE English, short questions, working software.
- **Push to GitHub after every update** (user asked explicitly).
- Ollama is WEDGED on this machine; OpenAI via `.env` is the working provider.
  `.env` is git-ignored — never push it.
- When the sandbox classifier blocks my shell (common this session), the user
  runs commands and pastes output — that works well.
- User's test command: `python -m pytest tests/ -q` in the project folder.

## Next session: start here
1. Read this file + CLAUDE.md + spec §4.
2. **Check `git status` first** — if Zone A work is uncommitted, commit+push it
   (commands at the bottom).
3. Then build **HYPOTHESIZE** (needs `instructor` package added to pyproject)
   — natural next step, runs on Windows (sandbox-free state).

## WSL2 + Docker + gVisor setup (DONE in session 4 — kept for reference)
Docker was already installed via the docker.com repo. gVisor runsc was
installed from Ubuntu apt but was a 2023 build (broken) — replaced with the
direct latest binary (commands at the top of this file). Verified working:
`docker info` lists runsc; `docker run --runtime=runsc hello-world` succeeds.

## If work is uncommitted, run this first (PowerShell, project folder)
```powershell
python -m pytest tests/ -q      # expect all green
git add -A
git commit -m "Zone B sandbox stack: WSL2 gVisor verified, sandbox image files, image probe in doctor/sandbox_available"
git push origin main
```
