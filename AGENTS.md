# Kryonsec — Project Instructions

## What this is
Kryonsec is a single-user CLI cybersecurity platform with two modes:

- **Mode A — General Copilot:** conversational security assistant (chat, CVE lookup,
  scoped file ops, web search). Works on Windows/macOS/Linux.
- **Mode B — Purple Team:** deterministic 10-state loop + terminal HALT penetration
  testing engine. Requires Linux + Docker + gVisor (WSL2 works).

The dev machines are **Omarchy / Arch Linux** (primary) and **Windows 11**
(Copilot mode only). Purple Team tool execution must never be attempted
on the Windows host — it is gated behind a `kryonsec doctor` runtime check.

## Authoritative documents
- `kryonsec-v2.1.1-dual-mode-architecture.md` — the merged, corrected spec
  (design-of-record; supersedes v2.1.0 draft)
- `kryonsec-v2.1-dual-mode-architecture.md` — original v2.1.0 (kept for history)
- `kryonsec-v2.1-fixes-draft.md` — errata that fed v2.1.1 (kept for history)

## Core design rules (never break these)
1. **The LLM is creative, so the system around it must be rigid.** No LLM-driven
   state transitions. The orchestrator is plain Python. Tool calls are argv lists,
   never shell strings.
2. **Allowlists, not blocklists.** ToolRunner validates argv against per-subagent
   templates; anything outside the template is rejected.
3. **PostgreSQL is the system of record** (schema in spec §10.1). SQLite is allowed
   only as the Profile-1 embedded fallback for Copilot-mode memory. Redis is
   ephemeral cache only. MinIO is evidence object storage.
4. **Secrets never leave the machine by default.** Compaction redacts/tokens
   secrets before any LLM call and routes to Ollama when secrets are present.
   Engagement data, credentials, and raw evidence are never sent to third-party LLMs.
5. **General mode cannot see live engagement data.** It reads only sanitized
   post-REPORT summaries from `ltm_engagement_summaries`.
6. **RECON_PASSIVE sends zero packets to the target.** Passive recon runs as
   host-side modules (Zone A: third-party APIs only). Zone B (sandbox) egress is
   target-scope only.
7. **No docker.sock in the kryonsec container.** Docker access goes through the
   socket proxy with endpoint allowlisting; sandbox image is pinned by digest.
8. **Audit chain:** append-only JSONL, SHA256 chained, hashes computed over
   canonical JSON (sorted keys, separators) — the same serialization that is
   written to disk. The head hash is displayed at engagement end (report +
   CLI) and patched into the report as its fingerprint; periodic WORM-object
   anchoring of the head is **planned, not implemented** — never describe it
   as done.
9. Purple Team is Linux-only. `kryonsec doctor` checks Docker, `runsc` runtime,
   pinned image, and refuses to start Mode B otherwise.
10. **Mode B tool execution is Docker-only.** Every Purple security-tool
   launch goes through `KaliSandbox.spawn` (`src/kryonsec/purple/sandbox.py`)
   — gVisor `runsc`, non-root, read-only rootfs, resource caps, and the
   spawn-time isolation guard that refuses to launch if any of those
   flags disappear. No host-side subprocess may run a security tool;
   sandbox unavailability fails closed (audited `zone_b_blocked` halt),
   never falls back to host execution. Zone A is fetch-only against its
   host allowlist. Policed by `tests/test_mode_b_isolation.py` — a new
   `subprocess` use under `purple/` fails that test and must be added to
   it consciously, never silently.
11. **MCP never reaches Mode B execution.** Mode A's MCP toolbox stays
   host-side. Remote MCP command-execution servers (HexStrike-HTTP style,
   or any "tool" endpoint that runs commands for you) must never be
   connected to Mode B: remote execution cannot be presented as
   Docker-contained execution. Any future MCP-to-Mode-B integration must
   pass the same Layer-2 argv allowlist and the sandbox boundary, with
   its own approval gate.

## Build order (agreed with user)
1. Merged v2.1.1 spec ✅ (in progress)
2. Project scaffold: pyproject, package layout, `kryonsec doctor`, storage layer
3. Copilot mode MVP (TUI, LiteLLM router Ollama/OpenAI, compaction, file tools)
4. Purple Team core (state machine, audit chain, ToolRunner) — code complete,
   execution gated on Linux/gVisor
5. Tests + README

## Code conventions
- Python 3.11+. Type hints everywhere. Pydantic v2 for structured data.
- LLM calls go through LiteLLM only (`litellm.completion`); structured outputs via
  Instructor where schemas are needed.
- Database access through a thin repository layer (`kryonsec/storage/`); schema
  changes go through migrations in `migrations/`, never ad-hoc DDL.
- Jinja2 templates for prompts and reports live in `kryonsec/templates/`.
- Tests: pytest. Every safety layer gets at least one unit test.

## Commands
- `pip install -e .` — install for development
- `kryonsec` — start the CLI
- `kryonsec doctor` — preflight checks (LLM providers, storage, and on Linux:
  Docker/gVisor/pinned sandbox image)
- `pytest` — run tests

## User preference
The user prefers communication in **simple, plain English**. Ask questions in
simple words before big decisions. Don't over-explain; deliver working software.

## Project memory (Obsidian vault)
A durable second project memory lives at
`~/Documents/Obsidian Vault/Kryonsec/` (Obsidian notes, NOT part of the app —
never a dependency, never committed to this repo).

**At the START of every task:**
1. Read `Memory/Current-State.md` and `Memory/Agent-Handoff.md` from the vault.
2. Read the vault notes relevant to the task (Architecture/, Security/, Tools/).
3. Reconcile against the real repo state (`git fetch`, `git log`, `git status`) —
   vault notes can go stale; the repository is the source of truth.

**At the END of every task:**
1. Update `Memory/Current-State.md` and `Memory/Agent-Handoff.md` with what
   changed, the commit SHA, test results, and the next task.
2. Append new architectural decisions to `Memory/Decision-Log.md`.
3. Update the affected Architecture/Security/Tools notes with a fresh
   `verified:` date and commit.
4. Log the session in `Logs/README.md`; save the task prompt in `Prompts/`.

**Vault rules:**
- Never commit the vault; never stage it in this repo.
- Never store credentials, tokens, real target evidence, engagement records,
  or client data in it — sanitized facts and file references only.
- Obsidian is developer workflow support only. It is not the Kryonsec
  engagement memory, not an MCP server, and not visible to the product.

## Current status pointer
Live status, test snapshots, and the release state (v1.3.11 preflight-ready,
NOT published) are maintained in the vault's `Memory/Current-State.md` and in
`CHANGELOG.md` / `README.md` here. Verify against the repo before trusting
either.
