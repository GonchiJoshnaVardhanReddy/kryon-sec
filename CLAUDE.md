# Kryonsec — Project Instructions

## What this is
Kryonsec is a single-user CLI cybersecurity platform with two modes:

- **Mode A — General Copilot:** conversational security assistant (chat, CVE lookup,
  scoped file ops, web search). Works on Windows/macOS/Linux.
- **Mode B — Purple Team:** deterministic 10-state loop + terminal HALT penetration
  testing engine. Requires Linux + Docker + gVisor (WSL2 works).

The dev machine is **Windows 11**. Purple Team tool execution must never be attempted
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
   written to disk. Head hash is anchored periodically (WORM object + stdout).
9. Purple Team is Linux-only. `kryonsec doctor` checks Docker, `runsc` runtime,
   pinned image, and refuses to start Mode B otherwise.

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
