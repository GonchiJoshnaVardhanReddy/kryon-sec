# Kryonsec

**v1.0.0** — first release.

A single-user CLI cybersecurity platform with two modes:

- **Mode A — Copilot:** conversational security assistant (chat, CVE lookup,
  scoped file ops, web search). Works on Windows, macOS, and Linux.
- **Mode B — Purple Team:** deterministic 10-state penetration testing
  engine with a tamper-evident audit chain. Requires Linux + Docker + gVisor
  (Profile 2; WSL2 works).

Design-of-record: [`kryonsec-v2.1.1-dual-mode-architecture.md`](kryonsec-v2.1.1-dual-mode-architecture.md)

## Quick start

```bash
pip install -e .          # from this repo
kryonsec                  # start the CLI (Copilot mode)
kryonsec doctor           # preflight checks
```

Set your LLM backend in `.env` (git-ignored):

```
OPENAI_API_KEY=sk-...     # or use local Ollama instead
```

## Copilot mode

| Command | What it does |
|---|---|
| *(just type)* | chat — answers security questions with full context |
| `/cve CVE-2024-1234` | CVE lookup from NVD, cached locally for offline use |
| `/search <query>` | web search — results go into chat context |
| `/read <path>`, `/ls <path>` | read files / list dirs (approval-gated outside the workspace) |
| `/write <path>` | write text to a file in the workspace |
| `/mode` | switch between copilot and purple mode |
| `/quit` (or `exit`) | leave |

Web search tries five keyless sources in order (DDG html/lite/API, Mojeek,
Wikipedia) so it works even when one search engine bot-challenges your
network. Results are cached for a day.

## Purple Team mode

One command runs a full engagement:

```bash
kryonsec purple --target your-authorized-target.com
```

Or switch inside the chat with `/mode`, then type a domain.

The engine walks 10 states — `RECON_PASSIVE → RECON_ACTIVE → HYPOTHESIZE →
HUMAN_REVIEW → EXPLOIT → VERIFY → BLUE_TEAM → REPORT → HALT` — with **no
LLM-driven transitions**: the orchestrator is plain Python, every tool call
is an argv list validated against an allowlist, and every step is appended
to a SHA256-chained audit log. In the sandbox (Docker + gVisor), sqlmap
tests the LLM's approved hypotheses; **VERIFIED** means an independent
second tool (curl boolean probes) agreed with the finding. The report
includes repeatable test steps in plain words so a human tester can
re-check every finding.

Prerequisites (Linux/WSL2 only — `kryonsec doctor` checks all of this):
Docker, the gVisor `runsc` runtime, and the pinned `kryonsec/sandbox`
image. Kryonsec refuses to run tool execution without them.

**Only run it against systems you are authorized to test.**

## LLM backends

Kryonsec routes through LiteLLM with a fallback chain:

1. **Ollama (local, preferred):** `ollama serve` + `ollama pull llama3.1`
2. **OpenAI:** set `OPENAI_API_KEY` (third-party — never used for
   compaction when secrets are present; those always route locally)

## Safety rules (v2.1.1)

- No LLM-driven state transitions; the orchestrator is plain Python
- Tool calls are argv lists validated against allowlists — never shell strings
- Secrets are redacted-and-tokenized before any LLM call (`«SECRET_n»`)
- RECON_PASSIVE sends zero packets to the target (host-side Zone A)
- Zone B (sandbox) egress is target-scope only; sandbox image pinned by digest
- No docker.sock in the app container (socket proxy + payload shim)
- Audit chain: append-only JSONL, SHA256-linked, canonical-JSON hashed
- Engagement data never leaves the machine — general mode sees only
  sanitized post-REPORT summaries

## Development

```bash
pip install -e ".[dev]"
pytest                     # 190 tests
```

## Status

| Component | State |
|---|---|
| v2.1.1 spec | done |
| Storage layer (SQLAlchemy) | done |
| Copilot chat loop + compaction | done |
| Secret redaction | done |
| CVE lookup + web search | done |
| Purple Team state machine (all 10 states) | done — live-verified on WSL2 |
| Audit chain | done |
| Tool allowlist + Kali sandbox (Docker/gVisor) | done — live-verified |
| Evidence ladder (tested → confirmed → verified) | done — live-verified |
| POST_EXPLOIT | intentionally stubbed (needs separate approval flow) |
