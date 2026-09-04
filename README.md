# Kryonsec

**v1.0.0** — first release.

A single-user CLI cybersecurity platform with two modes:

- **Mode A — Copilot:** conversational security assistant (chat, CVE lookup,
  scoped file ops, web search). Works on Windows, macOS, and Linux.
- **Mode B — Purple Team:** deterministic 10-state-loop penetration testing
  engine. Requires Linux + Docker + gVisor (Profile 2).

Design-of-record: [`kryonsec-v2.1.1-dual-mode-architecture.md`](kryonsec-v2.1.1-dual-mode-architecture.md)

## Install

```bash
pip install -e .          # from this repo
kryonsec                  # start the CLI (Copilot mode)
kryonsec doctor           # preflight checks
```

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
- No docker.sock in the app container (socket proxy + payload shim)
- Audit chain: append-only JSONL, SHA256-linked, canonical-JSON hashed

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Status

| Component | State |
|---|---|
| v2.1.1 spec | done |
| Storage layer (SQLAlchemy) | done |
| Copilot chat loop + compaction | done |
| Secret redaction | done |
| Purple Team state machine | done (code) — execution gated on Linux/gVisor |
| Audit chain | done |
| Tool allowlist | done |
| Kali sandbox (Docker/gVisor) | spec only — Profile 2, Linux |
