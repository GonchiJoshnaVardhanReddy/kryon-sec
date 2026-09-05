# Kryonsec

**v1.1.0** — installer + setup wizard + tool-using agent.

A single-user CLI cybersecurity platform with two modes:

- **Mode A — Copilot:** a real tool-using agent (LLM function-calling) — it
  can read/write files anywhere (approval-gated outside the workspace),
  search the web, look up CVEs, and call MCP servers. Works on WSL,
  Linux, and macOS.
- **Mode B — Purple Team:** deterministic 10-state penetration testing
  engine with a tamper-evident audit chain. Requires Linux + Docker + gVisor
  (Profile 2; WSL2 works).

Design-of-record: [`kryonsec-v2.1.1-dual-mode-architecture.md`](kryonsec-v2.1.1-dual-mode-architecture.md)

## Install (WSL / Linux / macOS)

One command:

```bash
curl -fsSL https://raw.githubusercontent.com/GonchiJoshnaVardhanReddy/kryon-sec/main/install.sh | bash
```

It checks Python 3.11+, creates `~/.kryonsec/venv`, installs kryonsec,
adds it to PATH, and starts the **setup wizard**:

1. pick your LLM provider — OpenAI or Ollama
2. OpenAI: paste your API key → it is tested → pick a model from the list
   (most recent first). Ollama: pick from your pulled models
3. pick the built-in tools (space to select, enter to continue)
4. pick MCP servers (presets or add your own)
5. a banner + summary of everything you chose

The wizard writes `~/.kryonsec/config.toml` — that file holds your API
key, so it is written with owner-only permissions. Re-run anytime with
`kryonsec setup`; the first run without a config starts the wizard
automatically. Environment variables (`OPENAI_API_KEY`, `DATABASE_URL`,
`OLLAMA_HOST`) still override the file for power users.

## Copilot mode

```bash
kryonsec                  # start the chat
kryonsec doctor           # preflight checks
kryonsec setup            # re-run the wizard
```

| Command | What it does |
|---|---|
| *(just type)* | agent chat — the LLM decides when to use tools |
| `/cve CVE-2024-1234` | CVE lookup from NVD, cached locally for offline use |
| `/search <query>` | web search — results go into chat context |
| `/read <path>`, `/ls <path>` | read files / list dirs (approval-gated outside the workspace) |
| `/write <path>` | write a file (approval-gated outside the workspace) |
| `/mode` | switch between copilot and purple mode (or Shift+Tab) |
| `/quit` (or `exit`) | leave |

The agent itself can call `file_read`, `list_dir`, `file_write`,
`web_search`, and `cve_lookup` on its own when that helps the answer —
only the tools you enabled in setup, and every file action outside
`~/kryonsec/workspace` asks you first. It remembers durable facts about
you (long-term memory) and compacts long chats with secrets redacted.

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

Kryonsec routes through LiteLLM with a fallback chain, configured by the
setup wizard:

1. **Ollama (local, preferred):** `ollama serve` + `ollama pull llama3.1`
2. **OpenAI:** API key from the wizard / `OPENAI_API_KEY` (third-party —
   never used for compaction when secrets are present; those always
   route locally)

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
pytest
```

Dev note: since v1.1 config comes from `~/.kryonsec/config.toml` (the old
`.env` loading is gone). Run `kryonsec setup` once, or export
`OPENAI_API_KEY` for a quick start.

## Status

| Component | State |
|---|---|
| v2.1.1 spec | done |
| Storage layer (SQLAlchemy) | done |
| Installer (curl one-liner) + setup wizard | done |
| Config file (~/.kryonsec/config.toml) | done |
| Copilot agent loop (LLM function-calling) | done |
| Built-in agent tools (read/list/write, web search, CVE) | done |
| MCP server integration | done |
| Long-term memory (fact recall + extraction) | done |
| TUI (Shift+Tab mode toggle, history) | done — live-verified |
| Purple Team state machine (all 10 states) | done — live-verified on WSL2 |
| Audit chain | done |
| Tool allowlist + Kali sandbox (Docker/gVisor) | done — live-verified |
| Evidence ladder (tested → confirmed → verified) | done — live-verified |
| POST_EXPLOIT | intentionally stubbed (needs separate approval flow) |
