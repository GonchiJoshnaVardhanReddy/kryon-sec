<div align="center">

<img src="docs/logo.png" alt="Kryonsec" width="220"/>

# Kryonsec

**A single-user CLI cybersecurity platform with two modes: an AI copilot and a deterministic purple-team engine.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.1.0-8e44ad)](https://github.com/GonchiJoshnaVardhanReddy/kryon-sec)
[![Tests](https://img.shields.io/badge/tests-276%20passing-brightgreen)](#development)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2%20%7C%20macOS%20%7C%20Windows%20(copilot)-lightgrey)](#requirements)

[Install](#install) · [Copilot mode](#mode-a--general-copilot) · [Purple Team mode](#mode-b--purple-team) · [Safety design](#safety-design) · [Configuration](#configuration-reference)

</div>

---

## Table of contents

1. [What is Kryonsec?](#what-is-kryonsec)
2. [Requirements](#requirements)
3. [Install](#install)
4. [First-run setup wizard](#first-run-setup-wizard)
5. [Mode A — General Copilot](#mode-a--general-copilot)
6. [Mode B — Purple Team](#mode-b--purple-team)
7. [Safety design](#safety-design)
8. [Configuration reference](#configuration-reference)
9. [Storage schema](#storage-schema)
10. [Project structure](#project-structure)
11. [Development](#development)
12. [Roadmap / status](#roadmap--status)

---

## What is Kryonsec?

Kryonsec is a **dual-mode security CLI for one operator** — you. It is not a framework
and not a multi-user SaaS. It is a tool you install on your machine, talk to in a
terminal, and — when you have written authorization — point at a target.

The two modes are deliberately built on opposite philosophies:

| | **Mode A — General Copilot** | **Mode B — Purple Team** |
|---|---|---|
| What it is | A conversational security assistant with real tools (LLM function-calling) | A penetration-testing engine with a fixed 10-state loop |
| Who decides | The LLM decides *when* to call tools | **Plain Python** decides every state transition — the LLM only proposes, never transitions |
| What it touches | Your files, the web, CVE databases, MCP servers | An authorized target, through a gVisor sandbox |
| Where it runs | Linux, WSL, macOS, Windows | **Linux/WSL2 only** — Docker + gVisor required, enforced by `kryonsec doctor` |
| Data visibility | Sanitized post-REPORT engagement summaries only — never raw evidence | Full engagement graph, evidence, and audit chain |

> **Design-of-record:** [`kryonsec-v2.1.1-dual-mode-architecture.md`](kryonsec-v2.1.1-dual-mode-architecture.md)
> is the authoritative spec. v2.1.0 and the fixes draft are kept in the repo for history.

The core principle that shapes everything else:

> **The LLM is creative, so the system around it must be rigid.**

No LLM-driven state transitions. Tool calls are argv lists, never shell strings.
Allowlists, not blocklists. Secrets never leave the machine by default.

---

## Requirements

| Component | Copilot (Mode A) | Purple Team (Mode B) |
|---|---|---|
| Python 3.11+ | ✅ | ✅ |
| Linux / WSL2 | optional | ✅ required (gVisor) |
| Docker | — | ✅ required |
| [gVisor](https://github.com/google/gvisor) `runsc` runtime | — | ✅ required |
| Pinned `kryonsec/sandbox` image | — | ✅ required (built by installer) |
| Ollama (local LLM) | optional (recommended) | optional (recommended) |
| OpenAI API key | optional | optional |
| PostgreSQL | optional (SQLite fallback) | optional (SQLite fallback in v1.1) |

`kryonsec doctor` checks all of this and refuses to start Purple Team if anything is missing.

---

## Install

### One command (WSL / Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/GonchiJoshnaVardhanReddy/kryon-sec/main/install.sh | bash
```

The installer:

1. Checks for Python 3.11+ (tries `python3.12`, `python3.11`, `python3`)
2. Creates a dedicated virtualenv at `~/.kryonsec/venv`
3. Installs kryonsec into it from GitHub
4. Adds `~/.kryonsec/venv/bin` to your `PATH` (in `.bashrc`, idempotent)
5. **Builds the Zone B sandbox image** when Docker is available (Purple Team)
6. Runs `kryonsec setup` — the first-run wizard

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/GonchiJoshnaVardhanReddy/kryon-sec/main/install.ps1 | iex
```

Windows gets Copilot mode only — Purple Team is gated behind a runtime check and
must never run on the Windows host. Use WSL2 for Mode B.

### From source (development)

```bash
git clone https://github.com/GonchiJoshnaVardhanReddy/kryon-sec.git
cd kryon-sec
pip install -e ".[dev]"
kryonsec setup
```

---

## First-run setup wizard

The first launch without a config starts the wizard automatically (re-run anytime
with `kryonsec setup`). It walks you through:

1. **Pick your LLM provider** — OpenAI or Ollama (local)
2. **Provider setup**
   - *OpenAI:* paste your API key → it is tested live → pick a model from the list (most recent first)
   - *Ollama:* pick from your already-pulled local models
3. **Pick the built-in agent tools** (space to select, enter to continue)
4. **Pick MCP servers** — presets or add your own (see [MCP integration](#mcp-integration))
5. **A summary screen** of everything you chose

The wizard writes `~/.kryonsec/config.toml` with **owner-only permissions** — that
file holds your API key. Environment variables (`OPENAI_API_KEY`, `DATABASE_URL`,
`OLLAMA_HOST`, `KRYONSEC_HOME`, `KRYONSEC_WORKSPACE`) still override the file for
power users and CI.

---

## Mode A — General Copilot

```bash
kryonsec                  # start the chat
kryonsec doctor           # preflight checks
kryonsec setup            # re-run the wizard
```

### The agent

The copilot is a real tool-using agent (LLM function-calling), not a chat wrapper.
It decides when to call tools, up to 8 tool rounds per answer, then must produce
text. You see every tool call as it happens:

```
[COPILOT]> is CVE-2024-3094 relevant to my nginx setup?
  └─ cve_lookup(cve_id=CVE-2024-3094)
  └─ file_read(path=/etc/nginx/nginx.conf)
Yes — here's what matters for your config...
```

Built-in tools the agent can call (only the ones you enabled in setup):

| Tool | What it does |
|---|---|
| `file_read` | read a file — **approval-gated** outside `~/kryonsec/workspace` |
| `file_write` | write a file — **approval-gated** outside the workspace |
| `list_dir` | list a directory — **approval-gated** outside the workspace |
| `web_search` | keyless multi-engine web search, results enter chat context |
| `cve_lookup` | NVD CVE lookup, cached locally for offline reuse |

Every file action outside the workspace shows a yellow approval panel — why the
agent wants the file, and Approve/Deny. **Deny is the default (Enter = Deny).**

### Slash commands

| Command | What it does |
|---|---|
| `/cve CVE-2024-1234` | CVE lookup from NVD, cached offline |
| `/search <query>` | web search — results go into context |
| `/read <path>` | read a file (approval-gated outside workspace) |
| `/ls <path>` | list a directory (approval-gated outside workspace) |
| `/write <path>` | write text to a file in the workspace |
| `/workspace` | show the workspace path |
| `/mode` | switch copilot ⇄ purple mode — or press **Shift+Tab** |
| `/help` | command reference |
| `/quit` (`exit`, `quit`, `q`) | leave — session is persisted |

### Memory

- **Session STM:** messages are kept and compacted when they exceed 80% of the
  token budget — compaction runs with secrets redacted, and a broken compaction
  model skips itself rather than killing your chat mid-turn.
- **Long-term memory:** after each exchange, a background pass extracts durable
  facts about you (role, preferences, ongoing projects) into `general_user_ltm`
  — best-effort by design; memory failure never breaks the chat.
- **Long-term memory is isolated:** the copilot can see *sanitized post-REPORT
  engagement summaries* only. It never sees raw evidence, credentials, or live
  engagement data (see [safety design](#safety-design)).

### Web search

`/search` (and the agent's `web_search` tool) tries five keyless sources in
order — DuckDuckGo html/lite/API, Mojeek, Wikipedia — so it keeps working when
one engine bot-challenges your network. Results are cached for a day.

### MCP integration

Copilot is an MCP client. During setup you can enable servers (stdio transport,
one subprocess per server, connected once per session — not per message):

| Preset | Command | Notes |
|---|---|---|
| `fetch` | `uvx mcp-server-fetch` | fetch web pages as clean text, no API key |
| `filesystem` | `npx -y @modelcontextprotocol/server-filesystem` | needs Node; wizard asks for the allowed directory |

You can also add any custom stdio MCP server (name + command + env). Every MCP
tool the server exposes becomes a tool the agent can call.

---

## Mode B — Purple Team

One command runs a full engagement:

```bash
kryonsec purple --target your-authorized-target.com
# or: kryonsec purple --target example.com --id my-engagement
```

Or switch inside the chat with `/mode` (or **Shift+Tab**), then type a domain.

> ⚠️ **Only run this against systems you are authorized to test.**

### The 10-state loop

The engine walks a fixed state machine — **no LLM-driven transitions, ever**:

| # | State | Agent | What it does | Zone |
|---|---|---|---|---|
| 1 | `INIT` | init | load config, validate scope | — |
| 2 | `RECON_PASSIVE` | passive-recon | third-party lookups — **zero packets to target** (crt.sh, Wayback) | A (host) |
| 3 | `RECON_ACTIVE` | active-recon | scan the target — nmap, httpx, wappalyzer, wafw00f, feroxbuster, nuclei | B (sandbox) |
| 4 | `HYPOTHESIZE` | hypothesizer (LLM) | **propose** vulnerability hypotheses from recon data — proposes only | — |
| 5 | `HUMAN_REVIEW` | operator (you) | **approve or reject each hypothesis** — blocking gate | — |
| 6 | `EXPLOIT` | exploit | execute **approved hypotheses only** — sqlmap, nuclei, ffuf, jwt_tool, dalfox, commix, ssrfmap | B (sandbox) |
| 7 | `POST_EXPLOIT` | post-exploit | enumerate shells — needs **separate approval** (currently stubbed) | B (sandbox) |
| 8 | `VERIFY` | verifier | **independently confirm** findings — curl, httpie, python, netcat, openssl | B (sandbox) |
| 9 | `BLUE_TEAM` | blue-team (LLM) | generate fixes and detection rules | — |
| 10 | `REPORT` | reporter | compile the engagement report (Jinja2) | — |
| — | `HALT` | — | terminal absorbing state | — |

Deterministic transition table (plain Python in `purple/orchestrator.py`):

- `HUMAN_REVIEW` with **zero approvals** → routes through `BLUE_TEAM` (v2.1.1 fix:
  rejection still produces defensive recommendations, never jumps straight to REPORT)
- `EXPLOIT` → `POST_EXPLOIT` only if a shell was obtained *and* post-exploit was
  separately approved; otherwise → `VERIFY`
- `REPORT` → `HALT`, always

A **budget tracker** (tokens / wall-clock / cost) halts the loop when exhausted —
the same guard that refuses to leave `INIT` when the Profile-2 prerequisites
(Linux + Docker + gVisor) are missing.

### The evidence ladder

Findings are never just "the scanner said so." Each climbs a three-rung ladder:

| Rung | Meaning |
|---|---|
| **tested** | a tool ran against the target |
| **confirmed** | the exploit tool reported the finding |
| **verified** | an **independent second tool** (e.g. curl boolean probes) agreed with the finding |

Only **verified** findings are reported as such. The generated report includes
repeatable test steps in plain words so a human tester can re-check every finding
by hand.

### Zones

- **Zone A (host):** passive recon runs host-side using only third-party APIs
  (crt.sh certificates, Wayback Machine archives). **Zero packets to the target.**
  API keys are injected per-call and never logged.
- **Zone B (sandbox):** all active tool execution happens inside a Kali-based
  Docker container under the **gVisor `runsc` runtime**, with a seccomp profile,
  egress limited to target scope, and a **non-root** user. The sandbox image is
  pinned by digest.

### The audit chain

Every step is appended to a **tamper-evident audit log**: append-only JSONL,
SHA256-chained records, hashes computed over canonical JSON (sorted keys, tight
separators) — the same serialization written to disk. The chain head hash is
printed at the end of every engagement and can be anchored periodically (WORM
object + stdout).

### End of engagement

The summary screen gives you a one-line verdict first (halted / verified findings /
possible-but-unverified / nothing confirmed), then the evidence sections:
subdomains found, hypotheses with confidence scores, tool runs with exit codes,
findings with their verified status, the audit chain head, and the report path
(`~/.kryonsec/engagements/<id>/report.md`).

If the sandbox isn't available, the engagement still runs — it stops after
passive recon, because Zone A works everywhere.

---

## Safety design

Ten safety layers from the v2.1.1 spec, all implemented and unit-tested:

1. **No LLM-driven state transitions** — the orchestrator is plain Python with a
   deterministic transition table.
2. **Allowlists, not blocklists** — ToolRunner validates every argv against
   per-tool templates; anything outside the template is rejected. E.g. `nmap`
   may only be `-Pn -sT -sV -sC --max-rate {rate} -p {ports} {target}`.
3. **argv lists, never shell strings** — tools receive container arguments, not
   shell-interpreted text. There is no `shell=True` anywhere in the tool path.
4. **Secrets never leave the machine by default** — secrets are
   redacted-and-tokenized (`«SECRET_n»`) before any LLM call; compaction with
   secrets present always routes to local Ollama, never a third-party API.
   Engagement data, credentials, and raw evidence are never sent to third-party LLMs.
5. **RECON_PASSIVE sends zero packets to the target** — host-side Zone A only.
6. **Zone B egress is target-scope only**, sandbox image pinned by digest.
7. **No docker.sock in the kryonsec container** — Docker access goes through a
   socket proxy with endpoint allowlisting.
8. **Audit chain** — append-only JSONL, SHA256-linked, canonical-JSON hashed.
9. **Purple Team is Linux-only** — `kryonsec doctor` checks Docker, the `runsc`
   runtime, and the pinned sandbox image, and refuses to start Mode B otherwise.
10. **Mode isolation** — general mode reads only sanitized post-REPORT summaries
    from `ltm_engagement_summaries`; live engagement data is invisible to it.

Plus, in Copilot mode: every file action outside the workspace requires explicit
approval (deny by default), and tool output is size-bounded
(`max_tool_output_chars`).

---

## Configuration reference

Config lives at `~/.kryonsec/config.toml` (override the directory with
`KRYONSEC_HOME`). Written by the wizard; hand-editable.

```toml
[llm]
provider = "openai"                  # "openai" | "ollama"
chat_model = "ollama/llama3.1"       # main copilot model
search_model = "gpt-4o-mini"         # fact-extraction / light calls
compaction_model = "gpt-4o-mini"     # chat compaction (local when secrets)
local_model = "ollama/llama3.1"      # fallback + secrets-present routing
openai_api_key = "sk-..."
ollama_host = "http://localhost:11434"

[session]
max_session_tokens = 16000
compaction_trigger_ratio = 0.8
compaction_keep_tokens = 8000
max_messages = 50

[limits]
max_tool_output_chars = 20000

[sandbox]
image = "kryonsec/sandbox:latest"    # or kryonsec/sandbox@sha256:<digest>

[tools]
enabled = ["file_read", "file_write", "web_search", "cve_lookup"]

[[mcp.servers]]
name = "fetch"
command = "uvx mcp-server-fetch"
env = "{}"
```

Environment variables (they win over TOML): `OPENAI_API_KEY`, `DATABASE_URL`,
`OLLAMA_HOST`, `KRYONSEC_HOME`, `KRYONSEC_WORKSPACE`, `KRYONSEC_SANDBOX_IMAGE`.

### LLM backends

All LLM calls route through **LiteLLM** with a fallback chain:

1. **Ollama (local, preferred):** `ollama serve` + `ollama pull llama3.1` — nothing leaves your machine
2. **OpenAI:** API key from the wizard or `OPENAI_API_KEY` — used for chat and
   light analysis, but **never** for compaction when secrets are present (those
   calls always route locally)

---

## Storage schema

SQLAlchemy models (`src/kryonsec/storage/models.py`). PostgreSQL via `DATABASE_URL`
is the system of record; without it, kryonsec falls back to an embedded SQLite DB
(`~/.kryonsec/kryonsec.db`) for Copilot-mode memory.

| Table | Mode | Purpose |
|---|---|---|
| `general_sessions` | A | persisted chat sessions |
| `general_user_ltm` | A | long-term facts + preferences about the user |
| `system_knowledge` | A | system-level knowledge |
| `stm_nodes` | B | engagement graph nodes (subdomains, hypotheses, attempts, findings) |
| `ltm_target_profiles` | B | per-target knowledge across engagements |
| `ltm_engagement_summaries` | B | sanitized summaries — the only engagement data Mode A can read |
| `engagement_secret_map` | B | `«SECRET_n»` → secret mappings for an engagement |
| `checkpoints` | B | engagement checkpoints |

---

## Project structure

```
kryon-sec/
├── install.sh / install.ps1          # one-line installers (bash + PowerShell)
├── pyproject.toml                    # deps: litellm, pydantic, sqlalchemy,
│                                     #       prompt_toolkit, jinja2, rich, mcp
├── kryonsec-v2.1.1-dual-mode-architecture.md   # design-of-record spec
├── docs/
│   └── logo.png
├── containers/sandbox/
│   ├── Dockerfile.kali               # pinned Kali base, tool install w/ SHA256
│   │                                 #   verification, non-root user
│   └── entrypoint.sh                 # argv-only tool execution + JSON output
├── src/kryonsec/
│   ├── cli.py                        # CLI entry: chat loop, purple runner
│   ├── containers/
│   │   └── kryonsec-seccomp.json     # seccomp profile for Zone B
│   ├── config.py                     # TOML config (read/write, env overrides)
│   ├── doctor.py                     # preflight checks
│   ├── wizard.py                     # first-run setup wizard
│   ├── tui.py                        # prompt_toolkit input, Shift+Tab toggle
│   ├── status.py                     # spinner/status line
│   ├── llm.py                        # LiteLLM routing + fallback chain
│   ├── secrets.py                    # detect / redact («SECRET_n») / restore
│   ├── copilot/                      # ---- Mode A ----
│   │   ├── agent.py                  #   tool-calling agent loop (8-round cap)
│   │   ├── session.py                #   session STM + compaction
│   │   ├── tools.py                  #   file tools + approval gate
│   │   ├── cve.py                    #   NVD lookup w/ offline cache
│   │   ├── websearch.py              #   5-source keyless search
│   │   └── mcp_tools.py              #   MCP client (stdio, one process/server)
│   ├── purple/                       # ---- Mode B ----
│   │   ├── orchestrator.py           #   10-state loop, budget guard, HALT
│   │   ├── runner.py                 #   engagement runner + state registry
│   │   ├── zonea.py                  #   passive recon (crt.sh, Wayback)
│   │   ├── recon_active.py           #   active recon (sandbox tools)
│   │   ├── hypothesize.py            #   LLM hypothesis proposals
│   │   ├── human_review.py           #   blocking approval gate
│   │   ├── exploit.py                #   approved-hypothesis execution
│   │   ├── verify.py                 #   independent verification
│   │   ├── blue_team.py              #   fixes + detection rules
│   │   ├── report.py                 #   Jinja2 report generation
│   │   ├── allowlist.py              #   per-tool argv templates
│   │   ├── audit.py                  #   SHA256-chained JSONL audit log
│   │   └── sandbox.py                #   Zone B gVisor container driver
│   ├── storage/                      # SQLAlchemy models + db session layer
│   └── templates/                    # Jinja2: system_prompt, hypothesize,
│                                     #   blue_team, report
└── tests/                            # 26 files, 276 tests
```

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

- **Python 3.11+**, type hints everywhere, **Pydantic v2** for structured data
- LLM calls go through **LiteLLM only** (`litellm.completion`)
- Database access through a thin repository layer (`kryonsec/storage/`)
- Prompts and reports are **Jinja2 templates** in `kryonsec/templates/`
- **Every safety layer has at least one unit test** — 276 tests across 26 files
  covering the audit chain, allowlist, secrets redaction, orchestrator
  transitions, compaction, sandbox, TUI, wizard, and more

Optional extras: `pip install -e ".[postgres]"` for the PostgreSQL driver
(`psycopg[binary]`).

Dev note: since v1.1 config comes from `~/.kryonsec/config.toml` (the old `.env`
loading is gone). Run `kryonsec setup` once, or export `OPENAI_API_KEY` for a
quick start.

---

## Roadmap / status

| Component | State |
|---|---|
| v2.1.1 spec | ✅ done |
| Storage layer (SQLAlchemy) | ✅ done |
| Installer (curl one-liner) + setup wizard | ✅ done |
| Config file (`~/.kryonsec/config.toml`) | ✅ done |
| Copilot agent loop (LLM function-calling) | ✅ done |
| Built-in agent tools (read/list/write, web search, CVE) | ✅ done |
| MCP server integration | ✅ done |
| Long-term memory (fact recall + extraction) | ✅ done |
| TUI (Shift+Tab mode toggle, history) | ✅ done — live-verified |
| Purple Team state machine (all 10 states) | ✅ done — live-verified on WSL2 |
| Audit chain | ✅ done |
| Tool allowlist + Kali sandbox (Docker/gVisor) | ✅ done — live-verified |
| Evidence ladder (tested → confirmed → verified) | ✅ done — live-verified |
| POST_EXPLOIT | ⛔ intentionally stubbed — needs a separate approval flow |

---

<div align="center">

**Kryonsec is built for authorized security testing only.**
You are responsible for having written permission before pointing Purple Team at any target.

</div>
