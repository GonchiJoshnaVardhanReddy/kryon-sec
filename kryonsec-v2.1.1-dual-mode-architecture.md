# Kryonsec v2.1.1 — Dual-Mode Architecture Specification

**Version:** 2.1.1
**Date:** 2026-09-04
**Supersedes:** v2.1.0-draft (2026-09-03)
**Scope:** Single-user CLI cybersecurity platform with conversational copilot mode and deterministic purple-team engagement mode.
**Status:** Design-of-record.

**Changelog (v2.1.0 → v2.1.1):**
- §4.6/§10.1: JSONB primary keys replaced with SHA256 fingerprint hashes (pgcrypto).
- §4.5: `pg_column_size()` generated column replaced with app-layer `size_bytes`.
- §8.5: entrypoint fixed — argv passed as container args, real exit codes, jq dependency removed.
- §5/§8.2/§8.3: two execution zones introduced (Zone A host-side passive recon, Zone B sandbox). RECON_PASSIVE now functional.
- §8.5: seccomp allowlist widened to a workable set; inbound-listening syscalls removed.
- §8.6: docker.sock removed from the kryonsec container; socket proxy with endpoint allowlisting; image pinned by digest; rootless-Docker recommendation.
- §6.4 (new): secret redaction-and-tokenization during compaction; local-model routing when secrets present.
- §4.3: HUMAN_REVIEW rejection now routes through BLUE_TEAM before REPORT.
- §3.2: reworded — General mode may read sanitized engagement summaries only.
- §10.2: audit chain hashes canonical JSON; periodic external anchor; documented threat model.
- §11: deployment profiles (Profile 1 Copilot / Profile 2 full stack); Linux requirement for Purple Team stated honestly.
- Counts fixed everywhere: 10-state loop + terminal HALT; 10 safety layers.
- masscan removed from allowlist; nuclei templates baked into the image.
- §10.1: `check_stm_size()` trigger now actually attached; covering index added.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Mode A: General Copilot](#3-mode-a-general-copilot)
4. [Mode B: Purple Team](#4-mode-b-purple-team)
5. [Mode Switching](#5-mode-switching)
6. [Memory Architecture](#6-memory-architecture)
7. [LLM Layer](#7-llm-layer)
8. [Tool Layer](#8-tool-layer)
9. [Safety Boundaries](#9-safety-boundaries)
10. [Storage & Persistence](#10-storage--persistence)
11. [Deployment](#11-deployment)
12. [Observability](#12-observability)
13. [Testing Strategy](#13-testing-strategy)
14. [Quick Reference](#14-quick-reference)

---

## 1. Executive Summary

Kryonsec is a **single-user CLI cybersecurity platform** with two distinct operating modes, toggled via **Shift+Tab**:

- **Mode A — General Copilot:** A conversational cybersecurity assistant that answers questions, explains concepts, performs scoped file operations, and conducts lightweight research. Think of it as "Claude for cybersecurity" that lives in your terminal. Works on Windows, macOS, and Linux (Profile 1).

- **Mode B — Purple Team:** A deterministic, bounded, human-in-the-loop offensive security engine that runs structured penetration tests against authorized targets. This is not a chatbot — it is a state machine with a 10-state loop plus terminal HALT, mandatory approval gates, and append-only audit trails. Requires Linux (bare metal, VM, or WSL2) with Docker and gVisor (Profile 2).

**Core design philosophy:** The LLM is creative, so the system around it must be rigid. The general mode lets the LLM converse freely within bounded tools. The purple mode removes LLM control over state transitions entirely.

**Key influences:**
- **Strix** (usestrix/strix): Context compaction algorithm, MCP supervised-session pattern, tool output bounding, Jinja2 skill system
- **Kryonsec v2.0:** Deterministic state machine, PostgreSQL STM/LTM, safety layers, human-in-the-loop gates

---

## 2. High-Level Architecture

```
+-----------------------------------------------------------------------------+
|                              KRYONSEC CLI                                    |
|  $ kryonsec                                                                  |
|                                                                              |
|  +-------------------------+    Shift+Tab    +---------------------------+  |
|  |   MODE A: GENERAL       | <-------------> |   MODE B: PURPLE TEAM     |  |
|  |   (Copilot)             |                 |   (Engagement)            |  |
|  |                         |                 |                           |  |
|  |  - Conversational       |                 |  - 10-state loop +        |  |
|  |  - File read/write      |                 |    terminal HALT          |  |
|  |    (scoped)             |                 |  - Mandatory HITL gates   |  |
|  |  - Web search           |                 |  - Append-only audit      |  |
|  |  - Concept explanation  |                 |  - Sandboxed exploits     |  |
|  |  - CVE lookups          |                 |  - Compliance reports     |  |
|  |                         |                 |                           |  |
|  |  LLM: OpenAI / Ollama   |                 |  LLM: OpenAI / Ollama     |  |
|  |  Memory: Session + User |                 |  Memory: Engagement +     |  |
|  |  LTM                    |                 |    System LTM             |  |
|  +-------------------------+                 +---------------------------+  |
|                                                                              |
|  SHARED INFRASTRUCTURE (Profile 2)                                           |
|  +-- PostgreSQL (STM + LTM + checkpoints)  <- system of record              |
|  +-- Redis (ephemeral cache, rate limiting only)                            |
|  +-- MinIO (evidence object storage)                                        |
|  +-- LiteLLM (provider routing)                                             |
|  +-- Docker + gVisor (sandbox) via socket proxy                             |
|  +-- Append-only JSONL audit chain                                          |
+-----------------------------------------------------------------------------+
```

### Design Decisions

| Decision | Rationale |
|---|---|
| **Two deployment profiles** | Profile 1 (`pip install`) gives Copilot mode with embedded storage — works everywhere. Profile 2 adds the full Purple Team stack — Linux only. See §11. |
| **Two modes, one binary** | Users don't install two tools. Context from general mode (target URLs, stack info) can seed purple team engagement config. |
| **Shift+Tab toggle** | Terminal-native. No GUI framework needed. Non-intrusive during chat. |
| **Separate memory systems** | General chat must never leak into purple team audit trails. A casual "what's my password" chat should not appear in a compliance report. |
| **Deterministic purple team** | LLMs cannot be trusted with state transitions in offensive security. The orchestrator is a Python state machine with zero LLM involvement. |
| **Strix-inspired compaction** | Token-aware summarization with exact-value preservation (after secret redaction — see §6.4). Better than naive truncation or rigid node caps. |
| **PostgreSQL is the system of record** | One database to back up, one migration strategy. Redis is ephemeral cache only (never backed up). MinIO is object storage for evidence. Profile 1 may use embedded fallback storage for general-mode memory only — Purple Team requires PostgreSQL. |

---

## 3. Mode A: General Copilot

### 3.1 Purpose
A conversational cybersecurity assistant accessible via `kryonsec` CLI. It can:
- Answer cybersecurity questions in simple terms
- Explain CVEs, OWASP categories, attack chains
- Read files the user explicitly approves
- Write files to a designated workspace
- Search the web for CVE details, documentation, advisories
- Look up tool documentation and usage examples
- Maintain conversation context across sessions

### 3.2 What It CANNOT Do
- Execute shell commands (blocked entirely)
- Read files outside user-approved paths
- Write files outside `~/kryonsec/workspace/`
- Access **live** purple-team engagement data (STM, raw evidence, credentials) — blocked. General mode sees only **sanitized, post-REPORT** engagement summaries via `ltm_engagement_summaries` (read-only), as defined in §5.3.
- Run offensive tools (nmap, sqlmap, etc.)
- Make network requests to arbitrary URLs (only approved search APIs)

### 3.3 Architecture

```
User Input (terminal prompt)
    |
    v
Context Assembler
    +-- Session STM (last 20 messages + compaction summaries)
    +-- User LTM (preferences, frequently asked topics)
    +-- System LTM (CVE DB, tool docs, cybersecurity knowledge)
    +-- Approved file contents (if user dragged/dropped or approved)
    |
    v
LiteLLM Router (OpenAI / Ollama)
    |
    v
Response Parser
    +-- Plain text -> direct to user
    +-- File read request -> Approval Gate -> read -> include in context
    +-- File write request -> Approval Gate -> write to workspace
    +-- Web search request -> Search API -> include results in context
    |
    v
User Output
```

### 3.4 Session STM (Short-Term Memory)

**Scope:** One conversation session (from `kryonsec` start until exit or mode switch).

**Storage:** In-memory deque + `general_sessions` table.

**Compaction (Strix-inspired, with secret handling — see §6.4):**
```python
class GeneralSession:
    max_tokens: int = 16000  # ~75% of typical 20k context
    max_messages: int = 50

    async def maybe_compact(self):
        if self.token_count < self.max_tokens * 0.8:
            return

        # Split into head (old) and recent (keep verbatim)
        head, recent = self.split_at_token_budget(self.messages, keep_tokens=8000)

        # Redact secrets BEFORE any LLM call (§6.4)
        head, secret_map = redact_secrets(head)

        # Summarize head with security-aware prompt
        summary = await llm.summarize(
            model=compaction_model_for(head),  # routes to Ollama if secrets present
            messages=head,
            instructions=(
                "Be EXHAUSTIVE, not concise. Preserve exact values: "
                "URLs, file paths, CVE IDs, version numbers, commands. "
                "Secrets appear only as placeholders («SECRET_n»); copy them verbatim. "
                "Do not lose technical details. "
                "Enumerate every distinct item."
            )
        )

        # Restore real values in the checkpoint — local, no LLM
        summary = restore_secrets(summary, secret_map)

        self.messages = [CheckpointMessage(summary=summary)] + recent
```

**Why this matters:** A user might paste a 500-line config file, discuss 10 CVEs, and then ask "what was the first CVE I mentioned?" Naive truncation loses it. Strix-style compaction preserves exact values in the summary.

### 3.5 User LTM (Long-Term Memory)

**Scope:** Cross-session, per-user preferences and history.

```sql
CREATE TABLE general_user_ltm (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL DEFAULT 'default',
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value JSONB NOT NULL,
    last_accessed TIMESTAMPTZ DEFAULT NOW(),
    access_count INT DEFAULT 1,
    UNIQUE(user_id, category, key)
);
```

**Examples:**
- `("preference", "explain_mode", "simple")` — User prefers simple explanations
- `("topic_history", "SQLi", {"last_asked": "2026-09-01", "count": 5})` — Frequently asked topic
- `("file_reference", "~/projects/app/main.py", {"last_read": "2026-09-02"})` — Recently accessed files

**Retrieval:** When a session starts, load top-N preferences by `access_count`. When user asks a question, query `topic_history` for related past discussions.

### 3.6 System LTM

**Scope:** Global cybersecurity knowledge, not user-specific.

**Contents:**
- CVE database (cached from NVD API, updated weekly)
- OWASP Top 10 mappings
- Tool documentation summaries (nmap, sqlmap, nuclei, etc.)
- Common attack pattern descriptions
- Defensive technique catalog

**Update mechanism:**
```bash
kryonsec knowledge update  # Pulls latest CVEs, tool docs
```

### 3.7 Tool Registry (General Mode)

| Tool | Purpose | Approval Required |
|---|---|---|
| `read_file` | Read a file's contents | Yes (always) |
| `write_file` | Write to `~/kryonsec/workspace/` | Yes (if outside workspace) |
| `list_directory` | List files in a directory | Yes (if outside workspace) |
| `web_search` | Search web for CVE/docs | No (scoped to approved APIs) |
| `explain_concept` | Pure LLM, no tools | No |
| `lookup_cve` | Query local CVE DB | No |
| `lookup_tool_doc` | Query tool documentation | No |

**File Approval Gate:**
```
Agent wants to read: /etc/passwd
+-- Approval Required ----------------------------+
| File: /etc/passwd                               |
| Reason: Agent requested to read system file     |
|                                                 |
| [APPROVE ONCE] [APPROVE ALWAYS] [DENY]         |
+-------------------------------------------------+
```

**Workspace enforcement:**
- Reads outside `~/kryonsec/workspace/` require explicit approval
- Writes outside `~/kryonsec/workspace/` are **blocked entirely**
- Shell command execution is **blocked entirely**

### 3.8 Prompt System (Jinja2 Skills)

```
skills/
  general/
    base.jinja              # Core behavior, safety rules
    explain_simple.jinja    # "Explain like I'm 5" mode
    explain_technical.jinja # Deep technical mode
    cve_analysis.jinja      # CVE lookup and analysis
    tool_guide.jinja        # Tool usage examples
    file_assistant.jinja    # File read/write behavior
```

The prompt is assembled dynamically per §3.8 of v2.1.0 (unchanged).

---

## 4. Mode B: Purple Team

### 4.1 Purpose
Deterministic, bounded, human-in-the-loop offensive security testing. This is the 10-state loop (plus terminal HALT) from Kryonsec v2.0, refined with lessons from Strix.

### 4.2 The 10-State Loop + Terminal HALT

```
INIT -> RECON_PASSIVE -> RECON_ACTIVE -> HYPOTHESIZE -> HUMAN_REVIEW
  -> EXPLOIT -> [HITL GATE if shell] -> POST_EXPLOIT -> VERIFY
  -> BLUE_TEAM -> REPORT -> HALT
```

**HALT is the terminal (absorbing) state — it is not part of the loop.**

Execution zones (see §5 and §8.3): RECON_PASSIVE runs in **Zone A** (host-side, third-party APIs only, zero packets to target). All states from RECON_ACTIVE onward run tools in **Zone B** (Kali sandbox, target-scope egress only).

| State | Purpose | LLM Role | Tools | Zone |
|---|---|---|---|---|
| INIT | Load config, validate scope, legal consent | None | None | — |
| RECON_PASSIVE | 3rd-party recon (no packets to target) | Summarize, prioritize | dnsx, subfinder, crt.sh, shodan, censys, waybackurls, gau | **A** |
| RECON_ACTIVE | Active scanning (packets to target) | Prioritize, flag anomalies | nmap, httpx, wappalyzer, wafw00f, feroxbuster, nuclei (passive) | B |
| HYPOTHESIZE | Generate vulnerability hypotheses | Propose CVSS vectors, select tools | None (pure LLM) | — |
| HUMAN_REVIEW | Blocking approval of hypotheses | None | None | — |
| EXPLOIT | Execute approved hypotheses | Select tool from allowlist, parse output | sqlmap, nuclei (active), ffuf, jwt_tool, dalfox, commix, ssrfmap, etc. | B |
| POST_EXPLOIT | Shell enumeration (with approval) | Decide what to enumerate | pwncat, linpeas, bloodhound-python, mimikatz | B |
| VERIFY | Independently confirm findings | Generate PoC, compare responses | curl, httpie, python, netcat, openssl | B |
| BLUE_TEAM | Defensive recommendations | Generate fixes, detection rules | None (pure LLM) | — |
| REPORT | Compile final report | Synthesize into templates | None (Jinja2 templates) | — |
| HALT | Terminal state (absorbing) | None | None | — |

### 4.3 Orchestrator (Plain Python, No LLM)
```python
class PurpleOrchestrator:
    # 10 loop states + terminal HALT = 11 entries
    STATES = [
        "INIT", "RECON_PASSIVE", "RECON_ACTIVE", "HYPOTHESIZE",
        "HUMAN_REVIEW", "EXPLOIT", "POST_EXPLOIT", "VERIFY",
        "BLUE_TEAM", "REPORT", "HALT"
    ]

    def __init__(self, engagement_id: str, config: EngagementConfig):
        self.engagement_id = engagement_id
        self.config = config
        self.state = "INIT"
        self.graph = EngagementGraph(engagement_id)
        self.audit = AuditLog(engagement_id)
        self.checkpoint = CheckpointManager(engagement_id)
        self.budget = BudgetTracker(
            max_tokens=config.llm_budget.max_total_tokens,
            max_time_s=config.cost_config.max_time_s,
            max_cost_usd=config.llm_budget.max_cost_usd
        )

    def run(self):
        while self.state != "HALT":
            if self.budget.exhausted():
                self._halt("budget_exhausted")
                break

            self.checkpoint.save(self.state)
            subagent = self.load_subagent(self.state)

            try:
                result = subagent.run(
                    graph=self.graph,
                    config=self.config,
                    audit=self.audit,
                    budget=self.budget
                )
            except Exception as e:
                self._handle_subagent_crash(e)
                result = SubagentResult(status="failed")

            self.state = self._next_state(result)

        self._finalize()

    def _next_state(self, result: SubagentResult) -> str:
        # Deterministic transitions. LLM never decides.
        transitions = {
            "INIT": "RECON_PASSIVE",
            "RECON_PASSIVE": "RECON_ACTIVE",
            "RECON_ACTIVE": "HYPOTHESIZE",
            "HYPOTHESIZE": "HUMAN_REVIEW",
            # Rejection still produces defensive recommendations for the
            # rejected hypotheses — never jump straight to REPORT.
            "HUMAN_REVIEW": "EXPLOIT" if result.approved_count > 0 else "BLUE_TEAM",
            "EXPLOIT": "POST_EXPLOIT" if (result.shell_obtained and result.post_exploit_approved) else "VERIFY",
            "POST_EXPLOIT": "VERIFY",
            "VERIFY": "BLUE_TEAM",
            "BLUE_TEAM": "REPORT",
            "REPORT": "HALT",
        }
        return transitions.get(self.state, "HALT")
```

### 4.4 Human-in-the-Loop Gates

#### Gate 1: Legal Consent (Pre-INIT)
Unchanged from v2.1.0. Consent hash is the **genesis entry** in the audit chain.

#### Gate 2: HUMAN_REVIEW (Pre-Exploit)
Unchanged from v2.1.0: hypotheses displayed with description, target, CVSS (calculator output), exact dry-run command, risk level; [APPROVE] [REJECT] [MODIFY].

#### Gate 3: POST_EXPLOIT (Pre-Enumeration)
Unchanged from v2.1.0. Authorization token expires in 30 minutes.

### 4.5 STM (Engagement Graph)

PostgreSQL schema with size enforcement. **`size_bytes` is computed by the application layer** (the repository computes `len(json.dumps(properties).encode())` before insert) — PostgreSQL does not permit `pg_column_size()` in a `GENERATED` column because it is not `IMMUTABLE`.

```sql
CREATE TABLE stm_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID NOT NULL,
    subagent TEXT NOT NULL,
    node_type TEXT NOT NULL CHECK (node_type IN (
        'target', 'subdomain', 'ip', 'cert', 'service', 'tech', 'waf',
        'endpoint', 'hypothesis', 'exploit_attempt', 'finding', 'shell',
        'cred', 'lateral', 'evidence', 'remediation', 'defense_posture',
        'compliance_map', 'post_exploit_chain'
    )),
    label TEXT NOT NULL,
    properties JSONB,
    size_bytes INT NOT NULL CHECK (size_bytes >= 0),  -- set by the writer
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Covering index: keeps the size-check trigger O(log n)-ish
CREATE INDEX idx_stm_nodes_engagement_size
    ON stm_nodes (engagement_id) INCLUDE (size_bytes);
CREATE INDEX idx_nodes_engagement ON stm_nodes(engagement_id);

-- Size enforcement trigger (note: it is actually ATTACHED below —
-- v2.1.0 defined the function but never created the trigger)
CREATE OR REPLACE FUNCTION check_stm_size()
RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COALESCE(SUM(size_bytes), 0) FROM stm_nodes
        WHERE engagement_id = NEW.engagement_id) > 8388608 THEN
        RAISE EXCEPTION 'STM size limit exceeded for engagement %', NEW.engagement_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_stm_size_check
BEFORE INSERT OR UPDATE ON stm_nodes
FOR EACH ROW EXECUTE FUNCTION check_stm_size();
```

**Compaction at 80%:** When STM hits 6.4MB, a compressor pass summarizes old recon nodes into clusters, preserving exact values (Strix-style), with secret redaction per §6.4.

### 4.6 LTM (Purple Team)

Separate from general LTM. Stores cross-engagement learnings.

PostgreSQL does not allow `jsonb` columns in a primary key, so the
fingerprint is hashed. `jsonb_hash()` uses pgcrypto and is `IMMUTABLE`
and deterministic (JSONB normalizes key order, `jsonb_strip_nulls` removes
optional-members noise):

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION jsonb_hash(v JSONB)
RETURNS TEXT AS $$
    SELECT encode(digest(jsonb_strip_nulls(v)::text, 'sha256'), 'hex')
$$ LANGUAGE sql IMMUTABLE;

CREATE TABLE ltm_target_profiles (
    target_hash TEXT PRIMARY KEY,
    stack_fingerprint JSONB,
    last_engagement TIMESTAMPTZ,
    engagement_count INT DEFAULT 1
);

CREATE TABLE ltm_tool_efficacy (
    tool_name TEXT NOT NULL,
    stack_fingerprint JSONB NOT NULL,
    stack_fingerprint_hash TEXT GENERATED ALWAYS AS (jsonb_hash(stack_fingerprint)) STORED,
    success_rate DECIMAL(3,2),
    avg_time_seconds INT,
    last_used TIMESTAMPTZ,
    PRIMARY KEY (tool_name, stack_fingerprint_hash)
);

CREATE TABLE ltm_negative_memory (
    pattern TEXT NOT NULL,
    stack_fingerprint JSONB NOT NULL,
    stack_fingerprint_hash TEXT GENERATED ALWAYS AS (jsonb_hash(stack_fingerprint)) STORED,
    false_positive_count INT DEFAULT 1,
    last_seen TIMESTAMPTZ,
    PRIMARY KEY (pattern, stack_fingerprint_hash)
);
```

`stack_fingerprint_hash` is a 64-character hex SHA256 digest. A
`CHECK (LENGTH(stack_fingerprint_hash) = 64)` may be added to catch any
future hash algorithm change.

**Stack fingerprint example:**
```json
{"app": ["Express", "Node.js", "16.x"], "db": ["MySQL"], "auth": ["JWT", "RS256"]}
```

### 4.7 Tool Execution

**Allowlist enforcement (not blocklist):**
```python
EXPLOIT_ALLOWLIST = {
    "sqlmap": ["-u", "{url}", "--batch", "--risk={1|2}", "--level={1|2|3}",
               "--technique={B|E|U|T|Q}", "--timeout={30|60|120}", "--threads={1|2|3|4}"],
    "nuclei": ["-u", "{url}", "-t", "{template}", "-rate-limit", "{rate}", "-timeout", "30"],
    "nmap": ["-sV", "-sC", "--max-rate", "{rate}", "-p", "{ports}", "{target}"],
}
```

Any argv outside the template is rejected. **`masscan` is not on the allowlist** — it can saturate a target faster than canary health checks can react. `nmap --max-rate` covers rate-limited port scanning.

**Sandbox:** Docker + gVisor with:
- Read-only rootfs
- Network egress through rate-limiting proxy only (Zone B profile — target scope, DNS, NTP)
- No general internet access
- Max 2GB RAM, 2 CPU, 100 PIDs
- seccomp-bpf default-deny (workable allowlist — see §8.5)

**Canary health checks:**
- Before each exploit tool: HTTP GET to target root
- After each exploit tool: HTTP GET to target root
- If target unresponsive or degraded -> halt immediately

### 4.8 CVSS Calculation

Unchanged from v2.1.0. LLM proposes vector string; deterministic calculator validates; HITL gate uses calculator output.

### 4.9 Report Generation

Jinja2 templates with post-validation. Post-validation checks:
- Every graph finding appears in report
- No duplicates
- PII regex scan (email, SSN, credit card)
- Credential/secret pattern redaction
- Max executive summary: 200 words

**End-of-REPORT sanitization for `ltm_engagement_summaries`:** the summary written for General-mode handoff contains **findings metadata only** — title, severity, CVSS, status, remediation summary. No raw evidence paths (metadata only: "screenshot exists"), no credentials, no PII. The same detector family as §6.4's secret scan and §4.9's PII scan runs before the summary is written.

---

## 5. Mode Switching

### 5.1 Trigger: Shift+Tab

Unchanged from v2.1.0: Bubble Tea-style TUI, `[COPILOT]>` vs `[PURPLE]>` prompt indicator.

### 5.2 Context Handoff (Not Hard Reset)

Unchanged from v2.1.0 (General → Purple serialization + pre-filled engagement config; Purple → General checkpoint + sanitized summary handoff). General mode reads `ltm_engagement_summaries` (read-only, sanitized per §4.9).

### 5.3 Memory Isolation

| Data | General Mode | Purple Team | Shared? |
|---|---|---|---|
| Chat history | Read/Write | No access | No |
| User preferences | Read/Write | Read-only (as config) | Yes |
| Engagement STM | No access | Read/Write | No |
| Raw evidence / credentials | No access | Read/Write | No |
| Live engagement state | No access | Read/Write | No |
| Tool efficacy | Read-only | Read/Write | Yes |
| Negative memory | Read-only | Read/Write | Yes |
| Engagement summaries (sanitized, post-REPORT) | Read-only | Read/Write | Yes |
| CVE/system knowledge | Read-only | Read-only | Yes |

---

## 6. Memory Architecture

### 6.1 Overview

Unchanged from v2.1.0 (same diagram: General session STM / user LTM / system LTM; engagement STM 8MB-capped / engagement LTM; shared system LTM).

### 6.2 Compaction Algorithm (Strix-Adapted)

Same algorithm as v2.1.0 with one change: the summarize step goes through §6.4's redact/restore pipeline, and the prompt no longer asks the model to preserve credentials verbatim — placeholders are preserved verbatim instead; real values are restored locally afterward.

### 6.3 Token Counting

Unchanged from v2.1.0 (LiteLLM `token_counter` with byte-length fallback).

### 6.4 Secret Handling During Compaction (NEW)

**Problem being fixed:** v2.1.0's compaction prompt told the LLM to preserve "credentials, tokens, keys, hashes" verbatim — and routed compaction to a third-party API. In a pentest context, extracted credentials leaving the engagement boundary is a reportable confidentiality breach under most engagement contracts.

**Pipeline:**

1. **Detect.** Scan head messages for credential patterns: API keys, JWTs, password assignments, private key blocks, bearer tokens, connection strings (same detector family as §4.9's PII scan).
2. **Redact-and-tokenize (local, no LLM).** Replace each secret with `«SECRET_1»`, `«SECRET_2»`, … Store the mapping in `engagement_secret_map` — a local, encrypted table never sent to any LLM and never included in summaries.
3. **Summarize the redacted head.** The model is told placeholders must be copied verbatim.
4. **Restore (local, no LLM).** Re-substitute real values into the checkpoint message so downstream states still see exact values.
5. **Route locally when secrets are present.**

```python
def compaction_model_for(messages) -> str:
    if detect_secrets(messages):
        return "ollama/llama3.1"  # local only, no third-party
    return "gpt-4o-mini"
```

If Ollama is unavailable and secrets are present, compaction **refuses and requires explicit user opt-in, recorded in the audit chain**.

---

## 7. LLM Layer

### 7.1 LiteLLM Router

```python
PROVIDER_ROUTING = {
    "general_chat": "ollama/llama3.1",
    "general_search": "gpt-4o-mini",
    "general_explain": "ollama/llama3.1",

    "recon-passive": "ollama/llama3.1",
    "recon-active": "ollama/llama3.1",
    "analysis-hypothesis": "gpt-4o",
    "exploit": "gpt-4o",
    "verify": "gpt-4o-mini",
    "blue-team": "ollama/llama3.1",
    "report": "ollama/llama3.1",

    "compaction": "gpt-4o-mini",   # overridden by compaction_model_for() per §6.4
    "cvss_validation": "gpt-4o-mini",
}
```

**Compaction routing rule:** whenever the redaction pass finds secrets, `compaction` routes to `ollama/*` regardless of this table (§6.4).

Cost controls and budget enforcement unchanged from v2.1.0 (§7.3).

### 7.2 Instructor (Structured Output)

Unchanged from v2.1.0.

### 7.3 Cost Controls

Unchanged from v2.1.0 (max_input_tokens / max_output_tokens / max_cost_usd / fallback_to_ollama; tracked in Redis, checked before every call).

---

## 8. Tool Layer

### 8.1 Tool Runner

All tool calls pass through a unified ToolRunner with **10 safety layers**:

| # | Layer | Enforced By |
|---|---|---|
| 1 | Scope Enforcer | Orchestrator + proxy |
| 2 | Tool Allowlist | ToolRunner per subagent |
| 3 | Context File Scan | ToolRunner |
| 4 | MCP Env Filter | ToolRunner + sidecar |
| 5 | STM Size Limiter | PostgreSQL trigger + orchestrator |
| 6 | Sandbox Isolation | Docker + gVisor + seccomp |
| 7 | Dry Run Gate | HUMAN_REVIEW state |
| 8 | Hardline Blocklist | Regex patterns (rm -rf, dd, DROP TABLE) |
| 9 | Audit Log | Append-only JSONL + SHA256 chain |
| **10** | **Output Bounding** | **ToolRunner (post-execution truncation/normalization)** |

```python
class ToolRunner:
    def __init__(self, scope, rate_limit, audit_log, sandbox):
        ...

    async def run(self, tool_name: str, argv: list[str], subagent: str) -> dict:
        # Layer 1: Scope check
        # Layer 2: Tool allowlist
        # Layer 3: File scan
        # Layer 4: Env filter
        # Layer 5: STM size check
        if self._stm_near_limit():
            raise STMFull("Engagement STM near capacity")
        # Layer 6: Sandbox spawn
        container = await self.sandbox.spawn(tool_name, argv)
        # Layer 7: Rate limit (proxy-enforced)
        # Layer 8: Blocklist (destructive patterns)
        if self._matches_blocklist(argv):
            raise BlocklistViolation("Destructive pattern detected")
        # Layer 9: Audit log
        self.audit.log(tool=tool_name, argv=argv, subagent=subagent)
        # Execute
        result = await container.run(timeout=300)
        # Layer 10: Output bounding
        return self._bound_output(result)
```

### 8.2 Sandbox Specification (Zone B)

```yaml
sandbox:
  runtime: gvisor
  network:
    mode: proxy
    egress:
      allowed: ["target_scope", "dns", "ntp"]
      denied: ["0.0.0.0/0"]
    note: >
      Passive recon does NOT run here. RECON_PASSIVE runs host-side
      in Zone A (see §8.3). This sandbox is RECON_ACTIVE onward.
  filesystem:
    rootfs: read-only
    tmpfs: /tmp (size=100MB, noexec)
    binds:
      - /engagement/{id}/evidence:rw
  resources:
    cpu: 2
    memory: 2GB
    pids: 100
  seccomp:
    default: deny
    allow: [workable syscall set — see §8.5]
```

### 8.3 Traffic-Shaping Proxy — Two Egress Profiles

All outbound traffic passes through the proxy, which applies one of two zone profiles:

| Zone | Tools | Egress | Runs In |
|---|---|---|---|
| **A** | Passive recon (dnsx, subfinder, crt.sh, shodan, censys, waybackurls, gau) | Third-party recon APIs only (api.shodan.io, search.censys.io, crt.sh, web.archive.org, otx.alienvault.com) + dns/ntp. **NO target contact — enforced at the proxy.** | Host-side modules (NOT the Kali sandbox) |
| **B** | Active recon, exploit, verify, post-exploit | Target scope only + dns/ntp, through the traffic-shaping proxy with rate limits and canary health checks. **NO general internet.** | Kali sandbox (gVisor) |

**Invariant (§9, §13.4): RECON_PASSIVE sends zero packets to the target.**

Zone A additionally:
- Enforces `target.rate_limit`-equivalent politeness toward third-party APIs (per-API rate limits)
- Logs all requests to the audit chain — tool called, API host, response status. **API keys are injected per-run from the secret sidecar and never written to the engagement graph or audit log.**

### 8.4 MCP Integration (Future-Proof)

Unchanged from v2.1.0.

### 8.5 Kali Linux Sandbox Base Image

**Purpose:** Use Kali Linux's tool collection as the sandbox base image, while maintaining all 10 safety layers.

**Why Kali / why not mcp-kali-server:** unchanged from v2.1.0.

**Dockerfile:**

```dockerfile
# containers/sandbox/Dockerfile.kali
FROM kalilinux/kali-rolling:latest

# jq is REQUIRED (entrypoint uses it) and is NOT in the base image —
# v2.1.0 used jq without installing it.
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq \
    nmap \
    dnsutils \
    curl \
    netcat-traditional \
    python3 \
    python3-pip \
    sqlmap \
    nikto \
    gobuster \
    ffuf \
    && rm -rf /var/lib/apt/lists/*

# linpeas is NOT an apt package — install from the PEASS release URL
# with SHA256 verification (pin the release tag):
ARG LINPEAS_VERSION=20260901
ARG LINPEAS_SHA256=<pinned-sha256>
ADD https://github.com/peass-ng/PEASS-ng/releases/download/${LINPEAS_VERSION}/linpeas.sh /opt/linpeas.sh
RUN echo "${LINPEAS_SHA256}  /opt/linpeas.sh" | sha256sum -c - \
    && chmod 0755 /opt/linpeas.sh

# bloodhound.py is a pip package, not apt:
RUN pip install --no-cache-dir bloodhound.py

# NOTE: no `apt-get remove` line — this minimal install never contained
# metasploit-framework/beef-xss/setoolkit, so removing them was a silent
# no-op in v2.1.0. The allowlist + image contents are the real control.

# Bake nuclei templates at BUILD time, not runtime (sandbox has no
# internet egress to template sources):
RUN nuclei -update-templates || true  # (if nuclei is installed via apt below)

# Create non-root user for tool execution
RUN useradd -m -s /bin/false kryonsec-runner

# Evidence directory
RUN mkdir -p /evidence && chown kryonsec-runner:kryonsec-runner /evidence

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
USER kryonsec-runner
```

**Entrypoint Script (fixed — argv arrives as container args, real exit codes):**

```bash
#!/bin/bash
# containers/sandbox/entrypoint.sh
# Receives tool argv as CONTAINER ARGUMENTS (docker run IMAGE tool arg1 arg2).
# Executes ONLY allowlisted tools. Defense-in-depth only — the authoritative
# allowlist check is ToolRunner Layer 2 on the host.

set -uo pipefail   # NOT -e: we must capture the tool's real exit code

TOOL="${1:-}"

ALLOWED_TOOLS=(
    "nmap" "dnsx" "subfinder"
    "sqlmap" "nikto" "gobuster" "ffuf"
    "curl" "wget" "nc" "ncat" "openssl" "python3"
    "linpeas.sh" "bloodhound-python"
)

if [[ -z "$TOOL" ]] || [[ ! " ${ALLOWED_TOOLS[*]} " =~ " ${TOOL} " ]]; then
    printf '{"error": "tool_not_in_allowlist", "tool": "%s"}\n' "$TOOL" >&2
    exit 125
fi

# Execute; capture output and the REAL exit code
OUTFILE="$(mktemp /tmp/toolout.XXXXXX)"
timeout --signal=KILL 300 "$@" >"$OUTFILE" 2>&1
EXIT_CODE=$?

# Emit JSON payload on stdout — jq is installed in the image
printf '{"exit_code": %d, "stdout": %s}\n' "$EXIT_CODE" "$(jq -Rs '.' < "$OUTFILE")"

rm -f "$OUTFILE"
exit "$EXIT_CODE"
```

**Corresponding `KaliSandbox.spawn()`** — argv passed as container `command`, never as stdin JSON:

```python
container = await self.docker.run(
    image=self.IMAGE,               # pinned by digest — see §8.6
    runtime="runsc",
    read_only=True,
    tmpfs={"/tmp": "size=100m,noexec"},
    binds={...},
    network_mode="container:kryonsec-proxy",
    user="kryonsec-runner",
    mem_limit="2g",
    cpu_quota=200000,
    pids_limit=100,
    security_opt=["seccomp=kryonsec-seccomp.json"],
    command=argv,                  # argv as container args
    auto_remove=True,
)
```

**gVisor seccomp profile (workable set):**

v2.1.0's allowlist was far too narrow — it omitted `sendto`/`recvfrom`/`setsockopt`/`getsockopt`/`poll`/`select`/`fcntl`/`ioctl`/`sigaction`/`futex`/`getrandom`/`stat`/`fstat`/`getdents64`/`clock_gettime`, so every tool (and even `timeout` itself) would die within the first few syscalls. The corrected set:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
        "fstatat", "getdents64", "lseek", "access", "readlink",
        "socket", "connect", "getsockopt", "setsockopt", "getsockname", "getpeername",
        "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
        "poll", "ppoll", "select", "pselect6", "epoll_create1", "epoll_ctl", "epoll_wait",
        "fcntl", "ioctl", "mmap", "munmap", "mprotect", "brk", "sbrk", "madvise",
        "execve", "execveat", "exit", "exit_group",
        "fork", "clone", "clone3", "wait4", "waitid", "waitpid",
        "sigaction", "sigprocmask", "rt_sigreturn", "kill", "tgkill",
        "getpid", "getppid", "getuid", "getgid", "geteuid", "getegid",
        "futex", "getrandom", "clock_gettime", "clock_nanosleep", "nanosleep",
        "uname", "getcwd", "chdir", "dup", "dup2", "dup3", "pipe", "pipe2",
        "rename", "unlink", "ftruncate", "fsync", "fdatasync"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

Notable decisions: **`bind`/`listen`/`accept` are NOT allowed** — the sandbox must not accept inbound connections. gVisor (userspace kernel) already provides a strong syscall boundary; this seccomp layer is defense-in-depth on top. Tools that fail under this profile are a bug to fix in the profile, not a reason to blanket-allow.

**Tool naming consistency (fix):** the executable installed by the `bloodhound.py` pip package is `bloodhound-python` — the entrypoint allowlist and §4.2 table use that name. The PEASS script is installed at `/opt/linpeas.sh` and allowlisted as `linpeas.sh` (spec tables say `linpeas` — the code names are authoritative).

**Tool Update Mechanism:**

```bash
kryonsec tools update
# Runs inside a temporary Kali container:
# 1. apt-get update && apt-get upgrade
# 2. Verify tool signatures (Kali GPG keys)
# 3. nuclei -update-templates   (templates refreshed here, not at runtime)
# 4. Commit new image layer, tag with new digest
# 5. Smoke tests (nmap --version, sqlmap --version, ...)
# 6. Rollback on failure
```

**Safety Guarantees table** — updated to 10 layers (adds Output Bounding; `masscan` removed; hardline blocklist notes that dangerous metapackages were never installed in the minimal base).

**What the LLM CANNOT do** — unchanged from v2.1.0 (no interactive shell, no host filesystem writes, no exfiltration to non-scope targets, no non-allowlisted tools, no Docker socket, no persistence).

### 8.6 Docker Socket Isolation (NEW — replaces the v2.1.0 docker.sock mount)

v2.1.0 mounted `/var/run/docker.sock` into the kryonsec container. Docker socket access is host-root-equivalent — a compromise of the kryonsec process (malicious tool output, prompt injection, library vuln) means full host takeover, bypassing the sandbox entirely.

**Mitigation stack:**

1. **Socket proxy (endpoint filtering).** The kryonsec process talks to
   `tecnativa/docker-socket-proxy` (or equivalent) with:
   `CONTAINERS=1, POST=1` (create/start/inspect), `IMAGES=0, EXEC=0, VOLUMES=0,
   NETWORKS=0, ALLOW_RESTARTS=0, SECRETS=0, SWARM=0`.
   This kills image pulls, exec, volume/network management, swarm actions.
2. **Image pinned by digest.** `KaliSandbox.IMAGE =
   "kryonsec/sandbox@sha256:<digest>"` — only that exact image can be spawned.
3. **Payload validation shim (required).** Endpoint filtering does not inspect
   request bodies: with `POST=1` a compromised process can still create a
   container with `{"Privileged": true, "Binds": ["/:/host"]}` using an image
   already on the host. Kryonsec therefore fronts the socket proxy with a small
   local shim that validates every `POST /containers/create` payload against a
   fixed allowlist: image digest must match the pinned digest; `Privileged`,
   `Binds`, `CapAdd`, `PidMode`, `NetworkMode: host`, `UsernsMode` and any
   `--runtime` other than `runsc` are rejected. Non-conforming requests are
   dropped and logged to the audit chain.
4. **Rootless Docker (recommended deployment).** Under rootless Docker the
   worst-case container escape is user-level compromise, not host root.
   `kryonsec doctor` checks for rootless mode and warns if absent.

**Security test (§13.4):** from inside the kryonsec container, attempt
`docker run --privileged -v /:/host <any image>` and
`docker run <non-pinned image>` — **both must fail**. (The v2.1.1 bar is
stricter than the socket proxy alone can meet; the shim makes it pass.)

```yaml
  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1
      POST: 1
      IMAGES: 0
      EXEC: 0
      VOLUMES: 0
      NETWORKS: 0
      ALLOW_RESTARTS: 0
      SECRETS: 0
      SWARM: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks: [kryonsec-internal]

  kryonsec:
    environment:
      DOCKER_HOST: tcp://kryonsec-docker-shim:2375   # shim -> socket proxy -> docker
    # NO docker.sock mount on this service
```

---

## 9. Safety Boundaries

### 9.1 Ten Safety Layers

| # | Layer | Enforced By |
|---|---|---|
| 1 | Scope Enforcer | Orchestrator + proxy |
| 2 | Tool Allowlist | ToolRunner per subagent |
| 3 | Context File Scan | ToolRunner |
| 4 | MCP Env Filter | ToolRunner + sidecar |
| 5 | STM Size Limiter | PostgreSQL trigger + orchestrator |
| 6 | Sandbox Isolation | Docker + gVisor + seccomp |
| 7 | Dry Run Gate | HUMAN_REVIEW state |
| 8 | Hardline Blocklist | Regex patterns (rm -rf, dd, DROP TABLE) |
| 9 | Audit Log | Append-only JSONL + SHA256 chain |
| 10 | Output Bounding | ToolRunner (truncation/normalization) |

### 9.2 General Mode Safety

Unchanged from v2.1.0.

### 9.3 Purple Mode Safety

- **Deterministic state machine** (no LLM control)
- **Mandatory HITL** at HUMAN_REVIEW and POST_EXPLOIT
- **RECON_PASSIVE sends zero packets to the target** (Zone A, proxy-enforced, tested in §13.4)
- **Canary health checks** before/after each exploit
- **Read-only post-exploit by default** (allowlist-enforced)
- **No exfiltration** (Zone B egress limited to target scope)
- **Secrets never sent to third-party LLMs** (§6.4 redaction + local routing)
- **Budget enforcement** (token + time + USD)

---

## 10. Storage & Persistence

### 10.1 PostgreSQL Schema

General-mode tables, purple-team tables (see §4.5, §4.6 — with the v2.1.1 hash-PK and
app-layer `size_bytes` fixes), `system_knowledge`, and `checkpoints` as in v2.1.0,
plus:

```sql
-- Local-only secret map for compaction (§6.4). Never sent to any LLM.
CREATE TABLE engagement_secret_map (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID NOT NULL,
    placeholder TEXT NOT NULL,       -- e.g. «SECRET_1»
    secret_encrypted BYTEA NOT NULL, -- application-layer encrypted
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(engagement_id, placeholder)
);
```

### 10.2 Audit Log

Append-only JSONL with SHA256 chain. **Hashes are computed over the exact
serialization written to disk** — canonical JSON (`sort_keys=True`,
`separators=(",", ":")`) — so verification replays byte-identically:

```python
CANON = dict(sort_keys=True, separators=(",", ":"))

class AuditLog:
    def write(self, entry: dict):
        entry["prev_hash"] = self.last_hash
        line = json.dumps(entry, **CANON)
        entry["hash"] = sha256(line.encode())
        line = json.dumps({**entry, "hash": entry["hash"]}, **CANON)
        with open(self.path, "a") as f:
            f.write(line + "\n")
        self.last_hash = entry["hash"]
```

Stored in MinIO with object-lock (WORM). Daily integrity verification.

**Trust anchor & threat model (explicit):** a bare SHA256 chain detects
accidental corruption; an attacker with file write access can rehash the whole
chain. Mitigations: the current head hash is written daily to a WORM-locked
MinIO object and printed to stdout for the user to record externally.
**Documented limitation:** this detects accidental corruption and un-anchored
tampering — not adversarial rehashing of the entire chain without key/anchor
compromise.

### 10.3 Evidence Storage

Unchanged from v2.1.0.

---

## 11. Deployment

### 11.0 Platform Truth (read this first)

**Purple Team mode requires Linux.** gVisor (`runsc`) does not exist on Windows
or macOS Docker Desktop. Windows/macOS users run Kryonsec Purple Team inside a
Linux VM or WSL2 with a Docker daemon configured with `--runtime=runsc` (WSL2
setup is finicky — test before relying on it). **Copilot mode works everywhere.**

### 11.1 Deployment Profiles

**Profile 1 — Copilot only (the `pip install` promise):**

- `pip install kryonsec && kryonsec` starts Copilot mode.
- Storage: PostgreSQL via `DATABASE_URL` if set; otherwise an **embedded
  PostgreSQL** instance (real PostgreSQL, packaged binaries — keeps one engine
  and one schema; Profile 1 never uses SQLite).
- No Redis, no MinIO, no Ollama, no Docker, no gVisor.
- Purple-team commands print: *"Purple Team mode requires the full stack
  (Docker, gVisor, Linux). Run `kryonsec doctor` for setup instructions."*

**Profile 2 — Full stack (Purple Team):**

- Linux only. Docker (rootless recommended) with `runsc` registered.
- `kryonsec doctor` preflight: Docker daemon reachable, `docker run --rm
  --runtime=runsc hello-world` succeeds, pinned sandbox image present (correct
  digest), socket proxy + shim reachable, PostgreSQL/Redis/MinIO/Ollama up.
  Prints a pass/fail report; Purple Team refuses to start on any failure.

### 11.2 Docker Compose (Profile 2)

```yaml
version: "3.8"
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: kryonsec
      POSTGRES_USER: kryonsec
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes: [postgres_data:/var/lib/postgresql/data]
    ports: ["5432:5432"]

  redis:
    image: redis:7-alpine
    volumes: [redis_data:/data]

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: kryonsec
      MINIO_ROOT_PASSWORD: ${MINIO_PASSWORD}
    volumes: [minio_data:/data]
    ports: ["9000:9000", "9001:9001"]

  ollama:
    image: ollama/ollama
    volumes: [ollama_data:/root/.ollama]

  # Sandbox image: built from containers/sandbox/Dockerfile.kali,
  # pinned by digest (§8.6). Never pulled at runtime.

  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1
      POST: 1
      IMAGES: 0
      EXEC: 0
      VOLUMES: 0
      NETWORKS: 0
      ALLOW_RESTARTS: 0
      SECRETS: 0
      SWARM: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks: [kryonsec-internal]

  kryonsec:
    build: .
    environment:
      DATABASE_URL: postgresql://kryonsec:${DB_PASSWORD}@postgres:5432/kryonsec
      REDIS_URL: redis://redis:6379
      MINIO_ENDPOINT: minio:9000
      OLLAMA_HOST: http://ollama:11434
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      DOCKER_HOST: tcp://kryonsec-docker-shim:2375   # shim (§8.6) -> proxy -> docker
    volumes:
      - ~/kryonsec/workspace:/app/workspace
      - ~/.kryonsec:/app/config
    stdin_open: true
    tty: true
    depends_on: [postgres, redis, minio, ollama, docker-socket-proxy]

volumes:
  postgres_data:
  redis_data:
  minio_data:
  ollama_data:
```

Note: **no `/var/run/docker.sock` mount on the `kryonsec` service** (see §8.6).

### 11.3 Installation

```bash
pip install kryonsec
kryonsec          # Profile 1: Copilot mode, embedded storage
kryonsec doctor   # Checks what's available; tells you how to get Profile 2
```

### 11.4 Secret Management

Unchanged from v2.1.0 (`.env` for development; Doppler/Infisical sidecar via
Unix socket in production; the Kryonsec process never reads env vars directly —
Zone A API keys are injected per-run and never logged).

---

## 12. Observability

Unchanged from v2.1.0 (metrics, tracing, health checks — health checks
extended to include the socket proxy/shim and pinned-image digest).

---

## 13. Testing Strategy

### 13.1 Unit Tests
- Orchestrator state transitions (mock everything) — including HUMAN_REVIEW
  rejection → BLUE_TEAM, and budget-exhaustion → HALT
- Tool allowlist validation (including `masscan` rejection)
- CVSS calculator accuracy
- Audit chain integrity (including canonical-hash replay)
- Compaction algorithm correctness (including redact/restore round-trip)
- Entrypoint: real exit codes, allowlist rejection, JSON payload shape

### 13.2 Integration Tests
- Mock LLM (returns fixed Pydantic objects)
- PostgreSQL test container (schema creation must succeed end-to-end —
  the regression v2.1.0's JSONB PKs would have caught)
- Redis test container
- ToolRunner with `echo` mock tools

### 13.3 E2E Tests
- DVWA — SQLi, XSS, file upload
- WebGoat — JWT, SSRF, IDOR
- VulnHub boxes — post-exploit chains

### 13.4 Security Tests
- LLM prompt injection resistance
- Sandbox escape attempts
- Scope enforcement (out-of-scope IP scan)
- Audit log tamper resistance (including chain rehash detection vs. anchor)
- File access boundary tests
- **RECON_PASSIVE zero-packet invariant:** run an engagement against a
  controlled target with a packet counter; assert 0 packets received during
  RECON_PASSIVE
- **Docker socket escape:** from inside the kryonsec container, attempt
  `docker run --privileged -v /:/host <any image>` and a non-pinned image
  spawn — both must fail (§8.6)
- **Compaction secret leakage:** seed a session with credentials, run
  compaction against a mock third-party endpoint, assert no secret material
  ever leaves (routing must go local)
- **Seccomp smoke:** each allowlisted tool runs to completion under the
  seccomp profile (catches an over-narrow profile)

---

## 14. Quick Reference

```
DUAL-MODE SYSTEM
  [COPILOT] <--Shift+Tab--> [PURPLE TEAM]

DEPLOYMENT PROFILES
  Profile 1 (any OS):  pip install -> Copilot only, embedded PostgreSQL
  Profile 2 (Linux):   full stack -> Purple Team, gVisor sandbox

GENERAL COPILOT
  - Conversational cybersecurity assistant
  - Scoped file read/write (approval-gated)
  - Web search, CVE lookup, tool docs
  - Session STM with Strix-style compaction (+ secret redaction)
  - User LTM + System LTM
  - Sees only sanitized post-REPORT engagement summaries

PURPLE TEAM (10-STATE LOOP + TERMINAL HALT)
  INIT -> RECON_PASSIVE* -> RECON_ACTIVE -> HYPOTHESIZE -> HUMAN_REVIEW
    -> EXPLOIT -> [HITL] -> POST_EXPLOIT -> VERIFY -> BLUE_TEAM -> REPORT -> HALT
  (* Zone A: host-side, zero packets to target)

10 SAFETY LAYERS
  Scope -> Allowlist -> File Scan -> Env Filter -> STM Size -> Sandbox
    -> Dry Run -> Blocklist -> Audit Chain -> Output Bounding

TWO EXECUTION ZONES
  Zone A: passive recon, third-party APIs only, no target contact
  Zone B: active/exploit/verify, target-scope only, gVisor sandbox

SECRETS
  Never sent to third-party LLMs. Redact-and-tokenize -> local model.

TECH STACK
  Python 3.11+ | LiteLLM | Instructor | PostgreSQL | Redis | MinIO
  Docker + gVisor | Jinja2 | Pydantic | Bubble Tea (TUI)

EXPLICITLY EXCLUDED
  LangChain | LangGraph | SQLite | KuzuDB | Shell strings
  LLM-driven state transitions | Unrestricted file access
  docker.sock in the app container | masscan
```

---

*End of Kryonsec v2.1.1 specification. This is the design-of-record.*
