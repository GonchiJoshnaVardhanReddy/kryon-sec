# Kryonsec v2.1 — Dual-Mode Architecture Specification

**Version:** 2.1.0-draft  
**Date:** 2026-09-03  
**Scope:** Single-user CLI cybersecurity platform with conversational copilot mode and deterministic purple-team engagement mode.  
**Status:** Design-of-record.

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

- **Mode A — General Copilot:** A conversational cybersecurity assistant that answers questions, explains concepts, performs scoped file operations, and conducts lightweight research. Think of it as "Claude for cybersecurity" that lives in your terminal.

- **Mode B — Purple Team:** A deterministic, bounded, human-in-the-loop offensive security engine that runs structured penetration tests against authorized targets. This is not a chatbot — it is a state machine with 10 fixed states, mandatory approval gates, and append-only audit trails.

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
|  |  - Conversational       |                 |  - 10-state deterministic |  |
|  |  - File read/write      |                 |    loop                   |  |
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
|  SHARED INFRASTRUCTURE                                                       |
|  +-- PostgreSQL (STM + LTM + checkpoints)                                   |
|  +-- Redis (ephemeral cache, rate limiting)                                  |
|  +-- MinIO (evidence storage)                                                |
|  +-- LiteLLM (provider routing)                                              |
|  +-- Docker + gVisor (sandbox)                                               |
|  +-- Append-only JSONL audit chain                                           |
+-----------------------------------------------------------------------------+
```

### Design Decisions

| Decision | Rationale |
|---|---|
| **Single-user CLI** | Startup-friendly. No auth server, no multi-tenant complexity. `pip install kryonsec && kryonsec` just works. |
| **Two modes, one binary** | Users don't install two tools. Context from general mode (target URLs, stack info) can seed purple team engagement config. |
| **Shift+Tab toggle** | Terminal-native. No GUI framework needed. Non-intrusive during chat. |
| **Separate memory systems** | General chat must never leak into purple team audit trails. A casual "what's my password" chat should not appear in a compliance report. |
| **Deterministic purple team** | LLMs cannot be trusted with state transitions in offensive security. The orchestrator is a Python state machine with zero LLM involvement. |
| **Strix-inspired compaction** | Token-aware summarization with exact-value preservation. Better than naive truncation or rigid node caps. |
| **PostgreSQL for everything** | One database to back up, one connection pool, one migration strategy. JSONB handles schema flexibility. |

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
- Access purple team engagement data
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

**Storage:** In-memory deque + PostgreSQL `general_sessions` table.

**Compaction (Strix-inspired):**
```python
class GeneralSession:
    max_tokens: int = 16000  # ~75% of typical 20k context
    max_messages: int = 50

    async def maybe_compact(self):
        if self.token_count < self.max_tokens * 0.8:
            return

        # Split into head (old) and recent (keep verbatim)
        head, recent = self.split_at_token_budget(self.messages, keep_tokens=8000)

        # Summarize head with security-aware prompt
        summary = await llm.summarize(
            messages=head,
            instructions=(
                "Be EXHAUSTIVE, not concise. Preserve exact values: "
                "URLs, file paths, CVE IDs, version numbers, commands, credentials, "
                "tokens, keys, hashes, payloads. Do not lose technical details. "
                "Enumerate every distinct item."
            )
        )

        self.messages = [CheckpointMessage(summary=summary)] + recent
```

**Why this matters:** A user might paste a 500-line config file, discuss 10 CVEs, and then ask "what was the first CVE I mentioned?" Naive truncation loses it. Strix-style compaction preserves exact values in the summary.

### 3.5 User LTM (Long-Term Memory)

**Scope:** Cross-session, per-user preferences and history.

**Storage:** PostgreSQL `general_user_ltm` table.

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

**Storage:** PostgreSQL `general_system_ltm` + external APIs.

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

Inspired by Strix's skill system. General mode loads skills based on context:

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

The prompt is assembled dynamically:
```python
def build_system_prompt(user_preferences):
    skills = ["base"]
    if user_preferences.explain_mode == "simple":
        skills.append("explain_simple")
    if user_preferences.last_topic == "CVE":
        skills.append("cve_analysis")

    return jinja_env.get_template("system_prompt.jinja").render(
        skills=load_skills(skills),
        user_prefs=user_preferences,
        safety_rules=SAFETY_RULES_GENERAL
    )
```

---

## 4. Mode B: Purple Team

### 4.1 Purpose
Deterministic, bounded, human-in-the-loop offensive security testing. This is the 10-state loop from Kryonsec v2.0, refined with lessons from Strix.

### 4.2 The 10-State Loop

```
INIT -> RECON_PASSIVE -> RECON_ACTIVE -> HYPOTHESIZE -> HUMAN_REVIEW
  -> EXPLOIT -> [HITL GATE if shell] -> POST_EXPLOIT -> VERIFY
  -> BLUE_TEAM -> REPORT -> HALT
```

| State | Purpose | LLM Role | Tools |
|---|---|---|---|
| INIT | Load config, validate scope, legal consent | None | None |
| RECON_PASSIVE | 3rd-party recon (no packets to target) | Summarize, prioritize | dnsx, subfinder, crt.sh, shodan, censys, waybackurls, gau |
| RECON_ACTIVE | Active scanning (packets to target) | Prioritize, flag anomalies | nmap, httpx, wappalyzer, wafw00f, feroxbuster, nuclei (passive) |
| HYPOTHESIZE | Generate vulnerability hypotheses | Propose CVSS vectors, select tools | None (pure LLM) |
| HUMAN_REVIEW | Blocking approval of hypotheses | None | None |
| EXPLOIT | Execute approved hypotheses | Select tool from allowlist, parse output | sqlmap, nuclei (active), ffuf, jwt_tool, dalfox, commix, ssrfmap, etc. |
| POST_EXPLOIT | Shell enumeration (with approval) | Decide what to enumerate | pwncat, linpeas, bloodhound, mimikatz |
| VERIFY | Independently confirm findings | Generate PoC, compare responses | curl, httpie, python, netcat, openssl |
| BLUE_TEAM | Defensive recommendations | Generate fixes, detection rules | None (pure LLM) |
| REPORT | Compile final report | Synthesize into templates | None (Jinja2 templates) |

### 4.3 Orchestrator (Plain Python, No LLM)
```python
class PurpleOrchestrator:
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
            "HUMAN_REVIEW": "EXPLOIT" if result.approved_count > 0 else "REPORT",
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
```
+-- Kryonsec Legal Consent ----------------------------+
| You are about to run active security tests against:   |
|   Target: acme-corp.com                               |
|   Scope: *.acme-corp.com, 1.2.3.0/24                  |
|                                                       |
| By continuing, you certify:                           |
|   [ ] I own this target or have written authorization |
|   [ ] I have backups of all critical data             |
|   [ ] I understand this tool will attempt exploits    |
|   [ ] I accept full liability for any damages         |
|                                                       |
|   [CONTINUE] [ABORT]                                  |
+-------------------------------------------------------+
```
Consent hash is the **genesis entry** in the audit chain.

#### Gate 2: HUMAN_REVIEW (Pre-Exploit)
All hypotheses displayed with:
- Description, target, CVSS (calculated, not LLM)
- Exact tool command (dry-run, not executed)
- Risk level
- [APPROVE] [REJECT] [MODIFY]

#### Gate 3: POST_EXPLOIT (Pre-Enumeration)
When shell access obtained:
```
+-- Shell Access Obtained -----------------------------+
| Host: web01.acme-corp.com                           |
| User: www-data                                      |
| Via: SQLi UNION-based injection                     |
|                                                     |
| Authorize post-exploit enumeration?                 |
|   [ ] Read-only system enumeration                  |
|   [ ] Privilege escalation check (linpeas)          |
|   [ ] Credential extraction                         |
|   [ ] Lateral movement (max 2 hosts)                |
|                                                     |
|   [AUTHORIZE SELECTED] [DECLINE] [HALT]            |
+-----------------------------------------------------+
```
Authorization token expires in 30 minutes.

### 4.5 STM (Engagement Graph)

PostgreSQL schema with size enforcement:

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
    size_bytes INT GENERATED ALWAYS AS (pg_column_size(properties)) STORED,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_nodes_engagement ON stm_nodes(engagement_id);

-- Size enforcement trigger
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
```

**Compaction at 80%:** When STM hits 6.4MB, a compressor pass summarizes old recon nodes into clusters, preserving exact values (Strix-style).

### 4.6 LTM (Purple Team)

Separate from general LTM. Stores cross-engagement learnings:

```sql
CREATE TABLE ltm_target_profiles (
    target_hash TEXT PRIMARY KEY,
    stack_fingerprint JSONB,
    last_engagement TIMESTAMPTZ,
    engagement_count INT DEFAULT 1
);

CREATE TABLE ltm_tool_efficacy (
    tool_name TEXT NOT NULL,
    stack_fingerprint JSONB,
    success_rate DECIMAL(3,2),
    avg_time_seconds INT,
    last_used TIMESTAMPTZ,
    PRIMARY KEY (tool_name, stack_fingerprint)
);

CREATE TABLE ltm_negative_memory (
    pattern TEXT NOT NULL,
    stack_fingerprint JSONB,
    false_positive_count INT DEFAULT 1,
    last_seen TIMESTAMPTZ,
    PRIMARY KEY (pattern, stack_fingerprint)
);
```

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
}
```

Any argv outside the template is rejected.

**Sandbox:** Docker + gVisor with:
- Read-only rootfs
- Network egress through rate-limiting proxy only
- No general internet access
- Max 2GB RAM, 2 CPU, 100 PIDs
- seccomp-bpf default-deny

**Canary health checks:**
- Before each exploit tool: HTTP GET to target root
- After each exploit tool: HTTP GET to target root
- If target unresponsive or degraded -> halt immediately

### 4.8 CVSS Calculation

LLM proposes vector string. Deterministic calculator validates:
```python
from cvss import CVSS3

def validate_cvss(vector: str) -> tuple[float, bool]:
    c = CVSS3(vector)
    return c.scores()[0], c.is_valid()
```

HITL gate uses calculator output, not LLM guess.

### 4.9 Report Generation

Jinja2 templates with post-validation:
```jinja2
# Penetration Test Report: {{ engagement.target }}
## Executive Summary
{{ executive_summary }}

## Findings
{% for finding in findings %}
### {{ finding.title }} (CVSS: {{ finding.cvss_score }})
**Status:** {{ finding.verification_status }}
**Evidence:** {{ finding.evidence_path }}
**Reproduction:**
```bash
{{ finding.repro_command }}
```
{% endfor %}
```

Post-validation checks:
- Every graph finding appears in report
- No duplicates
- PII regex scan (email, SSN, credit card)
- Max executive summary: 200 words

---

## 5. Mode Switching

### 5.1 Trigger: Shift+Tab

In the terminal UI (powered by Bubble Tea or similar TUI framework):
- **Shift+Tab** toggles between General and Purple Team mode
- Visual indicator in the prompt: `[COPILOT]>` vs `[PURPLE]>`

### 5.2 Context Handoff (Not Hard Reset)

When switching General -> Purple Team:
1. General session is **serialized** to PostgreSQL (`general_sessions` table)
2. Orchestrator extracts relevant context:
   - Target URLs mentioned in chat
   - Stack information discussed
   - User preferences (explain mode, verbosity)
3. User is shown a **pre-filled engagement config**:
   ```
   +-- Start Purple Team Engagement ----------------------+
   | Target: acme-corp.com (from chat)                   |
   | Scope: *.acme-corp.com                              |
   | Mode: Black-box                                     |
   | [EDIT SCOPE] [CONFIRM] [CANCEL]                     |
   +-----------------------------------------------------+
   ```
4. If confirmed, Purple Team loop starts at INIT

When switching Purple Team -> General:
1. Engagement pauses at current state (checkpoint saved)
2. Engagement summary (findings count, severity, status) passed to General mode
3. User can ask: "Explain finding #3 in simple terms"
4. General mode reads from `ltm_engagement_summaries` (read-only)

### 5.3 Memory Isolation

| Data | General Mode | Purple Team | Shared? |
|---|---|---|---|
| Chat history | Read/Write | No access | No |
| User preferences | Read/Write | Read-only (as config) | Yes |
| Engagement STM | No access | Read/Write | No |
| Tool efficacy | Read-only | Read/Write | Yes |
| Negative memory | Read-only | Read/Write | Yes |
| Engagement summaries | Read-only | Read/Write | Yes |
| CVE/system knowledge | Read-only | Read-only | Yes |

---

## 6. Memory Architecture

### 6.1 Overview

```
+-------------------------------------------------------------+
|                      MEMORY SYSTEMS                          |
+-------------------------------------------------------------+
|  GENERAL MODE                                                |
|  +-- Session STM (in-memory + PostgreSQL)                   |
|  |   +-- Strix-style compaction, token-aware               |
|  +-- User LTM (PostgreSQL)                                  |
|  |   +-- Preferences, topic history, file refs             |
|  +-- System LTM (PostgreSQL + cached APIs)                  |
|      +-- CVE DB, tool docs, attack patterns                |
+-------------------------------------------------------------+
|  PURPLE TEAM MODE                                            |
|  +-- Engagement STM (PostgreSQL)                            |
|  |   +-- Size-capped at 8MB, auto-compression              |
|  +-- Engagement LTM (PostgreSQL)                            |
|  |   +-- Target profiles, tool efficacy, negative memory   |
|  +-- System LTM (shared with General)                       |
|      +-- CVE DB, tool docs                                  |
+-------------------------------------------------------------+
```

### 6.2 Compaction Algorithm (Strix-Adapted)
```python
async def compact_session(messages: list, model: str, max_tokens: int):
    """Strix-inspired compaction with security-aware summarization."""

    # 1. Calculate current token usage
    used = count_tokens(model, serialize_messages(messages))
    if used <= max_tokens * 0.8:
        return messages

    # 2. Identify tool call/result pairs (must stay together)
    protected_indices = find_tool_pairs(messages)

    # 3. Split into head (summarize) and tail (keep verbatim)
    split_point = find_split_point(
        messages, 
        keep_tokens=max_tokens * 0.4,
        protected=protected_indices
    )
    head, tail = messages[:split_point], messages[split_point:]

    # 4. Check for previous summary in head
    previous_summary = extract_previous_summary(head)

    # 5. Generate security-aware summary
    summary_prompt = (
        "Summarize the following conversation history. Be EXHAUSTIVE, not concise.

"
        "Rules:
"
        "- Enumerate every distinct item as its own bullet
"
        "- Copy exact values VERBATIM: URLs, file paths, CVE IDs, version numbers,
"
        "  commands, credentials, tokens, keys, hashes, payloads
"
        "- Preserve the sequence of events
"
        "- Include the outcome of every tool call
"
        f"- Previous summary (if any): {previous_summary or 'None'}

"
        f"Messages to summarize:
{serialize_messages(head)}"
    )

    summary = await llm_call(model=model, messages=[{"role": "user", "content": summary_prompt}])

    # 6. Replace head with checkpoint message
    checkpoint = Message(role="system", content=f"[SESSION CHECKPOINT]
{summary}")
    return [checkpoint] + tail
```

### 6.3 Token Counting

Uses LiteLLM's `token_counter` with conservative fallback:
```python
def count_tokens(model: str, text: str) -> int:
    try:
        return litellm.token_counter(model=model, text=text)
    except Exception:
        return len(text.encode("utf-8"))
```

---

## 7. LLM Layer

### 7.1 LiteLLM Router

Unified interface for all providers:
```python
from litellm import completion

PROVIDER_ROUTING = {
    # General mode
    "general_chat": "ollama/llama3.1",
    "general_search": "gpt-4o-mini",
    "general_explain": "ollama/llama3.1",

    # Purple team mode
    "recon-passive": "ollama/llama3.1",
    "recon-active": "ollama/llama3.1",
    "analysis-hypothesis": "gpt-4o",
    "exploit": "gpt-4o",
    "verify": "gpt-4o-mini",
    "blue-team": "ollama/llama3.1",
    "report": "ollama/llama3.1",

    # Shared
    "compaction": "gpt-4o-mini",
    "cvss_validation": "gpt-4o-mini",
}

def llm_call(subagent: str, messages: list, temperature: float = 0.0):
    model = PROVIDER_ROUTING.get(subagent, "gpt-4o")
    return completion(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=4000,
        api_base="http://localhost:11434" if model.startswith("ollama/") else None
    )
```

### 7.2 Instructor (Structured Output)

All subagents that produce structured data use Instructor + Pydantic:
```python
import instructor
from pydantic import BaseModel, Field
from openai import OpenAI

client = instructor.from_openai(OpenAI())

class Hypothesis(BaseModel):
    description: str
    target_service_id: UUID
    cvss_vector_proposed: str = Field(pattern=r"^CVSS:3\.1/.+")
    confidence: float = Field(ge=0.0, le=1.0)
    planned_tool: str
    test_plan: str
    rationale: str

hypotheses = client.chat.completions.create(
    model="gpt-4o",
    response_model=List[Hypothesis],
    messages=[...],
    max_retries=3
)
```

### 7.3 Cost Controls

```yaml
llm_budget:
  max_input_tokens: 100000
  max_output_tokens: 50000
  max_cost_usd: 5.00
  fallback_to_ollama: true
```

Tracked per engagement/session in Redis. Checked before every LLM call.

---

## 8. Tool Layer

### 8.1 Tool Runner

All tool calls pass through a unified ToolRunner with 9 safety layers:
```python
class ToolRunner:
    def __init__(self, scope, rate_limit, audit_log, sandbox):
        self.scope = scope
        self.rate_limit = rate_limit
        self.audit = audit_log
        self.sandbox = sandbox

    async def run(self, tool_name: str, argv: list[str], subagent: str) -> dict:
        # Layer 1: Scope check
        if not self.scope.contains(argv):
            raise ScopeViolation("Target out of scope")

        # Layer 2: Tool allowlist
        if not self._check_allowlist(subagent, tool_name, argv):
            raise AllowlistViolation("Argv outside approved template")

        # Layer 3: File scan
        if not self._check_file_access(argv):
            raise FileAccessViolation("Unauthorized file access")

        # Layer 4: Env filter
        if not self._check_env_leak(argv):
            raise EnvLeakViolation("Potential secret leak")

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

### 8.2 Sandbox Specification

```yaml
sandbox:
  runtime: gvisor
  network:
    mode: proxy
    egress:
      allowed: ["target_scope", "dns", "ntp"]
      denied: ["0.0.0.0/0"]
  filesystem:
    rootfs: read-only
    tmpfs: /tmp (size=100MB)
    binds:
      - /engagement/{id}/evidence:rw
  resources:
    cpu: 2
    memory: 2GB
    pids: 100
  seccomp:
    default: deny
    allow: [read, write, open, close, socket, connect, execve, exit, wait4]
```

### 8.3 Traffic-Shaping Proxy

All outbound traffic from sandbox goes through a transparent proxy:
- Enforces `target.rate_limit` (packets per second)
- Logs all requests to audit chain
- Blocks egress to non-scope targets
- Canary health check endpoint (before/after each exploit)

### 8.4 MCP Integration (Future-Proof)

If MCP servers are added later, use Strix's supervised session pattern:
```python
class SupervisedMcpSession:
    async def _submit(self, job: Job) -> Outcome:
        future = asyncio.get_event_loop().create_future()
        await self._queue.put(Request(job=job, future=future))
        return await future
```


### 8.5 Kali Linux Sandbox Base Image

**Purpose:** Use Kali Linux's pre-installed 600+ security tool collection as the sandbox base image, while maintaining all 9 safety layers. This eliminates the need to individually install and maintain nmap, sqlmap, nuclei, gobuster, jwt_tool, etc.

**Why Kali as Base Image:**
- 600+ pentesting tools pre-installed and updated via `apt`
- Consistent tool versions across engagements
- Standard paths (`/usr/bin/nmap`, `/usr/share/nmap/scripts/`, etc.)
- Regular security updates via Kali repositories
- Familiar environment for security professionals

**Why NOT `mcp-kali-server`:**
The `mcp-kali-server` package (from kali.org) exposes a Flask API that lets an LLM run arbitrary shell commands on the Kali host. This violates Kryonsec's core safety principles:
- LLM controls what runs next (not deterministic)
- Shell strings, not argv lists
- No scope enforcement
- No rate limiting
- No audit trail
- No sandbox isolation (runs on host OS)

**Kryonsec's Modified Approach:**

```
Kryonsec Orchestrator (host)
    |
    v
ToolRunner (safety layers 1-5: scope, allowlist, file scan, env filter, STM size)
    |
    v
Docker + gVisor Sandbox (Kali Linux base image)
    |
    +-- Read-only rootfs with Kali tools
    +-- /tmp tmpfs (100MB)
    +-- /evidence bind mount (rw)
    +-- NO shell access for LLM
    +-- NO MCP bridge
    +-- NO Flask API
    |
    v
Traffic-Shaping Proxy (rate limit, scope check, canary health)
    |
    v
Target (authorized scope only)
```

**Dockerfile:**

```dockerfile
# containers/sandbox/Dockerfile.kali
FROM kalilinux/kali-rolling:latest

# Update and install only the tools Kryonsec needs
# (Kali has 600+ tools; we only expose a subset via allowlist)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Recon tools
    nmap \
    masscan \
    dnsutils \
    # Web tools
    sqlmap \
    nikto \
    gobuster \
    ffuf \
    # Network tools
    curl \
    netcat-traditional \
    # Post-exploit
    linpeas \
    bloodhound.py \
    # Utilities
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Remove dangerous tools that should never run in sandbox
RUN apt-get remove -y \
    metasploit-framework \
    beef-xss \
    setoolkit \
    2>/dev/null || true

# Create non-root user for tool execution
RUN useradd -m -s /bin/false kryonsec-runner

# Set up read-only evidence directory
RUN mkdir -p /evidence && chown kryonsec-runner:kryonsec-runner /evidence

# Entrypoint: wait for argv from ToolRunner, execute, return output
# NO shell, NO interactive mode, NO MCP bridge
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
USER kryonsec-runner
```

**Entrypoint Script:**

```bash
#!/bin/bash
# containers/sandbox/entrypoint.sh
# Receives argv as JSON via stdin, executes ONLY allowlisted tools

set -euo pipefail

# Read argv from stdin (JSON array from ToolRunner)
ARGV=$(cat)
TOOL=$(echo "$ARGV" | jq -r '.[0]')

# Validate tool is in allowlist
ALLOWED_TOOLS=(
    "nmap" "masscan" "dnsx" "subfinder"
    "sqlmap" "nikto" "gobuster" "ffuf"
    "curl" "nc" "ncat" "python3"
    "linpeas.sh" "bloodhound.py"
)

if [[ ! " ${ALLOWED_TOOLS[@]} " =~ " ${TOOL} " ]]; then
    echo '{"error": "Tool not in allowlist", "tool": "'"$TOOL"'"}' >&2
    exit 1
fi

# Execute with timeout and resource limits
# stdout/stderr captured and returned as JSON
timeout 300 "$@" 2>&1 | jq -Rs '{"stdout": ., "exit_code": 0}'
```

**ToolRunner Integration:**
```python
# kryonsec/tools/sandbox.py
class KaliSandbox:
    """gVisor + Kali Linux sandbox for tool execution."""

    IMAGE = "kryonsec/sandbox:kali-latest"

    async def spawn(self, tool_name: str, argv: list[str]) -> SandboxContainer:
        # Safety layers 1-5 already passed in ToolRunner

        container = await self.docker.run(
            image=self.IMAGE,
            runtime="runsc",  # gVisor
            read_only=True,
            tmpfs={"/tmp": "size=100m,noexec"},
            binds={
                f"/engagement/{self.engagement_id}/evidence": {
                    "bind": "/evidence",
                    "mode": "rw"
                }
            },
            network_mode="container:kryonsec-proxy",  # Through proxy
            user="kryonsec-runner",
            mem_limit="2g",
            cpu_quota=200000,  # 2 CPUs
            pids_limit=100,
            security_opt=["seccomp=kryonsec-seccomp.json"],
            stdin=json.dumps(argv).encode(),  # Pass argv as JSON
            auto_remove=True,
        )

        return SandboxContainer(container)
```

**gVisor Seccomp Profile:**

```json
// containers/sandbox/kryonsec-seccomp.json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "openat", "close",
        "socket", "connect", "bind", "listen", "accept",
        "execve", "execveat", "exit", "exit_group",
        "wait4", "waitpid", "fork", "clone",
        "mmap", "munmap", "mprotect",
        "brk", "sbrk",
        "getpid", "getppid", "getuid", "getgid"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Tool Update Mechanism:**

```bash
# Update Kali tools without rebuilding the entire stack
kryonsec tools update

# This runs inside a temporary Kali container:
# 1. apt-get update && apt-get upgrade
# 2. Verify tool signatures (Kali GPG keys)
# 3. Commit new image layer
# 4. Tag as kryonsec/sandbox:kali-latest
# 5. Run smoke tests (nmap --version, sqlmap --version, etc.)
# 6. Rollback on failure
```

**Safety Guarantees Maintained:**

| Safety Layer | Kali Sandbox Implementation |
|---|---|
| 1. Scope Enforcer | Proxy blocks egress to non-scope targets |
| 2. Tool Allowlist | `entrypoint.sh` validates tool name against hardcoded list |
| 3. File Scan | Read-only rootfs + tmpfs only; no host filesystem access |
| 4. Env Filter | Container has no env vars from host; secrets injected via sidecar |
| 5. STM Size Limiter | Orchestrator checks before spawning container |
| 6. Sandbox Isolation | gVisor + Docker + seccomp-bpf; Kali tools run inside, not on host |
| 7. Dry Run Gate | HUMAN_REVIEW state approves before any container spawn |
| 8. Hardline Blocklist | `msfconsole`, `beef`, `setoolkit` removed from image |
| 9. Audit Log | Every container spawn, argv, and output logged to JSONL chain |

**What the LLM CANNOT Do (Even With Kali Tools):**
- Spawn an interactive shell (`/bin/bash` not in allowlist)
- Run `msfconsole` or `beef` (removed from image)
- Write to system directories (read-only rootfs)
- Exfiltrate data (egress blocked to non-scope targets)
- Run tools not in the allowlist (entrypoint rejects)
- Access host Docker socket (not mounted in sandbox)
- Persist between runs (container auto-removed)

**What You Get:**
- All Kali recon tools: `nmap`, `masscan`, `dnsrecon`, `theHarvester`
- All Kali web tools: `sqlmap`, `nikto`, `gobuster`, `ffuf`, `dirb`
- All Kali network tools: `curl`, `wget`, `nc`, `openssl`
- Post-exploit: `linpeas`, `winpeas`, `bloodhound.py`
- Updated weekly via Kali repos
- Zero individual tool installation maintenance

**Build Command:**

```bash
cd containers/sandbox
docker build -f Dockerfile.kali -t kryonsec/sandbox:kali-latest .
# Verify
docker run --rm -i kryonsec/sandbox:kali-latest <<< '["nmap", "--version"]'
```
---

## 9. Safety Boundaries

### 9.1 Nine Safety Layers

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

### 9.2 General Mode Safety

- **No shell execution** (blocked at ToolRunner)
- **File reads outside workspace require approval**
- **File writes outside workspace are blocked**
- **No network requests except approved search APIs**
- **No access to purple team engagement data**

### 9.3 Purple Mode Safety

- **Deterministic state machine** (no LLM control)
- **Mandatory HITL at HUMAN_REVIEW and POST_EXPLOIT**
- **Canary health checks** before/after each exploit
- **Read-only post-exploit by default** (allowlist-enforced)
- **No exfiltration** (egress blocked in sandbox)
- **Budget enforcement** (token + time + USD)

---

## 10. Storage & Persistence

### 10.1 PostgreSQL Schema

```sql
-- GENERAL MODE
CREATE TABLE general_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL DEFAULT 'default',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    messages JSONB NOT NULL DEFAULT '[]',
    summary TEXT,
    token_count INT DEFAULT 0
);

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

-- PURPLE TEAM MODE
-- stm_nodes, stm_edges, ltm_target_profiles, ltm_tool_efficacy,
-- ltm_negative_memory, ltm_engagement_summaries
-- (see section 4.5 and 4.6 for full schema)

-- SHARED
CREATE TABLE system_knowledge (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(category, key)
);

-- CHECKPOINTS
CREATE TABLE checkpoints (
    engagement_id UUID PRIMARY KEY,
    current_state TEXT NOT NULL,
    completed_states TEXT[] DEFAULT '{}',
    graph_size_bytes INT DEFAULT 0,
    audit_log_path TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 10.2 Audit Log

Append-only JSONL with SHA256 chain:
```python
class AuditLog:
    def write(self, entry: dict):
        entry["prev_hash"] = self.last_hash
        entry["hash"] = sha256(json.dumps(entry, sort_keys=True))
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "
")
        self.last_hash = entry["hash"]
```

Stored in MinIO with object-lock (WORM). Daily integrity verification.

### 10.3 Evidence Storage

- MinIO bucket: `kryonsec-evidence/{engagement_id}/{finding_id}/`
- Max 1GB per engagement
- Auto-deleted after 90 days (configurable)

---

## 11. Deployment

### 11.1 Docker Compose (Single-User Local)

```yaml
version: "3.8"
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: kryonsec
      POSTGRES_USER: kryonsec
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
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
    deploy:
      resources:
        reservations:
          devices: [{driver: nvidia, count: 1, capabilities: [gpu]}]

  # Kali-based security tool sandbox
  # Built from: containers/sandbox/Dockerfile.kali
  # kryonsec/sandbox:kali-latest

  kryonsec:
    build: .
    environment:
      DATABASE_URL: postgresql://kryonsec:${DB_PASSWORD}@postgres:5432/kryonsec
      REDIS_URL: redis://redis:6379
      MINIO_ENDPOINT: minio:9000
      OLLAMA_HOST: http://ollama:11434
      OPENAI_API_KEY: ${OPENAI_API_KEY}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ~/kryonsec/workspace:/app/workspace
      - ~/.kryonsec:/app/config
    stdin_open: true
    tty: true
    depends_on: [postgres, redis, minio, ollama]

volumes:
  postgres_data:
  redis_data:
  minio_data:
  ollama_data:
```

### 11.2 Installation

```bash
# One-line install (future)
curl -sSL https://kryonsec.dev/install | bash

# Or pip
pip install kryonsec

# First run
kryonsec
# -> Starts in General Copilot mode
# -> Press Shift+Tab to switch to Purple Team
```

### 11.3 Secret Management

**Development:** `.env` file (never committed)
**Production:** Doppler or Infisical sidecar injects secrets via Unix socket. Kryonsec process never reads env vars directly.

---

## 12. Observability

### 12.1 Metrics (Prometheus)

```python
engagements_total = Counter('kryonsec_engagements_total', 'Total engagements', ['status'])
findings_total = Counter('kryonsec_findings_total', 'Total findings', ['severity'])
llm_tokens = Counter('kryonsec_llm_tokens_total', 'LLM tokens', ['provider', 'mode', 'subagent'])
llm_cost = Counter('kryonsec_llm_cost_usd', 'LLM cost', ['provider', 'mode'])
tool_duration = Histogram('kryonsec_tool_duration_seconds', 'Tool time', ['tool'])
stm_size = Gauge('kryonsec_stm_size_bytes', 'STM size', ['engagement_id'])
mode_switches = Counter('kryonsec_mode_switches_total', 'Mode switches', ['from', 'to'])
```

### 12.2 Tracing

Each engagement/session gets a trace ID. Subagent spans logged as structured JSON.

### 12.3 Health Checks

- PostgreSQL connectivity
- Redis connectivity
- MinIO connectivity
- Ollama model availability
- Docker daemon responsive

---

## 13. Testing Strategy

### 13.1 Unit Tests
- Orchestrator state transitions (mock everything)
- Tool allowlist validation
- CVSS calculator accuracy
- Audit chain integrity
- Compaction algorithm correctness

### 13.2 Integration Tests
- Mock LLM (returns fixed Pydantic objects)
- PostgreSQL test container
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
- Audit log tamper resistance
- File access boundary tests

---

## 14. Quick Reference

```
DUAL-MODE SYSTEM
  [COPILOT] <--Shift+Tab--> [PURPLE TEAM]

GENERAL COPILOT
  - Conversational cybersecurity assistant
  - Scoped file read/write (approval-gated)
  - Web search, CVE lookup, tool docs
  - Session STM with Strix-style compaction
  - User LTM + System LTM

PURPLE TEAM (10-STATE LOOP)
  INIT -> RECON_PASSIVE -> RECON_ACTIVE -> HYPOTHESIZE -> HUMAN_REVIEW
    -> EXPLOIT -> [HITL] -> POST_EXPLOIT -> VERIFY -> BLUE_TEAM -> REPORT -> HALT

9 SAFETY LAYERS
  Scope -> Allowlist -> File Scan -> Env Filter -> STM Size -> Sandbox
    -> Dry Run -> Blocklist -> Audit Chain

TECH STACK
  Python 3.11+ | LiteLLM | Instructor | PostgreSQL | Redis | MinIO
  Docker + gVisor | Jinja2 | Pydantic | Bubble Tea (TUI)

EXPLICITLY EXCLUDED
  LangChain | LangGraph | SQLite | KuzuDB | Shell strings
  LLM-driven state transitions | Unrestricted file access
```

---

*End of Kryonsec v2.1 specification. This is the design-of-record.*
