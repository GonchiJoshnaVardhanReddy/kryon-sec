# Kryonsec v2.1 — Draft Fixes

**Date:** 2026-09-03
**Base document:** `kryonsec-v2.1-dual-mode-architecture.md`
**Status:** Proposed changes. None of these are merged into the spec yet.

---

## Table of Contents

1. [Critical Schema Bugs](#1-critical-schema-bugs)
2. [Broken Entrypoint Script](#2-broken-entrypoint-script)
3. [Count Inconsistencies](#3-count-inconsistencies)
4. [Deployment Weight vs. Pitch](#4-deployment-weight-vs-pitch)
5. [Passive Recon vs. Sandbox Egress](#5-passive-recon-vs-sandbox-egress)
6. [Mode A / Purple Team Data Access Contradiction](#6-mode-a--purple-team-data-access-contradiction)
7. [Secrets Flowing to Third-Party LLMs During Compaction](#7-secrets-flowing-to-third-party-llms-during-compaction)
8. [Docker Socket Exposure](#8-docker-socket-exposure)
9. [Smaller Fixes](#9-smaller-fixes)
10. [Priority Order](#10-priority-order)

---

## 1. Critical Schema Bugs

### 1.1 JSONB in PRIMARY KEY (invalid in PostgreSQL)

**Affected:** `ltm_tool_efficacy`, `ltm_negative_memory` (spec §4.6, lines 463–478)

PostgreSQL does not allow `jsonb` columns in a primary key. Replace the JSONB key
with a deterministic hash of the fingerprint.

**Fixed schema:**

```sql
-- Helper: stable hash of a JSONB value (canonical form)
CREATE OR REPLACE FUNCTION jsonb_hash(v JSONB)
RETURNS TEXT AS $$
    SELECT encode(digest(jsonb_strip_nulls(v)::text, 'sha256'), 'hex')
$$ LANGUAGE sql IMMUTABLE;

-- Requires the pgcrypto extension:
CREATE EXTENSION IF NOT EXISTS pgcrypto;

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

**Note:** `ltm_target_profiles` (line 456) is unaffected — its PK is `target_hash TEXT`, which is fine.

### 1.2 Non-immutable function in a GENERATED column

**Affected:** `stm_nodes.size_bytes` (spec §4.5, line 430)

`pg_column_size()` is not `IMMUTABLE`, so it cannot be used in a `GENERATED ALWAYS
AS ... STORED` expression — the `CREATE TABLE` will fail.

Two options; **Option A is recommended** (simpler, no trigger timing issues):

**Option A — compute in the application layer, enforce via CHECK:**

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
```

The repository layer computes `size_bytes = len(json.dumps(properties).encode())`
before insert. Keep the existing size-enforcement trigger as-is — it already
works off `size_bytes`.

**Option B — BEFORE INSERT/UPDATE trigger (keeps it in the DB):**

```sql
CREATE OR REPLACE FUNCTION set_stm_node_size()
RETURNS TRIGGER AS $$
BEGIN
    NEW.size_bytes := pg_column_size(NEW.properties);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_stm_node_size
BEFORE INSERT OR UPDATE ON stm_nodes
FOR EACH ROW EXECUTE FUNCTION set_stm_node_size();
```

---

## 2. Broken Entrypoint Script

**Affected:** spec §8.5 `entrypoint.sh` (lines 965–994)

Three bugs in the current draft:

1. The script reads argv as JSON from **stdin**, then executes `timeout 300 "$@"` —
   but `$@` is the *container's* arguments, not the parsed JSON. The JSON is never
   executed.
2. `... 2>&1 | jq -Rs '{"stdout": ., "exit_code": 0}'` hardcodes `exit_code: 0`
   and effectively reports jq's exit status, not the tool's.
3. `set -euo pipefail` + the pipe means tool failures get masked entirely.

**Fixed approach — pass argv as container args (no stdin JSON, no jq dependency):**

The cleaner design is for `KaliSandbox.spawn()` to pass the argv list as actual
container arguments (`command=argv`) rather than JSON on stdin. The entrypoint
then never parses anything untrusted:

```dockerfile
# ENTRYPOINT receives the tool argv as container args: docker run ... nmap -sV target
ENTRYPOINT ["/entrypoint.sh"]
```

```bash
#!/bin/bash
# containers/sandbox/entrypoint.sh
# Receives tool argv as container arguments. Executes ONLY allowlisted tools.
# Usage: entrypoint.sh <tool> [args...]

set -uo pipefail

TOOL="${1:-}"

# ---- Layer 2 (in-sandbox): tool allowlist ----
ALLOWED_TOOLS=(
    "nmap" "masscan" "dnsx" "subfinder"
    "sqlmap" "nikto" "gobuster" "ffuf"
    "curl" "wget" "nc" "ncat" "openssl" "python3"
    "linpeas.sh" "bloodhound.py"
)

if [[ -z "$TOOL" ]] || [[ ! " ${ALLOWED_TOOLS[*]} " =~ " ${TOOL} " ]]; then
    printf '{"error": "tool_not_in_allowlist", "tool": "%s"}\n' "$TOOL" >&2
    exit 125
fi

# ---- Execute, capture output and REAL exit code ----
OUTFILE="$(mktemp /tmp/toolout.XXXXXX)"
timeout --signal=KILL 300 "$@" >"$OUTFILE" 2>&1
EXIT_CODE=$?

# Emit JSON: stdout payload + true exit code on stderr's FD convention:
# payload on stdout, metadata on fd 3
printf '{"exit_code": %d, "stdout": ' "$EXIT_CODE"
python3 - "$OUTFILE" <<'PY'
import json, sys
with open(sys.argv[1], "rb") as f:
    sys.stdout.write(json.dumps(f.read(errors="replace").decode("utf-8", "replace")))
PY
printf '}\n'
rm -f "$OUTFILE"

exit "$EXIT_CODE"
```

**Corresponding `KaliSandbox.spawn()` change** (spec lines 1004–1028):

```python
container = await self.docker.run(
    image=self.IMAGE,
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
    command=argv,          # <-- argv as container args, NOT stdin JSON
    auto_remove=True,
)
```

**Additional hardening notes:**

- The mktemp output file lives in `/tmp` (tmpfs, `noexec`) — bounded at 100MB by
  the mount, which also serves as output bounding at the sandbox level.
- `noexec` on `/tmp` already prevents dropping-and-running a binary; keep it.
- The hardcoded allowlist in the entrypoint is defense-in-depth *only* — the
  authoritative allowlist check remains Layer 2 in `ToolRunner` on the host.

---

## 3. Count Inconsistencies

Two mislabels, both low-effort:

### 3.1 "10-state loop" is actually 11 states

`STATES` (spec line 307) lists: INIT, RECON_PASSIVE, RECON_ACTIVE, HYPOTHESIZE,
HUMAN_REVIEW, EXPLOIT, POST_EXPLOIT, VERIFY, BLUE_TEAM, REPORT, HALT — that is
**11** entries.

**Fix (pick one, be consistent everywhere — §1, §4.2, §14):**

- **Option A (recommended):** "10-state loop + terminal HALT" — describe HALT as
  the terminal state, not a loop state. The transition table already treats it
  that way (nothing transitions out of HALT).
- **Option B:** Just say "11-state" everywhere.

### 3.2 "9 safety layers" vs. 10 in the code

`ToolRunner.run()` (spec §8.1) implements Layers 1–10 (Layer 10 is output
bounding), but §8.1's prose says "9 safety layers," the §9.1 table lists 9, and
§8.5's table says 9. Meanwhile §4.5/§9.3 also reference "9 layers."

**Fix:** Add output bounding to the §9.1 table as Layer 10 and change all prose
to "10 safety layers":

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

Update the Quick Reference (§14) accordingly.

---

## 4. Deployment Weight vs. Pitch

**Problem:** The spec sells "`pip install kryonsec && kryonsec` just works"
(§2 Design Decisions) but requires PostgreSQL + Redis + MinIO + Ollama + Docker
**+ gVisor**. Additionally, gVisor (`runsc`) is **Linux-only** — it does not run
on Windows or macOS Docker Desktop, which silently breaks the core sandbox
guarantee on those platforms.

**Proposed fix — tiered deployment profiles:**

### Profile 1 — "Copilot only" (the `pip install` promise)

No Docker, no gVisor, no purple team. This is what `pip install kryonsec` gets
you:

- SQLite (or embedded Postgres via `pg_embed`-style binary) for general-mode
  memory — despite §14's "EXPLICITLY EXCLUDED: SQLite," general-mode chat
  history does not need Postgres-grade concurrency. Revisit that exclusion, or
  scope it to "purple team never uses SQLite."
- Purple team commands print: *"Purple Team mode requires the full stack
  (Docker, gVisor, Linux). Run `kryonsec doctor` for setup instructions."*

### Profile 2 — "Full stack" (purple team)

- Linux only (bare metal or VM). State this explicitly in §11.
- `kryonsec doctor` command: preflight-checks Docker, runsc availability
  (`docker run --rm --runtime=runsc hello-world`), PostgreSQL, proxy container,
  Kali image, and prints a pass/fail report.
- On Windows/macOS hosts, document the supported path: Linux VM (or WSL2 with a
  Docker daemon configured with `--runtime=runsc` inside WSL2 — note this is
  finicky and should be tested before promising it).

### Spec edits

- §2 Design Decisions: change the "Single-user CLI" rationale to reflect the
  two profiles.
- §11.1: add a prominent **"Linux required for Purple Team mode (gVisor)"**
  note at the top of the compose section.
- §11.2: installation section describes both profiles.

---

## 5. Passive Recon vs. Sandbox Egress

**Problem:** RECON_PASSIVE uses shodan, censys, crt.sh, waybackurls, gau — all
**third-party APIs**, not the target. But the sandbox blocks egress to
everything except `target_scope` (§8.2/§8.3). As written, every passive recon
tool fails at the network layer, or — worse — someone "fixes" it by opening
egress and breaks the isolation story.

**Proposed fix — two execution zones:**

```
┌─────────────────────────────────────────────────────────────┐
│ ZONE A: HOST-ORCHESTRATED (RECON_PASSIVE only)              │
│                                                             │
│  Passive tools run as host-side modules, NOT in the Kali    │
│  sandbox. Egress rules:                                     │
│    ALLOW: dns, ntp, and an explicit allowlist of            │
│      third-party recon APIs:                                │
│      api.shodan.io, search.censys.io, crt.sh,               │
│      web.archive.org, otx.alienvault.com                    │
│    DENY:  everything else, INCLUDING the target's own       │
│      web infrastructure (passive = no packets to target;    │
│      enforced at the proxy for this zone)                   │
│                                                             │
│  API keys (shodan/censys) injected per-run from the         │
│  secret sidecar; never on disk in the engagement record.    │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ ZONE B: KALI SANDBOX (RECON_ACTIVE, EXPLOIT, POST_EXPLOIT,  │
│ VERIFY)                                                     │
│                                                             │
│  Unchanged from §8.2: egress only to target scope, through  │
│  the traffic-shaping proxy, with canary health checks.      │
└─────────────────────────────────────────────────────────────┘
```

**Spec edits:**

- §4.2 state table: annotate RECON_PASSIVE tools as *Zone A (host modules)*;
  everything from RECON_ACTIVE onward as *Zone B (sandboxed)*.
- §8.2 sandbox config: add a comment that passive recon does not run here.
- §8.3 proxy: define two egress profiles (Zone A / Zone B) instead of one.
- New invariant worth stating in §9: **"RECON_PASSIVE sends zero packets to the
  target"** — make it a testable claim (§13.4: run an engagement against a
  controlled target with a packet counter; assert 0 packets during
  RECON_PASSIVE).

---

## 6. Mode A / Purple Team Data Access Contradiction

**Problem:** §3.2 says General mode "cannot access purple team engagement
data" (line 108), but §5.2 has General mode reading
`ltm_engagement_summaries` (line 483) and §5.3's table explicitly grants
"Engagement summaries: Read-only" to General mode.

**Fix:** Reword §3.2 to match the §5.3 matrix (the matrix is the intended
behavior — the whole point of the Purple → General handoff is "explain finding
#3 in simple terms"):

> **§3.2, replace the fourth bullet:**
> - Access live purple-team engagement data (STM, raw evidence, credentials)
>   — **blocked**. General mode sees only sanitized, post-REPORT engagement
>   summaries via `ltm_engagement_summaries` (read-only), as defined in §5.3.

Also add to the sanitization step when summaries are written (end of REPORT
state):

- PII regex scan (reuse §4.9's report checks)
- Credential/secret pattern redaction (the same patterns §6.2's compaction
  prompt tries to *preserve* — here we *strip* them)
- Only findings metadata: title, severity, CVSS, status — never raw evidence
  paths' contents

---

## 7. Secrets Flowing to Third-Party LLMs During Compaction

**Problem:** The compaction prompt (§6.2) explicitly instructs the model to
preserve "credentials, tokens, keys, hashes, payloads" verbatim — and
`PROVIDER_ROUTING` sends compaction to `gpt-4o-mini` (line 718), i.e., a
third-party API. In a pentest context, extracted credentials leaving the
engagement boundary for OpenAI's servers is a serious confidentiality and
chain-of-custody problem (and would be a reportable issue in most engagement
contracts).

**Proposed fix — classify and route:**

1. **Add a secret-detection pass before compaction.** Scan the head messages
   for credential patterns (API keys, JWTs, password strings, private key
   blocks — same detector family as §4.9's PII scan).
2. **Redact-and-tokenize before the LLM call.** Replace each detected secret
   with a placeholder (`«SECRET_1»`, `«SECRET_2»`, …) and keep the mapping in
   a local, encrypted side table (`engagement_secret_map`, never sent to any
   LLM, never included in the summary).
3. **Restore after summarization.** The compressor re-substitutes placeholders
   with real values in the checkpoint message, so downstream states still see
   exact values — the behavior §3.4 wants is preserved.
4. **Route compaction locally when secrets are present.** If the head contains
   secrets and any provider routing points at a hosted API, fall back to
   `ollama/*` for that compaction call (or refuse and require explicit
   user opt-in, recorded in the audit chain).

```python
async def compact_session(messages, model, max_tokens):
    ...
    head, tail = split(...)
    head, secret_map = redact_secrets(head)          # local, no LLM
    summary = await llm_call(model=compaction_model_for(head), ...)
    summary = restore_secrets(summary, secret_map)   # local, no LLM
    return [checkpoint(summary)] + tail
```

**Spec edits:** new subsection §6.4 "Secret handling during compaction";
§7.1 routing table gains a note that `compaction` routes to Ollama whenever
`secret_map` is non-empty.

---

## 8. Docker Socket Exposure

**Problem:** §11.1 mounts `/var/run/docker.sock` into the `kryonsec` container
(line 1275). Docker socket access is host-root-equivalent — a compromise of the
kryonsec process (e.g., via a malicious tool output, prompt injection, or a
library vuln) means full host takeover. This materially undermines the "LLM
cannot escape" story, because the escape doesn't need to go through the sandbox
at all.

**Proposed fix — socket proxy with command allowlisting:**

Use [`tecnativa/docker-socket-proxy`](https://github.com/Tecnativa/docker-socket-proxy)
(or equivalent) so the kryonsec process can only perform the specific Docker
operations it needs (create/start/inspect containers with the pinned sandbox
image), not arbitrary ones:

```yaml
  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1        # list/create/inspect containers
      POST: 1              # create + start (needed to spawn sandbox)
      IMAGES: 0            # no image management from the app
      NETWORKS: 0
      VOLUMES: 0
      EXEC: 0              # no exec into arbitrary containers
      ALLOW_RESTARTS: 0
      SECRETS: 0
      SWARM: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks: [kryonsec-internal]

  kryonsec:
    environment:
      DOCKER_HOST: tcp://docker-socket-proxy:2375
    # NO docker.sock mount on this service
    depends_on: [postgres, redis, minio, ollama, docker-socket-proxy]
```

**Defense-in-depth additions:**

- Pin the sandbox image reference (`kryonsec/sandbox:kali-latest@sha256:...`)
  so the app can only ever spawn that digest, and have the socket proxy
  config disallow image pulls (`PULL: 0` / ` IMAGES: 0`).
- Consider a dedicated `kryonsec-docker` user on the host restricted via
  Docker's rootless mode, if the deployment supports it.
- Add a §13.4 security test: from inside the kryonsec container, attempt
  `docker run` with a different image and mount the host root — must fail.

---

## 9. Smaller Fixes

### 9.1 `masscan` + canary health checks are a bad combination

`masscan` can saturate a target in seconds — far faster than a before/after
canary can react. Options (recommend A):

- **A (recommended): Remove `masscan` from the allowlist.** `nmap` with
  `--max-rate` covers rate-limited port scans; anything needing masscan speeds
  is out of scope for a HITL, canary-guarded tool.
- **B: Keep it, but make the rate a *required* template parameter with a hard
  ceiling** (`--max-rate={<=1000}`), enforced by the proxy's packets-per-second
  limit set *lower* than the ceiling, and add an intra-run canary (checked
  every N seconds, not only before/after).

### 9.2 Kali Dockerfile package names

- `linpeas` is not a standard Kali apt package — it comes from the PEASS
  repository (or `peass` package, depending on Kali version). Either install
  from the PEASS release URL with **checksum verification**, or vendor a pinned
  copy into the image build context.
- `bloodhound.py` is a pip package (`pipx install bloodhound` or
  `pip install bloodhound.py`), not apt.
- The `apt-get remove ... 2>/dev/null || true` line (line 945) will silently
  no-op on the minimal install since those packages were never installed —
  fine as belt-and-braces, but the comment should say so. Better: use a Kali
  metapackage-free base and never install them at all (which the Dockerfile
  already does).

### 9.3 Nuclei template downloads vs. no-internet sandbox

`nuclei -t` needs template files. Options:

- Bake templates into the image at build time (`nuclei -update-templates`
  during `docker build`), refreshed by the `kryonsec tools update` flow (§8.5
  already has the update mechanism — extend it to cover templates).
- Or allow egress to `http://templates.nuclei.sh`/GitHub raw only, via the
  Zone A proxy profile (see §5 of this document), fetched host-side and
  mounted into the sandbox read-only.

### 9.4 "PostgreSQL for everything" claim

§2 says "one database to back up" while the stack also runs Redis and MinIO —
and now (per fix #4) possibly SQLite for Profile 1. Reword the rationale to
"PostgreSQL is the *system of record*; Redis is ephemeral cache only;
MinIO is object storage for evidence" so the claim is accurate about what
actually needs backing up.

### 9.5 Audit chain: SHA256 without a trust anchor

A bare SHA256 chain detects accidental corruption but a attacker with file
access can rehash the whole chain. For a single-user local tool this is
arguably acceptable, but one cheap hardening: periodically (daily per §10.2)
write the current head hash to an external anchor — e.g., a WORM-locked MinIO
object, and/or print it for the user to record. State the threat model
explicitly in §10.2 so the limitation is documented rather than implied.

### 9.6 STM size trigger is O(n) per insert

The `check_stm_size()` trigger runs `SELECT SUM(size_bytes)` over all
engagement nodes on every insert. Fine at expected scale, but a covering index
makes it cheap and future-proof:

```sql
CREATE INDEX idx_stm_nodes_engagement_size
    ON stm_nodes (engagement_id) INCLUDE (size_bytes);
```

---

## 10. Priority Order

If this is heading toward implementation, apply in roughly this order:

| # | Fix | Why this order |
|---|---|---|
| 1 | §5 — Passive recon execution zone | Blocks the RECON_PASSIVE state from working *at all* as specced |
| 2 | §1 — Schema bugs (JSONB PK, generated column) | The `CREATE TABLE`s literally fail; fix before any migration is written |
| 3 | §2 — Entrypoint script | The sandbox executes the wrong thing and reports wrong exit codes |
| 4 | §8 — Docker socket proxy | Closes the biggest hole in the isolation story |
| 5 | §7 — Secret redaction in compaction | Confidentiality issue that compounds over every engagement |
| 6 | §4 — Deployment profiles | Sets honest expectations; gates platform support (Windows/macOS) |
| 7 | §3 — Count fixes | Trivial, do alongside any edit pass |
| 8 | §6 — §3.2 rewording | One paragraph |
| 9 | §9 — Smaller fixes | Batch with the relevant sections when touched |

---

*End of draft fixes. These are proposals — each numbered section should be
reviewed and, if accepted, merged back into the v2.1 spec (or carried into a
v2.2 changelog) rather than maintained as a separate document long-term.*
