# Changelog

## Unreleased — Tool Expansion Batches 1–6 + Waves 1–2 (feature branch, not released)

Six new vetted RECON_ACTIVE adapters — `naabu-probe`, `dnsx-probe`,
`katana-probe` (Batch 1), then `nmap-probe`, `feroxbuster-probe`,
`gowitness-probe` (Batch 2) — built on the existing Phase 2B adapter
framework, structured agent handoffs with a deterministic coordinator and
shared evidence (Batch 3, Phase 3A + 3C), the advanced multi-agent
layer above it: bounded specialist scheduling, task-scoped context, real
checkpoint resume with shared budgets, and reviewed read-only skill packs
(Batch 4, Phase 4A–4D), and the exploit/verification contract layer:
typed EXPLOIT input contracts, a registered per-category verification
contract, recorded counterevidence with the honest `unresolved` status,
and the read-only verification-support specialist (Batch 5, Phase
5A–5D), and the controlled Post-Exploit lifecycle: engagement-bound,
stamped, expiring and revocable capability records, one ordered
consumption-time eligibility check, a one-shot consumption guard with
crash-safe recovery, and bounded coordinator handoffs (Batch 6, Phase
6A–6D), and the Wave-1 archives module — historical URL + parameter
discovery from third-party archives as host-side Zone A sources (zero
packets to the target, no image change), and the Wave-2b JWT token
producer — an offline analyzer that feeds the previously-gated
jwt_tool lane from captured evidence. Branch
`feature/tool-expansion-batch1`; nothing below is published yet.

### New vetted adapters (Batch 2)

- **nmap-probe** (the authoritative stage-1 service scan) runs nmap with the
  SAME fixed argv the legacy discovery entry uses (`-Pn -sT -sV -sC
  --max-rate 100 -p RECON_PORTS` — `-sT` because gVisor grants no raw
  sockets; the bounded 18-port list, never a full-range scan). It REUSES the
  legacy TEXT parser (`parse_nmap_services` — no second regex to drift) and
  emits the SAME legacy-shape `service` nodes, now with adapter provenance
  (`target:port/proto` labels, first-wins dedupe). Replaces the legacy nmap
  entry deterministically; NOT planner-gated (pre-plan discovery lane,
  reported `covered` post-hoc like naabu/dnsx).
- **feroxbuster-probe** (content discovery) runs feroxbuster with the legacy
  `-u {urlfuzz} -w <baked seclists> -t 5 --timeout 30` shape. The FUZZ-marker
  URL is composed DETERMINISTICALLY by the adapter framework from the
  scope-validated base (`base.rstrip('/') + '/FUZZ'` — the same composition
  the legacy entry applies); the lane can never point the fuzzing at a
  different origin than the base it was given, and a params dict carrying
  `urlfuzz` is refused as unexpected. Reuses the legacy result-line regex
  (`_FEROX_RE`/`_FEROX_STATUS` — lockstep by construction); emits legacy
  shape `path` nodes with adapter provenance, first-wins dedupe by label
  (cross-source: a path katana or a passive source already placed is
  skipped). Replaces the legacy feroxbuster entry; planner-gated like every
  other web lane.
- **gowitness-probe** (screenshots) runs gowitness with the legacy
  `scan website --url {base} --screenshot-path /evidence --no-console
  --disable-db` shape — the PNG lands in the rw `/evidence` mount (the
  engagement folder), NOT in tool output. There is NO text contract to
  parse: the run's exit code is the truth. ONE legacy-shape `screenshot`
  node per successful run (label = the base URL, `dir=/evidence` plus
  adapter provenance); a refused/failed run records NO node. Replaces the
  legacy gowitness entry; planner-gated like every other web lane.
- **TEXT output contracts, not `-json/-oX`**: the shipped Layer-2 templates
  stay in lockstep, and XML/JSON field shapes could not be verified against
  the real binaries from the development environment.
- **No allowlist or image change**: all three binaries were already
  allowlisted and baked into the pinned sandbox image.

### New vetted adapters (Batch 1)

- **naabu-probe** (TCP port discovery) runs the image's real naabu with the
  SAME fixed argv the legacy discovery entry uses — the lane pins
  `ports=RECON_PORTS` (the bounded 18-port list, never a full-range scan) and
  `rate=100`. Legacy parity preserved: the parsed ports merge into the shared
  `open_ports` set and the adapter adds **no graph nodes of its own** — the
  run's `adapter_attempt` node is the evidence. Replaces the legacy naabu
  entry deterministically (one probe per check, never both).
- **dnsx-probe** (DNS resolution) runs dnsx with the legacy `-d {target}
  -silent` shape and emits ONE legacy-shape `dns_resolution` node (all IPs,
  adapter provenance, first-wins dedupe). A clean run that resolves nothing
  is an honest INCONCLUSIVE — no node, no negative claim. Replaces the legacy
  dnsx entry.
- **katana-probe** (web crawl) runs katana with the legacy `-u {url} -d 2
  -silent` shape, the crawl depth pinned to `2` via a named constant (a
  deeper crawl would be a conscious code change, never caller input).
  Emits legacy-shape `path` nodes with adapter provenance, first-wins dedupe
  by label (cross-source: a path another source already placed is skipped).
  Replaces the legacy katana entry; planner-gated like every other web lane.
- **TEXT output contracts, not `-json`**: the shipped Layer-2 templates must
  stay in lockstep, and the JSON field shapes could not be verified against
  the real binaries from the development environment. `-silent` text lines
  (`host:port`, IPs, bare URLs) parse deterministically with bounded,
  defensive parsers.
- **No allowlist or image change**: all three binaries were already
  allowlisted and baked into the pinned sandbox image.

### Planner (2B.6) — domain-target pairing

- `ToolPlanner.plan()` gained a `domain_targets` parameter: domain-kind
  adapters (nmap-probe, naabu-probe, dnsx-probe) are paired ONLY with the
  engagement target, never with URL bases; URL-kind adapters pair only with
  bases. The three discovery lanes run BEFORE the plan (they produce the
  ports it plans from) and are reported as `covered` post-hoc; a FAILED lane
  stays selected and is honestly listed as planned-but-not-executed. The
  planner remains **OFF by default**; with it off, behavior is identical to
  the fixed plan plus the six adapter lanes. Planner metadata now covers all
  eleven registered adapters (priority, cost, requires/produces evidence).

### Tests and honest status

- Batch 1 mocked suites: `tests/test_dnsx_adapter.py` (24),
  `tests/test_naabu_adapter.py` (22), `tests/test_katana_adapter.py` (26).
- Batch 2 mocked suites: `tests/test_nmap_adapter.py` (28),
  `tests/test_feroxbuster_adapter.py` (27), `tests/test_gowitness_adapter.py`
  (25) — argv lockstep against the shipped Layer-2 templates (byte-identical,
  including the framework-composed `{urlfuzz}`), scope/option-injection
  refusals, unexpected-params refusals (the FUZZ URL and the screenshot dir
  are never caller input), gate/sandbox/egress refusals, honest failure
  classification, bounded output, `not_verified` invariants, either/or
  integration (one probe per check, never both), planner gating, and
  no-subprocess scans. Plus one opt-in real-gVisor lab IT per adapter
  (`KRYONSEC_NAABU_IT=1`, `KRYONSEC_DNSX_IT=1`, `KRYONSEC_KATANA_IT=1`,
  `KRYONSEC_NMAP_IT=1`, `KRYONSEC_FEROX_IT=1`, `KRYONSEC_GOWITNESS_IT=1`) —
  **armed but NOT RUN on the Windows dev host**; run them in the Linux lab.
- Full suite on the branch after Batch 2: 2,481 passed / 61 skipped (WSL2,
  Python 3.14); the 2 failures are environmental (no `ensurepip` in that
  Python; no docker group access), not regressions.

### Structured agent handoffs (Batch 3 — Phase 3A + 3C)

The specialist states now exchange **typed, de-duplicated, persisted**
messages through a deterministic coordinator — data exchange along the
existing workflow, never a second transition authority. No new LLM calls,
no new tools, no allowlist or image change; Gate 2 and Gate 3 are exactly
where they were.

- **Typed contracts** (`purple/handoff.py`): eight Pydantic message kinds —
  `TaskAssignment`, `EvidenceRef`, `Observation`, `TaskResult`, `BlockedTask`,
  `HumanApprovalRequest`, `VerificationResult`, `CompletionSummary` — each
  carrying engagement id, source/destination, correlation id, hypothesis /
  finding / evidence refs, a bounded sanitized `content` (one line, capped,
  **redacted first** so a length cap can never split a secret into a
  fragment that no longer matches a pattern) and a status from a closed
  vocabulary. `extra="forbid"` is the impersonation control: **no schema
  accepts an `approved` field**, so a producer cannot claim a human decision
  it did not receive; the only approval-shaped message is a `HumanApprovalRequest`
  pinned `requested_of="human"`, and `requires_approval` on assignments is
  derived from the task-type safety class, never declared by the caller.
- **Deterministic dedup**: stable content-addressed identities
  (`task_identity` / `message_identity` = SHA256 over engagement, task type,
  normalized target, subject — plus content for data messages). A re-dispatch
  of a known identity never creates a second record; it returns one word from
  the closed `DISPATCH_OUTCOMES` set that says what the known record means:
  `new`, `already_registered`, `already_completed`, `already_recorded`,
  `in_progress`, `safe_retry`, `needs_approval`, `blocked`, `failed`,
  `inconclusive`. Outcomes are **never invented** — a record that says
  `failed` stays `failed`.
- **The one rule the batch exists for**: a failed/inconclusive/cancelled
  **state-changing** task (exploit test, verification probe, post-exploit
  enumeration) is never silently re-run because a dispatcher asked twice —
  the answer is the same status word, and `retry()` is refused until the
  task goes back through a recorded human approval. Read-only work may
  retry freely (`safe_retry`).
- **A closed transition table** (`purple/coordinator.py`): every status
  change is validated against `TRANSITIONS`; anything else raises
  `HandoffTransitionError` and is audited (`handoff_invalid_transition`).
  Terminal statuses have no exits; `needs_approval -> registered` is the one
  recovery, and it is `approve()` recording a decision a human gate already
  made — never a message's word.
- **Shared evidence stays in the ONE graph**: evidence links are node ids
  plus a `produced`/`consumed` role into the engagement's `EngagementGraph`
  — never a copy of raw output. A register whose evidence refs don't resolve
  in the live graph is refused (`MissingEvidenceError`); another
  engagement's evidence is unreachable (`CrossEngagementError`).
- **Persistence via the existing storage layer**: one `handoff_records` row
  per record (SQLAlchemy `HandoffRecordRow`, unique on engagement +
  identity-key), replaced per engagement in a single transaction — replaying
  a save writes the same rows, a restored coordinator re-deduplicates, and a
  foreign or future-version payload is refused loudly. Migration
  `0003_handoff_records`, gated on the same purple-storage check as 0002
  (the Copilot fallback database never grows engagement tables).
- **Wired at the state boundary**: `purple/runner.start_engagement` attaches
  a `StageBoundaryRecorder` to the same `on_state_complete` boundary the
  graph checkpoint uses. After a state finishes (and AFTER the orchestrator
  has already chosen the next one), it derives records from the graph —
  RECON summaries, HYPOTHESIZE observations, the Gate 2 outcome plus one
  assignment per approved hypothesis (registered as data, never as the
  reason EXPLOIT runs), EXPLOIT/VERIFY execution results read from the
  attempts' own evidence (a not-run attempt produces NO invented record),
  BLUE_TEAM/REPORT summaries. Every handler is best-effort: a derivation
  problem is audited (`stage_boundary_failed`) and never fatal, and the
  loop's transition decision is never an input to it. Records checkpoint at
  every boundary and persist at HALT (`handoff_checkpoint_written`,
  `handoff_persisted`), with the same reported-never-fatal failure policy
  as the graph checkpoint.
- **What it does not do (yet — Batch 4)**: no agent memory/context, no
  per-agent token budgets, no scheduler that dispatches specialists from the
  records, and no real Docker/gVisor validation of the wiring (mocked tests
  only, by design on this host).

### Advanced multi-agent intelligence (Batch 4 — Phase 4A–4D)

The layer ABOVE Batch 3's coordinator: bounded specialist scheduling, a
task-scoped context builder, real checkpoint resume with shared budgets,
and reviewed read-only skill packs. Same shape as the previous batches —
deterministic Python, no new LLM calls at the boundaries, no new tools, no
allowlist or image change, Gate 2/Gate 3 exactly where they were. Nothing
below runs a security tool: the only deterministic executor is graph
analysis.

- **Bounded scheduling (4A, `purple/specialist.py`)**: six typed
  `SpecialistRole` capability descriptions — `recon_analysis`,
  `hypothesis_analysis`, `evidence_assessment`, `verification_support`,
  `defensive_recommendation`, `reporting`. Exactly ONE has a deterministic
  executor today (`EvidenceAssessmentSpecialist` — reads
  `hypothesis_engine_view` and grades with the engine's own standing
  vocabulary); the two LLM-backed roles say so in their `implements`
  mapping and are **deferred, never improvised** — `run_ready` refuses to
  fake an LLM role with a stub. `SpecialistTask` validates stage against
  the orchestrator's `STATES`, priority 0–100, timeout 10–3600 s, ≤8
  dependencies, `extra="forbid"`; submission must cite a known
  task-assignment record of the role's type, in the role's stage, in the
  coordinator's engagement (cross-engagement and type-mismatch refusals).
  Model proposals become read-only scheduled work ONLY through the
  coordinator's dedup identity; a state-changing proposal is refused at
  the door (audited `specialist_proposal_refused`).
- **Derivation at the HYPOTHESIZE boundary**: the Batch-3 recorder now
  derives one READ-ONLY `evidence_assessment` assignment per proposed
  hypothesis (capped at 12 per boundary, over-cap audited
  `handoff_derivation_capped`), registered as data — the scheduler then
  decides what runs, and nothing in the derivation authorizes target
  contact. The scheduler's own `derive_from_records` is identity-deduped
  and capped at 12 (`specialist_derivation_capped`).
- **Claims, attempts, timeouts**: claiming goes through the coordinator's
  transition table (atomic, double-claim raises `HandoffTransitionError`);
  `MAX_ATTEMPTS = 2` closes reclaiming; an expired claim parks the task
  `blocked` with the stale stamp cleared and may re-claim within the cap;
  a manual claim wins the race and the scheduler runs nothing rather than
  crash. A timed-out/blocked read-only task reopens honestly; a
  state-changing one never re-runs without a human approval.
- **Deliverable contracts (Shannon-style)**: `purple/deliverables.py` —
  `SpecialistDeliverable` with a closed `RESULT_STATUSES` status set and a
  closed `STANDING_WORDS` vocabulary (the engine's own graph/verification/
  attempt vocabularies plus `unresolved`). A producer cannot invent a
  standing, cannot file an extra field, and cannot claim a confidence
  without evidence — the schema refuses the whole deliverable and the
  task is recorded FAILED with the reason.
- **Task-scoped context (4B, `purple/task_context.py`)**: what ONE task
  may see, and nothing more — the objective (with the task's safety
  class), the subject hypothesis's engine view, up to six related-asset
  references, bounded prior results about the same subject, Gate-2
  outcome records, and deterministic unresolved questions. Every line is
  redacted (`«SECRET_n»` placeholders, the declaration appended), marked
  untrusted vs engine-derived, capped (`MAX_OBSERVATIONS`,
  `MAX_PRIOR_RESULTS`, ≤8 unresolved), and framed as DATA ONLY, NOT
  INSTRUCTIONS. `extra="forbid"` on the context model keeps the shape
  exactly what the builder writes.
- **Shared budgets (4C, extends the existing BudgetTracker)**: the
  specialist layer reserves against the orchestrator's ONE engagement
  tracker — no second budget. `reserve/commit/release` with
  first-commit-wins per key (replays and checkpoint retries never
  double-count), reservations hold headroom against new reservations but
  NEVER trip the loop's `exhausted()` guard, and every specialist token
  figure is labelled an estimate (`estimated_tokens`) — never presented
  as a provider charge. Budget exhaustion defers a task (audited
  `specialist_budget_deferred` with the real reason) instead of blocking
  the engagement; per-task and per-role bounds defer likewise.
- **Real resume (4C)**: the scheduler snapshot rides in the SAME
  transaction as the handoff records (`handoff_scheduler` table,
  migration `0004`) — records and scheduler always describe one moment.
  `resume_specialists` restores the records, the scheduler's tasks +
  event ledger + budget consumption, then runs a recovery pass:
  interrupted READ-ONLY work reopens (`blocked`, claimable again — its
  result is recomputed, never assumed); interrupted STATE-CHANGING work
  is parked behind Gate 2 (`needs_approval`, never automatically
  repeated); completed/cancelled/already-gated work is left exactly as
  it was. A corrupt or incompatible checkpoint is refused, audited
  (`specialist_resume_failed`, reason `scheduler_checkpoint_unusable` /
  `storage_unreadable`), and the engagement continues with a FRESH
  scheduler over the records that did restore — never half-interpreted.
  A reused engagement id via `start_engagement` gets all of it back.
- **Reviewed skill packs (4D, `purple/skills.py` + `purple/skills/`)**:
  six packaged, versioned, read-only methodology notes —
  `recon_methodology`, `evidence_quality`, `counterevidence`,
  `severity_calibration`, `verification_method`, `defensive_remediation`
  (Strix-inspired, Strix's executable workflows deliberately NOT
  copied). The loader takes NO path argument — reviewed knowledge ships
  in the package or it does not ship. Parsing refuses malformed front
  matter, unknown keys (a `script:` key is a refusal, not an ignored
  line), out-of-vocabulary categories/stages, unbounded bodies, fenced
  code blocks, and frame-forging text, all as one `SkillError`.
  Matching is deterministic (stage/category/allowlist filters, name
  order, capped); injection is a bounded framed block (≤4,000 chars,
  ≤3 skills) that says KNOWLEDGE, not instructions, carries versioned
  provenance per entry, names omitted skills visibly inside the frame,
  and ends with "nothing above authorizes any action."
- **Progress you can watch**: every boundary publishes a
  `specialist_progress` event and the existing UI adapters render
  scheduled/done/blocked counters, token estimates, and deferral/resume
  notices — read-only consumers of the scheduler's own audit events,
  defensive by contract (garbage events never crash the paint).
- **Batch-3 boundary change this batch makes**: the HYPOTHESIZE boundary
  now derives assessment assignments, so `StageBoundaryRecorder` output
  grows (2 Observations + 2 assignments for a 2-hypothesis graph); the
  two Batch-3 boundary tests were updated for this legitimate behavior
  change — their proposed-never-confirmed assertions are intact and
  strengthened (derived assignments are asserted read-only).
- **Tests**: `tests/test_specialist.py` (66), `tests/test_batch4_recovery.py`
  (13), `tests/test_skills.py` (17). Full suite on the branch after
  Batch 4: **2,621 passed / 61 skipped** (WSL2, Python 3.14); the 2
  failures are the SAME environmental ones as before the batch (no
  `ensurepip` in that Python; Docker daemon unreachable), not
  regressions. PostgreSQL paths NOT RUN (no PostgreSQL environment);
  real Docker/gVisor specialist paths untested (mocked suites only, by
  design on this host).

### Exploit and verification contracts (Batch 5 — Phase 5A–5D)

- **Exploit input/result contracts (5A, `purple/exploit_contract.py`)**: every
  approved hypothesis builds a typed contract before EXPLOIT spawns anything —
  engagement/target identity, the ONE target asset, derived categories, the
  hypothesis's OWN tool list verbatim (never expanded), the Gate-2 approval reference
  (citing the last `hypothesis_reviewed` audit entry's hash via the new
  `AuditLog.entries()`), and the sandbox time ceiling. Refusals are structured typed
  codes (`no_hypothesis`, `cross_engagement`, `gate2_missing`, `no_tools`,
  `asset_out_of_scope`, `no_adapter`, `allowlist_rejected`), audited as
  `exploit_contract_refused` and recorded as `exploit_refusal` graph nodes — a skipped
  test is visible evidence. Historical audit events are byte-identical. The attempt
  record gains engagement/hypothesis/approval references, input evidence node ids, a
  structured failure classification reusing the sandbox's `SPAWN_ERROR_KIND_*` words
  verbatim (+ `tool_exit_error` / `unknown_spawn_failure`), duration, the
  `tool_result` audit hash for correlation, and the written limitations of
  marker-based confirmation: a successful spawn and an exit code are neither evidence
  of a vulnerability nor an independent check.
- **The finding-verification contract registry (5B, `purple/verify_contract.py`)**:
  the boolean curl probe is a REGISTERED contract scoped to `sqli` — the one category
  it is evidence for. A contract binds category → one independent method and states
  tool, prerequisites, expected/contradictory observations, budget (probes +
  per-probe seconds, enforced in the fixed `curl --max-time` argv), stage (VERIFY
  only), approval basis, and `confidence_limit` (what the method CANNOT establish),
  recorded on every attempt. Registration fails closed: unimplemented `method_type`,
  `unknown`/unreachable categories, duplicates, bad bounds all refuse. Production
  starts with exactly ONE entry. The false-positive fix: a nikto/dalfox finding on
  `?id=1` is no longer probed with the boolean-SQL method — unsupported categories
  take an honest `not_run` ("no verification contract for category 'x'") and keep
  only reachability evidence. Independence is enforced: a contract whose tool can
  produce findings in its own category refuses a finding from that tool.
- **Counterevidence and `unresolved` (5C, `purple/evidence_quality.py` + verify/views
  changes)**: every verify_attempt records a `counterevidence` list — observations
  that undermine its own verdict — verbatim, never discarded. On an agreeing signature
  the verifier fetches a SECOND baseline (the contract's 4th probe): if the baseline
  moves, content rotates and the difference may be benign — counterevidence recorded,
  finding NOT promoted, status `unresolved` (new vocabulary word: agreeing difference
  seen, benign explanation stands, question left open). A substantial difference
  without a baseline no longer reads `verified`. Promotion requires agreement AND
  zero counterevidence. The quality review derives five Strix/Shannon-style checks
  per attempt (ran, reachability, baseline control, independence,
  conclusion-strength-vs-observations) and quality words (`supported` /
  `contradicted` / `contested` / `weak` / `reachability_only` / `blocked` / `none`)
  — annotation over the status derivation, never a promotion path;
  `finding_verification_detail` exposes counterevidence additively.
- **The verification-support specialist (5D, `purple/specialist.py` + handoff)**:
  new READ-ONLY task type `verification_analysis` (distinct from the state-changing
  `verify_check`, which stays the VERIFY state's own work); the role's deterministic
  executor reads a finding's verification records (`finding_verification_detail` +
  `evidence_quality`) and files the derived standing, the counterevidence verbatim,
  and the deterministic open questions. It never spawns a tool — a specialist that
  could probe would be a second, uncontracted path to target contact. Derivation:
  verification_analysis records registered at the VERIFY boundary become specialist
  tasks (identity-deduped, capped at 12); checkpoint/resume covers it like every
  other read-only task.
- **Tests**: `tests/test_exploit_contract.py` (32), `tests/test_verify_contract.py`
  (19), `tests/test_evidence_quality.py` (21), `tests/test_verification_support.py`
  (14). Full suite on the branch after Batch 5: **2,710 passed / 61 skipped** (WSL2,
  Python 3.14); the 1 failure is the SAME environmental one as before (no `ensurepip`
  in that Python — the Docker-daemon failure passed this run), not a regression.
  PostgreSQL paths NOT RUN (no PostgreSQL environment); real Docker/gVisor paths
  untested (mocked suites only, by design on this host). Honest coverage note: SQL
  injection boolean-probing is the ONLY finding category independently verifiable
  today; XSS, command injection, web/discovery categories are recorded and
  reachability-checked but NOT independently verified — never labeled otherwise.

### Wave 2b — the JWT token producer + offline analyzer (2026-11-16, `556a564`)

- **The gated lane gets its input (`purple/jwt_tokens.py`, code only)**: jwt_tool
  was allowlisted (`["{token}"]`) but unreachable — nothing produced its input.
  The producer is a pure host-side module: it scans the evidence graph's
  OBSERVED-evidence nodes (api observations, endpoint metadata, candidate
  findings, notes, path labels) for JWT-shaped strings, accepts only tokens whose
  header decodes to JSON with a string `alg` (a lookalike that does not decode is
  not a token), and records one `jwt_token` node per token (label = SHA-256
  fingerprint; the raw token stays in node properties — engagement data that
  never leaves the machine). One audited capture event carries counts only,
  never token bytes. LLM-authored nodes (hypotheses/plans) are deliberately NOT
  scanned: a token feeding a tool must come from observed evidence, never from
  prompt text. Bounded: 64 KB per string, 16 new tokens per pass.
- **Offline analysis, never verification**: `inspect_token()` reads what a token
  says about itself (alg, kid, iss, sub, jti, exp/iat/nbf as ISO strings,
  staleness notes against the caller's clock). It never verifies a signature,
  never contacts anything, and never calls a token "valid".
- **EXPLOIT wiring**: the capture pass runs once per EXPLOIT entry (a capture
  failure never kills the state); `build_argv()` builds the fixed argv
  `["jwt_tool", <token>]` only when a token was captured; the no-token path is
  byte-identical to the historical pinned skip plus a precise audited
  `jwt_input_missing` event. jwt_tool joins `_NEVER_CONFIRMS` consciously —
  offline token analysis is an observation, never a confirmed finding.
- **Tests**: 15 new (`tests/test_jwt_tokens.py`: decode strictness, claim
  reading with pinned clocks, collection caps/idempotence/oversized-skips/
  LLM-node exclusion, count-only audit) + 3 integration (`tests/test_exploit.py`:
  captured token → Layer-2-valid argv, unchanged no-token skip, capture-failure
  resilience). `test_execution_truth_a14`'s audit-order assertion updated
  consciously. Full suite: **2,779 passed / 61 skipped**; the 1 failure is the
  documented environmental ensurepip one. Honest limit: a real sandbox jwt_tool
  run NOT exercised (FakeSandbox). **wafw00f** (the other Wave-2 half) is
  DEFERRED — it needs a sandbox image rebuild + a new pinned digest, a
  maintainer decision.

### Wave 1 — the Zone A archives module (2026-11-16, `31fa96e`)

- **Historical URL + parameter discovery, host-side (`purple/zonea.py`)**: the
  gau/waybackurls/paramspider capability as ONE Zone A source (`archive_urls`) —
  Wayback CDX + a PINNED Common Crawl index (`COMMONCRAWL_INDEX = CC-MAIN-2025-05`,
  reviewed configuration; a newer crawl is a deliberate one-line change, never an
  auto-updated feed), unioned and scope-filtered to the target's own domain.
  Parameter-bearing URLs and parameter NAMES are derived deterministically from the
  already-fetched archive data (never probed, never sent anywhere). Zero packets to
  the target by construction; no sandbox image change.
- **Egress**: `ZONE_A_ALLOWED_HOSTS` gains `index.commoncrawl.org` only; the
  redirect re-check and 20 MB body cap apply as to every other source. New source
  wired into `recon_passive.zone_a_fetchers()`; path labels dedupe against the
  existing wayback source at the runner.
- **Tests**: 11 new in `tests/test_zonea.py` (JSONL parsing + scoping + caps, the
  pinned index id in the request URL, retries-exhausted semantics matching
  `wayback_paths`, the pure parameter filter, union + derivation, one-archive-fails
  resilience, empty-not-error, egress allowlist membership, non-archive-host
  refusal, runner-level dedupe vs the wayback source). Two fetcher-composition
  tests updated consciously. Also fixes the Batch-6 clock time bomb (fixed test
  clock vs real stamps — `_elig` now defaults to the real clock; boundary tests
  pin stamp and clock together). Full suite: **2,759 passed / 61 skipped**; the 1
  failure is the documented environmental ensurepip one.

### The controlled Post-Exploit lifecycle (Batch 6 — Phase 6A–6D)

- **Engagement-bound, stamped, expiring capability records (6A, `purple/capability.py`)**:
  every claimed record now carries `engagement_id` (the claiming graph's engagement — a
  claim is never portable) and `recorded_at` (ISO-8601 UTC, written by
  `claim_from_attempt`). A new one-way `revoked` status joins the lifecycle.
  `capability_eligibility()` is the ONE ordered, pure, fail-closed check every consumer
  runs at consumption time: retyped node → consumed → revoked → not approved → not
  independently verified → unbound → cross-engagement → out of scope → missing/unusable
  stamp → expired (`CAPABILITY_MAX_AGE_S`, 6 h) → attempt missing / tool mismatch / no
  longer confirms (invalidated). Records expire because a capability is a statement about
  a shell that existed at a moment in time, never a standing authorization. The producer
  registry gains `register_capability_parser()` — the reviewed-configuration entry point
  (bounded ≤64-char names, no control characters, callable, deliberate overwrite on
  re-registration) — and the shipped registry stays EMPTY (dormant by emptiness, asserted
  as data by test).
- **The audited kill switch (6A)**: `revoke_capability()` flips a record to `revoked` in
  place (the same direct write the Gate 3 decision uses), records the revocation in the
  audit chain (`capability_revoked`, with the previous status), refuses unknown/malformed
  nodes, and is idempotent. Revocation is recorded, never deleted.
- **Bounded handoff records (6B, `purple/coordinator.py`)**: the EXPLOIT boundary derives
  one `post_exploit_enum` TaskAssignment per Gate-3-approved capability record — capped at
  3 (`handoff_derivation_capped`), identity-deduped on replay, `requires_approval`
  re-derived from the state-changing task type — registered AFTER the transition as data
  for the record, never the reason POST_EXPLOIT runs. Fixed: the POST_EXPLOIT boundary
  counted `engagement_note` nodes (which that state never writes) and always reported
  zero — it now counts the `post_exploit_evidence` nodes the state actually produced and
  carries them by id.
- **Consumption-time eligibility + the one-shot consumption guard (6C,
  `purple/post_exploit.py`)**: the subagent no longer hand-rolls its checks; eligibility
  is re-derived at consumption time via `capability_eligibility` with the graph's
  engagement id and the real clock. The eligible record is marked `consumed_at` at the
  START of the run (audited `capability_consumed`): after a crash or interruption a re-run
  REFUSES the record instead of silently replaying state-changing enumeration — recovery
  is a fresh claim from fresh evidence, not a replay.
- **The standing safety rule, unchanged**: nothing in Batch 6 activates a shell-producing
  tool. Every test record is schema-built data through the real validator, every sandbox
  is a fake, and both the producer and verifier registries ship EMPTY — activation remains
  a separate reviewed, human-approved, disposable-lab-validated decision registered in
  BOTH registries. With empty registries nothing claims, verifies, or consumes a
  capability, and EXPLOIT still routes EXPLOIT -> VERIFY exactly as before Batch 1.
- **Tests**: new `tests/test_post_exploit_batch6.py` (38): the eligibility ordering
  (consumed / revoked / the exact approval refusal string / verification / binding /
  cross-engagement / scope + subdomain / expiry boundary at exactly `MAX_AGE_S` /
  unusable stamps / all three staleness invalidations), `record_age_s`
  garbage-and-future refusal, registry validation + overwrite + the empty-registry
  assertion, fake-capability schema refusal, revocation (recorded, idempotent, refuses,
  never runs the plan), consumption (gate denial, scope, expiry, cross-engagement,
  duplicate execution, interrupted run, recovery-via-fresh-record, the happy path), two
  persistence roundtrips through the real embedded store (a consumed record stays
  consumed; eligibility survives reload), and the coordinator derivations (bounded,
  capped, unapproved records hand off nothing, the POST_EXPLOIT evidence-count fix).
  Full suite after Batch 6: **2,748 passed / 61 skipped** (WSL2, Python 3.14); the 1
  failure is the SAME environmental one as Batches 1–5 (no `ensurepip` in that Python —
  the Docker-daemon check passed this run), not a regression. PostgreSQL paths NOT RUN
  (no PostgreSQL environment); real Docker/gVisor paths untested (mocked suites only, by
  design on this host).

## v1.3.11 — the reviewed Nuclei manifest, TLS/API adapters, and honest failures

Eleven commits since v1.3.10, all in the Purple Team engine. The headline: the
Nuclei template policy is now an enforced, hash-pinned manifest instead of a
directory allowlist — and a packaging bug that would have made wheel installs
fail closed is caught and fixed before release.

### Packaging fix: the Nuclei manifest now ships in the wheel (v1.3.10 bug)

- **v1.3.10's wheel omitted `nuclei_manifest.json`.** pyproject.toml declared
  it under the wrong package-data key, so the pattern matched nothing: the
  file silently stayed out of the wheel. A wheel-installed RECON_ACTIVE then
  raised `NucleiPolicyError` at registry build — fail-closed, but Mode B was
  dead on arrival for wheel installs. Tests never saw it because the source
  tree kept the real file on disk. Caught in the v1.3.11 release preflight by
  building and inspecting the actual wheel.
- **The fix plus a class guard**: the manifest is declared with its directory
  (`purple/nuclei_manifest.json`), and `tests/test_packaging.py` now fails the
  suite if ANY declared package-data glob matches no real file — the mistake
  can never again ship silently.

### Mode B: the Nuclei template policy is an enforced manifest (2B.8)

- **1,605 reviewed templates, pinned by sha256 at upstream commit `1cb2d50b`.**
  The manifest replaces the four-directory allowlist as the RECON_ACTIVE
  probe's policy. `token-spray/` and `misconfiguration/` carry zero entries
  and are not execution-eligible.
- **Enforced at three layers**: the adapter's argv is built FROM the manifest
  (no caller input); adapter registration refuses a policy-violating
  configuration; and a sandbox-side gate refuses unapproved `-t` values at
  execution time (exit 125, fail-closed even if the gate itself cannot run).
- **The image bakes the policy**: the template tree is pinned at the reviewed
  commit and the build fails if any manifest entry is missing or drifted, or
  if an unsafe subtree appears in the manifest.
- **The legacy EXPLOIT-stage path keeps its spec semantics unchanged** — the
  exact template-tree root stays its one allowed directory, and every EXPLOIT
  nuclei run still requires explicit Gate-2 human approval per hypothesis
  (non-TTY approves nothing; every decision audited). **These approved
  whole-tree runs are genuinely state-changing**: nuclei probes can exercise
  potentially exploitable behavior against the authorized target, including
  effects on target systems and data. That is precisely why they sit behind
  Gate 2 per-hypothesis approval and are unreachable from RECON_ACTIVE or
  model-generated arguments — but they are not "detection-only", and the
  release notes state that plainly.

### New vetted adapters: tls-probe and api-probe (2B.5)

- **tls-probe** runs the image's real testssl binary through a baked wrapper
  with a frozen flag set — no phone-out, no authenticated testing, one
  approved https host:port, a 240s internal kill with honest partial-JSON
  salvage. **2B.8 adds the bounded summary**: a 10,000-character self-bound
  (inside the unchanged 20,000-character host cap), totals and severity
  histogram that reflect every salvaged finding, and the full redacted
  artifact written to the engagement evidence directory (O_EXCL|O_NOFOLLOW,
  0600, sha256 recorded).
- **api-probe** is read-only: GET/OPTIONS only, redirects recorded and never
  followed, one fixed inert CORS test origin, no credentials, at most 7
  requests, 512 KiB reads, `$ref` counted and never resolved.
- **One probe per check**: the either/or wiring keeps the legacy
  sslscan/testssl.sh and openapi_probe entries out exactly while the vetted
  adapters are registered. RECON_ACTIVE now carries five vetted web adapters
  (httpx-probe, whatweb-probe, searchsploit-term, tls-probe, api-probe) plus
  the nuclei-probe adapter from this range.

### Zone B boundary: Docker bridge integrity (2C.2)

- The egress gate now verifies the WHOLE network shape before adopting it —
  exact name, bridge driver, explicit bridge name (auto-named refused),
  inter-container communication disabled, ownership label, the policy subnet,
  and the bridge interface actually present in the host kernel right now. A
  foreign or stale network can no longer be adopted while the iptables chains
  match a name that binds to no traffic; the same check re-runs at every
  verify, so post-establishment drift fails the boundary before any spawn.

### Deterministic tool planning (2B.6) — OFF by default

- A bounded, evidence-backed execution planner for RECON_ACTIVE: eligibility
  gates, conservative dedupe, explicit priority ordering, a wall-clock budget
  with audited deferral. It is a VIEW over the vetted adapter registry and
  advisory-only — it can never supply executables, argv, targets or
  templates. Feature-gated: OFF unless `KRYONSEC_TOOL_PLANNER_ENABLED` or
  `[tool_planner] enabled = true` is set, and a planner crash falls back to
  the exact pre-2B.6 deterministic path with an audited notice.

### Honest failures and bounded retries (2B.7)

- Adapter failures are classified (policy, tool, infra, timeout…) instead of
  flattened, infrastructure errors get a bounded retry, and every adapter
  start/outcome reaches the operator as one redacted progress line.

### Image build integrity

- **A required-tool check now FAILS the sandbox image build** when any of the
  six Mode B adapter executables, the entrypoint helpers (jq, timeout,
  python3), the EXPLOIT/verify lane's core tools, or the frozen-argv
  wordlists is missing. Optional tools (checkov, graphql-cop, semgrep,
  hadolint, kube-bench) stay best-effort: their absence is an audited spawn
  failure, never a silent hole.
- apt installs retry per package with bounded timeouts, so one mirror hiccup
  cannot silently drop a tool (the whatweb lesson, measured live).

### Release engineering: two-stage publication

- **The one-stage tag-push release path is gone.** The old `release-wheel.yml`
  and `sandbox-image.yml` published a wheel, created the GitHub Release and
  moved the GHCR `latest` pointer straight off a `v*` tag push — a single
  unreviewed tag could expose unvalidated code to members and re-point
  production installs. They are replaced by `release-candidate.yml` (Stage A:
  builds wheel + image from one frozen commit as restricted artifacts — no
  tag, no release, no `latest`), `release-promote.yml` (Stage B: promotes the
  already-validated image by digest — no rebuild — publishes the release with
  the hash-verified wheel, and moves `latest` only after the release exists
  and only on explicit request, behind the `release-production` environment),
  and `release-guard.yml` (fails loudly on manually pushed `v*` tags).
- **No `--clobber`, no tag rewriting, no overwrite of published releases** —
  recovery is fixing forward with a new version; see RELEASING.md.
- RELEASING.md's stale "the repo is private" claims are corrected (the repo
  is public since the docs commit; distribution is gated by the membership
  key, not by repository visibility).

### Known limitations

- semgrep, hadolint and kube-bench are absent from the 2026-11 Kali snapshot;
  checkov and graphql-cop install best-effort from PyPI/GitHub. Spawns for
  those tools fail closed with an audited `tool_failure` — they are optional
  capabilities, not release requirements.
- Adapters remain network-none or target-scope-only; RECON_PASSIVE still
  sends zero packets to any target.

Test suite: **2331 passed, 55 skipped** (local full run, Python 3.11, on the
release-prep commit; the 55 skips are env-gated Docker/gVisor lab tests; CI
covers 3.11/3.12/3.13). Real Docker + gVisor verification: 12/12 adapter lab
ITs and 2/2 full-engagement e2e lab ITs against the digest-pinned image
`sha256:d759cef7d0b364bcb3f0182388797cbc3c0d9de980278b9f04bdf584400a8f85`.

## v1.3.10 — authorized MCP, the full-screen workspace, and version integrity

Everything merged since the v1.3.8 release ships together here, including the
full-screen workspace and the security fix that closed the window its merge
opened. The version string is now consistent across the wheel, the package
metadata, this changelog, and the README badge.

### Accurate release history: where v1.3.9 stands

The published v1.3.9 artifacts (the GitHub Release wheel and the GHCR sandbox
image tagged `:v1.3.9` and `:latest`) were built from commit `ccaf635`, a
pre-merge state: the full-screen Textual workspace had not yet been merged at
that point. Those artifacts therefore contain neither the workspace nor the
MCP agent-route regression described below — and neither do they include the
merged registry, UI, and the PR #3 fix that v1.3.10 ships. The v1.3.9 tag,
release, and image are intentionally left untouched; v1.3.10, once published,
supersedes them as the release to install.

### Mode B sandbox and security hardening

- **Spawn-time isolation is verified before anything runs.** A launch guard
  refuses every Purple security-tool execution that is not Docker-only
  (`runsc`, non-root, read-only rootfs, resource caps, exactly one
  network-none flag); a missing guard fails closed to an audited `zone_b_blocked`
  halt, never a host execution.
- **Zone B egress is policed at the Docker host boundary**, so a process inside
  the sandbox cannot reach outside the engagement scope.
- **EXPLOIT records and hands off on evidence**: structured, evidence-derived
  attempt records, and an evidence-driven EXPLOIT → POST_EXPLOIT capability
  handoff instead of a schedule.

### MCP registry authorization and audit

- **One execution choke point.** Every real MCP tool call goes through
  `McpRegistry.call_mcp_tool`: trust policy → tool allowance → human approval →
  schema validation → concurrency bound → redaction, each decision audited and
  fail closed.
- **Connection-level startup policy** decides which MCP server process may
  launch at all; blocked servers stay visible but never start, and the block is
  audited.
- **A vetted read-only DocSafe provider** with path-scope confinement
  (traversal, absolute-path, and symlink escapes refused before dispatch).
- **A ship-aware wiring scan** in CI asserts the shipped code cannot execute an
  MCP tool or feed a raw catalog outside the registry.

### Mode B adapters (sandbox-contained, entrypoint-allowlisted)

- **httpx-probe**, **searchsploit-term**, **whatweb-probe**: the first three
  production Mode B adapters, each with allowlisted executables, in-scope-only
  arguments, verified network-none isolation, and audited inputs/outputs.

### Verification and evidence improvements

- **Capability verification separated from approval**, with verification
  statuses derived from concrete recorded evidence, a lineage graph over that
  evidence, and a deterministic `report.json`.
- **Independent capability verification** via static producer contracts, plus
  doctor's sandbox-image validation pre-flight.

### The full-screen Textual workspace

- Live session tabs with persisted history, a Mode B engagement console with
  live state/evidence views, inline approvals, the memory-browser launch point,
  and the mode-driven workspace palette.

### Fixed: the workspace goes through the MCP registry too (PR #3)

- The merge sequence landed the workspace against a pre-registry base, which
  opened a temporary authorization gap on `main`: its agent loop wired the
  legacy toolbox catalog without policy or audit, and its launcher started MCP
  server processes without the startup-policy gate. v1.3.10 carries the fix:
  the workspace sees MCP exactly like the approved chat path (registry-derived
  discovery only, `connect_all` gated by `startup_allowance()`), fail-closed
  without a registry, pinned by dedicated regression tests.

### Installation, config, and license

- Installer profiles with dry run, repair, and strict pre-flight; the Windows
  install is approved in the browser, not in the URL; the license endpoint
  names the identity a beta key needs; site-call transport failures are named
  without printing credentials; config writes are atomic and section-scoped.

Test suite: **2128 passed, 8 skipped** on Python 3.11, 3.12, and 3.13 (CI on
`388821a`); Docker + gVisor integration runs green on Linux.

## v1.3.8 — reliable installation and runtime validation

The release now fails closed when the required Purple Team runtime is not ready,
while keeping Copilot installation independent of Docker and gVisor.

- **Installers are repeatable.** Linux and Windows installers support dry runs,
  repair paths, explicit approval for host changes, wheel-hash verification, and
  preserved configuration.
- **Purple readiness is strict.** Docker context and daemon mismatches, missing
  `runsc`, mutable or mismatched images, and unsafe fallback runtimes are
  reported before execution. `kryonsec doctor --deep --strict` includes the
  network-disabled smoke test.
- **Site failures are explained safely.** Login, connection, logout, and license
  checks distinguish HTTP, DNS, TLS, timeout, and malformed-response failures
  without printing credentials or transport internals.

Test suite: **1747 passed, 4 skipped** (1751 collected across 55 test files).

## v1.3.7 — a crash the licence cache could reach

One fix. Test suite: **1676 tests green**.

- **A date-only expiry crashed the offline path.** The endpoint's documented
  `expires` shape is a date, not a datetime, and `fromisoformat` returns a
  naive one — subtracting it from an aware `now` is a `TypeError`, which the
  `ValueError` guard around it did not catch. So `verify()` could raise out of
  a function whose whole contract is that it never does, on the cached path a
  member hits on every launch for a day after a successful check. It now uses
  the `_parse_ts` helper that already existed for exactly this. Not reachable
  today, because the endpoint answers `expires: ""` — it becomes reachable the
  day expiry is added, which is the reason to fix it now rather than then.

## v1.3.6 — the membership gate, and `kryonsec connect`

The security engine is untouched: no state transition, tool allowlist,
sandbox behaviour, exploit or verify logic, or authorization gate was
modified. Test suite: **1675 tests green** (was 1667).

v1.3.5 shipped a licence check that nothing called. The key gated the
download and stopped there, so a Purple Team engagement ran for anyone who
had the code. This release wires it in and adds the one-time step that makes
it know *who*, not just *whether*.

- **`kryonsec connect` registers this machine.** It prints a link, opens a
  browser once, and waits for you to confirm your email. After that the
  machine is known and never asks again. Nothing types a password into a
  terminal, and the key is never pasted into a web page.
- **Purple Team now needs a connected machine, not just a valid key.** A key
  proves a membership exists; it does not say whose machine this is. Copilot
  mode is free and calls nothing.
- **The key travels in a header, not the URL.** A query string lands in access
  logs, proxy logs and Referer headers, and a membership key is a credential.
  Older installs still work — the endpoint accepts `?key=` as well.
- **Cloudflare no longer refuses the app's own requests.** urllib's default
  User-Agent is on the zone's banned-signature list, so every activation was
  answered 403 and silently interpreted as "offline", which the grace period
  then covered. What looked like working offline tolerance was a wall.
- **`kryonsec doctor` reports the membership and the machine.** A new row says
  whether the key is good *and* whether this box is connected, because those
  are different problems with different fixes.

## v1.3.5 — closed source, key-gated install

Kryonsec is commercial software now. The security engine is untouched: no
state transition, tool allowlist, sandbox behaviour, exploit or verify logic,
authorization gate, or provider code was modified.

- **The licence is proprietary and the repository is private.** Nothing had
  ever granted reuse rights, but a public repo fronting a one-command install
  read as open source.
- **Installing needs a membership key.** `install.sh` / `install.ps1` fetch the
  built wheel from `kryonsec.in` instead of cloning a repo, and save the key to
  `~/.kryonsec/config.toml` so Purple Team does not ask for it twice. Building
  the sandbox image locally is no longer a fallback — it is a pull, or nothing.
- **Purple Team asks `kryonsec.in` whether the key is still good**, at most once
  a day per machine, with a multi-day offline grace period. Copilot mode stays
  free and needs no key.
- **`zstd` is installed first.** Ollama's installer cannot unpack its own
  archive without it.

## v1.3.2 — Purple Team operations console

Presentation-only change. The security engine is untouched: no state
transition, tool allowlist, sandbox behaviour, exploit or verify logic,
authorization gate, or provider code was modified. Test suite: **861 tests
green** (was 854).

Purple Team output used to be raw developer logs — a spinner printing
`purple 20%` over a one-line inventory of every tool in the state, full
tracebacks from free public APIs answering 429/403/404, and a final summary
in plain text. It is now a single live console.

- **One live region** (`purple/ui.py`, new) replaces the scrolling log. The
  console learns everything from two existing streams — the orchestrator's
  state callback and the audit chain via a new read-only `AuditLog.add_observer`
  — so no subagent knows a UI exists.
- **Honest progress.** The old `20%` was the fraction of *states entered*,
  which reads as work completed. The bar is now labelled `Stage 3 of 10`.
- **Tool activity.** Every tool shows its operator-facing name (`crt.sh`,
  not `crt_sh_subdomains`), what it does, how long it took, and its result.
  Completed tools stay as history; only tools that actually ran appear.
  Columns are dropped, not crushed, as the terminal narrows.
- **Tracebacks are split, not shown.** `PurpleLogHandler` renders one line
  per warning to the console; the untouched record, `exc_info` intact, goes
  to `engagements/<id>/debug.log`. The stderr handler `basicConfig()`
  installs is silenced while the console owns the screen (it sat at WARNING
  already, so pinning it there left the raw line — and its traceback —
  printing beside the notice) and restored on exit.
- **Consistent dashboard.** `Panel(expand=False)` measures content and only
  caps at `width`, so panels boxed themselves at wildly different widths.
  All panels now share one width, capped at 100 columns.
- **ASCII fallback completed.** The glyph set alone was not enough: rich
  still drew Unicode borders unless it detected a legacy Windows console.
  The box style now travels with the glyph set, and the hardcoded `●` in the
  RUNNING/STOPPED indicator was added to it.
- **Piped and CI runs stay observable.** With no TTY there is no live region
  and the run was previously silent; it now prints one line per state.
- **Human review** is an approval panel (`A`/`R`, with `y`/`n` still
  accepted) instead of a bare `y/N` prompt; the live region pauses so the
  prompt owns the terminal.
- **Final summary** is a complete/halted panel carrying duration, verified
  findings, hypotheses, tool executions and evidence count, with paths
  written relative to the kryonsec home.

Loading a state no longer prints its full tool inventory — the inventory is
shown per tool, as each one actually runs.

## v1.3.0 — Purple Team tool expansion Phase 8 (user tool map)

Test suite: **559 tests green** (was 496).

The user supplied a complete tool map for every state; Phase 8 closes the
gaps against the ~40 tools already present. Every addition keeps the hard
invariants: argv templates (never shell strings), fixed plans (no LLM-driven
tool choice), every spawn audited, sandbox hardening unchanged.

- **Passive recon** (8A): RDAP WHOIS (IANA bootstrap-derived registry hosts),
  GitHub recon (free API, optional `GITHUB_TOKEN`), HackerTarget DNS history,
  cloud asset discovery (local pass, zero fetch), certificate issuer/validity
  enrichment. Zone A is now 10 sources.
- **Active recon** (8B): gowitness screenshots (new read-write `/evidence`
  mount — the only one; screenshots land under
  `engagements/<id>/evidence/`), massdns (allowlisted, not in the default
  plan), and a baked `openapi_probe.py` that finds OpenAPI/Swagger/GraphQL
  endpoints per web port (found paths become graph nodes).
- **Hypothesis enrichment** (8C): OSV and GitHub Advisory lookups, CWE ids
  from the NVD record, and nuclei template metadata (front-matter scan of the
  baked templates) — all rendered in the report's known-risk block.
- **Post-exploit** (8D): controlled impacket subset + bloodhound-python
  allowlisted and in the image but **dormant** (excluded from the plan — they
  need shell/domain context that does not exist today); cloud metadata
  enumeration script added to the plan (probes the sandbox's own metadata
  service, which is none).
- **Blue-team scanners** (8E): syft (SBOM), osv-scanner, grype join the scan
  plan as pinned binaries — syft offline, the other two need vuln-DB egress
  (same caveat as trivy). The report gained a "Code scanning results" section
  with an SBOM summary line.
- **Report** (8F): audit entries now carry an ISO-8601 UTC `ts` (informational
  — the hash chain remains the ordering guarantee, old chains still verify),
  a Timeline table built from the chain, and an `owasp_api` suggestion field
  (e.g. API1:2023-BOLA) in the fixes section.
- **Docs & version** (8G): expansion doc Phase 8 section, README tool tables,
  version 1.3.0.

**Deferred / skipped** (reasons in the expansion doc): Playwright (breaks the
argv-only rule; gowitness covers screenshots), Interactsh + Burp Community
(need listening services / callback traffic — revisit with the egress proxy),
kube-bench (audits live nodes, not code folders).

**Sandbox image changed** — rebuild required in WSL2:
`docker build -t kryonsec/sandbox -f containers/sandbox/Dockerfile.kali .`

**Known limitations**: gowitness 3.x flags could not be live-verified during
development (drift would surface as an audited spawn failure); sandbox egress
still uses the default docker bridge (proxy pending); POST_EXPLOIT dormant.

## v1.2.0 — Purple Team tool expansion (7 phases)

Test suite: **496 tests green** (was 321).

The Purple Team tool inventory grew from ~10 to **~40 sandboxed tools**,
every spawn allowlisted (argv templates, never shell strings), audited
(SHA256-chained), and run inside the gVisor sandbox. Highlights:

- **Zone B tool inventory** (Phase 1): passive subdomain tools (subfinder /
  amass / assetfinder, forced `-passive`), active recon (naabu, rustscan,
  whatweb, katana, hakrawler, sslscan, testssl.sh, dnsx), exploit
  specialists (dalfox, commix, ssrfmap, arjun, tplmap, jwt_tool, wfuzz,
  kiterunner, graphql-cop), verify tools (http, dig, nc, ncat), and a
  per-subagent template split so each state validates against its own set.
- **Passive recon expansion** (Phase 2): OTX passive DNS, RIPEstat
  whois/ASN, Shodan + Censys (API keys via config/wizard, never logged),
  all through the bounded, redirect-rechecked Zone A fetcher.
- **Hypothesis enrichment** (Phase 3): NVD/CPE, CISA KEV, EPSS, and
  sandboxed searchsploit per hypothesis — free public APIs, cached 24h,
  failures are audited skips, unknown ≠ absent.
- **POST_EXPLOIT** (Phase 4): wired-but-dormant (no current tool yields a
  shell). Fixed evidence-collection plan behind a separate terminal
  approval gate; the EXPLOIT boundary decides via shell detection +
  Gate 3.
- **Blue-team code scanners** (Phase 5): `purple --code FOLDER` mounts
  the folder read-only at `/code`; semgrep, bandit, gitleaks, trivy,
  checkov, hadolint run before the LLM, whose remediations are grounded
  in real scanner evidence. Remediations may carry suggested
  CWE/OWASP/ATT&CK mappings.
- **Report enrichment** (Phase 6): known-risk block per hypothesis (KEV /
  EPSS / exploit availability / CPE), pure-Python CVSS 3.1 base-score
  calculator (verified against FIRST examples), evidence normalizer
  (ANSI/whitespace/uniform truncation), duplicate-hypothesis merging with
  pointer remapping, and validate_report checks for dropped enrichment,
  unmerged duplicates, and ANSI leaks.
- **Docs & version** (Phase 7): this changelog, README tool tables,
  version 1.2.0.

**Known limitations** (recorded in the expansion doc): sandbox egress
still uses the default docker bridge (the target-scope-only proxy is not
built yet); POST_EXPLOIT is dormant pending a shell-yielding tool;
semgrep `--config=auto` and trivy DB need sandbox internet egress;
`--code` is CLI-only (not reachable from the chat loop).

## v1.1.2 — code-review fixes (10 findings + 1 bonus bug)

All fixes verified against the review of commit `f286273` (v1.1.1).
Test suite: **321 tests green** (was 216 — 40+ new tests cover every fix).

### Secret leaks (CLAUDE.md rule 4)

1. **Copilot agent tool loop leaked secrets to hosted LLMs**
   (`src/kryonsec/copilot/agent.py`)
   The secrets gate ran once, *before* the tool loop. If a tool result
   (e.g. `file_read` on `.env`) introduced a secret in round 1, round 2
   sent it verbatim to the third-party provider. The gate now re-runs
   before **every** LLM round: secrets in the conversation route to the
   local Ollama model; when no local model is up, the outbound messages
   are redacted (`«SECRET_n»` placeholders, mapping never leaves the
   machine) instead of leaking. The chat never crashes either way.

2. **Blue-team instructor path bypassed the secrets gate**
   (`src/kryonsec/purple/blue_team.py`)
   The instructor (structured-output) call went to the provider directly,
   skipping `chat()`'s gate. It now uses the same gate as HYPOTHESIZE.

3. **Report redaction used a private, drifting pattern list**
   (`src/kryonsec/purple/report.py`)
   The report's own `_SECRET_PATTERNS` list had already diverged from
   `secrets.py` and missed AWS keys, GitHub tokens, bearer tokens, and
   connection strings — in the one artifact meant to be shared. The
   private list is deleted; redaction delegates to the shared detector.
   Password/key labels are kept, only the value is replaced.

New shared helper: `kryonsec.llm.secrets_safe_prompt()` — the
single-prompt form of the §6.4 gate for the purple-team LLM states.
Routes to the local model when one is up, redacts when not, and never
raises.

### Purple-team logic regressions

4. **VERIFY baseline stripped the entire query string**
   (`src/kryonsec/purple/verify.py`)
   The baseline fetch for the boolean check dropped `?id=1`, fetching a
   different page (missing-param error), so `true_out == base_out` could
   almost never hold — genuine boolean-SQLi findings systematically
   "failed" verification. The baseline is now the original URL with its
   original query string.

5. **Over-strict hypothesis-id pattern zeroed hypothesis sets**
   (`src/kryonsec/purple/hypothesize.py`)
   The v1.1.1 pattern `^[A-Za-z][A-Za-z0-9_-]{0,19}$` rejected ids LLMs
   naturally emit (`1`, 21+ chars), and validation is all-or-nothing —
   one bad id ended the engagement with zero hypotheses. The pattern now
   only rejects what actually breaks things: `:` (it corrupts the
   `H1:sqlmap` label joins), plus whitespace/wild characters.

6. **Secrets gate could crash the HYPOTHESIZE state**
   (`src/kryonsec/purple/hypothesize.py`)
   `secrets_safe_model` was called outside the try block, so a
   false-positive secret pattern in recon data (e.g. a Wayback path
   `/login?password=forgot123`) raised `SecretsMustStayLocal` and the
   state failed with zero hypotheses. The gate (now
   `secrets_safe_prompt`) never raises — it routes or redacts.

7. **Negative `skipped` count written into the chained audit log**
   (`src/kryonsec/purple/exploit.py`)
   `skipped` was computed as `len(approved) - executed`, which went
   negative once multi-tool hypotheses began executing every listed tool
   (one approved hypothesis, tools `[nmap, sqlmap]` → `skipped: -1`).
   It now counts planned tool runs that never spawned.

### Smaller but real

8. **`/cve` output showed a Rich object repr instead of the table**
   (`src/kryonsec/cli.py`)
   The Rich Table was f-string-interpolated into a Panel title body, so
   every `/cve` lookup printed `<rich.table.Table object at 0x…>`. The
   Table is now a proper Panel child via `Group`.

9. **MCP servers slower than 10s were silently dropped for the session**
   (`src/kryonsec/copilot/mcp_tools.py`)
   A server whose tool list arrived after the 10s connect timeout (cold
   `npx` cache) was dropped with only a log line, and its tools were
   never registered. Now: a visible console notice, the server keeps
   booting in the background, and its tools merge into the live toolbox
   when they arrive (picked up on the next chat turn via a thread-safe
   `snapshot()`). A server that never becomes ready is dropped *with* a
   notice.

   **Bonus bug found while fixing this:** `_ServerConnection.ready` was
   initialized to `None` and never turned into a `threading.Event`, so
   every *real* MCP connect crashed into the "failed to start" path.
   Fixed — the Event is created in `__init__`.

10. **Token/cost budgets were never enforced**
    (`src/kryonsec/purple/orchestrator.py`, `hypothesize.py`,
    `blue_team.py`, `runner.py`)
    `BudgetTracker.record_usage()` existed but had zero call sites, so
    `used_tokens`/`used_cost_usd` stayed 0 forever and the guard could
    only trip on wall-clock time. The HYPOTHESIZE and BLUE_TEAM
    subagents now accrue their (approximate) prompt+response token
    usage; the runner passes the engagement's tracker to both.

### Tests added/updated

- Agent loop: secrets entering via tool results — local routing and
  redaction paths (2 tests)
- `secrets_safe_prompt`: routes / redacts / passes through / local
  model (4 tests)
- HYPOTHESIZE: natural id formats accepted, `:` rejected, secret
  prompt is redacted not fatal, budget usage recorded (4 tests)
- BLUE_TEAM: instructor-path gate, budget usage recorded (2 tests)
- VERIFY: baseline keeps the query string (regression test); existing
  sandbox fakes updated to identify the baseline by "no injection"
  instead of "no `?`"
- EXPLOIT: `skipped` never negative; skipped tool runs counted (2 tests)
- REPORT: AWS keys / GitHub tokens / connection strings redacted;
  password label survives (updated parametrize + 1 test)
- MCP: slow-server tools merge late with notices; dead server noticed
  (2 tests + updated disabled-server test)
- Runner: fake subagent `__init__` accepts the new `budget` kwarg

## v1.1.1

Audit fixes + detailed README with logo (see commit `f286273`).

## v1.1.0

Installer (bash + PowerShell), setup wizard, agent tool loop, MCP
tools, status line (see commit `ce8a442`).
