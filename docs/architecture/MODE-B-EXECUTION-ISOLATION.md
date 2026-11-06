# Mode B execution isolation — Docker-only tool execution

**Status: architectural invariant (2026-11-05). Permanent security requirement.**

> Every Mode B (Purple Team) agent security-tool execution MUST occur inside the
> Docker sandbox under gVisor (`runsc`). No Mode B tool may execute directly on
> the host. Sandbox unavailability fails closed — an audited halt — and never
> falls back to host execution. MCP never reaches Mode B execution.

Related design rules: AGENTS.md §Core design rules 7, 9, 10, 11.
Policed by: `tests/test_mode_b_isolation.py` (source policy + behavioral tests).

---

## 1. What hosts what

| Concern | Where | Why allowed on host |
|---|---|---|
| Orchestrator state machine | `purple/orchestrator.py` | pure Python, no execution |
| UI rendering, progress, Textual workspace | `purple/ui.py`, `ui/` | display only |
| LLM calls (LiteLLM, Instructor) | `hypothesize.py`, `blue_team.py` | provider API, not tool execution |
| Human approval gates (Gate 2 / Gate 3) | `human_review.py`, `post_exploit.py`, `ui/workspace.py` | interactive terminal |
| Audit chain | `purple/audit.py` | append-only JSONL on disk |
| Checkpoints / graph persistence | `runner.py`, `graph_store.py` | storage writes (secret-redacted) |
| Docker management | `purple/sandbox.py`, `purple/runtime_checks.py` | the `docker` CLI itself — this IS the sandbox boundary |
| Zone A passive recon | `purple/zonea.py` + friends | HTTP only, `ZONE_A_ALLOWED_HOSTS` allowlist incl. redirect hops; zero packets to the target |
| **Security-tool execution** | **`KaliSandbox.spawn` only** | — |

## 2. Every Mode B execution path (audited 2026-11-05)

All eight Zone B tool-executing surfaces call `sandbox.spawn(argv)` after
Layer-2 (`ToolAllowlist.validate` + `check_blocklist`) and audit a
`tool_spawn`/`tool_result` pair:

| Agent | Module | Spawn sites | Gate |
|---|---|---|---|
| RECON_ACTIVE | `recon_active.py` | `_spawn` (line 424) | validate + blocklist, lines 407–408 |
| EXPLOIT | `exploit.py` | initial (455) + https retry (489) | `_validate_argv` 546–568; scope via `compose_url` 92–127 |
| POST_EXPLOIT | `post_exploit.py` | plan runner (196) | fixed `POST_EXPLOIT_PLAN`, validate 177–179 |
| VERIFY | `verify.py` | `_spawn_tool` (306) | validate 291–292 |
| BLUE_TEAM scanners | `blue_team.py` | `run_code_scanners` (169) | validate 153–154 |
| RECON_PASSIVE (sandboxed passive tools) | `recon_passive.py` | `sandbox_passive_fetcher` (108) | validate 93–94 |
| HYPOTHESIZE enrichment | `enrichment.py` | searchsploit (281), nuclei_meta (333) | validate 264–265, 316–317 |

No other execution surface exists in `purple/`. Zone A has **no local process
execution at all** (`test_zone_a_agent_runs_no_local_processes`). Browser-like
capability is limited to gowitness inside the sandbox; no
playwright/selenium/puppeteer driver exists for Mode B.

## 3. Enforcement layers (defense in depth)

1. **Runner wiring (`runner.resolve`):** Zone B states are constructed only
   with a sandbox object. Without a sandbox they return an audited
   `zone_b_blocked` halt — never a host substitute (`tests/test_runner.py`).
2. **Layer 2 — host allowlist (`allowlist.py`):** argv must match a per-tool
   template exactly (anchored regexes, no shell strings); blocklist for
   hardline patterns. Fail closed: `ToolAllowlist({})` accepts nothing.
3. **Layer 2b — image entrypoint:** `/entrypoint.sh` re-checks the tool name
   inside the container (kept in sync by `tests/test_allowlist.py`).
4. **Image gate (`runtime_checks.validate_image`):** digest-pinned ref, version
   label matching the release, Linux, `/entrypoint.sh`, non-root — hard FAIL,
   checked by `doctor` and at every engagement start (`runner.sandbox_available`).
5. **Spawn guard (*new*, 2026-11-05):** `KaliSandbox.spawn` verifies the docker
   argv still carries the gVisor (`--runtime runsc`) isolation — non-root user,
   read-only rootfs, memory/CPU/pids caps — via `missing_isolation_flags()`
   and **refuses to launch** otherwise (`ok=False` + explicit diagnostic).
   Guards against a future `_docker_argv` refactor silently dropping isolation.
6. **Source policy (`tests/test_mode_b_isolation.py`):** only `sandbox.py` and
   `runtime_checks.py` may import `subprocess`; every `.spawn(` call site must
   be allowlist-gated and fail closed; `purple/` must not import the Mode A
   MCP/agent surface; `copilot/` must not import `purple` execution modules;
   `runner.py` must contain no MCP references.

## 4. MCP boundary (enforced)

Mode A's MCP toolbox (`copilot/mcp_tools.py`) launches user-configured stdio
servers as child processes and exposes their tools to the Mode A agent only.
Mode B's wiring (`purple/runner.py`) contains no MCP references, Mode B
dispatch never builds a toolbox, and the copilot agent layer imports no
purple modules — there is no path from MCP to Mode B execution today, and the
source-policy tests keep it that way.

**Prohibition (standing):** remote MCP command-execution servers
(HexStrike-HTTP style) must never be connected to Mode B. A remote HTTP
endpoint that runs commands for callers is host-equivalent execution by
construction — pointing it at targets while claiming "sandboxed"
misrepresents the containment and violates this invariant. Any future
MCP-to-Mode-B integration must come through the Layer-2 allowlist, the
sandbox boundary, and a dedicated approval gate.

## 5. Network egress — enforced at the host layer (Phase 1E)

- **Enforced:** Zone A egress allowlist at the HTTP layer, including redirect
  hops (`zonea.py:92–133`); Docker-level resource isolation; the `runsc` guest
  isolation for all tool execution; and since Phase 1E a **host-layer allow-only
  egress boundary for every Zone B tool container**:
  - Each engagement builds a DEDICATED Docker bridge network
    (`kryonsec-egress-<id8>`, explicit bridge iface `ksb<id8>`,
    inter-container communication disabled) — never the default bridge.
  - The Docker host's `DOCKER-USER` chain receives a per-engagement chain
    (`KRYONSEC-EGRESS-<id8>`) for BOTH embodiments (`iptables` and
    `ip6tables`), matching only that bridge in/out: allow ESTABLISHED,RELATED;
    DNS (udp/tcp 53) only to the pinned resolver set; allow only the
    engagement's authorized destinations; absolute DROP.
  - `spawn()` re-verifies the boundary before every launch and hard-rejects
    `--network bridge|host|none`, a wrong network, or wrong DNS pinning —
    approved tool argv cannot override the egress policy.
  - **Fail closed:** policy build (`build_policy`) raises on empty/dangerous
    scope (loopback, link-local incl. cloud metadata 169.254.169.254,
    multicast, unspec are stripped even if operator-listed); establishment
    failure, post-program verification drift, or a spawn-time verification
    failure halts Zone B with an audited reason (`egress_policy_failed` /
    `zone_b_blocked`) — never default-bridge execution.
  - **Audit:** `egress_policy_established` (with the policy summary),
    `egress_policy_failed`, and per-run spawns only after verification;
    teardown at engagement end removes ONLY this engagement's chain, jumps
    and network.
  - Why this works with gVisor: once a packet leaves the sandbox container
    across the veth onto the host it is ordinary host-netns traffic filtered
    by the host's netfilter — independent of the guest runtime. gVisor's
    netstack does not implement netfilter (no in-container iptables), and
    netns-sharing topologies (`network_mode: container:` / `service:`) are
    the recorded WSL2/gVisor incompatibility; both approaches are avoided.
- **Honest residuals:** the L3 boundary pins the DNS resolver set but cannot
  inspect DNS payloads (a tool could park exfiltration data in query names
  sent to the allowed resolvers); an authorized destination whose DNS record
  rotates after policy creation resolves to an unallowlisted address and is
  dropped (fail-closed) until the operator widens scope or starts a new
  engagement. The runtime smoke test runs `--network none`, which is
  preflight only and unrelated to this boundary.

## 6. Fail-closed paths (checked)

| Failure | Result |
|---|---|
| No sandbox (non-Linux/no Docker/no runsc/digest FAIL) | audited `zone_b_blocked` halt; Zone A results preserved |
| Passive recon without sandbox | sandbox fetchers simply not wired — audited skip, no host fallback |
| Tool timeout inside spawn | container killed (`docker kill`), `ok=False`, timed-out error |
| docker CLI crash / KeyboardInterrupt / SystemExit | container killed before re-raise or reporting; never left running |
| Allowlist refusal | audited rejection, nothing spawned, counted as skipped |
| Spawn isolation flags missing | **spawn refused outright, launcher never invoked** (new guard) |
| Egress boundary cannot be established or verify drifts | **Zone B blocked** (`egress_policy_failed`, then `zone_b_blocked` in each state); no default-bridge fallback |
| Spawn argv tampered off the engagement network / DNS pinning | **spawn refused outright** (`missing_egress_flags`) |
| Engagement ends (any outcome) | egress chain/jumps/network removed (only ours); fail-safe leftover = default-deny |
| Orchestrator budget exhaustion | deterministic `budget_exhausted` halt |
