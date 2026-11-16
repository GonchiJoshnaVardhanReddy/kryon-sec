# Kryonsec IEEE-research — Phase 3: tool inventory (8-rung evidence ladder)

Generated from source at commit `094fe59` (branch `feature/tool-expansion-batch1`),
2026-11-16. Sources of truth (no memory, no docs-only claims):

- `src/kryonsec/purple/allowlist.py` — Layer-2 argv templates (6 groups)
- `containers/sandbox/entrypoint.sh` `ALLOWED_TOOLS` (lines 15–60) —
  image-side defense-in-depth (kept in sync by
  `tests/test_allowlist.py::test_entrypoint_allowlist_in_sync`)
- `src/kryonsec/purple/adapter_*.py` — 12 registered vetted adapters
- `src/kryonsec/purple/runtime_checks.py` — doctor's runtime verification
  (docker / runsc / pinned image digest / smoke)
- Real-sandbox runs recorded 2026-11-16 (real runsc spawn, real pinned
  image, NO target network) + the 9/9 plumbing check
  (`research/lab/plumbing-results.json`)

## The 8 rungs (each needs its own proof — never inferred from the rung above)

| Rung | Meaning | Proof required |
|---|---|---|
| R1 | Layer-2 allowlisted | fixed argv template in `allowlist.py` |
| R2 | Named in the image entrypoint allowlist | entrypoint sync test |
| R3 | Runnable in the REAL sandbox | real runsc spawn, exit 0 |
| R4 | Version output verified | version string recorded from a real run |
| R5 | Vetted adapter registered | fixed-argv adapter + scope enforcement |
| R6 | Real-path run vs the lab target | EgressGate+KaliSandbox run on the approved scope |
| R7 | Output parsed into the evidence graph | schema verified on REAL target data |
| R8 | Detection functionality proven | end-to-end, scored vs recorded ground truth |

**HARD RULE: R3/R4 success is infrastructure only. A version banner or a
clean spawn says NOTHING about whether a tool detects anything (R8).
Only R6–R8 evidence, produced in Phases 4–6, can support detection
claims — and each is labeled REAL / MOCKED / SKIPPED / NOT RUN /
INCONCLUSIVE.**

## Known rung-2 ≠ rung-3 cases (why the ladder exists)

- `httpx` (legacy template name): R2 yes, R3 **no** — the plain `httpx`
  binary is absent from this image (exit 127); the real binary is
  `httpx-toolkit`, which the adapter uses.
- `amass`: R2 yes, R3 **partial** — runs but demands root for its
  libpostal data download (upstream limitation, unresolved).

## Phase-4-relevant tools — full ladder

| Tool | R1 | R2 | R3 | R4 | R5 adapter | R6 | R7 | R8 |
|---|---|---|---|---|---|---|---|---|
| naabu | yes | yes | REAL | REAL | naabu-probe | NOT RUN | NOT RUN | NOT RUN |
| nmap (pinned flags) | yes | yes | REAL | REAL (7.991) | nmap-probe | NOT RUN | NOT RUN | NOT RUN |
| dnsx | yes | yes | REAL | REAL | dnsx-probe | NOT RUN | NOT RUN | NOT RUN |
| httpx-toolkit | yes | yes | REAL | REAL | httpx-probe | NOT RUN | NOT RUN | NOT RUN |
| whatweb | yes | yes | REAL | REAL (0.6.4) | whatweb-probe | NOT RUN | NOT RUN | NOT RUN |
| katana (d2) | yes | yes | REAL | REAL | katana-probe | NOT RUN | NOT RUN | NOT RUN |
| feroxbuster (t5) | yes | yes | REAL | REAL (2.13.1) | feroxbuster-probe | NOT RUN | NOT RUN | NOT RUN |
| gowitness | yes | yes | REAL | REAL | gowitness-probe | NOT RUN | NOT RUN | NOT RUN |
| /opt/kryonsec/openapi_probe.py | yes | yes | NOT RUN | NOT RUN | — (no adapter) | NOT RUN | NOT RUN | NOT RUN |
| nuclei (+ template gate) | yes | yes | REAL | REAL (3.11.1) | nuclei-probe | NOT RUN (only w/ approved template hosts; lab.hosts pin first) | NOT RUN | NOT RUN |
| sslscan | yes | yes | REAL | REAL (2.1.5) | tls-probe* | NOT RUN (no TLS on target) | NOT RUN | NOT RUN |
| testssl.sh | yes | yes | NOT RUN | NOT RUN | tls-probe* | NOT RUN (no TLS on target) | NOT RUN | NOT RUN |
| curl | yes | yes | REAL | REAL (8.22.0) | — (verify tool) | REAL (plumbing: 1 approved GET, exit 0) | n/a (infra probe) | NOT RUN |
| dig | yes | yes | REAL | REAL (9.20.30) | — (verify tool) | REAL (plumbing: pinned-resolver query) | n/a (infra probe) | NOT RUN |
| sqlmap | yes | yes | REAL | REAL (1.10.10) | — (contract-driven) | NOT RUN | NOT RUN | NOT RUN |

\* `tls-probe` is the adapter over the baked wrapper `/opt/kryonsec/tls_probe.py`
(fixed argv `[script, url]`), which owns the image's real testssl binary.
R6 for TLS tools is NOT RUN because the approved target serves plain HTTP
only — recorded as SKIPPED with that reason, never as a failure.

## Full Layer-2 inventory by group (64 keys: 56 programs + 8 image scripts)

R3/R4 marks: ✅ = REAL run recorded 2026-11-16 (version noted where
transcribed); ⚠️ = runs with an upstream limitation; blank = NOT RUN.

- **PASSIVE (3):** subfinder ✅ (2.17.0) · amass ⚠️ · assetfinder
- **ACTIVE_RECON (15):** nmap ✅ (7.991) · naabu ✅ · httpx (legacy name,
  binary absent) · httpx-toolkit ✅ · rustscan ✅ (2.3.0) · whatweb ✅
  (0.6.4) · katana ✅ · hakrawler · feroxbuster ✅ (2.13.1) · sslscan ✅
  (2.1.5) · testssl.sh · dnsx ✅ · gowitness ✅ · massdns ·
  /opt/kryonsec/openapi_probe.py
- **EXPLOIT (18):** nuclei ✅ (3.11.1) · sqlmap ✅ (1.10.10) · nikto ·
  curl ✅ (8.22.0) · wget · ffuf ✅ (2.3.0) · gobuster ✅ (3.8.2) ·
  wfuzz ✅ (3.1.0) · dalfox · commix · ssrfmap · arjun · tplmap ·
  jwt_tool (offline analyzer; real-sandbox run NOT exercised) · kr ·
  graphql-cop · searchsploit (local DB; adapter `searchsploit-term`,
  network-none contract) · /opt/kryonsec/nuclei_meta.py
- **VERIFY (7):** curl ✅ (same key as EXPLOIT) · http · openssl ✅
  (3.6.5) · dig ✅ (9.20.30) · nc · ncat · /opt/kryonsec/probe.py
- **POST_EXPLOIT (13):** linpeas.sh · pspy64 ·
  linux-exploit-suggester.sh · /opt/kryonsec/enum_processes.py ·
  /opt/kryonsec/enum_fs.py · /opt/kryonsec/enum_network.py ·
  /opt/kryonsec/find_secrets.py · /opt/kryonsec/cloud_meta.py ·
  GetNPUsers.py · GetUserSPNs.py · GetADUsers.py · findDelegation.py ·
  bloodhound-python (all dormant until a shell-producing tool exists;
  none exercised on the network)
- **BLUE_TEAM (9):** semgrep · bandit · gitleaks · trivy · checkov ·
  hadolint · syft · osv-scanner · grype (run against the read-only
  /code mount — no target network; NOT RUN in this research)

Image-side extras in the entrypoint but NOT host-allowlisted (dead at
Layer 2, listed for completeness): `python3`, `kube-bench`.
masscan: deliberately NOT allowlisted anywhere (spec v2.1.1 §9.1).

## Registered vetted adapters (R5) — 12

`naabu-probe`, `dnsx-probe`, `nmap-probe`, `httpx-probe`, `whatweb-probe`,
`katana-probe`, `feroxbuster-probe`, `gowitness-probe`, `tls-probe`,
`api-probe` (baked `/opt/kryonsec/api_probe.py`), `nuclei-probe`,
`searchsploit-term`.

All enforce: fixed argv template, scope at `prepare_adapter_run`,
failure classification (`refused_approval/policy/allowlist/invariant`,
`sandbox_infrastructure`, `timeout`, `tool_failure`), and counterevidence-
preserving records. R5 does NOT imply any target traffic has ever happened.

## What this inventory does NOT claim

1. No tool is proven to detect anything (R8 is empty by construction).
2. The 19 ✅ runs were infrastructure probes in the sandbox with no
   target — they prove the runtime + binary exist, nothing more.
3. R2 (entrypoint name) never implies the binary exists (see `httpx`).
4. WebGoat (10.213.43.11) is out of scope until separately approved;
   nothing in this inventory may be run against it.
5. Any REAL/MOCKED/SKIPPED/NOT-RUN labeling of later phases must cite
   its own artifacts (Phase 4+), never this table.
