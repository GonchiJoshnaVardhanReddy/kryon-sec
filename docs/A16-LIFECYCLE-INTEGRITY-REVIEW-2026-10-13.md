# A16 — Consolidated Lifecycle Integrity and Release Readiness Review

**Date:** 2026-10-13
**Type:** audit and documentation only. No production code was changed, no state was
reordered, no approval/scope/allowlist/sandbox/secret-routing semantics were touched, no
migration was added, and nothing was committed or pushed.

---

## 1. Exact state reviewed

| | |
|---|---|
| Repository | `C:\Users\gonch\OneDrive\Desktop\kryonsec\kryonsec` |
| Branch | `main` |
| HEAD | `7cd447fe9baec8b9619272e1d2fbc664d3da189d` — *feat(purple): show the memory browser link when an engagement starts* |
| HEAD date | 2026-10-11 00:40:49 +0530 |
| Working tree | dirty: 17 modified, 15 untracked (8 of them the milestone itself) |
| Diff vs HEAD | 17 files changed, 1250 insertions(+), 219 deletions(-) |

Everything below describes the **uncommitted A9–A15 working tree** on top of that HEAD. The
diffstat is against HEAD, so it is the whole milestone, not one phase.

### Modified (17)

| File | +/− |
|---|---|
| `src/kryonsec/cli.py` | 13 / 2 |
| `src/kryonsec/memory/data.py` | 36 / 1 |
| `src/kryonsec/memory/static/app.js` | 29 / 0 |
| `src/kryonsec/purple/allowlist.py` | 23 / 0 |
| `src/kryonsec/purple/blue_team.py` | 79 / 7 |
| `src/kryonsec/purple/context.py` | 145 / 41 |
| `src/kryonsec/purple/human_review.py` | 62 / 6 |
| `src/kryonsec/purple/hypothesize.py` | 170 / 15 |
| `src/kryonsec/purple/report.py` | 496 / 78 |
| `src/kryonsec/templates/blue_team.jinja` | 22 / 1 |
| `src/kryonsec/templates/hypothesize.jinja` | 12 / 5 |
| `src/kryonsec/templates/report.jinja` | 48 / 12 |
| `tests/test_blue_team_report.py` | 11 / 5 |
| `tests/test_context.py` | 54 / 34 |
| `tests/test_hypothesize.py` | 19 / 9 |
| `tests/test_memory.py` | 9 / 2 |
| `tests/test_purple_ui.py` | 22 / 1 |

### Untracked (15)

Milestone (8): `src/kryonsec/purple/views.py` (new, 379 lines), `src/kryonsec/purple/text.py`
(new, 65), `tests/test_context_a10.py`, `tests/test_hypothesis_eval_a9.py`,
`tests/test_hypothesis_multi_asset_a11.py`, `tests/test_hypothesis_dedup_a12.py`,
`tests/test_hypothesis_lifecycle_a13.py`, `tests/test_execution_truth_a14.py`,
`tests/test_dedup_conservatism_a15.py`, `tests/a9_live_runner.py` (10 files), plus the three
prior audit documents `docs/A9-…-2026-10-11.md`, `docs/A12-…-2026-10-12.md`,
`docs/A13-…-2026-10-12.md`.

**Out of scope, present in the tree:** `src/kryonsec/license.py` (252 lines — parked license
scaffolding; `grep` finds no importer anywhere in the tree, so it is inert) and
`kryonsec_architecture_files/` (a design-docs drop dated Oct 2, unrelated to the A-series).

---

## 2. Files changed across the milestone series

| Phase | What it is | Files |
|---|---|---|
| A9 | Hypothesis evaluation + provenance | `hypothesize.py`, `templates/hypothesize.jinja`, `tests/test_hypotheses*.py`, `tests/a9_live_runner.py`, `docs/A9-…` |
| A10 | History made locatable (asset join); `tool` must be a program name | `context.py`, `allowlist.py` (`is_program_name`, `exploit_tool_names`), `tests/test_context*.py` |
| A11 | Multi-asset claims (`related_assets`, `relationship`) | `hypothesize.py`, `templates/hypothesize.jinja`, `tests/test_hypothesis_multi_asset_a11.py` |
| A12 | Dedup equivalence + absorbed-claim record | `report.py`, `templates/report.jinja`, `tests/test_hypothesis_dedup_a12.py`, `docs/A12-…` |
| A13 | Lifecycle-integrity audit (pinned D1–D7) | `docs/A13-…`, `tests/test_hypothesis_lifecycle_a13.py` |
| A14 | Execution truth + one engine view for all surfaces | `views.py` *(new)*, `text.py` *(new)*, `report.py`, `blue_team.py`, `human_review.py`, `cli.py`, `memory/data.py`, `memory/static/app.js`, `templates/report.jinja`, `templates/blue_team.jinja`, `tests/test_execution_truth_a14.py`, `tests/test_memory.py`, `tests/test_purple_ui.py` |
| A15 | Conservative dedup (D6) + Blue Team clarity (D3) | `report.py`, `blue_team.py`, `templates/blue_team.jinja`, `tests/test_dedup_conservatism_a15.py`, plus flips in `tests/test_hypothesis_dedup_a12.py`, `tests/test_hypothesis_lifecycle_a13.py`, `tests/test_blue_team_report.py` |
| A16 | This document | `docs/A16-LIFECYCLE-INTEGRITY-REVIEW-2026-10-13.md` |

The blue-team/report `templates/*.jinja` are included above where they changed. No file was
added to `migrations/` in the whole series, and no schema or storage-layer file changed
except `memory/data.py`, which only *reads* (`_add_engine_views`).

---

## 3. Test results

**Full suite, run locally on this working tree:**

```
py -3.13 -m pytest -q
1657 passed, 3 skipped in 217.73s (0:03:37)
exit code 0
```

- The 222 tests in the new A9–A15 files collect cleanly.
- Baseline before A15 was 1630 passed / 3 skipped; A15 added 27 (`test_dedup_conservatism_a15.py`).

**Environmental limitations — read these before quoting the number.**

1. **No CI was run.** This is a local Windows-host run only. Nothing in this document claims
   an independent or remote build.
2. The 3 skips are `tests/test_file_tools.py:97,123,161` — symlink tests skipped because
   creating symlinks needs a Windows privilege this host does not have. They are unrelated
   to the A-series.
3. **Mode B was never executed.** Purple Team requires Linux + Docker + gVisor (`runsc`);
   the dev machine is Windows 11. Every execution-truth claim below is verified at unit
   level against a fake sandbox and synthetic graphs — no container was spawned, no live
   engagement was run, and no LLM was called by these tests.
4. `tests/a9_live_runner.py` is a manual, model-requiring helper, not part of the suite.

---

## 4. Traced areas and verified invariants

### 4a. The trace, area by area

| # | Area | Where it lives | What is actually guaranteed |
|---|---|---|---|
| 1 | Hypothesis generation, schema validation, provenance, proposed status | `hypothesize.py`, `templates/hypothesize.jinja` | Ids bounded by pattern, max 10 per set with uniqueness enforced; `status` written as `"proposed"` and provenance `{source_type: "model", …, prompt_version: "hypothesize-v3"}` — the model's output can never enter as anything but a proposal |
| 2 | Investigation context, token budgeting, redaction, provider routing | `context.py` (1122 lines), `llm.py:570-617,695-743`, `secrets.py` | Explicit node-type/field allowlist (`_SOURCES`); 800-token default with a 256 floor; redaction runs on the whole raw value *before* any length cap; the redaction count is declared in the block and re-read by the routing gate |
| 3 | Evidence references and prior test history | `context.py:196-281,452-502` | Every history line joins finding/attempt→hypothesis id→asset, or says `unresolved`; a non-program `tool` value renders `unresolved` rather than a sandbox path |
| 4 | Multi-asset claims and engine-derived standing | `hypothesize.py`, `views.py` | `related_assets` capped at 4 by drop-then-cap; the basis ladder (`proposed`→`supported`→`tested`→`validated`) is derived from graph records only |
| 5 | Human review and execution gating | `human_review.py`, `exploit.py:302-305,343-367`, `orchestrator.py:63-88` | `approved` has exactly one writer; non-TTY stdin approves nothing ("silence is never consent"); rejection routes to BLUE_TEAM, never straight to REPORT |
| 6 | Actual execution outcome semantics | `exploit.py:477-488`, `views.py`, `report.py:617-625` | `ok` is process creation only; each attempt records `ok`/`exit_code`/`confirmed`/`error_excerpt`; the report distinguishes "tools ran" from "tools were tried" from "nothing started" |
| 7 | Dedup equivalence, absorbed claims, kept-apart records | `report.py:191-475` | The relation, the absorb, the label remap and the chain entry are one code path |
| 8 | Blue Team context before REPORT dedup | `blue_team.py`, `templates/blue_team.jinja` | Dedup still runs in REPORT; the prompt is *told* what REPORT will do, read from the same relation |
| 9 | Final report validation and remediation references | `report.py:543-589,753-841`, `templates/report.jinja` | Every hypothesis, remediation, related asset, relationship and merged claim must appear; a remediation id is resolved against hypotheses and scans, and a dangling one is both printed-with-a-note and recorded as a validation problem |
| 10 | Persistence and Memory Browser consistency | `graph_store.py`, `memory/data.py:286-316`, `memory/static/app.js` | One engine view function feeds report and browser; persistence runs after REPORT's dedup, so both surfaces see the same node set |

### 4b. The nine required checks

**1. Unknown vulnerability classes do not merge into known classes — HOLDS.**
`_vuln_class` (`report.py:191-203`) returns `unknown` unless *exactly one* class matches, so a
missing, blank, non-string, unrecognised **or multi-class** title is never a class. `_apart_reason`
(`report.py:257-266`) then keeps that pair apart with the reason
`vulnerability class unclear on one side (sqli vs unknown)`, which lands on the audit chain.
Two unreadable titles still merge — deliberate legacy preservation, not an oversight.

**2. Missing or ambiguous references are not presented as resolved — HOLDS.**
`remediation_reference` (`report.py:543-589`) has three outcomes: zero matches → "nothing in
this engagement is recorded under the name …"; more than one → ambiguous, and it refuses to
guess which was meant; exactly one → resolved. The report prints the advice either way and
`validate_report` (`report.py:772-776`) records the gap. In context building,
`_hypothesis_assets` (`context.py:229-257`) resolves an id only when exactly one asset agrees
across every node carrying it, and the literal `unresolved` is engine text at line start
(`context.py:672`), not a value — so it cannot be forged from engagement data.

**3. Approval is not represented as execution — HOLDS.**
`approved` is written in exactly one place (`human_review.py:232`). It is *read* as a gate
(`exploit.py:302-305`) and *rendered* (`report.py:665`, `blue_team.jinja:16,22`) — never used
for an execution claim. Every "it was tested" line reads `hypothesis_engine_view`
(`report.py:666`), which is merged in **after** `**props`, so nothing the model wrote can
outrank it. Post-exploitation has its own separate approver (`exploit.py:350-362`), so
approving a hypothesis is not approving a shell it might yield.

**4. An unexecuted tool is not represented as a negative test result — HOLDS.**
`attempt_outcome` maps a spawn failure to `not-run` and a missing node to `unrecorded`;
`OUTCOMES_RUN = {inconclusive, confirmed}` counts only tests that really ran. The report
carries `exploit_ran` (something ran) and `exploit_attempted` (something was tried) as two
separate facts, and `cli.py`'s summary panel was corrected in A14 to read the same predicate —
a sandbox that never started now says **"no tests could be run … nothing was checked"** rather
than "no findings confirmed". On the VERIFY side, every non-verdict path writes
`verified: False` **with a `reason`** (`verify.py:133-178`), and both `_verify_status`
(`context.py:260-281`) and `attempt_outcome` collapse reason-carrying nodes to `inconclusive`
— so "we could not check" never reads as "we checked and it is not there".

**5. Model-generated claims cannot grant approval or engine-derived standing — HOLDS.**
No LLM path writes `approved`; the basis ladder is derived from graph records in `views.py`
and merged after the model's properties. A model that writes its own `basis: "validated"`,
`tested: true`, `confirmed: true` into properties changes nothing the reader sees — pinned by
`tests/test_hypothesis_lifecycle_a13.py:176-242`. See limitation L3 for the one surface where
the model's own words remain *visible as data*.

**6. Redacted secrets and provider-routing decisions remain consistent — HOLDS.**
Redaction happens on the whole raw value before any cap (`context.py:420-449`), which destroys
the pattern the routing gate looks for. The block therefore declares a *count* —
`SECRET-PATTERNS-REDACTED: n` — that `secrets_safe_prompt` (`llm.py:570-617`) and `chat`
(`llm.py:695-743`) both read, so already-redacted engagement data keeps taking the local route
while it exists, and fails closed (one upstream attempt, no same-provider retry) when it does
not. The declaration is placed outside the preamble swap (`context.py:753-757`), so no budget
can cost the block this line, and it is matched at line start while every value is rendered
behind `- ` — a graph value cannot forge it. `redact_secrets` in the report delegates to the
same detector (`report.py:500-511`), so the report and the gates cannot drift.

**7. Deduplication does not silently destroy materially distinct claims — HOLDS.**
`_apart_reason` (`report.py:242-272`) keeps a pair two when they differ in tool set or asset,
name different vulnerability classes (including the A15 unknown rule), carry different
related-asset claims, or carry different operator decisions; a degenerate `((), "")` key merges
nothing. When a merge does happen, `merged_claim_record`/`_absorb` (`report.py:292-323,354-375`)
keep the absorbed title, rationale, relationship and asset references on the survivor, and the
survivor's label is remapped onto every depending node (`report.py:448-456`) so no join breaks.
`_absorb` writes no standing field at all — a merge cannot move `approved`, the asset claim or
the basis. A decision *not* to merge is on the chain with its reason (`report.py:465-471`).

**8. Blue Team duplicate annotations match the final REPORT decision — HOLDS.**
Both surfaces read the one function `hypothesis_relations` (`report.py:378-412`):
`dedup_hypotheses` consumes its result (`report.py:434-435`), and `blue_team._relation_notes`
describes it to the model. Because BLUE_TEAM runs before REPORT and both walk the same node
list in insertion order, the promise and the act cannot disagree — pinned by
`tests/test_dedup_conservatism_a15.py:313-343` ("what the prompt promises is what the report
does") and, in the other direction, `:333-343` (the prompt says nothing about a merge that
will not happen). No hypothesis is filtered by BLUE_TEAM for sharing a test; each keeps its
own id, title and evidence, and the template's task item 7 makes the two cases explicit.

**9. Legacy graphs remain readable — HOLDS.**
`graph_store.load_graph` reads `row.properties or {}`; `_normalize_node` defaults the rest;
the report merges a `blank` defaults dict under each node's properties before rendering under
`StrictUndefined` (`report.py:639-643`); every `views.py` accessor uses `.get(...)`/`or {}` and
`hypothesis_engine_view` always emits every key. `properties` has no inner key whitelist, so
`merged_claims` and `related_assets` round-trip with no migration. A node written before A11
(no title, no claim, no `approved`) merges exactly as it always did
(`tests/test_dedup_conservatism_a15.py:182-195`). One caveat: redaction can rewrite
secret-shaped string values on save (`graph_store.py:65-84`), so round-trip is not
byte-for-byte when a value matched a pattern.

---

## 5. Known limitations and deferred decisions

**L1 — Deduplication still runs in REPORT, after BLUE_TEAM (A13 D3, half-open).** The state
order was frozen by instruction, so A15 answered D3 inside BLUE_TEAM by *describing* the
coming decision. What remains: the identity keys on the tool **set**, so the same claim tested
by two different tools is never merged and is counted twice. Pinned deliberately as still open
at `tests/test_hypothesis_lifecycle_a13.py:151-171`. Fixing it means either moving dedup or
changing its key — both are ordering/semantics changes, so they need a decision, not a patch.

**L2 — `_vuln_class` is a 13-entry keyword table (`report.py:170-188`), not a classifier.**
A real duplicate whose class is not in the table stays two items rather than merging. This
fails safe — the cost is a missed merge, never a lost claim — and is marked with a `ponytail:`
note naming the upgrade path (add a tuple when a class shows up twice in real reports).

**L3 — The browser's raw `properties.json` is not overridden by the engine view.**
`memory/data.py:311-316` attaches the engine view under `properties["engine"]` rather than
flattening it over the model's keys, so `app.js:1065` renders whatever the model wrote for
`basis`/`tested`/`confirmed` verbatim, next to the engine panel at `app.js:1023-1030` that
shows the engine's answer. The **report does not have this asymmetry** — it overrides
(`report.py:662-666`). Nothing persisted or derived is wrong; it is a presentation gap, and it
is visible only if the model happened to write those key names.

**L4 — Browser and report present the same facts with different presence and wording.**
The browser always shows a `standing` row and a `tested by the exploit phase` row; the report
shows them only when they are relevant (`report.jinja:132,138`). The unobserved-asset marker
is worded differently in the two surfaces ("not recorded by this engagement" vs "this
engagement never recorded this asset"). Same derivation (`hypothesis_engine_view`), different
rendering — intentional, but it means a reader diffing the two sees differences that are not
disagreements.

**L5 — `merged_claims` has no Memory Browser view.** The report renders them through
`merged_claim_views`; the browser shows them only as raw JSON. A merged-away claim is
therefore auditable in the report and in `properties.json`, not as a normalised panel.

**L6 — The canvas legend's "confirmed" is driven by node `status`, not by `engine.confirmed`**
(`app.js:92-94,1161-1162`). Today this is consistent because hypotheses are written
`status="proposed"` and render hollow, but the two axes are independent.

**L7 — A reused engagement id can leave the browser and `report.md` out of step.** Graph rows
and `report.md` are replaced in place, so a second run under the same id can show one run's
graph beside another's report file. The mismatch is flagged in `meta.graph_current` /
`meta.report_current` (`memory/data.py:629-637`, surfaced at `app.js:278-283`); the
per-hypothesis engine panel carries no run marker of its own.

**L8 — `app.js:1019` carries a stale comment** claiming the engine panel is absent on nodes
saved before A14; `memory/data.py:311-316` stamps `engine` on every hypothesis node at load
time. Comment only — no behaviour bug.

**L9 — Mode B has never been run end to end.** Every execution-truth invariant in §4 was
verified with a fake sandbox and synthetic graphs on Windows. The first live Linux/gVisor
engagement remains an unperformed acceptance test.

**L10 — Working-tree content outside the milestone** (`license.py`, `kryonsec_architecture_files/`)
is untracked and unreferenced. It needs its own disposition, not a place in this series.

---

## 6. Recommended commit sequence

The A-series was built as one continuous working tree, so several files (`report.py`,
`blue_team.py`, `hypothesize.py`, `templates/*.jinja`) carry hunks from more than one phase.
Two honest options; the second is what I would do.

**Option A — split by phase.** Requires splitting `report.py`, `blue_team.py`,
`hypothesize.py` and the templates by hunk, and committing the A13 test file only once all its
assertions are green (i.e. with A14/A15, not with the A13 audit doc that pinned the defects):

1. `feat(purple): evaluate hypotheses with provenance and proposed status` — A9
   (`hypothesize.py`, `templates/hypothesize.jinja`, `tests/test_hypothesis_eval_a9.py`,
   `tests/a9_live_runner.py`, `tests/test_hypothesize.py`, `docs/A9-…`)
2. `feat(purple): make the engagement's history locatable in the context block` — A10
   (`context.py`, `allowlist.py`, `tests/test_context_a10.py`, `tests/test_context.py`)
3. `feat(purple): structured multi-asset claims` — A11 (`hypothesize.py`,
   `templates/hypothesize.jinja`, `tests/test_hypothesis_multi_asset_a11.py`)
4. `fix(purple): dedup on claim equivalence, keep what a merge absorbs` — A12 (`report.py`,
   `templates/report.jinja`, `tests/test_hypothesis_dedup_a12.py`, `docs/A12-…`)
5. `docs(purple): record the hypothesis lifecycle-integrity audit` — A13 (`docs/A13-…` only)
6. `fix(purple): execution truth and one engine view for every surface` — A14+`tests/test_hypothesis_lifecycle_a13.py`
   (`views.py`, `text.py`, `report.py`, `blue_team.py`, `human_review.py`, `cli.py`,
   `memory/data.py`, `memory/static/app.js`, both templates, `tests/test_execution_truth_a14.py`,
   `tests/test_memory.py`, `tests/test_purple_ui.py`, `tests/test_blue_team_report.py`)
7. `fix(purple): never merge an unreadable class; tell BLUE_TEAM what REPORT will merge` — A15
   (`report.py`, `blue_team.py`, `templates/blue_team.jinja`,
   `tests/test_dedup_conservatism_a15.py`, `tests/test_hypothesis_dedup_a12.py`)
8. `docs: A16 consolidated lifecycle-integrity review` — this file
9. `chore: park the unused license scaffolding` — `src/kryonsec/license.py` (separate, and
   decide `kryonsec_architecture_files/` — commit as docs or add to `.gitignore`)

**Option B — one commit for the series.** `feat(purple): hypothesis lifecycle integrity
(A9–A15)`, message body listing the seven phases and their audit documents, then a second
commit for this report and a third for the parked license file. The series is internally
consistent (1657 green as a whole), and every phase is already documented by its own `docs/`
file, so the split buys history tidiness at the cost of hand-splitting four files.

**Before either:** re-run the full suite on the machine that will tag the release. The number
in §3 is this Windows host's, with Mode B unexercised.

---

## 7. What this review did not do

No production code changed. No state was reordered. Approval, scope, allowlist, sandbox and
secret-routing semantics are exactly as A15 left them. No migration was added. Nothing was
committed or pushed. No CI was run, and no claim of remote or independent verification is
made anywhere in this document.
