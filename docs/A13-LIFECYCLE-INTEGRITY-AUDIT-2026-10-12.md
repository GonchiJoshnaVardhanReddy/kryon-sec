# A13 — End-to-end hypothesis integrity (read-only audit)

**Date:** 2026-10-12
**Audited commit:** `7cd447fe9baec8b9619272e1d2fbc664d3da189d`
("feat(purple): show the memory browser link when an engagement starts",
Sun Oct 11 00:40:49 2026 +0530)
**Working tree:** A9–A12 are implemented but uncommitted; the audit ran on that
tree. No production code was changed, no migration added, nothing committed or
pushed. Every defect below was **reproduced by running the real subagents on
synthetic graphs with fake sandboxes** — the quoted output is real, not a
reading. Live exploitation was not run and no data left the machine.

---

## 1. The lifecycle, as it actually runs

```
INIT → RECON_PASSIVE → RECON_ACTIVE → HYPOTHESIZE → HUMAN_REVIEW →
EXPLOIT → (POST_EXPLOIT) → VERIFY → BLUE_TEAM → REPORT → HALT
```

| Stage | What it writes | Where the hypothesis id lives |
|---|---|---|
| HYPOTHESIZE | `hypothesis` node, `status="proposed"` | node `label`; `provenance.agent` |
| HUMAN_REVIEW | `properties["approved"]` (bool) | audit `hypothesis_reviewed` |
| EXPLOIT | `exploit_attempt` `"{id}:{tool}"`, `finding` `"{id}"` | labels, and audit `hypothesis_id` |
| VERIFY | `verify_attempt` `"{id}"`, `verified` flag on the finding | labels, audit `finding_id` |
| BLUE_TEAM | `remediation` `"{id}"` (**model-supplied**) | label, audit `hypothesis_id` |
| REPORT | dedup (merge), then render | remap of the four label types |

The id is **not a foreign key**. It is a string embedded in other nodes' labels
and in two audit key names. The only rewrite of those strings is A12's remap in
`report.py` (`dedup_hypotheses`), which covers exactly four node types —
`remediation`, `finding`, `verify_attempt` (label equality) and `exploit_attempt`
(`"{id}:{rest}"` prefix). Every other node type uses asset/tool/source labels,
so nothing else can dangle. The `merged_from` / `merged_claims[].id` values on
the survivor *do* name removed nodes, deliberately, as a historical record.

Audit entries keep their pre-merge ids. That is correct and must stay: the chain
is append-only and hash-linked; `hypotheses_merged` carries the alias map that
makes the old ids resolvable.

**Persistence order (checked because it decides whether the browser and the
report can disagree):** the graph is saved twice after the report is written —
the REPORT checkpoint (`orchestrator.py:162` → `runner.py:370`
`checkpoint_graph`) and the final `persist_graph` (`cli.py:831`) — and both run
*after* `dedup_hypotheses` (`report.py:725`). `save_graph` replaces the
engagement's rows wholesale, so the state the Memory Browser reads is the
post-dedup graph. The browser re-reads the database on every request with
`Cache-Control: no-store`; there is no server-side cache. **There is no resume
path** — nothing loads a checkpoint back into an orchestrator, so no node ever
enters a run already carrying `merged_claims`.

---

## 2. Demonstrated defects

### D1 — a tool run that never executed is reported as a completed check (HIGH)

`EXPLOIT` writes an `exploit_attempt` node for every tool it *tries*, whether or
not the tool ran (`exploit.py:478-491`), keeping `ok`, `exit_code` and
`error_excerpt`. The report never consults them: it reads only the attempt's
existence and its `confirmed` flag (`report.py:507-512`).

Reproduced with a sandbox that fails every spawn (`ok=False`, "Cannot connect to
the Docker daemon"):

```
engine record -> ok=False exit=-1 error='Cannot connect to the Docker daemon' confirmed=False
findings created: 0
  REPORT> Tools were run against the target to test the approved items.
  REPORT> - **H1:sqlmap** (sqlmap): ran.
  REPORT> 3. Result: the tool did not find the issue (it checked and got no proof).
  REPORT> - Tested: yes
validate_report: []
```

Four false statements about a run that did not happen, from a graph that says so
in plain text. The report even has the honest wording ready — the "**No testing
was done against the website.**" branch is taken only when there are **zero**
attempt nodes, so an engagement where every tool failed takes the other branch.
`validate_report` returns clean.

This is the worst direction a security report can be wrong in: it tells the
reader an issue was looked for and not found, when nothing was looked for. It is
check 3 and check 4 together.

### D2 — BLUE_TEAM is told an approved hypothesis was tested (HIGH)

`blue_team.jinja:12` derives the status line from `approved` alone:

```jinja
status: {% if h.approved | default(false) %}tested-by-exploit-phase{% else %}proposed-only (not tested){% endif %}
```

`approved` is set by HUMAN_REVIEW, *before* EXPLOIT runs, so it means "the
operator allowed this to be tested". Reproduced with an approved hypothesis
whose tool (`jwt_tool`) has no argv template, so `EXPLOIT` skipped it and wrote
no attempt node:

```
attempt nodes after EXPLOIT: 0
BLUE TEAM prompt says:
     - H1: SQL injection in the artist parameter
     status: tested-by-exploit-phase
```

A downstream LLM is handed, as fact, a test that never ran — and it is asked to
produce remediation advice from it. Same root cause as D1 (existence of intent
read as existence of a record), different consumer.

### D3 — BLUE_TEAM sees duplicates that REPORT then merges (MEDIUM)

Dedup lives inside REPORT (`report.py:725`); BLUE_TEAM is state 8 of 10, so it
always runs on the un-merged graph. Two hypotheses proposing the same claim with
different tools (`sqlmap` / `nuclei`) are listed to the model as two hypotheses,
and any remediation the model returns is mapped to two ids:

```
blue-team hypotheses listed: 2
report-side dedup merged: 0
```

The report then presents the same claim as two issues. This is check 5: one
claim double-counted as independent evidence, and the double count is visible in
the report's own sentence "the assistant suggested 2 possible security issues".
A12 keys the merge on the tool set, so a same-claim/different-tool pair is
*never* mergeable — the duplicate survives by design, not by accident.

*(The merge count of 0 in that run is correct A12 behaviour: different tools,
different test identity.)*

### D4 — the Memory Browser shows the claim without standing or resolution (MEDIUM)

Persisted hypothesis properties, read back through `load_engagement`:

```json
{
  "title": "SQL injection in the artist parameter",
  "target_asset": "/never-recorded.asp?artist=1",
  "related_assets": [{"asset": "/also-never-recorded.asp", "role": "carries it"}],
  "relationship": "the two are linked"
}
```

- **No `basis`.** The standing ladder is derived at render time and never
  stored (`hypothesize.py:46-50` says so explicitly), so the browser shows the
  model's relationship claim with no engine verdict next to it — while the
  report puts "What the engagement itself can say about that claim: proposed"
  underneath the same claim.
- **No `observed`.** That flag is computed only in `related_asset_views` at
  render time. In the browser, `/also-never-recorded.asp` is an ordinary
  reference with nothing saying recon never saw it. (`'observed'` does appear in
  the payload — as the node's own `status` field, which is a different thing.)
- `merged_from` / `merged_claims[].id` are shown as raw JSON naming nodes that no
  longer exist in the graph, with nothing marking them as historical.

The browser is the operator's inspection surface for the evidence graph, and on
it the engine's judgement is absent while the model's claim is present. Check 6
and check 7.

### D5 — a remediation can be attributed to an issue that does not exist (MEDIUM)

`blue_team.py:449-451` labels the `remediation` node with `r.hypothesis_id`,
which is an unconstrained string from the model (`blue_team.py:204`). Nothing
resolves it against the graph, and `validate_report` only checks that the
*remediation's own label* appears in the report:

```
report fix section: ['### Fix for H7 — Sanitise input']
hypothesis H7 exists in the graph: False
validate_report: []
```

The reader gets a fix section for an issue id that appears nowhere else in the
document. Check 6: an unresolved reference rendered as if it resolved.

### D6 — a vulnerability class the table does not know merges into one it does (LOW)

A12's class table can only say "different" or "unknown", so an unrecognised
title is mergeable with any class:

```
survivor title: SQL injection in the artist parameter
kept claim  : Log4Shell in the artist parameter
report heading: ['### H1 — SQL injection in the artist parameter']
merged: 1
```

Nothing is hidden — the absorbed title is rendered in the folded-in row — but
the issue inventory (headings, the count, the basis ladder) presents one SQLi
claim where the model made two claims of different kinds. This is A12's
documented limitation #1, now demonstrated with a concrete case rather than
asserted. Check 8.

### D7 — the primary asset is never marked as unobserved (LOW)

`report.jinja:100` renders `- Where: {{ h.target_asset }}` plainly, while the
related-asset rows carry "(this engagement never recorded this asset)"
(`report.jinja:102`). Reproduced with a hypothesis whose *primary* asset is a
path recon never saw:

```
REPORT> - Where: /never-recorded-by-recon.asp?artist=1
REPORT> - /also-never-recorded.asp — carries it (this engagement never recorded this asset)
```

The one asset the test would actually act on is the one not marked. A reader
reasonably takes "Where:" as an observed fact. Check 6, and the browser marks
neither (D4).

---

## 3. Checked and clean

Worth recording, because it is what tells us where the real fault lines are:

- **Verification outcomes are not read as proof of absence.** `VERIFY` writes
  `verified: False` with a `reason` when the probe could not run at all
  (`verify.py:133-178`), and the report renders that honestly — "the second
  check ran but did not agree **or could not run** — treat this finding with
  care" (`report.jinja:112`). The asymmetry with D1 is the finding: the
  verifier is honest about a run that did not happen and the exploiter's
  reporting is not.
- **Approval cannot be inherited by a merge.** A12 refuses to merge two
  hypotheses the operator decided differently about, and `merged_claim_record`
  stores no `approved` field, so there is no path by which one node's decision
  reaches another. Human review still sets the flag on every hypothesis and
  EXPLOIT still selects on it alone (`human_review.py:225-234`,
  `exploit.py:302-305`).
- **Validation cannot be inherited by a merge.** `verified` standing comes from
  a `verify_attempt` node's flag; a merge relabels nodes and creates none.
- **No label reference dangles after a merge.** The four node types that embed a
  hypothesis id are exactly the four the remap handles; every other node type
  uses asset/tool/source labels. Readers (`report.py`, `context.py:205-219`,
  `cli.py:1005`) all read segment 0 of the same label shape the remap rewrites.
- **The persisted graph and the report agree on the node set** — both are
  post-dedup (§1). The divergence is in the *fields* (D4), not the nodes.
- **The audit chain keeps pre-merge ids, by design**, with the alias map in
  `hypotheses_merged`. Not a defect; changing it would break append-only.

---

## 4. Prioritized recommendation for the next phase (A14)

1. **D1 first.** It is the only defect that can hand an operator a false
   assurance of absence, and the fix is local: the report must read the attempt's
   `ok` / `exit_code` it already stores, and say "could not run" rather than
   "checked and found nothing". The `Tested:` and "Tools were run" lines must
   come from runs that actually happened. One shared predicate, used by all
   three lines.
2. **D2 with it.** Same root cause, one line of template, and it feeds an LLM
   rather than a human — so an unrun test propagates into remediation advice.
3. **D5, then D4.** D5 is a resolution check on a model-supplied id (reject or
   mark it, and teach `validate_report` to notice). D4 is a rendering decision:
   either persist nothing new and let the browser compute the same views the
   report does, or expose the two markers it already has the data for. Both are
   "do not present the model's claim without the engine's answer".
4. **D3 is a placement question, not a bug** — it needs a decision, not a patch:
   whether dedup belongs before BLUE_TEAM (so one claim yields one remediation)
   or whether BLUE_TEAM should be told a pair is a duplicate. Changing when
   dedup runs touches ordering, so it wants explicit approval.
5. **D6/D7 are the known ceilings** of A12's class table and A11's asset
   marking. Extend the table when a real report shows a collision; mark the
   primary asset when the next report revision happens.

## 5. Regression tests added

`tests/test_hypothesis_lifecycle_a13.py` — 10 tests, all passing, no
production code touched:

- **One per demonstrated defect** (D1–D7), each pinning today's behaviour with
  a docstring that names it a defect. Two of them run the real `EXPLOIT`
  subagent against a fake sandbox so the false report is produced by the
  product, not by a hand-built fixture.
- **Three for properties that hold**, so a later fix cannot quietly undo them:
  a failed verification is not reported as agreement; no node label refers to
  a hypothesis a merge removed; the persisted graph and the report agree on
  the node set.

Approval- and validation-inheritance are already pinned by
`tests/test_hypothesis_dedup_a12.py` (A12 requirements 5 and 6) and are not
duplicated here.

These tests are the failing targets for A14: each one asserts the defective
output, so the fix makes it fail and forces the assertion to be inverted into
the correct expectation. Nothing was fixed in this phase.

Full suite on this tree: **1587 passed, 3 skipped, 7 failed** — the 7 are
`test_openai_compatible.py`, all `DLL load failed while importing jiter: An
Application Control policy has blocked this file` on this machine, and they
fail identically on the unmodified HEAD.
