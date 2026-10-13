# A12 — Hypothesis Deduplication (read-only audit)

**Date:** 2026-10-12
**Audited commit:** `7cd447fe9baec8b9619272e1d2fbc664d3da189d`
("feat(purple): show the memory browser link when an engagement starts",
Sun Oct 11 00:40:49 2026 +0530)
**Working tree:** A9–A11 are implemented but uncommitted (the audit ran on
that tree, which is the tree A12 must build on). No migration, no graph
change, no commit, no push. The findings below were produced by running the
current `dedup_hypotheses` on constructed graphs — the four collision cases
in §5 are reproduced output, not a reading.

---

## 1. The current key and its call sites

`report.dedup_hypotheses(graph, audit)` — `src/kryonsec/purple/report.py:131`.
The key is:

```python
key = (
    tuple(sorted(str(t) for t in props.get("tools") or [])),
    str(props.get("target_asset", "")),
)
```

Two fields: the sorted tool set, and the target asset. **Exactly one
production call site:** `ReportSubagent.run`, `report.py:487`, at the top of
the REPORT state. It is wrapped in `try/except` — a dedup failure is audited
as `dedup_failed` and the report still renders, because REPORT must never
fail. Tests call it directly (`test_blue_team_report.py`, `test_graph_persistence.py`).

## 2. When it runs, relative to review and execution

The transition table (`orchestrator.py:70`) is
`… HYPOTHESIZE → HUMAN_REVIEW → EXPLOIT → (POST_EXPLOIT) → VERIFY →
BLUE_TEAM → REPORT → HALT`.

Dedup runs in **REPORT**, i.e. **after** the human gate and **after** every
tool run. So a merge never changes what was approved or what was executed;
it changes only what the graph and the report *say*. That is the right place
for it and A12 does not move it.

There is a second, unrelated dedup at hypothesis time
(`hypothesize.py`, duplicate *ids* from one model reply) which runs before
approval. It is not this function and A12 does not touch it.

Consequence worth stating plainly: by the time dedup runs, the merged-away
node has already been reviewed by the operator and may already have been
executed. The merge is therefore **only ever allowed to be a bookkeeping
identity**, never a decision.

## 3. What survives a merge

The victim's fields are folded into the canonical node in `report.py:155-164`:

| Field | Rule |
|---|---|
| `confidence` | max of the two |
| `cve` | first non-empty wins |
| `cvss_vector` | first non-empty wins |
| `enrichment` | first present wins |
| `merged_from` | victim label appended |
| everything else on the canonical | untouched |

**Lost from the victim, with no copy anywhere in `properties`:**
`title`, `rationale`, `approved`, `related_assets`, `relationship`, and the
victim's own `cve` / `cvss_vector` / `enrichment` when the canonical already
had one.

The only trace of the victim after the merge is
`provenance["merged_nodes"]` (written by `EngagementGraph._record_merge`,
`recon_passive.py:546`), which keeps the victim's `label`, `status` and
`provenance` — **not its `properties`**. That is enough to say a node was
absorbed and where it came from; it is not enough to recover what it
claimed. It does survive `save_graph`/`load_graph` (`graph_store.py:154`).

## 4. How `merged_from` is used

Written at `report.py:164`. Read by **nothing**: not `report.jinja`, not
`blue_team.jinja`, not `memory/data.py`, not the memory browser JS, not
`validate_report`, not VERIFY. Its only readers are three test assertions.

So today an operator reading the report **cannot tell that two hypotheses
were merged**, let alone what was folded in. `hypotheses_merged` on the
audit chain carries the alias map, so the fact is reconstructible from the
chain — but the deliverable, which is the report, does not say it.

## 5. Where hypotheses collide — four demonstrated cases

**Case 1 — different vulnerability classes, same tool and asset.**

```
H1  title "SQL injection in artist parameter"    tools [sqlmap]  asset /ListProducts.asp?artist=1
H2  title "Stored XSS in artist parameter"       tools [sqlmap]  asset /ListProducts.asp?artist=1
```

`merged == 1`, survivor `H1`. The XSS hypothesis is gone: its title and
rationale are not stored anywhere, and nothing in the report says a second,
different claim existed. This is a **material security distinction
destroyed by the merge**: the report now claims the SQL-injection reading is
the only one, and the operator's approval decision was made about a
hypothesis set that no longer matches the deliverable.

**Case 2 — divergent operator decisions.**

```
H1  approved False, later tested     (same tools + asset)
H2  approved True
```

`merged == 1`; the survivor's `approved` stays `False`, but it inherits
H2's `exploit_attempt` edges, so the report renders:

```
- Your decision: not approved
- Tested: yes
- Result: **confirmed by the test tool**
```

A hypothesis the operator rejected is reported as tested and confirmed. The
test did run and the finding is real — but it ran for the *other* id, and
the report gives the reader no way to see that. This is an
**explainability failure with a security reading**: "not approved" and
"confirmed" on the same bullet.

**Case 3 — universal collision on degenerate fields.**

```
H1/H2/H3  title "unrelated idea 1/2/3", tools [], target_asset ""
```

`merged == 2`, one survivor. Every hypothesis with no tools and no asset
shares the key `((), "")` and collapses into one node. Three unrelated
claims became one. This is **pure data loss** and needs no adversarial
input — an empty `target_asset` is allowed by the schema
(`hypothesize.py`, no `min_length`).

**Case 4 — A11 structured claims collide and are discarded.**

```
H1  related_assets [/admin/list.asp]   relationship "…writes rows /admin/list.asp renders"
H2  related_assets [/reports/daily.asp] relationship "…writes rows /reports/daily.asp renders"
```

`merged == 1`. The survivor keeps H1's relationship and reference list;
H2's conflicting claim is dropped and survives only as
`merged_nodes[].label`. Two *conflicting* relationship claims became one,
silently — the exact thing A11 built the fields to make reviewable.

### Summary of the collision dimensions

| Distinction | In the key? | Survives a merge? |
|---|---|---|
| tool set | yes | n/a (equal by definition) |
| target asset | yes | n/a |
| vulnerability class (title) | no | **no** |
| rationale (distinct evidence) | no | **no** |
| CVE | no | only if the canonical had none |
| CVSS vector | no | only if the canonical had none |
| A11 `related_assets` | no | **no** |
| A11 `relationship` | no | **no** |
| operator decision (`approved`) | no | **no** |

Answering the audit question directly: **yes.** Hypotheses differing in
vulnerability class, evidence, CVE and asset relationship collide today, and
the differing content is discarded rather than preserved.

## 6. Why it was written this way, and what stays

The dedup exists for a real problem: the model re-proposes the same test
across passes, and the report should not double-count it. Phase 6 chose
"merge in the graph, not at render time" so every consumer sees one view
(`docs/TOOL-EXPANSION-2026-09-13.md`, "Decisions made during Phase 6"), and
`merge_node` was introduced so a merge stops cascading the victim's edges
away.

Both decisions are right and are kept. What is wrong is that (a) the key
cannot tell "the same test" from "the same claim", and (b) the merge keeps
only the fields it thought to keep, so the classes of collision in §5 are
invisible after the fact.

## 7. What A12 therefore has to do

1. A merge must require the two hypotheses to be *the same claim*, not
   merely the same test — so a class difference cannot be merged away.
2. When a merge does happen, the absorbed claim's title, rationale,
   relationship and reference list must be **kept on the survivor** and
   **shown in the report** — nothing silently dropped.
3. Standing must not move because of a merge (A11's ladder, §"Standing").
4. `validate_report`'s duplicate rule keys on the same definition, or a
   safe merge decision would be reported as a validation failure.
5. No migration: `properties` is free-form JSON with no size cap
   (`recon_passive.py:222` computes size, never enforces one).

---

## 8. What was implemented

The key became an **equivalence**, not a bucket. `report._apart_reason(left,
right)` returns `""` when two hypotheses are the same claim and otherwise the
reason they are not; `mergeable()` is that returning nothing, and both
`dedup_hypotheses` and `validate_report` use it, so the merge decision and the
validation rule cannot drift apart.

A pair is the same claim when **all** of these hold:

| Term | Blocks the merge when |
|---|---|
| `_test_key` (tools, target asset) | different — unchanged from Phase 6 |
| test identity | both empty: no tool and no asset names no test |
| `_vuln_class(title)` | both titles name a *known* class and the classes differ |
| `_claim_asset_keys` | both name related assets and the sets differ |
| `approved` | the operator decided differently about them |

An absent claim conflicts with nothing (a legacy node and a single-asset node
stay mergeable in every direction), which is what keeps legacy graphs behaving
as they did. The class test is a keyword table, deliberately unable to say
"same" — only "different" or "unknown" — so rewording the same idea across
model passes still merges, which was the whole point of keying on the test
rather than the prose.

Two further properties:

- **Nothing is lost.** A merge keeps the absorbed hypothesis's own `title`,
  `rationale`, `relationship` and `related_assets` in
  `properties["merged_claims"]` (bounded, single-lined), alongside the legacy
  `merged_from` label list, and the report renders them under the survivor.
  Before this, `merged_from` was written and read by nothing at all (§4).
- **Nothing moves.** The merge writes no standing-bearing field: not
  `approved`, not `related_assets`, not `relationship`, not the basis ladder.
  So a merge cannot grant approval (req. 6) and cannot raise engine-derived
  standing (req. 5) — it can only ever be a bookkeeping identity, which is
  what running after the human gate and after execution requires (§2).

Outcomes are deterministic (insertion order; first mergeable canonical wins)
and explainable: `hypotheses_merged` now carries `kept_apart` — each pair that
shared a test and was deliberately left as two nodes, with the reason — and a
run that merges nothing but keeps such a pair writes
`hypotheses_kept_apart` instead of staying silent.

**Not changed:** the state machine, the human approval gate, execution order,
scope/allowlist/sandbox, secret routing, tool argument construction, and the
verification criteria. No migration. No graph edges added. `merge_node`'s
behaviour is untouched.

