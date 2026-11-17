---
name: defensive_remediation
version: 1
category: remediation
stages: [BLUE_TEAM]
description: How to write remediation guidance that survives contact with an engineering team — specific, prioritised, verifiable, and proportionate to standing.
---
Methodology for defensive remediation.

**Fix the cause, name the pattern.** Guidance aimed at one line of code
is guidance that expires at the next refactor. Name the vulnerable
pattern (the missing authorization check class, the unparameterised
query construction, the client-side trust decision) and the
counter-pattern that replaces it, so the fix generalises to every place
the pattern occurs — and say where else in the asset class the pattern
should be hunted.

**Prioritise by exposure and reversibility.** Order remediation by what
closes the most risk soonest: exposures that are internet-reachable and
cheap to fix first; conditions needing design work scheduled next;
hardening that reduces blast radius in parallel. Say the reasoning in
one line per item, so the reader can re-order it against their own
constraints without losing the logic.

**Every fix needs a verification step.** Guidance without a check is a
wish. For each recommendation, state how the fix will be shown to work
— the test to run, the behaviour to exercise, the regression to guard —
in words the team can execute. A fix that cannot be verified should be
rewritten until it can.

**Proportion the response to the standing.** Findings the engine has
validated deserve planned engineering work; findings that are still
candidates deserve containment and a validation path, not a redesign.
Writing remediation that assumes an unvalidated finding is true spends
the team's trust on a story, and the next report pays for it.

**Prefer controls that survive mistakes.** Where a choice exists,
recommend the control that holds when someone is tired: server-side
authorization on every request, parameterised storage access by
default, fail-closed parsing, centralized session checks. Human
discipline is a control of last resort; when guidance depends on it,
say so and offer the structural alternative.

**Record what was assumed.** Remediation is written against the
engagement's records, and records have gaps. When advice rests on an
assumption — that the deployment matches the observed configuration,
that the dataset is what the endpoints suggest — mark the assumption
and what observing it differently would change. Honest guidance
survives review; confident guidance does not.
