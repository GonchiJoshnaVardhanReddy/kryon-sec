---
name: severity_calibration
version: 1
category: calibration
stages: [BLUE_TEAM, REPORT]
description: How to calibrate severity honestly — impact and exposure against the engine's own standing, without inflating unvalidated findings.
---
Methodology for severity calibration.

**Severity follows standing.** A finding the engine has not validated is
a candidate, not a confirmed exposure — and its severity must be stated
as the severity it would have IF the standing rises, not as a present
fact. Use the engine's standing words (proposed, supported, tested,
validated) next to every severity judgement, and never assign a
validated finding's severity to an unvalidated one.

**Impact first, but evidenced.** Impact is what the exposure lets an
attacker do, to what data, under what conditions. Ground every impact
statement in a recorded observation: the data class the endpoint
handles, the privilege level the parameter bypasses, the component the
version string exposes. "Could lead to full compromise" is not a
severity argument unless the records show the path.

**Exposure is a multiplier, not a substitute.** Internet-reachable and
unauthenticated is worse than internal and authenticated — but a
critical-impact condition behind strong authentication can matter more
than a low-impact condition on the open internet. Rate the two axes
separately and combine them deliberately, saying which axis carried the
judgement.

**Resist the escalation reflex.** The most common calibration failure is
grading by story: an exploit chain drawn in prose raises severity
without adding evidence. Each link in a chain needs its own standing,
and a chain whose middle links are unvalidated has the standing of its
weakest link — say which link that is.

**Calibrate the fix urgency, not just the number.** A severity rating
that does not say what to do differently is noise. Pair every severity
with the response it implies: what to fix first, what to verify after
fixing, and what compensating control would reduce exposure while the
fix is pending. Keep that advice proportionate — over-prescribing for a
low-severity finding erodes trust in the high-severity ones.

**Uncertainty is part of the rating.** Two findings with identical
impact but different evidence quality do not get the same rating: the
one with weak standing carries the words "if validated" and the review
path that would settle it. Stating uncertainty is not hedging; it is
the difference between a calibrated rating and a confident guess.
