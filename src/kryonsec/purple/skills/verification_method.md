---
name: verification_method
version: 1
category: verification
stages: [EXPLOIT, VERIFY]
description: How independent verification should be designed and read — minimal reproduction, evidence capture, and the difference between inconclusive and absent.
---
Methodology for independent verification.

**Verify the recorded claim, not the hypothesis's potential.** A
verification check answers one question: does an independent probe
reproduce what the earlier stage recorded? Design the smallest check
that would produce the recorded marker if the claim is true and fail to
produce it if the claim is false. Anything larger turns verification
into re-exploitation, and inherits every ambiguity it was meant to
resolve.

**Independence is the point.** A check that reuses the original probe,
the original payload and the original parser is not independent — it
can repeat the original's mistakes with full confidence. Change the
vantage, the payload family or the detection method, so agreement
between the two paths is genuinely informative.

**Capture evidence before you conclude.** Every verification run must
record what it observed — the response excerpt, the timing, the
artifact — at the moment it observed it, into the engagement's evidence
store. A conclusion written without captured evidence is unverifiable
itself, and a verifier's word is only worth as much as what it saved.

**Inconclusive is a real outcome.** A check that could not establish the
claim either way — because the target was unreachable, the response was
ambiguous, or the marker was not designed to distinguish the
hypothesis from its alternatives — must be recorded as inconclusive,
with the reason. Never grade an inconclusive check as agreement, and
never grade it as refutation.

**Read negatives with coverage in mind.** "The marker did not appear"
means the check ran and did not reproduce the claim — nothing more.
State what the check actually covered (endpoint, parameter, encoding,
condition) and what remained outside it. A negative result narrows the
claim; it does not delete it.

**Stay inside the authorized scope.** Verification runs against the
assets the engagement is authorized to test, with the methods the
engagement's own records describe. A reproducing check that had to
leave scope to work has not verified the claim — it has produced a new,
unauthorized observation, and it must be reported as a problem with the
check rather than used as evidence about the target.
