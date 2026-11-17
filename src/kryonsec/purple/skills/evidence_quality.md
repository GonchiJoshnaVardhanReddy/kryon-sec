---
name: evidence_quality
version: 1
category: analysis
stages: [HYPOTHESIZE, VERIFY]
description: How to grade the quality of recorded evidence — source independence, tool coverage, freshness, and the standing words the engine itself derives.
---
Methodology for grading evidence quality.

**Grade the record, not the story.** An engagement's evidence has an
engine-derived standing for every claim: proposed (a model suggested it),
supported (the assets it names are recorded facts), tested (an approved
check ran), validated (an independent check reproduced it). Use those
words, and only those words, when stating what a claim is worth. A
confident-sounding summary does not move standing; records do.

**Count the independent sources.** One source reporting an observation is
one source. Two sources that both derive from the same upstream data are
still one source. When assessing whether an observation is solid, name
the sources and ask whether they can fail together: same vantage, same
dataset, same tool bug. Independence is the strongest quality signal
there is.

**Separate the observation from its interpretation.** A header value, a
port that answered, a page that rendered — these are observations. What
they imply ("this framework is exploitable") is interpretation. Record
both, label them separately, and never let an interpretation inherit the
confidence of the observation it came from.

**Weight freshness honestly.** Evidence ages at different rates: a
certificate list is historical, a fingerprint is point-in-time, a
configuration record describes the moment of capture. When a conclusion
depends on something being true now, state how old the supporting
observation is and what would change if it were stale.

**Say what the tool could not see.** Every tool has blind spots — the
paths it does not follow, the encodings it does not decode, the states it
does not reach. An assessment that ignores blind spots overstates what
was established. Name the coverage limit next to the conclusion it
bounds.

**A test that found nothing is not evidence of absence.** The most
common quality failure in security work is reading an empty result as a
clean bill. If the check did not run, say "not run". If it ran and found
nothing, say what it covered and what remained outside that coverage.
Never write "no vulnerability found" as if it were a finding.
