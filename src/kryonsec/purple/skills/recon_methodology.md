---
name: recon_methodology
version: 1
category: methodology
stages: [RECON_PASSIVE, RECON_ACTIVE]
description: How to read an engagement's recon record honestly — what each observation class is worth, where the gaps are, and what must never be inferred from absence.
---
Methodology for reading reconnaissance records.

**Facts before conclusions.** Every statement about the target must trace
to a recorded observation: a node the engagement holds, with its source
(provenance) and status. Name the record when you cite it. A claim that
cannot name where it came from is a guess, and must be marked as one.

**Know what each class of observation is worth.** A passive source
(certificate transparency, third-party records) tells you what has
existed and what others have seen; it does not tell you what is alive
today. An active check tells you what answered at the time it ran, from
one vantage point; it does not tell you what is true from everywhere.
Screenshots and page captures describe the application as the tool saw
it, not as every user sees it. Weigh age, vantage and tool coverage
together, and say which of the three limits a conclusion.

**Absence is not evidence of absence.** A port that did not answer, a
subdomain no source reported, a technology no fingerprint matched — none
of these establish that the thing is not there. They establish that this
tool, at this time, from this vantage, did not find it. Record that
sentence, not the shorter one.

**Prefer bounded enumeration to open claims.** When listing what an
asset exposes, enumerate the specific observations (ports, headers,
paths, technologies) rather than summarising ("looks like a standard
stack"). A summary hides the exact evidence a reviewer needs to weigh,
and it invites the reader to accept a shape the evidence only partly
shows.

**Never conclude reachability from adjacency.** That a subdomain
resolves, or a service is registered, does not establish that it is
reachable from any vantage the engagement holds, and nothing here
establishes exploitability. Note dependencies ("depends_on", "hosts")
as recorded relationships, and keep the question of whether they hold
from the testing vantage open unless an observation answers it.

**Gaps are findings too.** The most useful recon answer is often a
precisely stated gap: the asset class that was never enumerated, the
host range no source covered, the API surface no crawler reached. State
gaps as gaps, with what would be needed to close them — never as
assumptions that they are empty.
