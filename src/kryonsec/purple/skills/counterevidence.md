---
name: counterevidence
version: 1
category: analysis
stages: [HYPOTHESIZE, VERIFY]
description: How to argue against your own working hypothesis — the alternative explanations a recorded observation admits, and what would genuinely disconfirm a claim.
---
Methodology for counterevidence and false-positive analysis.

**Every observation admits alternatives.** Before treating a recorded
observation as support for a hypothesis, list at least two other
explanations that would produce the same record: a misconfigured
monitoring path, a cached response, a default page, a tool behaviour
that emits the marker without the condition being met. If the
hypothesis only beats the alternatives on tone — because it is more
interesting — that is not evidence.

**State the disconfirming test.** For a claim to be assessable, there
must be something that, if observed, would count against it. Write that
observation down explicitly ("a response that returns X without Y would
disconfirm this"). A hypothesis that no observation could disconfirm is
not a strong hypothesis; it is an unfalsifiable one, and it should be
recorded as such.

**Watch for the echo.** The same source read twice, the same conclusion
copied into two places, a finding re-stated with the word "confirmed"
attached — these create the feeling of independent support. When
assessing how much support a claim has, count distinct observations,
not distinct sentences.

**Consider the benign explanation seriously.** Version banners, verbose
error pages, exposed documentation endpoints and permissive headers are
often simply how the application ships. The question is not whether the
condition is present but whether it matters given how the system is
actually used and defended — and that question is answered with
evidence about usage and defence, which mostly lives outside the
scanner.

**Record the counter-case, not just the winner.** An assessment that
ends with one conclusion and no runner-up hides its uncertainty from
the reader. Record the strongest alternative alongside the supported
one, with what evidence would separate them. Downstream stages — and
the human reviewer — can act on that honestly.

**Do not let severity leak into confidence.** A frightening potential
impact can make weak evidence feel strong. Keep the two separate: how
bad it would be if true (impact), and how much reason there is to
believe it is true (standing). A high-impact claim with weak standing
should be recorded as exactly that, in those words.
