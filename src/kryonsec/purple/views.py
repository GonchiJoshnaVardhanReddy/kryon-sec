"""Engine-derived views over an engagement graph.

Every function here answers a question about what the **engine** recorded,
from the graph alone: which assets the engagement observed, what standing a
hypothesis's claim has, and how far the EXPLOIT phase actually got with it.
None of it is model text, and none of it can be raised by model text — a
hypothesis whose prose says "confirmed" renders the same view as one that
says nothing, because the ladder is read off the engine's own nodes.

This module is read-only: no subagent, no LLM call, no sandbox, no audit
chain, no state transition, nothing that can act. The report, the blue-team
prompt, the human-review screen and the memory browser all render the same
answers through it, which is the point of having one home for them (A14) —
two surfaces reading the same graph can no longer describe it differently.

The functions used to live in ``hypothesize`` (which is where A11 put them).
They were never about that subagent: they are what the *engagement* can say
about a claim the subagent produced. ``hypothesize`` re-exports every name
below, so nothing that imported them from there had to change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# ``text`` and not ``context``: this module is imported by the memory browser,
# and ``context`` would drag the LLM client and the tool allowlist into a
# read-only viewer process. ``text`` is stdlib-only, which is what lets the
# whole of this module be reachable from there (A14/D4).
from .text import normalize_line

if TYPE_CHECKING:  # the graph type only — this module imports no subagent
    from .recon_passive import EngagementGraph

__all__ = [
    "ASSET_NODE_TYPES",
    "ATTEMPT_CONFIRMED",
    "ATTEMPT_INCONCLUSIVE",
    "ATTEMPT_NONE",
    "ATTEMPT_NOTES",
    "ATTEMPT_NOT_RUN",
    "ATTEMPT_TOOL_ERROR",
    "ATTEMPT_UNRECORDED",
    "BASIS_NOTES",
    "BASIS_PROPOSED",
    "BASIS_SUPPORTED",
    "BASIS_TESTED",
    "BASIS_VALIDATED",
    "MAX_ASSET_CHARS",
    "MAX_RELATIONSHIP_CHARS",
    "MAX_ROLE_CHARS",
    "OUTCOMES_RUN",
    "VERIFICATION_DISAGREED",
    "VERIFICATION_INCONCLUSIVE",
    "VERIFICATION_NOTES",
    "VERIFICATION_NOT_RUN",
    "VERIFICATION_UNRESOLVED",
    "VERIFICATION_VERIFIED",
    "asset_key",
    "attempt_names",
    "attempt_outcome",
    "exploit_status",
    "finding_verification_status",
    "hypothesis_engine_view",
    "observed_assets",
    "primary_asset_observed",
    "related_asset_views",
    "relationship_basis",
    "verification_status",
]


# --- the multi-asset claim and its standing (A11) ---------------------------
#
# The *standing* of a claim is never a field. A model can describe a
# relationship; it cannot say what the engine makes of it. The four levels
# below are derived from the engine's own records, so a model that writes
# "confirmed" into its prose produces a hypothesis whose rendered basis still
# says otherwise.

MAX_ASSET_CHARS = 300
MAX_ROLE_CHARS = 120
MAX_RELATIONSHIP_CHARS = 400

BASIS_PROPOSED = "proposed"
BASIS_SUPPORTED = "supported"
BASIS_TESTED = "tested"
BASIS_VALIDATED = "validated"

# What each level means, in the operator's words. The first two are about the
# claim; the last two are about the engagement, and neither model text nor
# an asset that merely *looks* related can reach them.
BASIS_NOTES: dict[str, str] = {
    BASIS_PROPOSED: (
        "the assistant proposed this and the engagement supports none of it: "
        "at least one asset it names is not one this engagement observed"
    ),
    BASIS_SUPPORTED: (
        "every asset it names is one this engagement observed — the assets "
        "are facts the engine recorded, but what they might do together is "
        "still only the assistant's proposal"
    ),
    BASIS_TESTED: (
        "an approved test has run against this hypothesis; what that test "
        "recorded is in the test history, and a test having run is not a "
        "vulnerability having been found"
    ),
    BASIS_VALIDATED: (
        "an independent check reproduced the recorded finding"
    ),
}

# The node types that record an asset the engagement actually observed. A
# hypothesis's claim is graded against these labels and nothing else.
ASSET_NODE_TYPES = frozenset({
    "target", "subdomain", "web_endpoint", "path", "service",
})
# kept as the old private name: ``hypothesize`` and its tests referred to it
_ASSET_NODE_TYPES = ASSET_NODE_TYPES


def claim_text(value: object, limit: int) -> str:
    """One bounded, single-line piece of model-supplied claim text.

    The block's own line treatment, reused: whitespace and control
    characters collapse, the cap is applied after that, and the result
    cannot add a line to whatever renders it. Empty and non-string values
    become the empty string — a claim that names nothing is dropped, not
    guessed at.
    """
    return normalize_line(value, limit) or ""


# kept as the old private name: ``hypothesize``'s validators call it
_claim_text = claim_text


def asset_key(value: object) -> str:
    """An asset's identity, for asking whether the engagement observed it.

    A hypothesis names its asset *with* its parameter — the prompt asks for
    that — while recon records a path without one, so the query string and
    the fragment are not part of the identity, nor is a scheme, a trailing
    slash, or the case. Nothing else is normalised: a different path, host
    or spelling is a different asset, and an asset the engagement never
    recorded must never be read as one it did.
    """
    text = claim_text(value, MAX_ASSET_CHARS)
    if not text:
        return ""
    for sep in ("?", "#"):
        text = text.split(sep, 1)[0]
    if "://" in text:
        text = text.split("://", 1)[1]
    return (text.rstrip("/") or "/").lower()


def observed_assets(graph: EngagementGraph) -> set[str]:
    """The assets this engagement recorded, in :func:`asset_key` form."""
    return {
        asset_key(node.get("label"))
        for node in graph.nodes
        if isinstance(node, dict)
        and node.get("node_type") in _ASSET_NODE_TYPES
    } - {""}


def related_asset_views(node: dict, graph: EngagementGraph) -> list[dict]:
    """A hypothesis's extra asset references, each marked as observed or not.

    This is the render view: the reference text is normalised here exactly
    as it is stored, so a value that reached the graph by some other route
    cannot add a line to a report. A reference the engagement never recorded
    is marked ``observed: False`` and stays that way — it is never resolved
    against a similarly-named asset.
    """
    properties = node.get("properties") or {}
    if not isinstance(properties, dict):
        return []
    raw = properties.get("related_assets")
    if not isinstance(raw, (list, tuple)):
        return []

    observed = observed_assets(graph)
    views: list[dict] = []
    for entry in raw:
        if isinstance(entry, str):
            entry = {"asset": entry}
        if not isinstance(entry, dict):
            continue
        asset = claim_text(entry.get("asset"), MAX_ASSET_CHARS)
        if not asset:
            continue
        views.append({
            "asset": asset,
            "role": claim_text(entry.get("role"), MAX_ROLE_CHARS),
            "observed": asset_key(asset) in observed,
        })
    return views


def primary_asset_observed(node: dict, graph: EngagementGraph) -> bool:
    """Whether the asset a hypothesis names as its own is one recon observed.

    ``True`` when it names no asset at all: there is nothing there to call
    unobserved, and a hypothesis that named none is not claiming one. This
    is the same question :func:`related_asset_views` answers for the extra
    references — the asset the test would actually act on is not a special
    case (A13 D7).
    """
    properties = node.get("properties") or {}
    if not isinstance(properties, dict):
        return True
    key = asset_key(properties.get("target_asset"))
    if not key:
        return True
    return key in observed_assets(graph)


def relationship_basis(node: dict, graph: EngagementGraph) -> str:
    """What the engine can say about this hypothesis's relationship claim.

    A ladder over the engine's own records, highest rung first. The two top
    rungs are the engagement's: a verification that reproduced, or a test
    that actually ran. The next is the graph's: every asset the hypothesis
    names is one this engagement observed. Below that is the model's own
    proposal, and nothing else can raise it — which is what makes "the model
    may not call its own claim validated" a property of the system rather
    than a request to the model.
    """
    label = node.get("label")
    if isinstance(label, str) and label:
        for attempt in graph.by_type("verify_attempt"):
            if (attempt.get("label") == label
                    and verification_status(attempt)
                    == VERIFICATION_VERIFIED):
                return BASIS_VALIDATED
        # A14: an attempt node's existence used to be enough to reach this
        # rung, so a sandbox that never started still told the reader "an
        # approved test has run against this hypothesis". The node is written
        # for every tool EXPLOIT *tries*; only one that ran counts.
        if exploit_status(label, graph) in OUTCOMES_RUN:
            return BASIS_TESTED

    observed = observed_assets(graph)
    properties = node.get("properties") or {}
    named = [properties.get("target_asset")] if isinstance(properties, dict) else []
    named += [view["asset"] for view in related_asset_views(node, graph)]
    keys = [asset_key(value) for value in named]
    if keys and all(key in observed for key in keys):
        return BASIS_SUPPORTED
    return BASIS_PROPOSED


# --- what the EXPLOIT phase actually did (A14) ------------------------------
#
# EXPLOIT writes one ``exploit_attempt`` node per tool it *tries* to run,
# labelled ``"{hypothesis_id}:{tool}"``, whether or not the tool ran
# (``exploit.py``). The sandbox's own record rides along: ``ok`` is its
# verdict on **process creation** — docker reached, output parsed — and
# nothing else, ``error_excerpt`` says why it did not start, and ``confirmed``
# is set only when the tool's own output carried the marker.
#
# So ``ok=True`` never means "the security check succeeded", and a node's mere
# existence never means a check happened. Reading either as "we tested it and
# it came back clean" turns a sandbox that never came up into a clean bill of
# health — which is what the report did, four times, for a run no tool
# performed (A13 D1).

ATTEMPT_CONFIRMED = "confirmed"        # the tool ran; its output had the marker
ATTEMPT_INCONCLUSIVE = "inconclusive"  # the tool ran to completion; the marker was absent
ATTEMPT_TOOL_ERROR = "tool-error"      # the tool ran but exited nonzero — the check did not complete
ATTEMPT_NOT_RUN = "not-run"            # the record says the process never started
ATTEMPT_UNRECORDED = "unrecorded"      # no record either way
ATTEMPT_NONE = "none"                  # no attempt at all for this hypothesis

#: Every outcome, weakest first. This is also the comparison order when one
#: hypothesis has several attempts: the best one recorded wins, so a second
#: tool that could not start never undoes a first that ran. tool-error sits
#: below inconclusive: an interrupted check establishes even less than a
#: completed one that found nothing.
_ATTEMPT_ORDER: tuple[str, ...] = (
    ATTEMPT_NONE,
    ATTEMPT_NOT_RUN,
    ATTEMPT_UNRECORDED,
    ATTEMPT_TOOL_ERROR,
    ATTEMPT_INCONCLUSIVE,
    ATTEMPT_CONFIRMED,
)

#: The outcomes that mean a tool really ran against the target. tool-error
#: IS a run — a killed/partial tool touched the target — but its evidence
#: is incomplete, which the note below says in plain words.
OUTCOMES_RUN = frozenset({
    ATTEMPT_TOOL_ERROR, ATTEMPT_INCONCLUSIVE, ATTEMPT_CONFIRMED})

# What each outcome means, in the operator's words. The two that did not run
# are deliberately not phrased as results: nothing was checked, so there is
# no absence of anything to report.
ATTEMPT_NOTES: dict[str, str] = {
    ATTEMPT_NONE: "no test was proposed for it",
    ATTEMPT_NOT_RUN: (
        "the tool could not be started, so nothing about this was checked"
    ),
    ATTEMPT_UNRECORDED: (
        "an attempt was recorded, but the engagement did not record whether "
        "the tool started"
    ),
    ATTEMPT_TOOL_ERROR: (
        "a test started but did not complete (the tool exited with an "
        "error) — whatever it printed is partial evidence, not a clean "
        "result"
    ),
    ATTEMPT_INCONCLUSIVE: (
        "a test ran and did not confirm it — a test that found nothing is "
        "not evidence that the issue is absent"
    ),
    ATTEMPT_CONFIRMED: "a test ran and the tool's own output confirmed it",
}


def attempt_outcome(node: dict) -> str:
    """What one ``exploit_attempt`` node records about its own run."""
    properties = node.get("properties") if isinstance(node, dict) else None
    if not isinstance(properties, dict):
        return ATTEMPT_UNRECORDED
    # ``confirmed`` is only ever written by the producer for a run that
    # started (``ExploitSubagent._confirmed`` returns False when the spawn
    # did not), so it is a record of execution on its own — which is why it
    # is read first, and why a hand-built node carrying only ``confirmed``
    # still reads as a run.
    if properties.get("confirmed"):
        return ATTEMPT_CONFIRMED
    if properties.get("ok") is True:
        # a nonzero exit is NOT a completed check: it is an interrupted
        # one (Phase 2, 2026-11-17 — exit 137 at the sandbox cap and
        # curl 18 on a truncated response both used to read as
        # "inconclusive", i.e. a clean no-finding run). Records from
        # before exit codes were stored read as inconclusive, exactly
        # as before.
        exit_code = properties.get("exit_code")
        if isinstance(exit_code, int) and not isinstance(exit_code, bool) \
                and exit_code != 0:
            return ATTEMPT_TOOL_ERROR
        return ATTEMPT_INCONCLUSIVE
    if properties.get("ok") is False:
        return ATTEMPT_NOT_RUN
    return ATTEMPT_UNRECORDED


def attempt_names(attempt_label: object, hypothesis_id: str) -> bool:
    """Whether an ``exploit_attempt`` label belongs to this hypothesis.

    The label is ``"{id}:{tool}"``. An id cannot contain a colon —
    HYPOTHESIZE forbids it precisely because this is where it would break —
    so an exact match or a ``"{id}:"`` prefix is the whole test.
    """
    if not hypothesis_id or not isinstance(attempt_label, str):
        return False
    return (attempt_label == hypothesis_id
            or attempt_label.startswith(f"{hypothesis_id}:"))


# --- what the independent check (VERIFY) actually established ----------------
#
# VERIFY writes one ``verify_attempt`` node per finding it *works* on, and
# the node records its own execution evidence: whether the probes returned
# responses (``true_len``/``false_len``), whether a baseline was available
# (``baseline_len``), the boolean verdict (``verified``) and, when blocked,
# the actual blocking reason (``reason``). The status is *derived* from
# those fields — never from a stored label — exactly like the EXPLOIT
# attempt outcome above.

VERIFICATION_VERIFIED = "verified"          # an independent test agreed
VERIFICATION_DISAGREED = "disagreed"        # an independent test contradicted
VERIFICATION_UNRESOLVED = "unresolved"      # agreed-looking, but counterevidence stands
VERIFICATION_INCONCLUSIVE = "inconclusive"  # ran; cannot establish either
VERIFICATION_NOT_RUN = "not_run"            # no independent check executed

#: Most informative last — a finding checked by several VERIFY passes
#: reports the strongest status its records establish.
_VERIFICATION_ORDER: tuple[str, ...] = (
    VERIFICATION_NOT_RUN,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_UNRESOLVED,
    VERIFICATION_DISAGREED,
    VERIFICATION_VERIFIED,
)

#: What each status means, in the operator's words — "not checked" is
#: never a verdict about the vulnerability.
VERIFICATION_NOTES: dict[str, str] = {
    VERIFICATION_VERIFIED: (
        "an independent test ran and agreed with the finding"
    ),
    VERIFICATION_DISAGREED: (
        "an independent test ran and did NOT agree with the finding — treat "
        "it as the first tool's claim, not an established fact"
    ),
    VERIFICATION_UNRESOLVED: (
        "the independent test ran and saw an agreeing difference, but "
        "counterevidence stands that a benign explanation could produce "
        "the same difference — the question is left open, not settled "
        "either way"
    ),
    VERIFICATION_INCONCLUSIVE: (
        "the independent test ran but could not establish either conclusion"
    ),
    VERIFICATION_NOT_RUN: (
        "no independent check ran for this finding — it is unverified "
        "either way, and none of this says the issue is not real"
    ),
}


def verification_status(node: dict) -> str:
    """What one ``verify_attempt`` node establishes — derived, not read.

    The derivation reads only the node's execution evidence:
    ``verified`` (the boolean verdict), whether the probes returned both
    responses (``true_len``/``false_len``), whether a baseline was
    available (``baseline_len``), and the recorded ``counterevidence`` —
    observations the check itself made that a benign explanation could
    account for what it saw. A node whose probes never returned
    responses is ``not_run`` — scope refusal, missing parameter, failed
    spawn — and keeps its blocking ``reason``; it is never described as
    disproven or safe. A stored ``status`` word, if any producer writes
    one, is consulted by nothing: it cannot be the basis:
    - verified=True + probes returned responses -> ``verified``
    - verified=True + responses + counterevidence -> ``unresolved``
      (the agreeing difference was seen, but recorded counterevidence
      stands that a benign cause could produce it — no promotion)
    - verified=False + no responses            -> ``not_run`` (blocked)
    - verified=False + responses, no baseline  -> ``inconclusive``
    - verified=False + responses + baseline    -> ``disagreed``
    """
    properties = node.get("properties") if isinstance(node, dict) else None
    if not isinstance(properties, dict):
        return VERIFICATION_NOT_RUN
    responses = (properties.get("true_len") is not None
                 and properties.get("false_len") is not None)
    verdict = properties.get("verified")
    counterevidence = properties.get("counterevidence")
    has_counterevidence = (isinstance(counterevidence, list)
                           and bool(counterevidence))
    if verdict is True:
        # "verified" without the probe responses it is derived from is a
        # stored word, not execution evidence — a tampered or hand-built
        # node reads as what its evidence shows: nothing.
        if not responses:
            return VERIFICATION_NOT_RUN
        if has_counterevidence:
            return VERIFICATION_UNRESOLVED
        return VERIFICATION_VERIFIED
    if verdict is False:
        if not responses:
            return VERIFICATION_NOT_RUN
        if properties.get("baseline_len") is None:
            return VERIFICATION_INCONCLUSIVE
        return VERIFICATION_DISAGREED
    return VERIFICATION_NOT_RUN


def verify_block_reason(node: dict) -> str:
    """The recorded blocking reason of a verify_attempt that never ran
    ("" when none was recorded)."""
    properties = node.get("properties") if isinstance(node, dict) else None
    if not isinstance(properties, dict):
        return ""
    return str(properties.get("reason") or "")


def finding_verification_status(finding_id: str, graph: "EngagementGraph") -> str:
    """The independent-verification standing of one finding (by label).

    The strongest status any of the finding's ``verify_attempt`` records
    establishes; with no record at all that is ``not_run`` — no
    independent verification was executed.
    """
    statuses = [
        verification_status(attempt)
        for attempt in graph.by_type("verify_attempt")
        if attempt.get("label") == finding_id
    ]
    if not statuses:
        return VERIFICATION_NOT_RUN
    return max(statuses, key=_VERIFICATION_ORDER.index)


def finding_verification_detail(
        finding_id: str, graph: "EngagementGraph",) -> dict:
    """The render/print view of one finding's verification standing:
    derived status, operator note, the actual blocking reason when the
    check never ran, and — recorded, never discarded — the
    counterevidence the strongest attempt saw."""
    status = finding_verification_status(finding_id, graph)
    reason = ""
    counterevidence: "list[str]" = []
    for attempt in graph.by_type("verify_attempt"):
        if attempt.get("label") != finding_id:
            continue
        derived = verification_status(attempt)
        if derived == VERIFICATION_NOT_RUN and not reason:
            reason = verify_block_reason(attempt)
        if derived == status:
            ce = (attempt.get("properties") or {}).get("counterevidence")
            if isinstance(ce, list) and ce:
                counterevidence = [str(c) for c in ce]
    note = VERIFICATION_NOTES[status]
    return {"status": status, "note": note, "block_reason": reason,
            "counterevidence": counterevidence}


def exploit_status(hypothesis_id: str, graph: EngagementGraph) -> str:
    """How far EXPLOIT actually got with one hypothesis.

    The best outcome any of its attempts recorded. An engagement whose every
    tool failed to start therefore reads ``not-run`` — never a check that
    came back empty.
    """
    best = ATTEMPT_NONE
    for node in graph.by_type("exploit_attempt"):
        if not attempt_names(node.get("label"), hypothesis_id):
            continue
        outcome = attempt_outcome(node)
        if _ATTEMPT_ORDER.index(outcome) > _ATTEMPT_ORDER.index(best):
            best = outcome
    return best


def hypothesis_engine_view(node: dict, graph: EngagementGraph) -> dict:
    """What the engine makes of one hypothesis, as one shape for every surface.

    The report renders these values and the memory browser exposes the same
    dict, which is the point (A13 D4): the browser used to show the node's raw
    properties and nothing else, so a hypothesis whose prose said "confirmed"
    looked confirmed there while the report — reading the engine's records —
    said otherwise. Two surfaces reading one graph must not describe it
    differently, so they read one function.

    Every value is derived from the graph's own records, never from the
    node's text: a model that writes ``basis``, ``tested`` or ``confirmed``
    into its properties changes none of this. A caller that merges this in
    must apply it **after** the node's properties for that to hold.

    ``related_assets`` is always present, possibly empty, so no caller has to
    decide what a missing key means. The keys are the ones the report
    template already renders, so the two cannot drift apart by a rename.
    """
    status = exploit_status(node.get("label"), graph)
    basis = relationship_basis(node, graph)
    verification = finding_verification_detail(node.get("label"), graph)
    return {
        "basis": basis,
        "basis_note": BASIS_NOTES[basis],
        "exploit_status": status,
        "exploit_note": ATTEMPT_NOTES[status],
        "tested": status in OUTCOMES_RUN,
        "confirmed": status == ATTEMPT_CONFIRMED,
        "primary_asset_observed": primary_asset_observed(node, graph),
        "related_assets": related_asset_views(node, graph),
        # Phase 1C: the independent-verification standing, derived from
        # the same records on every surface. Additive — existing readers
        # are untouched.
        "verification_status": verification["status"],
        "verification_note": verification["note"],
        "verification_block_reason": verification["block_reason"],
    }
