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
    "asset_key",
    "attempt_names",
    "attempt_outcome",
    "exploit_status",
    "hypothesis_engine_view",
    "observed_assets",
    "primary_asset_observed",
    "related_asset_views",
    "relationship_basis",
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
                    and (attempt.get("properties") or {}).get("verified")):
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
ATTEMPT_INCONCLUSIVE = "inconclusive"  # the tool ran; the marker was absent
ATTEMPT_NOT_RUN = "not-run"            # the record says the process never started
ATTEMPT_UNRECORDED = "unrecorded"      # no record either way
ATTEMPT_NONE = "none"                  # no attempt at all for this hypothesis

#: Every outcome, weakest first. This is also the comparison order when one
#: hypothesis has several attempts: the best one recorded wins, so a second
#: tool that could not start never undoes a first that ran.
_ATTEMPT_ORDER: tuple[str, ...] = (
    ATTEMPT_NONE,
    ATTEMPT_NOT_RUN,
    ATTEMPT_UNRECORDED,
    ATTEMPT_INCONCLUSIVE,
    ATTEMPT_CONFIRMED,
)

#: The outcomes that mean a tool really ran against the target.
OUTCOMES_RUN = frozenset({ATTEMPT_INCONCLUSIVE, ATTEMPT_CONFIRMED})

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
    return {
        "basis": basis,
        "basis_note": BASIS_NOTES[basis],
        "exploit_status": status,
        "exploit_note": ATTEMPT_NOTES[status],
        "tested": status in OUTCOMES_RUN,
        "confirmed": status == ATTEMPT_CONFIRMED,
        "primary_asset_observed": primary_asset_observed(node, graph),
        "related_assets": related_asset_views(node, graph),
    }
