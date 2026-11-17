"""Evidence-quality analysis for independent verification (Batch 5C).

Verification has two failure modes this module guards against: a check
that agreed for a benign reason (rotating content, noise) being read as
confirmation, and a stored label ("verified") being read as evidence.
The status derivation (``views.verification_status``) already refuses
stored labels and downgrades contested verdicts to ``unresolved``; this
module is the ANNOTATION layer on top of it — the quality review an
operator (or a report) reads alongside the status.

What it is NOT: a promotion path. Nothing here changes a finding's
verification standing; it explains WHY the standing is what it is, and
surfaces the counterevidence the check itself recorded. Only the
VERIFY executor's response-difference evidence, via the registered
contract, can promote a finding — unchanged.

The checks are Strix/Shannon-style questions about one
``verify_attempt`` record, answered from its own fields:

* **ran** — did the method execute at all (both probe responses
  returned)?
* **reachability** — is there execution evidence (responses) or at
  least secondary reachability evidence (the asset answered http /
  nc / dig)?
* **baseline control** — was a baseline fetched, so rotating content
  had a chance of being caught? A verdict without a baseline control
  is weak by construction.
* **independence** — the producing tool differs from the verification
  tool (a repeat is not an independent check). Given the finding's
  tool as context, checked against the recorded contract.
* **conclusion strength vs observations** — the stored ``status``
  word (if a producer wrote one) must be re-derivable from the
  execution evidence; a word the evidence does not support is
  flagged, not obeyed.

Every check answers ``ok`` / ``failed`` / ``inapplicable`` with a one-
line detail. Counterevidence — recorded by the executor and derived
here — is carried through verbatim: it is never silently discarded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .views import (
    VERIFICATION_DISAGREED,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_NOT_RUN,
    VERIFICATION_UNRESOLVED,
    VERIFICATION_VERIFIED,
    verification_status,
)

# ---- quality words ----------------------------------------------------------
#
# The strength of the evidence BEHIND a status — not the status itself.
# "supported" and "contradicted" are conclusions an independent test made;
# "contested"/"weak"/"blocked"/"none" all mean: no conclusion yet.

QUALITY_SUPPORTED = "supported"          # clean agreement, controls in place
QUALITY_CONTRADICTED = "contradicted"    # clean disagreement, controls in place
QUALITY_CONTESTED = "contested"          # agreeing difference + counterevidence
QUALITY_WEAK = "weak"                    # ran, but a control was missing
QUALITY_BLOCKED = "blocked"              # never ran; only a block reason
QUALITY_REACHABILITY = "reachability_only"  # never ran; the asset answered
QUALITY_NONE = "none"                    # nothing usable recorded

_STRENGTH_BY_STATUS: "dict[str, str]" = {
    VERIFICATION_VERIFIED: QUALITY_SUPPORTED,
    VERIFICATION_DISAGREED: QUALITY_CONTRADICTED,
    VERIFICATION_UNRESOLVED: QUALITY_CONTESTED,
    VERIFICATION_INCONCLUSIVE: QUALITY_WEAK,
    VERIFICATION_NOT_RUN: QUALITY_NONE,
}

CHECK_OK = "ok"
CHECK_FAILED = "failed"
CHECK_NA = "inapplicable"


@dataclass(frozen=True)
class QualityCheck:
    """One Strix/Shannon-style question about a verify attempt."""

    #: the check's stable name (records name it, reports render it)
    name: str
    #: CHECK_OK / CHECK_FAILED / CHECK_NA
    result: str
    #: one line, in the operator's words
    detail: str


@dataclass(frozen=True)
class EvidenceQuality:
    """The read-time quality review of one ``verify_attempt`` record."""

    #: the derived verification status this quality review annotates
    status: str
    #: the evidence-strength word (QUALITY_*) behind that status
    strength: str
    #: every quality check, answered
    checks: "tuple[QualityCheck, ...]" = ()
    #: counterevidence — executor-recorded and derived — verbatim
    counterevidence: "tuple[str, ...]" = ()

    def detail(self) -> dict:
        """The render/print shape: status, strength, checks, evidence
        against."""
        return {
            "status": self.status,
            "strength": self.strength,
            "checks": [
                {"name": c.name, "result": c.result, "detail": c.detail}
                for c in self.checks
            ],
            "counterevidence": list(self.counterevidence),
        }


def _node_props(node: dict) -> dict:
    properties = node.get("properties") if isinstance(node, dict) else None
    return properties if isinstance(properties, dict) else {}


def _has_responses(props: dict) -> bool:
    return props.get("true_len") is not None and props.get("false_len") is not None


def evidence_quality(node: dict, finding_tool: str = "") -> EvidenceQuality:
    """Review one ``verify_attempt`` record's evidence quality.

    ``finding_tool`` (optional) is the tool that produced the finding —
    supplied, the independence check is answered against the recorded
    contract; without it the check is ``inapplicable`` (not skipped:
    inapplicable is itself recorded).
    """
    props = _node_props(node)
    status = verification_status(node)
    strength = _STRENGTH_BY_STATUS[status]
    checks: list[QualityCheck] = []
    counterevidence: list[str] = [
        str(c) for c in (props.get("counterevidence") or [])
        if str(c).strip()
    ]

    # ---- ran --------------------------------------------------------------
    ran = _has_responses(props)
    if ran:
        checks.append(QualityCheck(
            "ran", CHECK_OK,
            "the method executed: both probe responses returned"))
    else:
        reason = str(props.get("reason") or "no reason recorded")
        checks.append(QualityCheck(
            "ran", CHECK_FAILED,
            f"the method never ran ({reason})"))

    # ---- reachability -----------------------------------------------------
    secondary = props.get("secondary_evidence")
    if ran:
        checks.append(QualityCheck(
            "reachability", CHECK_OK,
            "the asset answered the probes directly"))
    elif isinstance(secondary, dict) and secondary:
        tools = ", ".join(sorted(str(k) for k in secondary))
        checks.append(QualityCheck(
            "reachability", CHECK_OK,
            f"the asset answered secondary probes ({tools}) — "
            "reachability only, not a vulnerability check"))
    elif str(props.get("reason") or "") == "asset outside engagement scope":
        checks.append(QualityCheck(
            "reachability", CHECK_NA,
            "the asset is outside engagement scope — probing it would "
            "have violated the engagement boundary"))
    else:
        checks.append(QualityCheck(
            "reachability", CHECK_FAILED,
            "no reachability evidence: the asset never answered"))

    # ---- baseline control (harmless explanations) --------------------------
    if ran:
        if props.get("baseline_len") is not None:
            rotation = any("rotat" in c for c in counterevidence)
            if rotation:
                checks.append(QualityCheck(
                    "baseline_control", CHECK_FAILED,
                    "the confirmation fetch differed from the first "
                    "baseline — content rotates between requests"))
            elif props.get("baseline2_len") is not None:
                checks.append(QualityCheck(
                    "baseline_control", CHECK_OK,
                    "a baseline was fetched and a confirmation fetch "
                    "stood — no rotation counterevidence recorded"))
            else:
                checks.append(QualityCheck(
                    "baseline_control", CHECK_OK,
                    "a baseline was fetched (no confirmation fetch "
                    "recorded)"))
        else:
            checks.append(QualityCheck(
                "baseline_control", CHECK_FAILED,
                "no baseline was fetched — dynamic content cannot be "
                "ruled out; the verdict is weak by construction"))
    else:
        checks.append(QualityCheck(
            "baseline_control", CHECK_NA,
            "no probes ran, so no baseline was needed"))

    # ---- independence -------------------------------------------------------
    contract = props.get("contract")
    verify_tool = ""
    if isinstance(contract, dict):
        verify_tool = str(contract.get("tool") or "")
    if not finding_tool or not verify_tool:
        checks.append(QualityCheck(
            "independence", CHECK_NA,
            "not assessable here — needs both the finding's tool and "
            "the recorded verification tool"))
    elif finding_tool != verify_tool:
        checks.append(QualityCheck(
            "independence", CHECK_OK,
            f"the finding came from {finding_tool!r}, the check ran "
            f"{verify_tool!r} — different tools"))
    else:
        checks.append(QualityCheck(
            "independence", CHECK_FAILED,
            f"the finding and the check both came from {verify_tool!r} "
            "— a repeat, not an independent check"))

    # ---- conclusion strength vs observations --------------------------------
    stored = props.get("status")
    if stored is not None and str(stored) != status:
        checks.append(QualityCheck(
            "conclusion_matches_observations", CHECK_FAILED,
            f"the stored status word {str(stored)!r} is NOT what the "
            f"execution evidence derives ({status!r}) — the word is "
            "ignored; the derivation stands"))
    else:
        checks.append(QualityCheck(
            "conclusion_matches_observations", CHECK_OK,
            f"the status {status!r} is derived from the execution "
            "evidence, not from any stored word"))

    # ---- derived counterevidence ---------------------------------------------
    # What the record itself shows that undermines a positive reading —
    # beyond what the executor already recorded.
    if status == VERIFICATION_INCONCLUSIVE and _has_responses(props):
        line = ("no baseline: the observed difference could be dynamic "
                "content rather than the claimed vulnerability")
        if line not in counterevidence:
            counterevidence.append(line)
    if status == VERIFICATION_NOT_RUN:
        line = ("the check never ran — there is no independent evidence "
                "either way")
        if line not in counterevidence:
            counterevidence.append(line)

    return EvidenceQuality(
        status=status,
        strength=strength if status != VERIFICATION_NOT_RUN else (
            QUALITY_REACHABILITY
            if isinstance(props.get("secondary_evidence"), dict)
            and props.get("secondary_evidence") else QUALITY_NONE),
        checks=tuple(checks),
        counterevidence=tuple(counterevidence),
    )
