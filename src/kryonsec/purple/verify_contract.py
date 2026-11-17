"""Finding-verification contracts (Batch 5B).

VERIFY is where a finding earns independent confirmation — and where a
wrong method quietly manufactures false positives. Before 5B the stage
hardcoded one method (the curl boolean probe) and applied it to every
finding whose URL had a numeric parameter, whatever the finding was
actually about: an XSS finding on ``?id=1`` would be "verified" by a
boolean SQL injection probe. The method was sound for SQL injection and
silently wrong for everything else it touched.

This module is the fix's shape: a typed contract per vulnerability
CATEGORY, registered, validated and closed.

Contract model
--------------
* One contract binds one category to ONE independent method: the tool
  that runs it, what the original evidence must supply (prerequisites),
  the observation that AGREES and the one that CONTRADICTS, the
  execution budget, the stage allowed to execute it, the approval basis
  it runs under, and — written down, not implied — what the method
  CANNOT establish (``confidence_limit``).
* A contract is trusted only if its ``method_type`` is one the engine
  implements (a closed set, validated at registration — registering a
  method nobody executes fails loudly instead of lying dormant) and its
  category is a real one some tool produces (``unknown`` can never be
  verified and refuses registration).
* The registry starts with exactly one entry: the SQLi boolean probe —
  the independent method this project already had, now scoped to the
  category it is actually evidence for. Every other category stays
  honestly unverified: ``not_run`` with the real reason, never a
  borrowed method and never a silent pass.

Only the contract's registered method, executed on its own evidence,
promotes a finding to ``verified`` — the same rule
``capability_verify`` applies to capabilities, applied to findings.
LLM wording, scanner banners, HTTP status codes and exit codes remain
unable to promote anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .exploit_contract import CATEGORY_UNKNOWN, TOOL_CATEGORIES, tool_category

# ---- the closed set of method types the engine implements -------------------
#
# A contract names a method_type; the VERIFY executor implements exactly
# these. Anything else fails at REGISTRATION (reviewed configuration,
# never runtime input) — a contract for a method nobody executes must
# never sit in the registry looking verified-able.

METHOD_BOOLEAN_CURL = "curl_boolean_probe"

IMPLEMENTED_METHOD_TYPES: frozenset[str] = frozenset({METHOD_BOOLEAN_CURL})

#: the one stage allowed to execute verification probes
VERIFY_STAGE = "VERIFY"

#: the approval basis verification runs under: the finding came from an
#: approved hypothesis (Gate 2 covered testing it), and an independent,
#: non-destructive re-check of the same asset needs no new gate. Written
#: on the contract so the basis is a record, not an assumption.
VERIFY_APPROVAL_BASIS = "gate2_engagement_scoped"

_CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}\Z")


@dataclass(frozen=True)
class VerificationContract:
    """The ONE independent verification method a category is trusted with.

    Reviewed configuration, fully static: no LLM, no operator runtime
    input, no templated argv (the executor composes scope-checked URLs
    from the finding's own hypothesis, exactly as EXPLOIT composes its
    targets — the only variable, and it passes through the same
    scope enforcement).
    """

    #: the one vulnerability category this contract may verify
    category: str
    #: short machine label of the method as records name it
    method: str
    #: which engine-implemented executor runs it (closed set)
    method_type: str
    #: the verification tool — must differ from the finding's own tool
    tool: str
    #: what the original evidence must supply, as checked facts
    prerequisites: "tuple[str, ...]"
    #: the budget: at most this many probe spawns, each at most this long
    max_probes: int
    max_probe_seconds: int
    #: what agreement looks like, and what contradiction looks like —
    #: the two outcomes the executor derives its verdict between
    expected_observation: str
    contradictory_observation: str
    #: the only execution stage allowed to run this contract
    stage: str = VERIFY_STAGE
    #: the approval basis the probes run under (a record, not a gate)
    approval: str = VERIFY_APPROVAL_BASIS
    #: what this method CANNOT establish — written on every result
    confidence_limit: str = ""


# ---- the registry -------------------------------------------------------------
#
# category -> contract. Deliberately SMALL in production: one entry (the
# boolean probe for SQL injection). Every other category is unsupported,
# and unsupported means an honest ``not_run`` — never a borrowed method.

FINDING_VERIFICATION_CONTRACTS: "dict[str, VerificationContract]" = {}


def register_finding_contract(contract: VerificationContract) -> None:
    """Explicit contract registration (reviewed code, never runtime
    input). A bad contract raises instead of registering — the registry
    shape is itself fail closed."""
    if not _CATEGORY_RE.match(contract.category or ""):
        raise ValueError(
            f"verification contract needs a category word, got "
            f"{contract.category!r}")
    if contract.category == CATEGORY_UNKNOWN:
        raise ValueError(
            "the 'unknown' category can never be independently verified — "
            "registering a contract for it would be a lie about coverage")
    if contract.category not in set(TOOL_CATEGORIES.values()):
        raise ValueError(
            f"category {contract.category!r} is not one the tools produce; "
            "a contract for an unreachable category is dead configuration")
    if not (contract.method or "").strip() or len(contract.method) > 64:
        raise ValueError("verification contract needs a method label")
    if contract.method_type not in IMPLEMENTED_METHOD_TYPES:
        raise ValueError(
            f"method_type {contract.method_type!r} is not implemented by "
            f"the engine; implemented: {', '.join(sorted(IMPLEMENTED_METHOD_TYPES))}")
    if not (contract.tool or "").strip() or "/" in contract.tool:
        raise ValueError("verification contract needs a tool name")
    if contract.stage != VERIFY_STAGE:
        raise ValueError(
            f"verification contracts execute in {VERIFY_STAGE} only, not "
            f"{contract.stage!r}")
    if not (contract.approval or "").strip():
        raise ValueError("verification contract needs an approval basis")
    if not (2 <= contract.max_probes <= 8):
        raise ValueError("max_probes must be 2..8")
    if not (1 <= contract.max_probe_seconds <= 600):
        raise ValueError("max_probe_seconds must be 1..600")
    if not (contract.expected_observation or "").strip() or \
            len(contract.expected_observation) > 300:
        raise ValueError(
            "verification contract needs an expected observation (<=300 chars)")
    if not (contract.contradictory_observation or "").strip() or \
            len(contract.contradictory_observation) > 300:
        raise ValueError(
            "verification contract needs a contradictory observation "
            "(<=300 chars)")
    if not (contract.confidence_limit or "").strip() or \
            len(contract.confidence_limit) > 300:
        raise ValueError(
            "a contract must state what its method CANNOT establish "
            "(confidence_limit, <=300 chars)")
    if not (contract.prerequisites and 1 <= len(contract.prerequisites) <= 6
            and all(p.strip() and len(p) <= 200
                    for p in contract.prerequisites)):
        raise ValueError(
            "verification contract needs 1..6 prerequisites (<=200 chars each)")
    if contract.category in FINDING_VERIFICATION_CONTRACTS:
        raise ValueError(
            f"category {contract.category!r} already has a verification "
            "contract — two methods for one category is ambiguity, "
            "not coverage")
    FINDING_VERIFICATION_CONTRACTS[contract.category] = contract


def verification_contract_for(category: str) -> "VerificationContract | None":
    """The contract for one category — or None: unsupported, and the
    caller records an honest ``not_run`` with the real reason."""
    return FINDING_VERIFICATION_CONTRACTS.get(category or "")


def finding_category(finding_node: dict) -> str:
    """The category a finding belongs to, derived from the tool that
    produced it. A finding without a tool is category ``unknown`` —
    which no contract can ever cover."""
    tool = str((finding_node.get("properties") or {}).get("tool") or "")
    return tool_category(tool)


def contracts_ready() -> bool:
    """True when at least one category has a contract."""
    return bool(FINDING_VERIFICATION_CONTRACTS)


# ---- the production contract: the method this project already had -----------
#
# The SQLi boolean probe (curl AND 1=1 vs AND 1=2 against the baseline),
# now a REGISTERED contract scoped to the one category it is evidence
# for. Its execution is the same code VERIFY always ran (verify.py),
# driven by this contract's budget and recorded with its identity and
# confidence limit. Categories without a contract stay unsupported —
# honestly unverified, never borrowed this method.

SQLI_BOOLEAN_CONTRACT = VerificationContract(
    category="sqli",
    method="curl boolean probe",
    method_type=METHOD_BOOLEAN_CURL,
    tool="curl",
    prerequisites=(
        "the finding's hypothesis names a target asset that composes "
        "into an in-scope URL",
        "the URL has a numeric query parameter the boolean can be "
        "injected into",
        "the finding was produced by a tool other than curl itself",
    ),
    max_probes=4,   # true + false + baseline + baseline-confirmation (5C)
    max_probe_seconds=30,
    expected_observation=(
        "the true injection (AND 1=1) matches the baseline while the "
        "false injection (AND 1=2) differs — the server executed the "
        "injected boolean"),
    contradictory_observation=(
        "all three responses match, or the true injection changes the "
        "page the way any two fetches differ (rotating content) — the "
        "boolean was not executed as SQL"),
    confidence_limit=(
        "a response difference shows boolean handling at the one "
        "injected parameter only — not data extraction, not other "
        "parameters, and never a severity claim"),
)

register_finding_contract(SQLI_BOOLEAN_CONTRACT)
