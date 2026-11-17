"""Deterministic plain-English explanations for Gate 2 hypotheses.

This module exists so an operator who is not a penetration tester can
decide what they are approving.  It is a formatter only:

* it reads one hypothesis dict (the same structure the engine and the
  audit chain already hold) and renders short English sentences;
* it is a pure function of that dict — no model call, no randomness, no
  network, no writes;
* it NEVER changes the approval contract.  ``hypothesis["label"]`` stays
  the approval key, untouched; nothing here feeds back into the engine.

Both approval surfaces share it — the Textual ApprovalScreen (Mode B
full-screen) and the Rich terminal reviewer in ``human_review.py`` — so
the same words are shown everywhere a hypothesis is decided.
"""

from __future__ import annotations

from typing import Any

# Tool names to plain descriptions.  The full table lives in purple.ui
# (TOOL_ACTION); it is imported lazily so this module stays cheap to
# import from anywhere.  The entries here are only the fallback used if
# that import ever fails — same words, fewer tools.
_MIN_TOOL_ACTION: dict[str, str] = {
    "nmap": "port and service scan",
    "httpx": "HTTP service discovery",
    "nuclei": "vulnerability template scan",
    "sqlmap": "SQL injection testing",
}

# Risk classes, phrased for an operator deciding what may touch the target.
# A tool name maps to exactly one class; unknown names are treated as the
# most conservative class they could belong to ("sends requests").
_RISK_INJECTION: frozenset[str] = frozenset({
    "sqlmap", "dalfox", "commix", "ssrfmap", "tplmap", "wfuzz", "ffuf",
})
_RISK_REQUESTS: frozenset[str] = frozenset({
    "nmap", "naabu", "dnsx", "httpx", "whatweb", "katana", "feroxbuster",
    "gobuster", "nikto", "nuclei", "gowitness", "sslscan", "testssl.sh",
    "arjun", "graphql-cop", "curl", "wget", "openapi_probe",
})

_RISK_PHRASES: dict[str, str] = {
    "lookup": (
        "read-only lookups: public records and local databases are "
        "consulted; no test traffic is sent to the target"
    ),
    "requests": (
        "active scanning: the target receives request traffic, but no "
        "attack payloads are sent"
    ),
    "injection": (
        "active injection testing: crafted test payloads are sent to the "
        "target; a fragile service could be affected"
    ),
}

_MAX_FIELD = 300


def _tool_action(name: str) -> str:
    if not name:
        return ""
    try:
        from .ui import TOOL_ACTION

        return TOOL_ACTION.get(name, "")
    except Exception:  # pragma: no cover - import is guaranteed in product
        return _MIN_TOOL_ACTION.get(name, "")


def risk_level(hypothesis: dict[str, Any]) -> str:
    """The strongest risk class among the proposed tools.

    Ordered from safest to strongest: lookup < requests < injection.  A
    hypothesis with no tool names at all reads as "lookup" — proposing
    nothing to run is the least risky thing an approval can describe.
    """
    tools = hypothesis.get("properties", {}).get("tools", []) or []
    names = {str(tool).strip().lower() for tool in tools if str(tool).strip()}
    if names & _RISK_INJECTION:
        return "injection"
    if names & _RISK_REQUESTS:
        return "requests"
    return "lookup"


def _confidence_text(value: Any) -> str:
    """The claimed confidence, honestly labelled as a claim."""
    try:
        percent = round(float(value) * 100)
    except (TypeError, ValueError):
        return "not stated"
    percent = max(0, min(100, percent))
    return f"about {percent}% (the assistant's own claim — VERIFY confirms or rejects it later)"


def plain_explanation(hypothesis: dict[str, Any]) -> str:
    """Short plain-English sentences for one Gate 2 hypothesis.

    Every sentence is derived from the hypothesis dict alone.  Long fields
    are bounded; nothing is invented, quoted from a model, or executed.
    """
    props = hypothesis.get("properties", {}) or {}
    title = str(props.get("title") or hypothesis.get("label") or "this proposal")[:_MAX_FIELD]
    target = str(props.get("target_asset") or "the recorded target")[:_MAX_FIELD]
    tools = [str(tool) for tool in (props.get("tools") or []) if str(tool).strip()]

    lines: list[str] = []
    lines.append(f"The idea to test: {title}.")
    lines.append(f"Where: {target}.")

    if tools:
        described = []
        for tool in tools[:8]:
            action = _tool_action(tool)
            described.append(f"{tool} ({action})" if action else tool)
        more = len(tools) - min(len(tools), 8)
        listing = ", ".join(described) + (f" — and {more} more" if more > 0 else "")
        lines.append(f"How: {listing}.")
    else:
        lines.append("How: no tools are named — approving runs nothing yet.")

    lines.append(f"How sure: {_confidence_text(props.get('confidence'))}.")
    lines.append(f"What the target receives: {_RISK_PHRASES[risk_level(hypothesis)]}.")
    lines.append(
        "Approving allows only the testing described above, against this "
        "target only. It does not approve post-exploitation access."
    )
    return "\n".join(lines)


__all__ = ["plain_explanation", "risk_level"]
