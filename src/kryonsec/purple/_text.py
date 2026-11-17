"""Shared text helpers for tool-output excerpt hygiene.

The excerpt contract across the engine is READABLE SIGNAL — for
HYPOTHESIZE context sections and for the report prompts — while raw
stdout keeps its fidelity in the audit trail and evidence files.
Presentation artifacts a TOOL injected (ANSI color codes) are not
engagement data and are stripped from excerpts only.
"""

from __future__ import annotations

import re

# ANSI CSI control sequences (ESC + parameters + final byte). dnsenum,
# enum4linux-ng and checksec unconditionally color their output — none
# ships a no-color flag for every surface (verified from the tools'
# own help output / real Phase 4b lab output) — and color codes in a
# bounded excerpt are presentation noise.
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def clean_excerpt(text: str) -> str:
    """Strip ANSI CSI sequences from text destined for a bounded excerpt.

    A no-op on clean output (verified against the real colored
    dnsenum/enum4linux-ng/checksec lab output).
    """
    return _ANSI_CSI_RE.sub("", text)
