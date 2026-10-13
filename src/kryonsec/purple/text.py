"""One-line text hygiene, shared by the prompt builder and the graph views.

Two callers need exactly the same treatment of untrusted text, and they need
it for different reasons:

* ``context`` collapses graph content into prompt lines, where a value that
  could add a line, a bullet or a heading of its own would be an instruction
  smuggled into data;
* ``views`` collapses the same content for the report and the memory browser,
  where a value that could add a line would be a claim the engine never made.

They share this module rather than one importing the other because of what
``context`` pulls in: the LLM client, the tool allowlist and the passive-recon
subagent. Anything that reads a graph for a *display* surface — the browser
above all — must be able to reach the normaliser without dragging a provider
client behind it (A14/D4), and this module imports nothing but ``re`` and
``typing``.

Nothing here knows about graphs, prompts, models or secrets. It is string
handling, and that is all it should ever be.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["DEFAULT_MAX_ITEM_CHARS", "normalize_line"]

# The default cap: enough for a URL, a title or a rationale line.
DEFAULT_MAX_ITEM_CHARS = 300

# C0 controls minus the whitespace ones (tab, LF, VT, FF, CR) and DEL. The
# whitespace five are left for the pass below so they become a space rather
# than nothing — deleting them would glue "user\nadmin" into "useradmin".
_CONTROL = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")
# Python's \s on str is Unicode-aware: it also covers NEL (U+0085), the
# line/paragraph separators (U+2028/2029) and no-break space, any of which
# some downstream parser could read as a line break.
_WHITESPACE = re.compile(r"\s+")


def cap(text: str, limit: int) -> str:
    """Cut to ``limit`` characters, marking the cut."""
    if limit <= 0 or len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def normalize_line(value: Any, limit: int = DEFAULT_MAX_ITEM_CHARS) -> str | None:
    """One prompt-safe line from untrusted content, or None if nothing is left.

    Every run of whitespace — newlines, tabs, and the Unicode characters
    some parsers treat as line breaks — collapses to a single space, and the
    remaining control characters are dropped. A value therefore cannot add a
    line, a bullet or a section heading of its own to the block: whatever it
    contains, it arrives as one line of data.
    """
    if not isinstance(value, str):
        return None
    text = _CONTROL.sub("", value)
    text = _WHITESPACE.sub(" ", text).strip()
    if not text:
        return None
    return cap(text, limit)
