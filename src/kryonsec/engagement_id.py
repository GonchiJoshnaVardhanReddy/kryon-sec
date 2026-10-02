"""The engagement-id rule, in one place.

An engagement id is not a label — it is a **path component**
(``~/.kryonsec/engagements/<id>/``), a Docker bind-mount source, and now a
URL path segment in the memory browser. Every one of those is a traversal
sink, so the validation lives here rather than being copied per caller.

The traversal was a real bug, not a hypothetical: ``--id ../../../tmp/x``
wrote the audit chain, evidence and report outside the engagements tree, and
``--id /etc`` aimed the sandbox mount at the host's ``/etc``.

The bound is deliberately conservative — 1 to 64 characters, starting
alphanumeric, then alphanumerics, dot, dash or underscore. Auto-generated
ids are uuid4 hex, so nothing legitimate is excluded.
"""

from __future__ import annotations

import re

ENGAGEMENT_ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"

_ENGAGEMENT_ID_RE = re.compile(ENGAGEMENT_ID_PATTERN)

__all__ = ["ENGAGEMENT_ID_PATTERN", "is_valid_engagement_id"]


def is_valid_engagement_id(value: object) -> bool:
    """True when ``value`` is a safe engagement id.

    Never raises — a non-string (a list from a query string, None from a
    missing path segment) is simply not valid.
    """
    return (
        isinstance(value, str)
        and _ENGAGEMENT_ID_RE.fullmatch(value) is not None
    )
