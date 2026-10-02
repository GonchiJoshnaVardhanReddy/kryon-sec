"""The memory browser: a read-only localhost view of persisted engagement memory.

``kryonsec memory`` serves three things from loopback: the engagements it can
find, their stored Security Graph, and nothing else. It cannot run a scan,
approve a hypothesis, spawn a tool or write a row — see ``viewer`` for how
that is enforced structurally rather than by convention.

Nothing in this package is imported by the Purple Team engine. The
dependency runs one way: the browser reads what the engine already wrote.
"""

from .data import (
    InvalidEngagementId,
    MemoryUnavailable,
    list_engagements,
    load_engagement,
    storage_status,
)
from .viewer import create_server, is_loopback_host, serve

__all__ = [
    "InvalidEngagementId",
    "MemoryUnavailable",
    "create_server",
    "is_loopback_host",
    "list_engagements",
    "load_engagement",
    "serve",
    "storage_status",
]
