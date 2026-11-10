"""Thread-safe, presentation-only UI events.

Backend code may publish an event from a worker thread, but the event carries
no command, transition, or approval callback.  Rendering consumes a snapshot
and can therefore fail without affecting the security engine.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..secrets import redact


@dataclass(frozen=True)
class UIEvent:
    """A sanitized observation for the terminal renderer."""

    kind: str
    text: str = ""
    data: Mapping[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.monotonic)


def _safe_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)[0]
    if isinstance(value, Mapping):
        return {str(k): _safe_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_value(v) for v in value[:50]]
    return value


class UIEventBus:
    """Small bounded queue for callbacks that must never block the backend."""

    def __init__(self, max_events: int = 256) -> None:
        self._events: deque[UIEvent] = deque(maxlen=max(1, max_events))
        self._lock = threading.Lock()

    def publish(
        self,
        kind: str,
        text: str = "",
        data: Mapping[str, Any] | None = None,
    ) -> UIEvent:
        safe_text = redact(str(text or ""))[0]
        event = UIEvent(
            kind=kind,
            text=safe_text,
            data={str(k): _safe_value(v) for k, v in (data or {}).items()},
        )
        with self._lock:
            self._events.append(event)
        return event

    def drain(self) -> list[UIEvent]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
        return events

    def snapshot(self) -> list[UIEvent]:
        with self._lock:
            return list(self._events)


class BackendEventAdapter:
    """Translate observable backend callbacks into UI events only."""

    def __init__(self, bus: UIEventBus) -> None:
        self.bus = bus

    def state_started(self, state: str) -> None:
        self.bus.publish("state_started", data={"state": state})

    def state_completed(self, state: str) -> None:
        self.bus.publish("state_completed", data={"state": state})

    def tool_started(self, tool: str, state: str = "") -> None:
        self.bus.publish("tool_started", data={"tool": tool, "state": state})

    def tool_finished(
        self,
        tool: str,
        *,
        ok: bool,
        summary: str = "",
        error: str = "",
    ) -> None:
        self.bus.publish(
            "tool_finished",
            data={"tool": tool, "ok": ok, "summary": summary, "error": error},
        )

    def notice(self, message: str) -> None:
        self.bus.publish("notice", text=message)

    def approval_required(self, gate: str, data: Mapping[str, Any]) -> None:
        self.bus.publish("approval_required", data={"gate": gate, **dict(data)})
