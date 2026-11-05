"""Presentation state shared by every Kryonsec terminal surface.

Nothing in this module decides anything.  It only reduces already-computed
engine observations into a bounded snapshot that a renderer can draw.  The
authoritative workflow, approvals, tool execution, and audit writes stay in
their existing modules.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from ..secrets import redact

log = logging.getLogger(__name__)


# The eight actual security agents are the executable subagents in the state
# table. INIT and HUMAN_REVIEW are orchestration/operator stages, not agent
# identities. The names and mapping come from the canonical runner registry.
SECURITY_AGENT_STATES: tuple[str, ...] = (
    "RECON_PASSIVE",
    "RECON_ACTIVE",
    "HYPOTHESIZE",
    "EXPLOIT",
    "POST_EXPLOIT",
    "VERIFY",
    "BLUE_TEAM",
    "REPORT",
)

AGENT_LABELS: dict[str, str] = {
    "RECON_PASSIVE": "Passive recon",
    "RECON_ACTIVE": "Active recon",
    "HYPOTHESIZE": "Hypothesizer",
    "EXPLOIT": "Exploit",
    "POST_EXPLOIT": "Post-exploit",
    "VERIFY": "Verifier",
    "BLUE_TEAM": "Blue team",
    "REPORT": "Reporter",
}

PURPLE_STATES: tuple[str, ...] = (
    "INIT",
    "RECON_PASSIVE",
    "RECON_ACTIVE",
    "HYPOTHESIZE",
    "HUMAN_REVIEW",
    "EXPLOIT",
    "POST_EXPLOIT",
    "VERIFY",
    "BLUE_TEAM",
    "REPORT",
)


def safe(value: Any, limit: int = 240) -> str:
    """Render-safe text: redacted and bounded."""
    return redact(str(value or ""))[0][:limit]


def status_style(status: str) -> str:
    """Semantic style name used by the textual sidebar and fallback views."""
    return {
        "connected": "success",
        "completed": "success",
        "running": "running",
        "starting": "warning",
        "waiting": "warning",
        "failed": "error",
        "disconnected": "error",
        "idle": "muted",
        "pending": "muted",
        "skipped": "muted",
    }.get(status, "muted")


def status_mark(status: str) -> str:
    return {
        "connected": "●",
        "completed": "✓",
        "running": "●",
        "starting": "…",
        "waiting": "!",
        "failed": "×",
        "disconnected": "×",
        "idle": "·",
        "pending": "·",
        "skipped": "·",
    }.get(status, "·")


def display_command(name: str, argv: list[str] | None) -> str:
    """Readable join of a backend tool and its real argv.

    The argv is whatever the backend recorded in its audit event.  Each part
    is redacted here too, so a caller that hands over raw argv cannot leak a
    secret into the screen.  argv[0] repeats the tool name by subprocess
    convention, so it is not printed twice.  The UI never constructs commands.
    """
    parts = " ".join(str(name or "").split()).split()
    rest = [str(item).strip() for item in (argv or []) if str(item).strip()]
    if rest and parts and " ".join(rest[0].split()) == " ".join(parts):
        rest = rest[1:]
    parts.extend(safe(item, 200) for item in rest)
    return " ".join(parts)[:200]


def elapsed(started_at: float | None, finished_at: float | None = None) -> str:
    if started_at is None:
        return "—"
    seconds = max(0, int((finished_at or time.monotonic()) - started_at))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


@dataclass
class DisplayMessage:
    role: str
    content: str


@dataclass
class PurpleToolRow:
    name: str
    state: str
    status: str = "running"
    detail: str = ""
    started_at: float = field(default_factory=time.monotonic)
    duration: float | None = None
    argv: list[str] = field(default_factory=list)


@dataclass
class ApprovalGate:
    """Cross-thread approval handoff; unset results are always denial."""

    gate: str
    done: threading.Event = field(default_factory=threading.Event)
    hypotheses: list[dict] = field(default_factory=list)
    index: int = 0
    approved: set[str] = field(default_factory=set)
    result: bool = False
    shell_evidence: str = ""


class PurpleWorkspaceState:
    """Thread-safe presentation snapshot for one engagement.

    Callbacks are invoked by the runner/audit writer thread.  Every method is
    defensive and only changes this snapshot; it cannot affect orchestration.
    """

    def __init__(
        self,
        target: str,
        engagement_id: str,
        *,
        sandbox_status: str = "checking",
    ) -> None:
        self.target = safe(target, 180)
        self.engagement_id = safe(engagement_id, 80)
        self.sandbox_status = sandbox_status
        self.graph: Any = None
        self.audit: Any = None
        self.orchestrator: Any = None
        self.current_state = ""
        self.completed_states: list[str] = []
        self.failed_states: set[str] = set()
        self.tools: list[PurpleToolRow] = []
        self.notices: list[str] = []
        self.activity: list[dict[str, Any]] = []
        self.state_started: dict[str, float] = {}
        self.state_duration: dict[str, float] = {}
        self.sandbox_detail: str | None = None
        self.findings: list[tuple[str, str, str]] = []
        self.counts: dict[str, int] = {
            "subdomains": 0,
            "endpoints": 0,
            "technologies": 0,
            "hypotheses": 0,
            "findings": 0,
            "evidence": 0,
            "errors": 0,
        }
        self.outcome: str | None = None
        self.halt_reason: str | None = None
        self.report_path: str | None = None
        self.started_at = time.monotonic()
        self.finished_at: float | None = None
        self._running: dict[str, PurpleToolRow] = {}
        self._lock = threading.RLock()

    def start(self) -> None:
        self.started_at = time.monotonic()

    def stop(self) -> None:
        # The worker owns its lifecycle.  This hook exists so the runner can
        # use the same adapter contract as the legacy presentation UI.
        return

    def on_state(self, state: str) -> None:
        with self._lock:
            previous = self.current_state
            if previous and previous != state:
                if previous not in self.completed_states:
                    self.completed_states.append(previous)
            if state and state != previous and state not in self.state_started:
                self.state_started[state] = time.monotonic()
            self.current_state = state
        if state and state != previous:
            self._log_activity("started", state=state)

    def on_state_complete(self, state: str) -> None:
        with self._lock:
            if state not in self.completed_states:
                self.completed_states.append(state)
            started = self.state_started.get(state)
            if started is not None:
                self.state_duration[state] = max(0.0, time.monotonic() - started)
            self._snapshot_graph_locked()
        duration = self.state_duration.get(state)
        suffix = f" in {duration:.0f}s" if duration else ""
        self._log_activity(f"stage completed{suffix}", state=state)

    def _log_activity(
        self,
        summary: str,
        *,
        state: str = "",
        tool: str = "",
    ) -> None:
        value = safe(summary, 200)
        if not value:
            return
        with self._lock:
            self.activity.append(
                {
                    "ts": time.monotonic(),
                    "state": safe(state, 40),
                    "tool": safe(tool, 80),
                    "summary": value,
                }
            )
            self.activity = self.activity[-40:]

    def on_audit(self, entry: dict) -> None:
        """Reduce audit observations to concise, non-sensitive activity."""
        try:
            event = entry.get("event")
            state = safe(entry.get("state") or self.current_state, 40)
            if event == "sandbox_check":
                self.sandbox_status = "ready" if entry.get("available") else "unavailable"
                reason = safe(entry.get("reason"), 160)
                if reason and not entry.get("available"):
                    self.sandbox_detail = reason
            elif event == "tool_spawn":
                argv = entry.get("argv")
                rows = [
                    safe(item, 80)
                    for item in (list(argv)[:24] if isinstance(argv, (list, tuple)) else [])
                ]
                self._begin_tool(safe(entry.get("tool"), 80), state, rows)
            elif event == "tool_result":
                self._finish_tool(
                    safe(entry.get("tool"), 80),
                    bool(entry.get("ok")),
                    self._result_summary(entry),
                )
            elif event == "passive_source_start":
                self._begin_tool(safe(entry.get("source"), 80), state)
            elif event == "passive_source_ok":
                self._finish_tool(
                    safe(entry.get("source"), 80), True, self._source_summary(entry)
                )
            elif event == "passive_source_failed":
                self._finish_tool(
                    safe(entry.get("source"), 80),
                    False,
                    safe(entry.get("error"), 140) or "failed",
                )
            elif event == "passive_source_skipped":
                self._finish_tool(
                    safe(entry.get("source"), 80),
                    False,
                    "skipped: " + (safe(entry.get("reason"), 120) or "not run"),
                    status="skipped",
                )
            elif isinstance(event, str) and event.endswith("_rejected_by_allowlist"):
                self._finish_tool(
                    safe(entry.get("tool"), 80),
                    False,
                    "rejected by allowlist",
                    status="failed",
                )
            elif event == "zone_b_blocked":
                self.on_notice("Zone B blocked — " + (safe(entry.get("reason")) or "sandbox unavailable"))
            elif event == "post_exploit_gate":
                self.on_notice(
                    "Post-exploitation approval: "
                    + ("approved" if entry.get("approved") else "denied")
                )
            with self._lock:
                self._snapshot_graph_locked()
        except Exception:
            # Audit observers must never change the result of AuditLog.write.
            log.debug("Purple render adapter failed", exc_info=True)

    def on_notice(self, message: str) -> None:
        value = safe(message, 300)
        if not value:
            return
        with self._lock:
            self.notices.append(value)
            self.notices = self.notices[-12:]
        self._log_activity(value)

    def on_log(self, record: logging.LogRecord) -> None:
        if record.levelno >= logging.WARNING:
            self.on_notice(record.getMessage())

    def finish(
        self,
        outcome: str,
        *,
        halt_reason: str | None = None,
        report_path: str | None = None,
    ) -> None:
        with self._lock:
            self.outcome = outcome
            self.halt_reason = safe(halt_reason, 220) if halt_reason else None
            self.report_path = safe(report_path, 240) if report_path else None
            self.finished_at = time.monotonic()
            if outcome in {"failed", "halted"} and self.current_state:
                self.failed_states.add(self.current_state)
            self._snapshot_graph_locked()
        suffix = f" — {self.halt_reason}" if self.halt_reason else ""
        self._log_activity(f"engagement {outcome}{suffix}")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "target": self.target,
                "engagement_id": self.engagement_id,
                "sandbox_status": self.sandbox_status,
                "sandbox_detail": self.sandbox_detail,
                "current_state": self.current_state,
                "completed_states": list(self.completed_states),
                "failed_states": list(self.failed_states),
                "state_started": dict(self.state_started),
                "state_duration": dict(self.state_duration),
                "tools": [
                    {
                        "name": row.name,
                        "state": row.state,
                        "status": row.status,
                        "detail": row.detail,
                        "duration": row.duration,
                        "argv": list(row.argv),
                        "started_at": row.started_at,
                    }
                    for row in self.tools[-16:]
                ],
                "activity": [dict(row) for row in self.activity[-20:]],
                "notices": list(self.notices[-8:]),
                "findings": list(self.findings[-6:]),
                "counts": dict(self.counts),
                "outcome": self.outcome,
                "halt_reason": self.halt_reason,
                "report_path": self.report_path,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "orchestrator": self.orchestrator,
            }

    def _begin_tool(self, name: str, state: str, argv: list[str] | None = None) -> None:
        if not name:
            return
        with self._lock:
            row = PurpleToolRow(name=name, state=state, argv=list(argv or []))
            self._running[name] = row
            self.tools = [
                existing
                for existing in self.tools
                if not (existing.name == name and existing.state == state and existing.status == "running")
            ]
            self.tools.append(row)
        command = display_command(name, row.argv)
        self._log_activity(f"launched {command}", state=state, tool=name)

    def _finish_tool(
        self,
        name: str,
        ok: bool,
        detail: str | None,
        *,
        status: str | None = None,
    ) -> None:
        if not name:
            return
        with self._lock:
            row = self._running.pop(name, None)
            if row is None:
                row = PurpleToolRow(name=name, state=self.current_state)
                self.tools.append(row)
            row.status = status or ("completed" if ok else "failed")
            row.detail = safe(detail, 160)
            row.duration = max(0.0, time.monotonic() - row.started_at)
            if not ok and row.status != "skipped":
                self.counts["errors"] += 1
        verb = "finished" if row.status == "completed" else row.status
        suffix = f" · {row.detail}" if row.detail else ""
        duration = f" in {row.duration:.1f}s" if row.duration is not None else ""
        self._log_activity(
            f"{verb} {display_command(name, row.argv)}{suffix}{duration}",
            state=row.state,
            tool=name,
        )

    def _result_summary(self, entry: dict) -> str:
        if not entry.get("ok"):
            text = safe(entry.get("error"), 140) or "failed"
            code = entry.get("exit_code")
            if isinstance(code, int) and code:
                text = f"{text} (exit {code})"
            return text
        chars = entry.get("output_chars")
        return f"{chars} chars" if isinstance(chars, int) and chars else "completed"

    def _source_summary(self, entry: dict) -> str:
        new = entry.get("new")
        found = entry.get("found")
        if isinstance(new, int) and new:
            return f"{new} new"
        if isinstance(found, int) and found:
            return f"{found} found"
        return "completed"

    def _snapshot_graph_locked(self) -> None:
        graph = self.graph
        if graph is None:
            return
        try:
            findings = graph.by_type("finding")
            verified = 0
            rows: list[tuple[str, str, str]] = []
            for node in findings:
                props = node.get("properties", {}) or {}
                is_verified = bool(props.get("verified"))
                verified += int(is_verified)
                rows.append(
                    (
                        safe(node.get("label") or "finding", 100),
                        "verified" if is_verified else "possible / unverified",
                        safe(props.get("severity") or "—", 30),
                    )
                )
            self.counts.update(
                subdomains=len(graph.by_type("subdomain")),
                endpoints=len(graph.by_type("web_endpoint")) + len(graph.by_type("path")),
                technologies=len(graph.by_type("tech_fingerprint")),
                hypotheses=len(graph.by_type("hypothesis")),
                findings=len(findings),
                evidence=len(graph.by_type("post_exploit_evidence")),
            )
            self.findings = rows[-6:]
        except Exception:
            log.debug("could not snapshot Purple graph for screen", exc_info=True)


__all__ = [
    "AGENT_LABELS",
    "ApprovalGate",
    "DisplayMessage",
    "PURPLE_STATES",
    "PurpleToolRow",
    "PurpleWorkspaceState",
    "SECURITY_AGENT_STATES",
    "display_command",
    "elapsed",
    "safe",
    "status_mark",
    "status_style",
]
