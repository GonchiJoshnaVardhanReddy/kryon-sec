"""Small repositories used by the full-screen terminal workspace.

The existing storage schema remains the source of truth.  These helpers only
adapt rows to the in-memory objects already used by the Copilot engine; they
do not add a second history database or change the message format.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import KryonsecConfig
from ..copilot.session import GeneralSession, Message
from ..secrets import redact
from ..storage import GeneralSession as GeneralSessionRow
from ..storage import get_session, init_db


def _title(messages: list[Message]) -> str:
    """Derive a tab label from real user content without showing secrets."""
    for message in messages:
        if message.role != "user":
            continue
        value = redact(str(message.content or ""))[0]
        value = " ".join(value.split())
        if value:
            return value[:120] + ("..." if len(value) > 120 else "")
    return "New session"


@dataclass
class SessionTab:
    """One general-mode tab, persisted or still being composed."""

    cfg: KryonsecConfig
    session: GeneralSession
    record_id: str | None = None
    started_at: datetime | None = None
    # Operator-chosen display title, optional.  Renaming never changes the
    # stored message history; an unsaved (empty) tab keeps it in memory only.
    custom_title: str | None = None

    @property
    def title(self) -> str:
        if self.custom_title:
            return self.custom_title
        return _title(self.session.messages)

    @property
    def persisted(self) -> bool:
        return self.record_id is not None

    @property
    def short_id(self) -> str:
        return self.record_id[:8] if self.record_id else "new"


class SessionStore:
    """Repository for the existing ``general_sessions`` rows."""

    def __init__(self, cfg: KryonsecConfig) -> None:
        self.cfg = cfg

    def ensure_schema(self) -> None:
        init_db(self.cfg, include_purple=False)

    def list_tabs(self, limit: int = 8) -> list[SessionTab]:
        """Load recent real sessions; newest sessions appear first."""
        self.ensure_schema()
        with get_session(self.cfg) as db:
            rows = (
                db.query(GeneralSessionRow)
                .filter(GeneralSessionRow.user_id == "default")
                .order_by(GeneralSessionRow.started_at.desc())
                .limit(max(1, limit))
                .all()
            )
            return [self._tab_from_row(row) for row in rows]

    def new_tab(self) -> SessionTab:
        return SessionTab(self.cfg, GeneralSession(cfg=self.cfg))

    def save(self, tab: SessionTab) -> str | None:
        """Create or update one row; empty tabs are intentionally not stored."""
        if not tab.session.messages:
            return tab.record_id
        self.ensure_schema()
        payload = [message.as_dict() for message in tab.session.messages]
        with get_session(self.cfg) as db:
            row: GeneralSessionRow | None = None
            if tab.record_id:
                row = db.get(GeneralSessionRow, tab.record_id)
            if row is None:
                row = GeneralSessionRow(
                    user_id="default",
                    messages=payload,
                    token_count=tab.session.token_estimate,
                    ended_at=None,
                )
                db.add(row)
            else:
                row.messages = payload
                row.token_count = tab.session.token_estimate
            if tab.custom_title:
                # The summary column is the display-title storage, so a
                # renamed session reads back with the same tab label.
                row.summary = tab.custom_title
            db.commit()
            tab.record_id = row.id
            tab.started_at = row.started_at
        return tab.record_id

    def save_all(self, tabs: list[SessionTab]) -> None:
        for tab in tabs:
            try:
                self.save(tab)
            except Exception:
                # The interactive UI must not hide an otherwise usable chat
                # behind a storage failure.  The caller reports the notice.
                continue

    def _tab_from_row(self, row: Any) -> SessionTab:
        session = GeneralSession(cfg=self.cfg)
        raw_messages = row.messages if isinstance(row.messages, list) else []
        session.messages = [
            Message(
                role=str(message.get("role", "user")),
                content=str(message.get("content", "")),
            )
            for message in raw_messages
            if isinstance(message, dict)
        ]
        session.token_estimate = int(row.token_count or 0)
        if session.token_estimate <= 0 and session.messages:
            # Startup must not import the LLM stack just to paint a number.
            # This cheap estimate is replaced by the real count on the next
            # send/compaction, and it keeps the first screen instant.
            serialized = "\n".join(message.content for message in session.messages)
            session.token_estimate = max(1, len(serialized.encode("utf-8")) // 4)
        return SessionTab(
            cfg=self.cfg,
            session=session,
            record_id=str(row.id),
            started_at=row.started_at,
            custom_title=(row.summary or None),
        )


@dataclass
class EngagementTab:
    """A real engagement directory represented as a Mode B tab."""

    engagement_id: str
    target: str = "unknown target"
    status: str = "recorded"
    last_state: str = ""
    path: Path | None = None
    started_at: str = ""
    # Operator-chosen display title, optional.  Renaming NEVER changes the
    # engagement id, the recorded target, or any stored event; the title
    # lives beside the audit chain as display_title.json.
    custom_title: str | None = None

    @property
    def title(self) -> str:
        if self.custom_title:
            return self.custom_title[:28] + ("…" if len(self.custom_title) > 28 else "")
        return self.target[:28] + ("…" if len(self.target) > 28 else "")

    @property
    def short_id(self) -> str:
        return self.engagement_id[:8]


class EngagementStore:
    """Read-only index of the existing engagement audit records.

    "Read-only" applies to the audit chain: the one operator-owned display
    title is stored as ``display_title.json`` beside it, and nothing else
    in the engagement directory is ever written here.
    """

    DISPLAY_TITLE_FILE = "display_title.json"

    def __init__(self, cfg: KryonsecConfig) -> None:
        self.cfg = cfg

    def rename(self, engagement_id: str, title: str) -> bool:
        """Store one engagement's display title; returns True when written.

        The engagement id is a path component, so it is re-checked here the
        same way ``--id`` is at creation.  An unknown id (no directory) is
        refused rather than created.
        """
        from ..engagement_id import is_valid_engagement_id

        if not is_valid_engagement_id(engagement_id):
            return False
        directory = self.cfg.home / "engagements" / engagement_id
        if not directory.is_dir():
            return False
        cleaned = " ".join(str(title or "").split())[:120]
        if not cleaned:
            return False
        try:
            (directory / self.DISPLAY_TITLE_FILE).write_text(
                json.dumps({"title": cleaned}, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            return False
        return True

    def read_display_title(self, directory: Path) -> str | None:
        try:
            payload = json.loads(
                (directory / self.DISPLAY_TITLE_FILE).read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        title = " ".join(str(payload.get("title") or "").split())
        return title[:120] or None

    def list_tabs(self, limit: int = 8) -> list[EngagementTab]:
        root = self.cfg.home / "engagements"
        if not root.is_dir():
            return []
        records: list[EngagementTab] = []
        for directory in root.iterdir():
            audit_path = directory / "audit.jsonl"
            if not directory.is_dir() or not audit_path.is_file():
                continue
            record = self._read(audit_path, directory.name)
            if record is not None:
                records.append(record)
        records.sort(
            key=lambda item: (item.started_at, item.path.stat().st_mtime if item.path else 0),
            reverse=True,
        )
        return records[: max(1, limit)]

    def read_events(self, tab: EngagementTab) -> list[dict[str, Any]]:
        if tab.path is None:
            return []
        path = tab.path / "audit.jsonl"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        events: list[dict[str, Any]] = []
        for line in lines:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                events.append(value)
        return events

    def _read(self, path: Path, engagement_id: str) -> EngagementTab | None:
        events: list[dict[str, Any]] = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in lines:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                events.append(value)
        if not events:
            return None
        created = next(
            (event for event in events if event.get("event") == "engagement_created"),
            {},
        )
        finished = next(
            (event for event in reversed(events) if event.get("event") == "engagement_finished"),
            {},
        )
        target = redact(str(created.get("target") or "unknown target"))[0]
        return EngagementTab(
            engagement_id=engagement_id,
            target=target,
            status=str(finished.get("outcome") or "running"),
            last_state=str(finished.get("last_state") or ""),
            path=path.parent,
            started_at=str(created.get("ts") or ""),
            custom_title=self.read_display_title(path.parent),
        )


__all__ = [
    "EngagementStore",
    "EngagementTab",
    "SessionStore",
    "SessionTab",
]
