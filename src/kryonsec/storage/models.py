"""Database models (spec v2.1.1 §10.1).

UUIDs are stored as 36-char strings and JSON as the portable JSON type so the
same models work on PostgreSQL (system of record) and the Profile-1 embedded
fallback. Purple-team tables are PostgreSQL-only in practice; on the fallback
backend only general/shared tables are created.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    UniqueConstraint,
    String,
    Integer,
    Text,
    DateTime,
    Float,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------
# GENERAL MODE (spec §3, §10.1)
# --------------------------------------------------------------------------

class GeneralSession(Base):
    __tablename__ = "general_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(64), default="default")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    messages: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_count: Mapped[int] = mapped_column(Integer, default=0)


class GeneralUserLtm(Base):
    __tablename__ = "general_user_ltm"
    __table_args__ = (UniqueConstraint("user_id", "category", "key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(64), default="default")
    category: Mapped[str] = mapped_column(String(64))
    key: Mapped[str] = mapped_column(String(255))
    value: Mapped[dict | list] = mapped_column(JSON)
    last_accessed: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    access_count: Mapped[int] = mapped_column(Integer, default=1)


# --------------------------------------------------------------------------
# SHARED (spec §10.1)
# --------------------------------------------------------------------------

class SystemKnowledge(Base):
    __tablename__ = "system_knowledge"
    __table_args__ = (UniqueConstraint("category", "key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    category: Mapped[str] = mapped_column(String(64))
    key: Mapped[str] = mapped_column(String(255))
    value: Mapped[dict | list] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


# --------------------------------------------------------------------------
# PURPLE TEAM (spec §4.5, §4.6, §10.1 — PostgreSQL only)
# --------------------------------------------------------------------------

class StmNode(Base):
    __tablename__ = "stm_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(String(36), index=True)
    subagent: Mapped[str] = mapped_column(String(64))
    node_type: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(Text)
    properties: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # App-layer computed (spec §4.5): pg_column_size() is not IMMUTABLE.
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class LtmTargetProfile(Base):
    __tablename__ = "ltm_target_profiles"

    target_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    stack_fingerprint: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_engagement: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    engagement_count: Mapped[int] = mapped_column(Integer, default=1)


class LtmEngagementSummary(Base):
    """Sanitized post-REPORT summaries readable by General mode (spec §5.3)."""

    __tablename__ = "ltm_engagement_summaries"

    engagement_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_label: Mapped[str] = mapped_column(Text)
    findings_metadata: Mapped[list] = mapped_column(JSON, default=list)  # title/severity/cvss/status only
    status: Mapped[str] = mapped_column(String(32), default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class EngagementSecretMap(Base):
    """Local-only placeholder->secret mapping for compaction (spec §6.4).
    Never sent to any LLM. Values are application-layer encrypted."""

    __tablename__ = "engagement_secret_map"
    __table_args__ = (UniqueConstraint("engagement_id", "placeholder"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(String(36))
    placeholder: Mapped[str] = mapped_column(String(64))
    secret_encrypted: Mapped[bytes] = mapped_column(String)  # base64 ciphertext
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Checkpoint(Base):
    __tablename__ = "checkpoints"

    engagement_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    current_state: Mapped[str] = mapped_column(String(32))
    completed_states: Mapped[list] = mapped_column(JSON, default=list)
    graph_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    audit_log_path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


GENERAL_TABLES = [GeneralSession, GeneralUserLtm, SystemKnowledge]
PURPLE_TABLES = [StmNode, LtmTargetProfile, LtmEngagementSummary, EngagementSecretMap, Checkpoint]
