"""Persistence for handoff records (Batch 3).

The coordinator (``purple.coordinator``) is RAM-only, exactly like the
engagement graph — and this module is its whole boundary with storage,
the same shape ``purple.graph_store`` is for the graph:

* ``save_handoffs`` replaces the engagement's rows in one transaction
  committed once at the end, so a crash part-way leaves the previous
  checkpoint rather than half of a new one — which is what makes saving
  at every state boundary (``purple.runner.checkpoint_handoffs``) safe.
  Replaying the save is therefore idempotent: the second write lands on
  the same rows, never alongside them.
* ``load_handoffs`` rebuilds the coordinator after a restart, refusing a
  payload that claims to belong to another engagement (the
  cross-engagement rule holds in storage too) or a version this build
  does not understand.
* ``save_handoffs`` also carries the Batch 4 specialist scheduler's own
  snapshot (``handoff_scheduler``, one row per engagement) in the SAME
  transaction, so records and scheduler checkpoint can never disagree
  about where an interruption found them. ``load_scheduler_payload``
  reads that row back for :meth:`SpecialistScheduler.from_dict`.

Redaction is applied again on the way in, even though every text field
was sanitized at message construction: this is a durable copy, and the
belt-and-braces rule is the graph store's.

The ``handoff_records`` table is a *purple* table: created only where the
engagement tables live (PostgreSQL by default, the dedicated SQLite file
otherwise) — never inside the Copilot fallback database. The gate is the
same one revision 0002 uses: the migration checks the table list, and a
database without ``stm_nodes`` gets nothing.

Nothing here touches the audit chain, approval, the sandbox or the
allowlists — a storage boundary, and nothing else.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from ..secrets import redact
from ..storage.models import HandoffRecordRow, HandoffSchedulerRow
from .coordinator import HandoffCoordinator, HandoffError
from .handoff import HANDOFF_FORMAT_VERSION
from .recon_passive import CrossEngagementError, _parse_timestamp

if TYPE_CHECKING:  # pragma: no cover - hints only, never a runtime import
    from .recon_passive import EngagementGraph
    from .audit import AuditLog

__all__ = [
    "SCHEDULER_FORMAT_VERSION",
    "load_handoffs",
    "load_scheduler_payload",
    "save_handoffs",
]

# The scheduler snapshot's own format version — bumped when the snapshot
# shape changes, exactly like HANDOFF_FORMAT_VERSION. A checkpoint a
# build cannot read is refused, never half-interpreted.
SCHEDULER_FORMAT_VERSION = 1


def _redacted(value):
    """``value`` with secret-shaped strings replaced by placeholders.

    Same recursive walk as ``graph_store._redacted`` — defense in depth
    over payloads that were already sanitized at construction. The
    placeholder map is discarded: it maps placeholder -> real value.
    """
    if isinstance(value, str):
        return redact(value)[0]
    if isinstance(value, list):
        return [_redacted(item) for item in value]
    if isinstance(value, dict):
        return {key: _redacted(item) for key, item in value.items()}
    return value


def save_handoffs(
    session: Session,
    engagement_id: str,
    coordinator: HandoffCoordinator,
    *,
    scheduler: object | None = None,
) -> int:
    """Write the coordinator's records as the engagement's current state.

    Replace, not merge — the records are the current state of the
    structured exchange, and a record that no longer exists in RAM must
    not linger in the table. History lives in the audit chain, which this
    never touches.

    When ``scheduler`` is given, its snapshot is written into
    ``handoff_scheduler`` (one row per engagement, replaced the same way)
    INSIDE the same transaction — so the records and the scheduler
    checkpoint always describe the same moment, and a crash part-way
    leaves the previous checkpoint of both.

    Returns the record count. Commits before returning.
    """
    payload = coordinator.to_dict()
    if payload["engagement_id"] != engagement_id:
        raise CrossEngagementError(
            f"coordinator holds engagement {payload['engagement_id']!r}, "
            f"but was asked to save engagement {engagement_id!r}")

    # Rows are replaced wholesale, like the graph: one transaction, one
    # commit, so an interrupted write leaves the previous checkpoint.
    session.query(HandoffRecordRow).filter(
        HandoffRecordRow.engagement_id == engagement_id
    ).delete(synchronize_session=False)

    for raw in payload["records"]:
        record = _redacted(raw)
        session.add(HandoffRecordRow(
            id=record["message_id"],
            engagement_id=engagement_id,
            identity_key=record["identity_key"],
            kind=record["kind"],
            status=record["status"],
            payload={
                "version": HANDOFF_FORMAT_VERSION,
                "record": record,
            },
            created_at=_parse_timestamp(record.get("created_at")),
            updated_at=_parse_timestamp(record.get("updated_at")),
        ))

    if scheduler is not None:
        snapshot = scheduler.to_dict()
        if snapshot.get("engagement_id") != engagement_id:
            raise CrossEngagementError(
                f"scheduler holds engagement "
                f"{snapshot.get('engagement_id')!r}, but was asked to save "
                f"engagement {engagement_id!r}")
        session.query(HandoffSchedulerRow).filter(
            HandoffSchedulerRow.engagement_id == engagement_id
        ).delete(synchronize_session=False)
        session.add(HandoffSchedulerRow(
            engagement_id=engagement_id,
            payload=_redacted(snapshot),
        ))

    session.commit()
    return len(payload["records"])


def load_scheduler_payload(session: Session, engagement_id: str) -> dict | None:
    """The scheduler snapshot an earlier run saved, or None.

    A malformed or cross-engagement payload is REFUSED, not half-read:
    the caller's resume pass treats the refusal as a corrupt checkpoint
    and recovers the audited way. ``None`` simply means no scheduler
    checkpoint exists (Batch 3 saves, an engagement that scheduled
    nothing, or a hand-mixed store) — nothing to restore, nothing to
    fear.
    """
    rows = session.query(HandoffSchedulerRow).filter(
        HandoffSchedulerRow.engagement_id == engagement_id
    ).all()
    if not rows:
        return None
    if len(rows) > 1:
        # More than one row for one engagement means the replace-on-save
        # contract was violated somewhere — refuse rather than guess.
        raise HandoffError(
            f"engagement {engagement_id!r} holds "
            f"{len(rows)} scheduler checkpoint rows; expected exactly one")
    payload = rows[0].payload
    if not isinstance(payload, dict):
        raise HandoffError(
            "scheduler checkpoint row holds no readable payload")
    version = payload.get("version")
    if version != SCHEDULER_FORMAT_VERSION:
        raise HandoffError(
            f"scheduler checkpoint was written by format version "
            f"{version!r}; this build reads {SCHEDULER_FORMAT_VERSION}")
    if payload.get("engagement_id") != engagement_id:
        raise CrossEngagementError(
            f"scheduler checkpoint holds engagement "
            f"{payload.get('engagement_id')!r}, not {engagement_id!r}")
    return payload


def load_handoffs(
    session: Session,
    engagement_id: str,
    *,
    graph: EngagementGraph | None = None,
    audit: AuditLog | None = None,
) -> HandoffCoordinator:
    """Rebuild the coordinator an earlier run saved.

    ``graph``/``audit`` re-attach the live engagement's graph and chain so
    the restored coordinator is immediately usable (registering, claiming,
    linking all audit again); without them it is a read-only record holder.

    Rows written before a field existed cannot happen — the table is new
    with this feature — so every payload must validate. A row whose
    payload names a different engagement is a corrupt or hand-mixed
    store: refused loudly, never merged.
    """
    rows = session.query(HandoffRecordRow).filter(
        HandoffRecordRow.engagement_id == engagement_id
    ).all()

    records: list[dict] = []
    for row in rows:
        payload = row.payload or {}
        if not isinstance(payload, dict) or not isinstance(
                payload.get("record"), dict):
            raise HandoffError(
                f"handoff row {row.id!r} holds no readable record payload")
        version = payload.get("version")
        if version != HANDOFF_FORMAT_VERSION:
            raise HandoffError(
                f"handoff row {row.id!r} was written by format version "
                f"{version!r}; this build reads "
                f"{HANDOFF_FORMAT_VERSION}")
        record = payload["record"]
        if record.get("engagement_id") != engagement_id:
            raise CrossEngagementError(
                f"handoff row {row.id!r} holds engagement "
                f"{record.get('engagement_id')!r}, not {engagement_id!r}")
        records.append(record)

    return HandoffCoordinator.from_dict(
        {
            "version": HANDOFF_FORMAT_VERSION,
            "engagement_id": engagement_id,
            "records": records,
        },
        graph=graph,
        audit=audit,
    )
