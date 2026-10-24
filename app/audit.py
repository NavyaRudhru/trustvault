
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog


def record_audit_event(
    db: Session,
    action: str,
    resource_type: str,
    outcome: str,
    actor_id: int | None = None,
    resource_id: str | None = None,
    details: str = "",
    ip_address: str | None = None,
) -> AuditLog:
    """
    Create an audit entry linked to the previous entry.
    The caller is responsible for committing the transaction.
    """

    # Get the most recent audit entry
    previous_entry = db.scalar(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    )

    previous_hash = (
        previous_entry.entry_hash if previous_entry else None
    )

    # Use a consistent timestamp for the stored event and its hash
    created_at = datetime.now(timezone.utc)

    # Build a consistent payload for hashing
    event_data = {
        "actor_id": actor_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "details": details,
        "ip_address": ip_address,
        "created_at": created_at.isoformat(),
        "previous_hash": previous_hash,
    }

    canonical_data = json.dumps(
        event_data,
        sort_keys=True,
        separators=(",", ":"),
    )

    entry_hash = hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()

    audit_entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        details=details,
        ip_address=ip_address,
        created_at=created_at,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
    )

    db.add(audit_entry)
    db.flush()

# Tell the database session that a checkpoint update is needed
# after the transaction successfully commits.
    db.info["audit_checkpoint_pending"] = True

    return audit_entry


def verify_audit_chain(db: Session) -> tuple[bool, str]:
    """Verify each audit entry's hash and its link to the previous entry."""
    entries = db.scalars(
        select(AuditLog).order_by(AuditLog.id.asc())
    ).all()

    expected_previous_hash = None

    for entry in entries:
        if entry.previous_hash != expected_previous_hash:
            return False, f"Broken hash link at audit entry {entry.id}."

        if not entry.entry_hash:
            return False, f"Missing entry hash at audit entry {entry.id}."

        # SQLite may return timezone-naive datetimes.
        timestamp = entry.created_at
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        event_data = {
            "actor_id": entry.actor_id,
            "action": entry.action,
            "resource_type": entry.resource_type,
            "resource_id": entry.resource_id,
            "outcome": entry.outcome,
            "details": entry.details,
            "ip_address": entry.ip_address,
            "created_at": timestamp.isoformat(),
            "previous_hash": entry.previous_hash,
        }

        canonical_data = json.dumps(
            event_data, sort_keys=True, separators=(",", ":")
        )
        calculated_hash = hashlib.sha256(
            canonical_data.encode("utf-8")
        ).hexdigest()

        if calculated_hash != entry.entry_hash:
            return False, f"Hash mismatch at audit entry {entry.id}."

        expected_previous_hash = entry.entry_hash

    return True, "Audit chain verified successfully."
