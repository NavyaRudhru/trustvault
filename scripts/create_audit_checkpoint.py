
from sqlalchemy import select

from app.audit_checkpoint import create_checkpoint, save_checkpoint
from app.audit import verify_audit_chain
from app.database import SessionLocal
from app.models import AuditLog


def main():
    db = SessionLocal()

    try:
        # Refuse to checkpoint an audit history that already fails verification.
        is_valid, message = verify_audit_chain(db)

        if not is_valid:
            raise RuntimeError(
                f"Cannot create checkpoint: {message}"
            )

        latest_entry = db.scalar(
            select(AuditLog)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )

        if latest_entry is None:
            print("No audit entries exist. Nothing to checkpoint.")
            return

        checkpoint = create_checkpoint(
            audit_id=latest_entry.id,
            entry_hash=latest_entry.entry_hash,
        )

        checkpoint_path = save_checkpoint(checkpoint)

        print("Signed audit checkpoint created successfully.")
        print(f"Audit entry ID: {latest_entry.id}")
        print(f"Checkpoint file: {checkpoint_path}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
