
from sqlalchemy import select
from pathlib import Path

from app.audit_checkpoint import (
    create_checkpoint,
    load_checkpoint,
    save_checkpoint,
    verify_full_chain_against_checkpoint,
)
from app.audit import verify_audit_chain
from app.database import SessionLocal
from app.models import AuditLog


def main():
    db = SessionLocal()

    try:
        # 1. Verify the current audit chain.
        is_valid, message = verify_audit_chain(db)

        if not is_valid:
            raise RuntimeError(
                f"Cannot create checkpoint: audit chain verification failed: {message}"
            )

        # 2. Find the latest audit entry.
        latest_entry = db.scalar(
            select(AuditLog)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )

        if latest_entry is None:
            print("No audit entries exist. Nothing to checkpoint.")
            return

        # 3. If a checkpoint already exists, validate it before replacing it.
        existing_checkpoint = load_checkpoint()
        checkpoint_file = (
            Path(__file__).resolve().parent.parent
            / "audit_checkpoints"
            / "latest.json"
        )

        # Reject an existing checkpoint that cannot be loaded and verified.
        if existing_checkpoint is None and checkpoint_file.exists():
            raise RuntimeError(
                "Cannot replace the existing checkpoint: "
                "the saved checkpoint is invalid or unreadable."
            )

        if existing_checkpoint is not None:
            if not verify_full_chain_against_checkpoint(
                existing_checkpoint, db
            ):
                raise RuntimeError(
                    "Cannot replace the existing checkpoint: "
                    "it does not match the current audit history."
                )

            # Refuse to replace a checkpoint with an older audit position.
            if existing_checkpoint["audit_id"] > latest_entry.id:
                raise RuntimeError(
                    "Cannot create checkpoint: the existing checkpoint "
                    "is ahead of the current audit history."
                )

        # 4. Create a signed checkpoint for the latest entry.
        checkpoint = create_checkpoint(
            audit_id=latest_entry.id,
            entry_hash=latest_entry.entry_hash,
        )

        # 5. Save only after the verification checks pass.
        checkpoint_path = save_checkpoint(checkpoint)

        print("Signed audit checkpoint created successfully.")
        print(f"Audit entry ID: {latest_entry.id}")
        print(f"Checkpoint file: {checkpoint_path}")

    finally:
        db.close()


if __name__ == "__main__":
    main()