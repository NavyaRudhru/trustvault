
from app.database import SessionLocal
from app.models import AuditLog
from app.audit import verify_audit_chain


def test_audit_chain_detects_modified_entry():
    db = SessionLocal()

    try:
        entry = db.query(AuditLog).order_by(AuditLog.id).first()

        # If there are no audit entries, there is nothing to tamper with.
        if entry is None:
            return

        original_details = entry.details

        try:
            entry.details = original_details + " TAMPERED"
            db.commit()

            is_valid, message = verify_audit_chain(db)

            assert is_valid is False, (
                "Audit verification should detect modified entry data."
            )
            assert "Hash mismatch" in message

        finally:
            entry.details = original_details
            db.commit()

    finally:
        db.close()
