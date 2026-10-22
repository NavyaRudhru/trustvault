
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import AuditLog
from app.audit import record_audit_event, verify_audit_chain


@pytest.fixture
def audit_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    Base.metadata.create_all(bind=engine)
    db = TestSession()

    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_audit_chain_is_valid_for_new_entries(audit_db):
    record_audit_event(
        db=audit_db,
        action="DOCUMENT_UPLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="Test document uploaded",
    )

    audit_db.commit()

    is_valid, message = verify_audit_chain(audit_db)

    assert is_valid is True, message


def test_audit_chain_detects_modified_entry(audit_db):
    record_audit_event(
        db=audit_db,
        action="DOCUMENT_UPLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="Original details",
    )

    audit_db.commit()

    entry = audit_db.query(AuditLog).first()
    entry.details = "Original details TAMPERED"
    audit_db.commit()

    is_valid, message = verify_audit_chain(audit_db)

    assert is_valid is False, (
        "Audit verification should detect modified entry data."
    )
    assert "Hash mismatch" in message


def test_audit_chain_detects_broken_hash_link(audit_db):
    record_audit_event(
        db=audit_db,
        action="DOCUMENT_UPLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="First entry",
    )

    record_audit_event(
        db=audit_db,
        action="DOCUMENT_DOWNLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="Second entry",
    )

    audit_db.commit()

    second_entry = (
        audit_db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .first()
    )
    second_entry.previous_hash = "invalid_previous_hash"
    audit_db.commit()

    is_valid, message = verify_audit_chain(audit_db)

    assert is_valid is False
    assert "Broken hash link" in message
