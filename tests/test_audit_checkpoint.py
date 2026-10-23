
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.audit import record_audit_event
from app.audit_checkpoint import (
    sign_checkpoint,
    verify_checkpoint_signature,
    create_checkpoint,
    verify_checkpoint,
    save_checkpoint,
    load_checkpoint,
    verify_checkpoint_against_audit_log,
    verify_full_chain_against_checkpoint,
)
from app.models import Base, AuditLog


# --------------------------------------------------
# Shared test database fixture
# --------------------------------------------------

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


# --------------------------------------------------
# Checkpoint signature tests
# --------------------------------------------------

def test_checkpoint_signature_is_valid(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    checkpoint_data = "audit_id=10;entry_hash=abc123"
    signature = sign_checkpoint(checkpoint_data)

    assert verify_checkpoint_signature(
        checkpoint_data, signature
    ) is True


def test_modified_checkpoint_signature_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    checkpoint_data = "audit_id=10;entry_hash=abc123"
    signature = sign_checkpoint(checkpoint_data)

    assert verify_checkpoint_signature(
        "audit_id=10;entry_hash=changed",
        signature,
    ) is False


def test_modified_signature_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    checkpoint_data = "audit_id=10;entry_hash=abc123"

    assert verify_checkpoint_signature(
        checkpoint_data, "invalid-signature"
    ) is False


def test_missing_secret_is_rejected(monkeypatch):
    monkeypatch.delenv(
        "AUDIT_CHECKPOINT_SECRET",
        raising=False,
    )

    with pytest.raises(
        RuntimeError,
        match="AUDIT_CHECKPOINT_SECRET",
    ):
        sign_checkpoint("audit_id=10;entry_hash=abc123")


def test_short_secret_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "too-short",
    )

    with pytest.raises(
        RuntimeError,
        match="at least 32 characters",
    ):
        sign_checkpoint("audit_id=10;entry_hash=abc123")


# --------------------------------------------------
# Checkpoint creation and validation tests
# --------------------------------------------------

def test_created_checkpoint_is_valid(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    checkpoint = create_checkpoint(
        audit_id=10,
        entry_hash="abc123",
    )

    assert checkpoint["audit_id"] == 10
    assert checkpoint["entry_hash"] == "abc123"
    assert verify_checkpoint(checkpoint) is True


def test_modified_checkpoint_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    checkpoint = create_checkpoint(
        audit_id=10,
        entry_hash="abc123",
    )
    checkpoint["entry_hash"] = "tampered_hash"

    assert verify_checkpoint(checkpoint) is False


# --------------------------------------------------
# Checkpoint file storage tests
# --------------------------------------------------

def test_checkpoint_can_be_saved_and_loaded(
    monkeypatch, tmp_path
):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    checkpoint = create_checkpoint(
        audit_id=10,
        entry_hash="abc123",
    )

    path = save_checkpoint(checkpoint, str(tmp_path))
    loaded = load_checkpoint(str(tmp_path))

    assert path.exists()
    assert loaded is not None
    assert loaded["audit_id"] == 10
    assert loaded["entry_hash"] == "abc123"
    assert verify_checkpoint(loaded) is True


def test_missing_saved_checkpoint_returns_none(tmp_path):
    assert load_checkpoint(str(tmp_path)) is None


def test_tampered_saved_checkpoint_is_rejected(
    monkeypatch, tmp_path
):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    checkpoint = create_checkpoint(
        audit_id=10,
        entry_hash="abc123",
    )
    path = save_checkpoint(checkpoint, str(tmp_path))

    saved_data = json.loads(
        path.read_text(encoding="utf-8")
    )
    saved_data["entry_hash"] = "tampered_hash"

    path.write_text(
        json.dumps(saved_data),
        encoding="utf-8",
    )

    assert load_checkpoint(str(tmp_path)) is None


# --------------------------------------------------
# Checkpoint and database verification tests
# --------------------------------------------------

def test_checkpoint_matches_database_entry(
    monkeypatch, audit_db
):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    entry = AuditLog(
        action="DOCUMENT_UPLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="Test upload",
        previous_hash=None,
        entry_hash="abc123",
    )

    audit_db.add(entry)
    audit_db.commit()
    audit_db.refresh(entry)

    checkpoint = create_checkpoint(
        audit_id=entry.id,
        entry_hash=entry.entry_hash,
    )

    assert verify_checkpoint_against_audit_log(
        checkpoint, audit_db
    ) is True


def test_checkpoint_mismatching_database_hash_is_rejected(
    monkeypatch, audit_db
):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    entry = AuditLog(
        action="DOCUMENT_UPLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="Test upload",
        previous_hash=None,
        entry_hash="actual_hash",
    )

    audit_db.add(entry)
    audit_db.commit()
    audit_db.refresh(entry)

    checkpoint = create_checkpoint(
        audit_id=entry.id,
        entry_hash="different_hash",
    )

    assert verify_checkpoint_against_audit_log(
        checkpoint, audit_db
    ) is False


# --------------------------------------------------
# Full audit-chain verification tests
# --------------------------------------------------

def test_full_chain_matches_latest_checkpoint(
    monkeypatch, audit_db
):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    record_audit_event(
        db=audit_db,
        action="DOCUMENT_UPLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="First event",
    )
    audit_db.commit()

    latest = record_audit_event(
        db=audit_db,
        action="DOCUMENT_DOWNLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="Second event",
    )
    audit_db.commit()
    audit_db.refresh(latest)

    checkpoint = create_checkpoint(
        audit_id=latest.id,
        entry_hash=latest.entry_hash,
    )

    assert verify_full_chain_against_checkpoint(
        checkpoint, audit_db
    ) is True


def test_full_chain_rejects_checkpoint_for_old_entry(
    monkeypatch, audit_db
):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )

    first = record_audit_event(
        db=audit_db,
        action="DOCUMENT_UPLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="First event",
    )
    audit_db.commit()
    audit_db.refresh(first)

    checkpoint = create_checkpoint(
        audit_id=first.id,
        entry_hash=first.entry_hash,
    )

    record_audit_event(
        db=audit_db,
        action="DOCUMENT_DOWNLOAD",
        resource_type="document",
        resource_id="1",
        outcome="SUCCESS",
        details="Second event",
    )
    audit_db.commit()

    assert verify_full_chain_against_checkpoint(
        checkpoint, audit_db
    ) is False


def test_rollback_to_old_signed_checkpoint_is_rejected(audit_db, tmp_path, monkeypatch):
    import os

    from app.audit import record_audit_event
    from app.audit_checkpoint import (
        create_checkpoint,
        save_checkpoint,
        load_checkpoint,
        verify_full_chain_against_checkpoint,
    )
    from app.models import AuditLog

    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-only-audit-checkpoint-secret-123456",
    )

    # Create the first audit entry.
    record_audit_event(
        db=audit_db,
        actor_id=None,
        action="FIRST_EVENT",
        resource_type="TEST",
        resource_id="1",
        outcome="SUCCESS",
        details="First audit event",
    )
    audit_db.commit()

    first_entry = (
        audit_db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .first()
    )

    old_checkpoint = create_checkpoint(
        audit_id=first_entry.id,
        entry_hash=first_entry.entry_hash,
    )

    # Add a second audit entry after the first checkpoint.
    record_audit_event(
        db=audit_db,
        actor_id=None,
        action="SECOND_EVENT",
        resource_type="TEST",
        resource_id="2",
        outcome="SUCCESS",
        details="Second audit event",
    )
    audit_db.commit()

    # The old checkpoint is correctly signed, but it is no longer current.
    save_checkpoint(old_checkpoint, directory=str(tmp_path))
    loaded_checkpoint = load_checkpoint(directory=str(tmp_path))

    assert loaded_checkpoint is not None
    assert verify_full_chain_against_checkpoint(
        loaded_checkpoint,
        audit_db,
    ) is False


def test_invalid_existing_checkpoint_is_not_overwritten(
    monkeypatch, tmp_path
):
    from app.audit_checkpoint import save_checkpoint

    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-only-audit-checkpoint-secret-123456",
    )

    valid_checkpoint = create_checkpoint(
        audit_id=1,
        entry_hash="original-hash",
    )

    path = save_checkpoint(
        valid_checkpoint,
        directory=str(tmp_path),
    )

    original_content = path.read_text(encoding="utf-8")

    # Tamper with the saved checkpoint.
    saved_data = json.loads(original_content)
    saved_data["entry_hash"] = "tampered-hash"

    path.write_text(
        json.dumps(saved_data),
        encoding="utf-8",
    )

    tampered_content = path.read_text(encoding="utf-8")

    # The invalid checkpoint must not be accepted for replacement.
    assert load_checkpoint(directory=str(tmp_path)) is None

    # Confirm that the invalid checkpoint file remains unchanged.
    assert path.read_text(encoding="utf-8") == tampered_content


def test_checkpoint_script_refuses_invalid_existing_checkpoint(
    monkeypatch,
):
    from types import SimpleNamespace

    from scripts import create_audit_checkpoint as checkpoint_script

    fake_db = SimpleNamespace(
        scalar=lambda query: SimpleNamespace(
            id=1,
            entry_hash="current-audit-hash",
        ),
        close=lambda: None,
    )

    monkeypatch.setattr(
        checkpoint_script,
        "SessionLocal",
        lambda: fake_db,
    )
    monkeypatch.setattr(
        checkpoint_script,
        "verify_audit_chain",
        lambda db: (True, "Audit chain is valid"),
    )
    monkeypatch.setattr(
        checkpoint_script,
        "load_checkpoint",
        lambda: {"audit_id": 1, "entry_hash": "tampered"},
    )
    monkeypatch.setattr(
        checkpoint_script,
        "verify_full_chain_against_checkpoint",
        lambda checkpoint, db: False,
    )

    def unexpected_save(*args, **kwargs):
        pytest.fail("The script must not save over an invalid checkpoint.")

    monkeypatch.setattr(
        checkpoint_script,
        "save_checkpoint",
        unexpected_save,
    )

    with pytest.raises(
        RuntimeError,
        match="existing checkpoint",
    ):
        checkpoint_script.main()


def test_checkpoint_script_refuses_corrupted_checkpoint_file(
    monkeypatch, tmp_path
):
    from types import SimpleNamespace

    from scripts import create_audit_checkpoint as checkpoint_script

    fake_db = SimpleNamespace(
        scalar=lambda query: SimpleNamespace(
            id=1,
            entry_hash="current-audit-hash",
        ),
        close=lambda: None,
    )

    monkeypatch.setattr(
        checkpoint_script,
        "SessionLocal",
        lambda: fake_db,
    )
    monkeypatch.setattr(
        checkpoint_script,
        "verify_audit_chain",
        lambda db: (True, "Audit chain is valid"),
    )
    monkeypatch.setattr(
        checkpoint_script,
        "load_checkpoint",
        lambda: None,
    )

    # Make the script's resolved project root equal to tmp_path.
    monkeypatch.setattr(
        checkpoint_script.Path,
        "resolve",
        lambda self: tmp_path / "scripts" / "create_audit_checkpoint.py",
    )

    # The script checks audit_checkpoints/latest.json under that root.
    checkpoint_dir = tmp_path / "audit_checkpoints"
    checkpoint_dir.mkdir()
    checkpoint_file = checkpoint_dir / "latest.json"
    checkpoint_file.write_text(
        "{invalid JSON",
        encoding="utf-8",
    )

    def unexpected_save(*args, **kwargs):
        pytest.fail("The script must not overwrite a corrupted checkpoint.")

    monkeypatch.setattr(
        checkpoint_script,
        "save_checkpoint",
        unexpected_save,
    )

    with pytest.raises(
        RuntimeError,
        match="invalid or unreadable",
    ):
        checkpoint_script.main()

    assert checkpoint_file.read_text(encoding="utf-8") == "{invalid JSON"
