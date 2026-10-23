
import os

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.audit import record_audit_event
from app.audit_checkpoint import create_checkpoint, save_checkpoint
from app.auth import create_access_token
from app.database import Base, get_db
from app.main import app
from app.models import AuditLog, User
from app.security import hash_password


TEST_SECRET = "test-only-audit-checkpoint-secret-123456"


def setup_admin_test():
    # Use an isolated in-memory database for every test.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    # Set the test-only signing secret before creating checkpoints.
    os.environ["AUDIT_CHECKPOINT_SECRET"] = TEST_SECRET

    viewer = User(
        username="audit_viewer",
        email="audit_viewer@example.com",
        password_hash=hash_password("ViewerPassword123!"),
        role="viewer",
        is_active=True,
    )

    admin = User(
        username="audit_admin",
        email="audit_admin@example.com",
        password_hash=hash_password("AdminPassword123!"),
        role="admin",
        is_active=True,
    )

    db.add_all([viewer, admin])
    db.commit()
    db.refresh(viewer)
    db.refresh(admin)

    viewer_token = create_access_token(viewer.id)
    admin_token = create_access_token(admin.id)

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    return client, db, engine, viewer_token, admin_token


def create_matching_checkpoint(db, tmp_path):
    """Create a signed checkpoint matching the latest audit entry."""
    latest_entry = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .first()
    )

    if latest_entry is None:
        return None

    checkpoint = create_checkpoint(
        audit_id=latest_entry.id,
        entry_hash=latest_entry.entry_hash,
    )

    save_checkpoint(checkpoint, directory=str(tmp_path))
    return checkpoint


def cleanup_admin_test(client, db, engine):
    client.close()
    app.dependency_overrides.clear()
    db.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_audit_verification_requires_authentication(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.main.load_checkpoint",
        lambda: None,
    )

    client, db, engine, _, _ = setup_admin_test()

    try:
        response = client.get("/admin/audit/verify")
        assert response.status_code == 401
    finally:
        cleanup_admin_test(client, db, engine)


def test_viewer_cannot_verify_audit_log(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.main.load_checkpoint",
        lambda: None,
    )

    client, db, engine, viewer_token, _ = setup_admin_test()

    try:
        response = client.get(
            "/admin/audit/verify",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert response.status_code == 403
    finally:
        cleanup_admin_test(client, db, engine)


def test_admin_can_verify_audit_log(tmp_path, monkeypatch):
    client, db, engine, _, admin_token = setup_admin_test()

    try:
        # Add an audit entry so the checkpoint has a real entry to protect.
        record_audit_event(
            db=db,
            actor_id=None,
            action="TEST_EVENT",
            resource_type="TEST",
            resource_id="1",
            outcome="SUCCESS",
            details="Audit verification test",
        )
        db.commit()

        # Create a checkpoint matching the latest audit entry.
        create_matching_checkpoint(db, tmp_path)

        # Make the endpoint load this test's checkpoint.
        from app.audit_checkpoint import load_checkpoint

        monkeypatch.setattr(
            "app.main.load_checkpoint",
            lambda: load_checkpoint(directory=str(tmp_path)),
        )

        response = client.get(
            "/admin/audit/verify",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        assert response.json()["valid"] is True

    finally:
        cleanup_admin_test(client, db, engine)


def test_admin_verification_detects_tampered_audit_log(
    tmp_path, monkeypatch
):
    client, db, engine, _, admin_token = setup_admin_test()

    try:
        record_audit_event(
            db=db,
            actor_id=None,
            action="TEST_EVENT",
            resource_type="TEST",
            resource_id="1",
            outcome="SUCCESS",
            details="Original audit event",
        )
        db.commit()

        # Sign the original audit entry before tampering.
        create_matching_checkpoint(db, tmp_path)

        from app.audit_checkpoint import load_checkpoint

        monkeypatch.setattr(
            "app.main.load_checkpoint",
            lambda: load_checkpoint(directory=str(tmp_path)),
        )

        headers = {"Authorization": f"Bearer {admin_token}"}

        # The original chain and checkpoint should both be valid.
        response = client.get(
            "/admin/audit/verify",
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["valid"] is True

        # Modify a stored audit field without recalculating its hash.
        entry = db.query(AuditLog).first()
        entry.details = "Tampered audit event"
        db.commit()

        response = client.get(
            "/admin/audit/verify",
            headers=headers,
        )

        assert response.status_code == 200
        assert response.json()["valid"] is False

    finally:
        cleanup_admin_test(client, db, engine)
