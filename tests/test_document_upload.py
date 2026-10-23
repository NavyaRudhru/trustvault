
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.audit import record_audit_event
from app.auth import create_access_token
from app.database import Base, get_db
from app.main import app
from app.models import AuditLog, User
from app.security import hash_password


@pytest.fixture
def upload_test_env(tmp_path, monkeypatch):
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

    user = User(
        username="upload_owner",
        email="upload_owner@example.com",
        password_hash=hash_password("UploadOwnerPassword123!"),
        role="owner",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id)

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    # Keep uploaded test files isolated from real local storage.
    monkeypatch.setattr("app.documents.STORAGE_DIR", tmp_path / "storage")

    client = TestClient(app)

    yield client, db, token, user

    client.close()
    app.dependency_overrides.clear()
    db.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_valid_text_upload_succeeds(upload_test_env):
    client, db, token, user = upload_test_env

    response = client.post(
        "/documents/",
        headers={"Authorization": f"Bearer {token}"},
        data={"title": "Test document", "category": "General"},
        files={"file": ("sample.txt", b"TrustVault test content", "text/plain")},
    )

    assert response.status_code == 201
    assert response.json()["title"] == "Test document"
    assert response.json()["owner_id"] == user.id

    audit = (
        db.query(AuditLog)
        .filter(AuditLog.action == "DOCUMENT_UPLOAD")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.outcome == "SUCCESS"


@pytest.mark.parametrize(
    ("filename", "content", "expected_status"),
    [
        ("bad.exe", b"not allowed", 400),
        ("empty.txt", b"", 400),
        ("wrong.pdf", b"not a PDF file", 400),
    ],
)
def test_rejected_upload_is_audited(
    upload_test_env, filename, content, expected_status
):
    client, db, token, _user = upload_test_env

    response = client.post(
        "/documents/",
        headers={"Authorization": f"Bearer {token}"},
        data={"title": "Rejected document", "category": "General"},
        files={"file": (filename, content, "application/octet-stream")},
    )

    assert response.status_code == expected_status

    audit = (
        db.query(AuditLog)
        .filter(AuditLog.action == "DOCUMENT_UPLOAD")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert audit is not None
    assert audit.outcome == "DENIED"


def test_oversized_upload_is_rejected_and_audited(upload_test_env):
    client, db, token, _user = upload_test_env

    oversized_content = b"A" * (10 * 1024 * 1024 + 1)

    response = client.post(
        "/documents/",
        headers={"Authorization": f"Bearer {token}"},
        data={"title": "Oversized document", "category": "General"},
        files={
            "file": (
                "large.txt",
                oversized_content,
                "text/plain",
            )
        },
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "File exceeds the 10 MB limit."

    audit = (
        db.query(AuditLog)
        .filter(AuditLog.action == "DOCUMENT_UPLOAD")
        .order_by(AuditLog.id.desc())
        .first()
    )

    assert audit is not None
    assert audit.outcome == "DENIED"
    assert "10 MB limit" in audit.details


def test_upload_requires_authentication(upload_test_env):
    client, db, _token, _user = upload_test_env

    response = client.post(
        "/documents/",
        data={"title": "Unauthorized document", "category": "General"},
        files={
            "file": (
                "unauthorized.txt",
                b"This upload must be rejected.",
                "text/plain",
            )
        },
    )

    assert response.status_code == 401

    # An unauthenticated request must not create a document.
    from app.models import Document

    assert db.query(Document).count() == 0


def test_upload_normalizes_windows_style_filename(upload_test_env):
    client, db, token, _user = upload_test_env

    response = client.post(
        "/documents/",
        headers={"Authorization": f"Bearer {token}"},
        data={"title": "Filename test", "category": "General"},
        files={
            "file": (
                r"C:\fakepath\sample.txt",
                b"Safe test content",
                "text/plain",
            )
        },
    )

    assert response.status_code == 201
    assert response.json()["original_filename"] == "sample.txt"
