
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import AuditLog, Document, User
from app.security import hash_password
from app.auth import create_access_token


@pytest.fixture
def setup_download_test(tmp_path, monkeypatch):
    # Create an isolated in-memory database for this test.
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSession = sessionmaker(
        bind=test_engine,
        autoflush=False,
        autocommit=False,
    )
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Store test files in a temporary private directory.
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    monkeypatch.setattr("app.documents.STORAGE_DIR", storage_dir)

    db = TestSession()
    try:
        owner = User(
            username="download_owner",
            email="download_owner@example.com",
            password_hash=hash_password("Owner-Test-Password-2026!"),
            role="viewer",
            is_active=True,
        )
        viewer = User(
            username="download_viewer",
            email="download_viewer@example.com",
            password_hash=hash_password("Viewer-Test-Password-2026!"),
            role="viewer",
            is_active=True,
        )
        db.add_all([owner, viewer])
        db.flush()

        stored_name = "test-document.txt"
        (storage_dir / stored_name).write_text(
            "Private test document",
            encoding="utf-8",
        )

        document = Document(
            title="Private Test Document",
            category="Testing",
            original_filename="private.txt",
            storage_key=stored_name,
            content_type="text/plain",
            size_bytes=len("Private test document"),
            owner_id=owner.id,
        )
        db.add(document)
        db.commit()

        owner_id = owner.id
        viewer_id = viewer.id
        document_id = document.id
    finally:
        db.close()

    try:
        with TestClient(app) as client:
            yield {
                "client": client,
                "TestSession": TestSession,
                "owner_token": create_access_token(owner_id),
                "viewer_token": create_access_token(viewer_id),
                "document_id": document_id,
            }
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


def test_owner_can_download_and_success_is_audited(setup_download_test):
    test = setup_download_test
    response = test["client"].get(
        f"/documents/{test['document_id']}/download",
        headers={"Authorization": f"Bearer {test['owner_token']}"},
    )

    assert response.status_code == 200
    assert response.content == b"Private test document"

    db = test["TestSession"]()
    try:
        event = (
            db.query(AuditLog)
            .filter_by(
                action="DOCUMENT_DOWNLOAD",
                resource_id=str(test["document_id"]),
                outcome="SUCCESS",
            )
            .one()
        )
        assert event.details
    finally:
        db.close()


def test_unshared_viewer_cannot_download_and_denial_is_audited(
    setup_download_test,
):
    test = setup_download_test
    response = test["client"].get(
        f"/documents/{test['document_id']}/download",
        headers={"Authorization": f"Bearer {test['viewer_token']}"},
    )

    assert response.status_code == 404

    db = test["TestSession"]()
    try:
        event = (
            db.query(AuditLog)
            .filter_by(
                action="DOCUMENT_DOWNLOAD",
                resource_id=str(test["document_id"]),
                outcome="DENIED",
            )
            .one()
        )
        assert event.actor_id is not None
    finally:
        db.close()
