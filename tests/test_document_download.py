
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


def test_revoked_permission_blocks_download_and_is_audited(
    setup_download_test,
):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    owner_headers = {
        "Authorization": f"Bearer {test['owner_token']}"
    }
    viewer_headers = {
        "Authorization": f"Bearer {test['viewer_token']}"
    }

    # 1. Owner grants read access to the viewer.
    grant_response = client.post(
        f"/documents/{document_id}/permissions",
        headers=owner_headers,
        json={
            "username": "download_viewer",
            "can_read": True,
            "can_edit": False,
        },
    )
    assert grant_response.status_code == 200

    # 2. Viewer can download while permission exists.
    allowed_response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer_headers,
    )
    assert allowed_response.status_code == 200

    # 3. Owner revokes the viewer's permission.
    revoke_response = client.delete(
        f"/documents/{document_id}/permissions/download_viewer",
        headers=owner_headers,
    )
    assert revoke_response.status_code == 200

    # 4. The viewer is denied immediately after revocation.
    denied_response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer_headers,
    )
    assert denied_response.status_code == 404

    # 5. Verify grant, revoke, and denied-download audit entries.
    db = test["TestSession"]()
    try:
        events = (
            db.query(AuditLog)
            .filter(
                AuditLog.resource_id == str(document_id),
                AuditLog.action.in_(
                    [
                        "PERMISSION_GRANT",
                        "PERMISSION_REVOKE",
                        "DOCUMENT_DOWNLOAD",
                    ]
                ),
            )
            .all()
        )

        assert any(
            e.action == "PERMISSION_GRANT" and e.outcome == "SUCCESS"
            for e in events
        )
        assert any(
            e.action == "PERMISSION_REVOKE" and e.outcome == "SUCCESS"
            for e in events
        )
        assert any(
            e.action == "DOCUMENT_DOWNLOAD" and e.outcome == "DENIED"
            for e in events
        )
    finally:
        db.close()


def test_unshared_viewer_cannot_edit_document(setup_download_test):
    test = setup_download_test
    client = test["client"]
    viewer_token = test["viewer_token"]
    document_id = test["document_id"]

    response = client.patch(
        f"/documents/{document_id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "title": "Unauthorized title change",
            "category": "Unauthorized category",
        },
    )
    assert response.status_code == 404

    db = test["TestSession"]()
    try:
        # Verify the document was not changed.
        document = db.get(Document, document_id)
        assert document is not None
        assert document.title != "Unauthorized title change"
        assert document.category != "Unauthorized category"

        # Verify the denied edit was recorded in the audit log.
        denied_event = (
            db.query(AuditLog)
            .filter_by(
                action="DOCUMENT_UPDATE",
                resource_id=str(document_id),
                outcome="DENIED",
            )
            .first()
        )

        assert denied_event is not None, (
            "Unauthorized document edit must be recorded in the audit log."
        )
    finally:
        db.close()


def test_unshared_viewer_cannot_delete_document(setup_download_test):
    test = setup_download_test
    client = test["client"]
    viewer_token = test["viewer_token"]
    document_id = test["document_id"]

    response = client.delete(
        f"/documents/{document_id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 404

    db = test["TestSession"]()
    try:
        # Verify the document still exists.
        document = db.get(Document, document_id)
        assert document is not None

        # Verify the denied deletion was audited.
        denied_event = (
            db.query(AuditLog)
            .filter_by(
                action="DOCUMENT_DELETE",
                resource_id=str(document_id),
                outcome="DENIED",
            )
            .first()
        )

        assert denied_event is not None, (
            "Unauthorized deletion attempt should be audited."
        )
    finally:
        db.close()


def test_unshared_viewer_cannot_access_document_details(
    setup_download_test,
):
    test = setup_download_test
    client = test["client"]
    viewer_token = test["viewer_token"]
    document_id = test["document_id"]

    response = client.get(
        f"/documents/{document_id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 404


def test_unshared_viewer_cannot_see_private_document_in_list(
    setup_download_test,
):
    test = setup_download_test

    response = test["client"].get(
        "/documents",
        headers={
            "Authorization": f"Bearer {test['viewer_token']}"
        },
    )

    assert response.status_code == 200
    assert all(
        item.get("id") != test["document_id"]
        for item in response.json()
    )


def test_unshared_viewer_cannot_find_private_document_by_search(
    setup_download_test,
):
    test = setup_download_test

    response = test["client"].get(
        "/documents",
        params={"search": "Private Test Document"},
        headers={
            "Authorization": f"Bearer {test['viewer_token']}"
        },
    )

    assert response.status_code == 200
    assert all(
        item.get("id") != test["document_id"]
        for item in response.json()
    )


def test_non_owner_cannot_grant_permission_and_attempt_is_audited(
    setup_download_test,
):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    viewer_headers = {
        "Authorization": f"Bearer {test['viewer_token']}"
    }

    response = client.post(
        f"/documents/{document_id}/permissions",
        headers=viewer_headers,
        json={
            "username": "download_viewer",
            "can_read": True,
            "can_edit": False,
        },
    )

    assert response.status_code == 404

    db = test["TestSession"]()
    try:
        event = (
            db.query(AuditLog)
            .filter_by(
                action="PERMISSION_GRANT",
                resource_type="document",
                resource_id=str(document_id),
                outcome="DENIED",
            )
            .order_by(AuditLog.id.desc())
            .first()
        )

        assert event is not None
        assert event.actor_id is not None
    finally:
        db.close()


def test_revoking_missing_permission_is_audited(setup_download_test):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    owner_headers = {
        "Authorization": f"Bearer {test['owner_token']}"
    }

    # Attempt to revoke access that was never granted.
    response = client.delete(
        f"/documents/{document_id}/permissions/download_viewer",
        headers=owner_headers,
    )

    assert response.status_code == 404

    db = test["TestSession"]()
    try:
        event = (
            db.query(AuditLog)
            .filter_by(
                action="PERMISSION_REVOKE",
                resource_type="document",
                resource_id=str(document_id),
                outcome="DENIED",
            )
            .order_by(AuditLog.id.desc())
            .first()
        )

        assert event is not None
        assert event.actor_id is not None
    finally:
        db.close()


def test_read_only_viewer_cannot_edit_document(setup_download_test):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    owner_headers = {
        "Authorization": f"Bearer {test['owner_token']}"
    }
    viewer_headers = {
        "Authorization": f"Bearer {test['viewer_token']}"
    }

    # The owner grants read access, but not edit access.
    grant_response = client.post(
        f"/documents/{document_id}/permissions",
        headers=owner_headers,
        json={
            "username": "download_viewer",
            "can_read": True,
            "can_edit": False,
        },
    )
    assert grant_response.status_code == 200

    # The viewer must not be able to edit the document.
    response = client.patch(
        f"/documents/{document_id}",
        headers=viewer_headers,
        json={
            "title": "Unauthorized title change",
            "category": "Unauthorized category",
        },
    )
    assert response.status_code == 404

    # Confirm that the document was not modified.
    db = test["TestSession"]()
    try:
        document = db.get(Document, document_id)
        assert document is not None
        assert document.title == "Private Test Document"
        assert document.category == "Testing"

        # Confirm that the denied edit was audited.
        event = (
            db.query(AuditLog)
            .filter_by(
                action="DOCUMENT_UPDATE",
                resource_id=str(document_id),
                outcome="DENIED",
            )
            .first()
        )
        assert event is not None
    finally:
        db.close()


def test_unauthenticated_user_cannot_access_private_document(
    setup_download_test,
):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    # No Authorization header is provided.
    endpoints = [
        ("GET", f"/documents/{document_id}"),
        ("GET", f"/documents/{document_id}/download"),
        ("PATCH", f"/documents/{document_id}"),
        ("DELETE", f"/documents/{document_id}"),
    ]

    for method, url in endpoints:
        response = client.request(
            method,
            url,
            json={
                "title": "Unauthorized change",
                "category": "Unauthorized",
            } if method == "PATCH" else None,
        )

        assert response.status_code == 401, (
            f"{method} {url} should require authentication, "
            f"but returned {response.status_code}"
        )

    # Confirm that the private document still exists and is unchanged.
    db = test["TestSession"]()
    try:
        document = db.get(Document, document_id)
        assert document is not None
        assert document.title == "Private Test Document"
        assert document.category == "Testing"
    finally:
        db.close()


def test_read_only_viewer_cannot_delete_document(setup_download_test):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    owner_headers = {
        "Authorization": f"Bearer {test['owner_token']}"
    }
    viewer_headers = {
        "Authorization": f"Bearer {test['viewer_token']}"
    }

    # Owner grants read-only access.
    grant_response = client.post(
        f"/documents/{document_id}/permissions",
        headers=owner_headers,
        json={
            "username": "download_viewer",
            "can_read": True,
            "can_edit": False,
        },
    )
    assert grant_response.status_code == 200

    # Read-only viewer attempts to delete the document.
    response = client.delete(
        f"/documents/{document_id}",
        headers=viewer_headers,
    )
    assert response.status_code == 404

    # Verify the document still exists.
    db = test["TestSession"]()
    try:
        document = db.get(Document, document_id)
        assert document is not None
        assert document.title == "Private Test Document"

        # Verify the denied deletion was audited.
        event = (
            db.query(AuditLog)
            .filter_by(
                action="DOCUMENT_DELETE",
                resource_id=str(document_id),
                outcome="DENIED",
            )
            .first()
        )
        assert event is not None
    finally:
        db.close()


def test_changing_document_id_does_not_bypass_authorization(
    setup_download_test,
):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    # The viewer has no permission for the owner's document.
    viewer_headers = {
        "Authorization": f"Bearer {test['viewer_token']}"
    }

    # Try to access the private document by its ID.
    response = client.get(
        f"/documents/{document_id}",
        headers=viewer_headers,
    )
    assert response.status_code == 404

    # Try downloading the same private document by its ID.
    download_response = client.get(
        f"/documents/{document_id}/download",
        headers=viewer_headers,
    )
    assert download_response.status_code == 404

    # Verify the original document remains unchanged.
    db = test["TestSession"]()
    try:
        document = db.get(Document, document_id)
        assert document is not None
        assert document.title == "Private Test Document"
    finally:
        db.close()


def test_viewer_cannot_grant_themselves_edit_permission(
    setup_download_test,
):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    viewer_headers = {
        "Authorization": f"Bearer {test['viewer_token']}"
    }

    # The viewer attempts to grant themselves edit permission.
    response = client.post(
        f"/documents/{document_id}/permissions",
        headers=viewer_headers,
        json={
            "username": "download_viewer",
            "can_read": True,
            "can_edit": True,
        },
    )

    # A non-owner must not be allowed to grant permissions.
    assert response.status_code == 404

    # Verify that no permission was created for the viewer.
    db = test["TestSession"]()
    try:
        from app.models import DocumentPermission

        permission = (
            db.query(DocumentPermission)
            .filter_by(
                document_id=document_id,
                user_id=None,
            )
            .first()
        )

        # Check using the actual viewer ID from the database.
        viewer = (
            db.query(User)
            .filter_by(username="download_viewer")
            .first()
        )
        assert viewer is not None

        permission = (
            db.query(DocumentPermission)
            .filter_by(
                document_id=document_id,
                user_id=viewer.id,
            )
            .first()
        )

        assert permission is None
    finally:
        db.close()


def test_editor_can_update_document_and_update_is_audited(
    setup_download_test,
):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    owner_headers = {
        "Authorization": f"Bearer {test['owner_token']}"
    }
    viewer_headers = {
        "Authorization": f"Bearer {test['viewer_token']}"
    }

    # The owner grants both read and edit permission.
    grant_response = client.post(
        f"/documents/{document_id}/permissions",
        headers=owner_headers,
        json={
            "username": "download_viewer",
            "can_read": True,
            "can_edit": True,
        },
    )
    assert grant_response.status_code == 200

    # The authorized editor updates the document.
    update_response = client.patch(
        f"/documents/{document_id}",
        headers=viewer_headers,
        json={
            "title": "Updated by Authorized Editor",
            "category": "Approved Testing",
        },
    )
    assert update_response.status_code == 200

    # Verify the update was saved and audited.
    db = test["TestSession"]()
    try:
        document = db.get(Document, document_id)
        assert document is not None
        assert document.title == "Updated by Authorized Editor"
        assert document.category == "Approved Testing"

        event = (
            db.query(AuditLog)
            .filter_by(
                action="DOCUMENT_UPDATE",
                resource_id=str(document_id),
                outcome="SUCCESS",
            )
            .first()
        )
        assert event is not None
    finally:
        db.close()


def test_revoked_edit_permission_blocks_updates_immediately(
    setup_download_test,
):
    test = setup_download_test
    client = test["client"]
    document_id = test["document_id"]

    owner_headers = {
        "Authorization": f"Bearer {test['owner_token']}"
    }
    viewer_headers = {
        "Authorization": f"Bearer {test['viewer_token']}"
    }

    # Owner grants edit permission.
    grant_response = client.post(
        f"/documents/{document_id}/permissions",
        headers=owner_headers,
        json={
            "username": "download_viewer",
            "can_read": True,
            "can_edit": True,
        },
    )
    assert grant_response.status_code == 200

    # Verify the viewer can edit before revocation.
    allowed_response = client.patch(
        f"/documents/{document_id}",
        headers=viewer_headers,
        json={
            "title": "Allowed Before Revocation",
            "category": "Testing",
        },
    )
    assert allowed_response.status_code == 200

    # Owner revokes the viewer's permission.
    revoke_response = client.delete(
        f"/documents/{document_id}/permissions/download_viewer",
        headers=owner_headers,
    )
    assert revoke_response.status_code == 200

    # The same viewer must now be denied.
    denied_response = client.patch(
        f"/documents/{document_id}",
        headers=viewer_headers,
        json={
            "title": "Unauthorized After Revocation",
            "category": "Unauthorized",
        },
    )
    assert denied_response.status_code == 404

    # Verify the unauthorized update did not change the document.
    db = test["TestSession"]()
    try:
        document = db.get(Document, document_id)
        assert document is not None
        assert document.title == "Allowed Before Revocation"
        assert document.category == "Testing"

        event = (
            db.query(AuditLog)
            .filter_by(
                action="DOCUMENT_UPDATE",
                resource_id=str(document_id),
                outcome="DENIED",
            )
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert event is not None
    finally:
        db.close()
