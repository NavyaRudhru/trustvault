
from fastapi.testclient import TestClient

from app.main import app


def test_missing_token_is_rejected():
    with TestClient(app) as client:
        response = client.get("/me")

    assert response.status_code == 401


def test_invalid_token_is_rejected():
    with TestClient(app) as client:
        response = client.get(
            "/me",
            headers={"Authorization": "Bearer invalid-token"},
        )

    assert response.status_code == 401


def test_malformed_bearer_header_is_rejected():
    with TestClient(app) as client:
        response = client.get(
            "/me",
            headers={"Authorization": "Bearer"},
        )

    assert response.status_code in (401, 403)


def test_expired_token_is_rejected(monkeypatch):
    from fastapi.testclient import TestClient
    from app.auth import create_access_token
    import app.auth as auth

    # Make tokens expire immediately for this test.
    monkeypatch.setattr(auth, "TOKEN_MAX_AGE_SECONDS", -1)

    token = create_access_token(user_id=1)

    with TestClient(app) as client:
        response = client.get(
            "/me",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 401


def test_inactive_user_is_rejected(monkeypatch):
    from fastapi.testclient import TestClient
    from app.auth import create_access_token
    from app.database import get_db, SessionLocal
    from app.models import User

    db = SessionLocal()
    user = User(
        username="inactive_test_user_2",
        email="inactive_test_user_2@example.com",
        password_hash="not_used_in_this_test",
        role="viewer",
        is_active=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id)
    db.close()

    with TestClient(app) as client:
        response = client.get(
            "/me",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 401
