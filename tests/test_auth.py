
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
    from app.database import get_db
    from app.models import User
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app.database import Base

    # Create an isolated, in-memory database for this test.
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
    user = User(
        username="inactive_test_user",
        email="inactive_test_user@example.com",
        password_hash="not_used_in_this_test",
        role="viewer",
        is_active=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(user.id)
    db.close()

    def override_get_db():
        test_db = TestSession()
        try:
            yield test_db
        finally:
            test_db.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            response = client.get(
                "/me",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert response.status_code == 401
    finally:
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_me_returns_authenticated_users_details(monkeypatch):
    from fastapi.testclient import TestClient
    from app.auth import create_access_token
    from app.database import get_db, Base
    from app.models import User
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

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
    user = User(
        username="me_endpoint_test_user",
        email="me_endpoint_test_user@example.com",
        password_hash="not_used_in_this_test",
        role="viewer",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    user_id = user.id
    token = create_access_token(user_id)
    expected_username = user.username
    expected_email = user.email
    db.close()

    def override_get_db():
        test_db = TestSession()
        try:
            yield test_db
        finally:
            test_db.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            response = client.get(
                "/me",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 200
        assert response.json()["id"] == user_id
        assert response.json()["username"] == expected_username
        assert response.json()["email"] == expected_email
        assert response.json()["role"] == "viewer"
    finally:
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

