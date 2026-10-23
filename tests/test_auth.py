
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import create_access_token
from app.database import Base, get_db
from app.main import app
from app.models import User
from app.rate_limit import reset_rate_limits
from app.security import hash_password
from app.audit import verify_audit_chain
from app.models import AuditLog

def create_test_database():
    """Create an isolated in-memory database for a test."""
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

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    return engine, TestSession, override_get_db


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
    import app.auth as auth

    monkeypatch.setattr(auth, "TOKEN_MAX_AGE_SECONDS", -1)
    token = create_access_token(user_id=1)

    with TestClient(app) as client:
        response = client.get(
            "/me",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 401


def test_inactive_user_is_rejected():
    engine, TestSession, override_get_db = create_test_database()
    app.dependency_overrides[get_db] = override_get_db

    try:
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


def test_me_returns_authenticated_users_details():
    engine, TestSession, override_get_db = create_test_database()
    app.dependency_overrides[get_db] = override_get_db

    try:
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


def test_login_rate_limit_blocks_after_five_failed_attempts():
    reset_rate_limits()
    engine, TestSession, override_get_db = create_test_database()
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            for _ in range(5):
                response = client.post(
                    "/auth/login",
                    json={
                        "username": "missing_rate_limit_user",
                        "password": "WrongPassword123!",
                    },
                )
                assert response.status_code == 401

            response = client.post(
                "/auth/login",
                json={
                    "username": "missing_rate_limit_user",
                    "password": "WrongPassword123!",
                },
            )

            assert response.status_code == 429
            assert response.headers["retry-after"] == "900"

    finally:
        reset_rate_limits()
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_successful_login_clears_failed_attempts():
    reset_rate_limits()
    engine, TestSession, override_get_db = create_test_database()
    app.dependency_overrides[get_db] = override_get_db

    try:
        db = TestSession()
        user = User(
            username="rate_limit_test_user",
            email="rate_limit_test_user@example.com",
            password_hash=hash_password("StrongPassword123!"),
            role="viewer",
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.close()

        with TestClient(app) as client:
            # Four failed attempts should not trigger the limit.
            for _ in range(4):
                response = client.post(
                    "/auth/login",
                    json={
                        "username": "rate_limit_test_user",
                        "password": "WrongPassword123!",
                    },
                )
                assert response.status_code == 401

            # A successful login should clear the failure counter.
            response = client.post(
                "/auth/login",
                json={
                    "username": "rate_limit_test_user",
                    "password": "StrongPassword123!",
                },
            )

            assert response.status_code == 200
            assert response.json()["access_token"]

            # Five new failures should be allowed before blocking.
            for _ in range(5):
                response = client.post(
                    "/auth/login",
                    json={
                        "username": "rate_limit_test_user",
                        "password": "WrongPassword123!",
                    },
                )
                assert response.status_code == 401

            # The next attempt should be blocked.
            response = client.post(
                "/auth/login",
                json={
                    "username": "rate_limit_test_user",
                    "password": "WrongPassword123!",
                },
            )

            assert response.status_code == 429
            assert response.headers["retry-after"] == "900"

    finally:
        reset_rate_limits()
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_successful_login_is_audited():
    reset_rate_limits()
    engine, TestSession, override_get_db = create_test_database()
    app.dependency_overrides[get_db] = override_get_db

    try:
        db = TestSession()
        user = User(
            username="audit_login_user",
            email="audit_login_user@example.com",
            password_hash=hash_password("StrongPassword123!"),
            role="viewer",
            is_active=True,
        )
        db.add(user)
        db.commit()
        user_id = user.id
        db.close()

        with TestClient(app) as client:
            response = client.post(
                "/auth/login",
                json={
                    "username": "audit_login_user",
                    "password": "StrongPassword123!",
                },
            )

        assert response.status_code == 200

        db = TestSession()
        try:
            events = (
                db.query(AuditLog)
                .filter_by(action="login", actor_id=user_id)
                .all()
            )
            assert len(events) == 1
            assert events[0].outcome == "SUCCESS"
            assert events[0].resource_type == "authentication"
        finally:
            db.close()

    finally:
        reset_rate_limits()
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_failed_login_is_audited():
    reset_rate_limits()
    engine, TestSession, override_get_db = create_test_database()
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            response = client.post(
                "/auth/login",
                json={
                    "username": "unknown_audit_user",
                    "password": "WrongPassword123!",
                },
            )

        assert response.status_code == 401

        db = TestSession()
        try:
            events = (
                db.query(AuditLog)
                .filter_by(action="login", resource_type="authentication")
                .all()
            )
            assert len(events) == 1
            assert events[0].outcome == "DENIED"
            assert events[0].actor_id is None
            assert events[0].details == (
                "invalid_credentials_or_inactive_account"
            )
        finally:
            db.close()

    finally:
        reset_rate_limits()
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_existing_token_is_rejected_after_user_is_deactivated():
    engine, TestSession, override_get_db = create_test_database()
    app.dependency_overrides[get_db] = override_get_db

    try:
        db = TestSession()
        user = User(
            username="deactivation_test_user",
            email="deactivation_test_user@example.com",
            password_hash="not_used_in_this_test",
            role="viewer",
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token(user.id)

        # Deactivate the account after the token has been created.
        user.is_active = False
        db.commit()
        db.close()

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
