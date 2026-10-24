from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import Depends, FastAPI, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.access_requests import router as access_requests_router
from app.admin import router as admin_router
from app.audit import record_audit_event, verify_audit_chain
from app.audit_checkpoint import (
    load_checkpoint,
    verify_full_chain_against_checkpoint,
)
from app.auth import create_access_token, get_current_user
from app.database import Base, engine, get_db
from app.documents import router as documents_router
from app.models import User
from app.permissions import router as permissions_router
from app.rate_limit import (
    clear_failed_logins,
    is_login_rate_limited,
    record_failed_login,
)
from app.schemas import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.security import hash_password, verify_password


app = FastAPI(
    title="TrustVault API",
    description="Secure document-sharing application",
    version="0.4.0",
)

app.include_router(documents_router)
app.include_router(permissions_router)
app.include_router(admin_router)
app.include_router(access_requests_router)
# Development convenience only.
# Use database migrations in production.
Base.metadata.create_all(bind=engine)


app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).resolve().parent / "static"),
    name="static",
)


@app.get("/")
def home():
    frontend_file = Path(__file__).resolve().parent / "static" / "index.html"
    return FileResponse(frontend_file, media_type="text/html")


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "TrustVault",
    }


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Allow access only to users with the administrator role."""

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required.",
        )

    return current_user


@app.get("/admin/audit/verify")
def verify_audit_log(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Verify the audit hash chain and its signed checkpoint."""

    try:
        is_valid, _message = verify_audit_chain(db)

        if not is_valid:
            return {
                "valid": False,
                "message": "Audit chain verification failed.",
            }

        checkpoint = load_checkpoint()

        if checkpoint is None:
            return {
                "valid": False,
                "message": "Missing or invalid signed audit checkpoint.",
            }

        checkpoint_valid = verify_full_chain_against_checkpoint(
            checkpoint,
            db,
        )

        if not checkpoint_valid:
            return {
                "valid": False,
                "message": (
                    "Audit history does not match the signed checkpoint."
                ),
            }

        return {
            "valid": True,
            "message": (
                "Audit chain and signed checkpoint verified successfully."
            ),
        }

    except Exception:
        return {
            "valid": False,
            "message": "Audit verification could not be completed.",
        }


@app.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
):
    """Public registration always creates a viewer account."""

    username = data.username.strip()
    email = data.email.strip().lower()

    if not username or not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and email cannot be empty.",
        )

    existing_user = db.scalar(
        select(User).where(
            (User.username == username)
            | (User.email == email)
        )
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        )

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(data.password),
        role="viewer",
        is_active=True,
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        ) from None

    return user


def record_login_audit_or_fail(
    db: Session,
    *,
    actor_id: int | None,
    outcome: str,
    details: str,
    client_ip: str,
) -> None:
    """Persist login audit events before returning an authentication result."""

    try:
        record_audit_event(
            db=db,
            action="login",
            resource_type="authentication",
            outcome=outcome,
            actor_id=actor_id,
            details=details,
            ip_address=client_ip,
        )

        db.commit()

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication event could not be audited.",
        ) from None


@app.post("/auth/login", response_model=TokenResponse)
def login(
    data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Authenticate a user and audit successful and denied attempts."""

    username = data.username.strip()
    client_ip = request.client.host if request.client else "unknown"

    if is_login_rate_limited(client_ip, username):
        record_login_audit_or_fail(
            db,
            actor_id=None,
            outcome="DENIED",
            details="rate_limit_exceeded",
            client_ip=client_ip,
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": "900"},
        )

    user = db.scalar(
        select(User).where(User.username == username)
    )

    if (
        user is None
        or not user.is_active
        or not verify_password(data.password, user.password_hash)
    ):
        record_failed_login(client_ip, username)

        record_login_audit_or_fail(
            db,
            actor_id=user.id if user is not None else None,
            outcome="DENIED",
            details="invalid_credentials_or_inactive_account",
            client_ip=client_ip,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    record_login_audit_or_fail(
        db,
        actor_id=user.id,
        outcome="SUCCESS",
        details="login_successful",
        client_ip=client_ip,
    )

    clear_failed_logins(client_ip, username)

    return TokenResponse(
        access_token=create_access_token(user.id)
    )


@app.get("/me", response_model=UserResponse)
def get_me(
    current_user: User = Depends(get_current_user),
):
    """Return the currently authenticated user's public profile."""

    return current_user
