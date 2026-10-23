
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.documents import router as documents_router
from app.auth import create_access_token, get_current_user
from app.permissions import router as permissions_router
from app.database import Base, engine, get_db
from app.models import User
from app.schemas import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.security import hash_password, verify_password
from app.audit import verify_audit_chain
from app.audit_checkpoint import load_checkpoint, verify_full_chain_against_checkpoint

app = FastAPI(
    title="TrustVault API",
    description="Secure document-sharing application",
    version="0.3.0",
)

app.include_router(documents_router)
app.include_router(permissions_router)

# Temporary development convenience.
# Production deployments should use managed migrations instead.
Base.metadata.create_all(bind=engine)


@app.get("/")
def home():
    return {"application": "TrustVault", "status": "running"}


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "TrustVault"}


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
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
    # First verify the complete audit hash chain.
    is_valid, _message = verify_audit_chain(db)

    if not is_valid:
        return {
            "valid": False,
            "message": "Audit chain verification failed.",
        }

    # A valid chain alone does not prove it matches a signed checkpoint.
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
            "message": "Audit history does not match the signed checkpoint.",
        }

    return {
        "valid": True,
        "message": "Audit chain and signed checkpoint verified successfully.",
    }

@app.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    username = data.username.strip()
    email = data.email.strip().lower()

    existing_user = db.scalar(
        select(User).where(
            (User.username == username) | (User.email == email)
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
        )

    return user


@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(
        select(User).where(User.username == data.username.strip())
    )

    if (
        user is None
        or not user.is_active
        or not verify_password(data.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenResponse(access_token=create_access_token(user.id))


@app.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
