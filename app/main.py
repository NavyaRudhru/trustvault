
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

app = FastAPI(
    title="TrustVault API",
    description="Secure document-sharing application",
    version="0.2.0",
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
