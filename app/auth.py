
import os

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User


APP_ENV = os.getenv("APP_ENV", "development")
SECRET_KEY = os.getenv("SESSION_SECRET")

if not SECRET_KEY and APP_ENV.lower() == "production":
    raise RuntimeError("SESSION_SECRET must be configured in production.")

if not SECRET_KEY:
    SECRET_KEY = "local-development-only-change-before-deployment"

serializer = URLSafeTimedSerializer(
    SECRET_KEY,
    salt="trustvault-auth-v1",
)

bearer_scheme = HTTPBearer(auto_error=False)
TOKEN_MAX_AGE_SECONDS = 1800  # 30 minutes


def create_access_token(user_id: int) -> str:
    return serializer.dumps({"user_id": user_id})


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = serializer.loads(
            credentials.credentials,
            max_age=TOKEN_MAX_AGE_SECONDS,
        )
        user_id = payload.get("user_id")

        if not isinstance(user_id, int) or isinstance(user_id, bool):
            raise HTTPException(status_code=401, detail="Invalid authentication token.")

    except (BadSignature, SignatureExpired):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(User, user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="Invalid or inactive account.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Always load the user's current role from the database.
    return user
