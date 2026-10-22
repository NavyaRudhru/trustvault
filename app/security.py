
from argon2 import PasswordHasher
from argon2.exceptions import (
    HashingError,
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    if not password or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError,
        HashingError,
    ):
        return False
