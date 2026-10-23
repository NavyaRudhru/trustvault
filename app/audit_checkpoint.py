
import os
import hmac
import hashlib


def get_checkpoint_secret() -> bytes:
    """Load the secret used to authenticate audit checkpoints."""
    secret = os.getenv("AUDIT_CHECKPOINT_SECRET")

    if not secret or len(secret) < 32:
        raise RuntimeError(
            "AUDIT_CHECKPOINT_SECRET must be set "
            "and contain at least 32 characters."
        )

    return secret.encode("utf-8")


def sign_checkpoint(checkpoint_data: str) -> str:
    """Create an HMAC-SHA256 signature for checkpoint data."""
    secret = get_checkpoint_secret()

    return hmac.new(
        secret,
        checkpoint_data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_checkpoint_signature(
    checkpoint_data: str,
    signature: str,
) -> bool:
    """Verify a checkpoint signature without timing-sensitive comparison."""
    expected_signature = sign_checkpoint(checkpoint_data)

    return hmac.compare_digest(expected_signature, signature)


import json

def create_checkpoint(audit_id: int, entry_hash: str) -> dict:
    """Create a signed checkpoint for an audit-chain position."""
    checkpoint_data = json.dumps(
        {
            "audit_id": audit_id,
            "entry_hash": entry_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    return {
        "audit_id": audit_id,
        "entry_hash": entry_hash,
        "signature": sign_checkpoint(checkpoint_data),
    }


def verify_checkpoint(checkpoint: dict) -> bool:
    """Verify the integrity and signature of a checkpoint."""
    try:
        checkpoint_data = json.dumps(
            {
                "audit_id": checkpoint["audit_id"],
                "entry_hash": checkpoint["entry_hash"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        return verify_checkpoint_signature(
            checkpoint_data,
            checkpoint["signature"],
        )
    except (KeyError, TypeError, ValueError):
        return False
