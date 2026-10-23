
import os
import hmac
import hashlib
import json
from pathlib import Path

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


def save_checkpoint(checkpoint: dict, directory: str | None = None) -> Path:
    """Save a signed checkpoint as a JSON file."""
    from datetime import datetime, timezone

    if not verify_checkpoint(checkpoint):
        raise ValueError("Cannot save an invalid checkpoint.")

    checkpoint_dir = (
        Path(directory)
        if directory is not None
        else Path(__file__).resolve().parent.parent / "audit_checkpoints"
    )
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    checkpoint_path = checkpoint_dir / "latest.json"
    temporary_path = checkpoint_dir / "latest.tmp"

    payload = {
        **checkpoint,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }

    temporary_path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )
    temporary_path.replace(checkpoint_path)

    return checkpoint_path


def load_checkpoint(directory: str | None = None) -> dict | None:
    """Load and verify the saved checkpoint."""
    checkpoint_dir = (
        Path(directory)
        if directory is not None
        else Path(__file__).resolve().parent.parent / "audit_checkpoints"
    )
    checkpoint_path = checkpoint_dir / "latest.json"

    if not checkpoint_path.is_file():
        return None

    try:
        checkpoint = json.loads(
            checkpoint_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return None

    if not verify_checkpoint(checkpoint):
        return None

    return checkpoint


def verify_checkpoint_against_audit_log(checkpoint: dict, db) -> bool:
    """Verify a signed checkpoint matches its referenced audit entry."""
    from app.models import AuditLog

    if not verify_checkpoint(checkpoint):
        return False

    audit_id = checkpoint.get("audit_id")
    entry_hash = checkpoint.get("entry_hash")

    if not isinstance(audit_id, int) or isinstance(audit_id, bool):
        return False

    if not isinstance(entry_hash, str):
        return False

    entry = db.get(AuditLog, audit_id)

    if entry is None:
        return False

    return entry.entry_hash == entry_hash


def verify_full_chain_against_checkpoint(checkpoint: dict, db) -> bool:
    """Verify the audit chain and ensure it reaches the signed checkpoint."""
    from sqlalchemy import select

    from app.audit import verify_audit_chain
    from app.models import AuditLog

    if not verify_checkpoint(checkpoint):
        return False

    audit_id = checkpoint.get("audit_id")
    entry_hash = checkpoint.get("entry_hash")

    if not isinstance(audit_id, int) or isinstance(audit_id, bool):
        return False

    if not isinstance(entry_hash, str):
        return False

    is_valid, _message = verify_audit_chain(db)
    if not is_valid:
        return False

    entries = db.scalars(
        select(AuditLog).order_by(AuditLog.id.asc())
    ).all()

    checkpoint_entry = next(
        (entry for entry in entries if entry.id == audit_id),
        None,
    )

    if checkpoint_entry is None:
        return False

    if checkpoint_entry.entry_hash != entry_hash:
        return False

    # The checkpoint must describe the latest audit entry.
    if not entries or entries[-1].id != audit_id:
        return False

    return True
