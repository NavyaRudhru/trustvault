
import pytest

from app.audit_checkpoint import (
    sign_checkpoint,
    verify_checkpoint_signature,
    create_checkpoint,
    verify_checkpoint,
)


def test_checkpoint_signature_is_valid(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )
    checkpoint = "audit_id=10;entry_hash=abc123"
    signature = sign_checkpoint(checkpoint)

    assert verify_checkpoint_signature(checkpoint, signature) is True


def test_modified_checkpoint_signature_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )
    checkpoint = "audit_id=10;entry_hash=abc123"
    signature = sign_checkpoint(checkpoint)

    assert verify_checkpoint_signature(
        "audit_id=10;entry_hash=changed",
        signature,
    ) is False


def test_modified_signature_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )
    checkpoint = "audit_id=10;entry_hash=abc123"

    assert verify_checkpoint_signature(
        checkpoint, "invalid-signature"
    ) is False


def test_missing_secret_is_rejected(monkeypatch):
    monkeypatch.delenv("AUDIT_CHECKPOINT_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="AUDIT_CHECKPOINT_SECRET"):
        sign_checkpoint("audit_id=10;entry_hash=abc123")


def test_short_secret_is_rejected(monkeypatch):
    monkeypatch.setenv("AUDIT_CHECKPOINT_SECRET", "too-short")

    with pytest.raises(RuntimeError, match="at least 32 characters"):
        sign_checkpoint("audit_id=10;entry_hash=abc123")


def test_created_checkpoint_is_valid(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )
    checkpoint = create_checkpoint(audit_id=10, entry_hash="abc123")

    assert checkpoint["audit_id"] == 10
    assert checkpoint["entry_hash"] == "abc123"
    assert verify_checkpoint(checkpoint) is True


def test_modified_checkpoint_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "AUDIT_CHECKPOINT_SECRET",
        "test-secret-key-with-at-least-32-characters",
    )
    checkpoint = create_checkpoint(audit_id=10, entry_hash="abc123")
    checkpoint["entry_hash"] = "tampered_hash"

    assert verify_checkpoint(checkpoint) is False
