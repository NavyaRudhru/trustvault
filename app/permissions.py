
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.auth import get_current_user
from app.database import get_db
from app.models import Document, DocumentPermission, User


router = APIRouter()


class PermissionRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    can_read: bool = False
    can_edit: bool = False


def require_roles(*allowed_roles):
    """Create a dependency that checks a user's role."""

    def role_checker(
        current_user: User = Depends(get_current_user),
    ):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )

        return current_user

    return role_checker


def can_read_document(
    document: Document,
    user: User,
    db: Session,
) -> bool:
    """Check whether a user can read a document."""

    if document.owner_id == user.id:
        return True

    permission = (
        db.query(DocumentPermission)
        .filter_by(
            document_id=document.id,
            user_id=user.id,
        )
        .first()
    )

    return bool(
        permission
        and (permission.can_read or permission.can_edit)
    )


def can_edit_document(
    document: Document,
    user: User,
    db: Session,
) -> bool:
    """Check whether a user can edit a document."""

    if document.owner_id == user.id:
        return True

    permission = (
        db.query(DocumentPermission)
        .filter_by(
            document_id=document.id,
            user_id=user.id,
        )
        .first()
    )

    return bool(permission and permission.can_edit)


def _audit_denial(
    db: Session,
    *,
    action: str,
    document_id: int,
    actor_id: int,
    details: str,
) -> None:
    """
    Record a denied operation before returning an error.

    If the audit cannot be persisted, fail closed.
    """

    try:
        record_audit_event(
            db=db,
            action=action,
            resource_type="document",
            resource_id=str(document_id),
            actor_id=actor_id,
            outcome="DENIED",
            details=details,
        )
        db.commit()

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Denied action could not be audited.",
        ) from None


def require_document_read(
    document_id: int,
    user: User,
    db: Session,
    audit_action: str = "DOCUMENT_READ",
) -> Document:
    """Return a document only when the user has read permission."""

    document = (
        db.query(Document)
        .filter(Document.id == document_id)
        .first()
    )

    if document is None or not can_read_document(document, user, db):
        _audit_denial(
            db,
            action=audit_action,
            document_id=document_id,
            actor_id=user.id,
            details="document_missing_or_read_access_denied",
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found.",
        )

    return document


def require_document_edit(
    document_id: int,
    user: User,
    db: Session,
) -> Document:
    """Return a document only when the user has edit permission."""

    document = (
        db.query(Document)
        .filter(Document.id == document_id)
        .first()
    )

    if document is None or not can_edit_document(document, user, db):
        _audit_denial(
            db,
            action="DOCUMENT_UPDATE",
            document_id=document_id,
            actor_id=user.id,
            details="document_missing_or_edit_access_denied",
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found.",
        )

    return document


@router.post("/documents/{document_id}/permissions")
def grant_permission(
    document_id: int,
    data: PermissionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Allow a document owner to grant read or edit access."""

    document = (
        db.query(Document)
        .filter(Document.id == document_id)
        .first()
    )

    if document is None or document.owner_id != current_user.id:
        _audit_denial(
            db,
            action="PERMISSION_GRANT",
            document_id=document_id,
            actor_id=current_user.id,
            details="document_missing_or_grant_attempt_by_non_owner",
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found.",
        )

    username = data.username.strip()

    target = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if target is None or not target.is_active:
        _audit_denial(
            db,
            action="PERMISSION_GRANT",
            document_id=document_id,
            actor_id=current_user.id,
            details="grant_target_missing_or_inactive",
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found.",
        )

    if target.id == current_user.id:
        _audit_denial(
            db,
            action="PERMISSION_GRANT",
            document_id=document_id,
            actor_id=current_user.id,
            details="owner_attempted_self_grant",
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You already own this document.",
        )

    if not data.can_read and not data.can_edit:
        _audit_denial(
            db,
            action="PERMISSION_GRANT",
            document_id=document_id,
            actor_id=current_user.id,
            details="empty_permission_grant",
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Grant read or edit permission.",
        )

    permission = (
        db.query(DocumentPermission)
        .filter_by(
            document_id=document_id,
            user_id=target.id,
        )
        .first()
    )

    try:
        if permission is None:
            permission = DocumentPermission(
                document_id=document_id,
                user_id=target.id,
                can_read=data.can_read or data.can_edit,
                can_edit=data.can_edit,
                granted_by_id=current_user.id,
            )
            db.add(permission)
        else:
            permission.can_read = data.can_read or data.can_edit
            permission.can_edit = data.can_edit
            permission.granted_by_id = current_user.id

        record_audit_event(
            db=db,
            action="PERMISSION_GRANT",
            resource_type="document",
            resource_id=str(document_id),
            actor_id=current_user.id,
            outcome="SUCCESS",
            details=(
                f"permissions_granted_to={target.username};"
                f"can_read={data.can_read or data.can_edit};"
                f"can_edit={data.can_edit}"
            ),
        )

        db.commit()

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Permission grant could not be completed.",
        ) from None

    return {
        "message": "Permission granted.",
        "document_id": document_id,
        "username": target.username,
        "can_read": data.can_read or data.can_edit,
        "can_edit": data.can_edit,
    }


@router.delete("/documents/{document_id}/permissions/{username}")
def revoke_permission(
    document_id: int,
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Allow only the document owner to revoke a user's access."""

    document = (
        db.query(Document)
        .filter(Document.id == document_id)
        .first()
    )

    if document is None or document.owner_id != current_user.id:
        _audit_denial(
            db,
            action="PERMISSION_REVOKE",
            document_id=document_id,
            actor_id=current_user.id,
            details="document_missing_or_revoke_attempt_by_non_owner",
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found.",
        )

    target = (
        db.query(User)
        .filter(User.username == username.strip())
        .first()
    )

    if target is None:
        _audit_denial(
            db,
            action="PERMISSION_REVOKE",
            document_id=document_id,
            actor_id=current_user.id,
            details="revoke_target_missing",
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    permission = (
        db.query(DocumentPermission)
        .filter_by(
            document_id=document_id,
            user_id=target.id,
        )
        .first()
    )

    if permission is None:
        _audit_denial(
            db,
            action="PERMISSION_REVOKE",
            document_id=document_id,
            actor_id=current_user.id,
            details="permission_does_not_exist",
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found.",
        )

    try:
        record_audit_event(
            db=db,
            action="PERMISSION_REVOKE",
            resource_type="document",
            resource_id=str(document_id),
            actor_id=current_user.id,
            outcome="SUCCESS",
            details=f"permissions_revoked_from={target.username}",
        )

        db.delete(permission)
        db.commit()

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Permission revocation could not be completed.",
        ) from None

    return {
        "message": "Permission revoked.",
        "document_id": document_id,
        "username": target.username,
    }
