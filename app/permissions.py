
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.auth import get_current_user
from app.database import get_db
from app.models import Document, DocumentPermission, User


router = APIRouter(
    prefix="/documents",
    tags=["Document Permissions"],
)


class PermissionRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    can_read: bool = False
    can_edit: bool = False


def require_roles(*allowed_roles: str):
    def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to perform this action.",
            )
        return current_user

    return role_checker


def can_read_document(
    document: Document,
    user: User,
    db: Session,
) -> bool:
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


def require_document_read(
    document_id: int,
    user: User,
    db: Session,
) -> Document:
    document = db.get(Document, document_id)

    if document is None or not can_read_document(
        document, user, db
    ):
        raise HTTPException(
            status_code=404,
            detail="Document not found.",
        )

    return document



def require_document_edit(
    document_id: int,
    user: User,
    db: Session,
) -> Document:
    document = db.get(Document, document_id)

    if document is None:
        raise HTTPException(
            status_code=404,
            detail="Document not found.",
        )

    if not can_edit_document(document, user, db):
        record_audit_event(
            db=db,
            actor_id=user.id,
            action="DOCUMENT_UPDATE",
            resource_type="DOCUMENT",
            resource_id=str(document_id),
            outcome="DENIED",
            details="Unauthorized document edit attempt.",
        )
        db.commit()

        raise HTTPException(
            status_code=404,
            detail="Document not found.",
        )

    return document

@router.post("/{document_id}/permissions")
def grant_document_permission(
    document_id: int,
    data: PermissionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)

    # Only the document owner can grant permissions.
    if document is None or document.owner_id != current_user.id:
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="PERMISSION_GRANT",
            resource_type="document",
            resource_id=str(document_id),
            outcome="DENIED",
            details=(
                "Attempted to grant permissions without "
                "document ownership."
            ),
        )
        db.commit()

        raise HTTPException(
            status_code=404,
            detail="Document not found.",
        )

    target_user = (
        db.query(User)
        .filter(User.username == data.username.strip())
        .first()
    )

    if target_user is None or not target_user.is_active:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="You already own this document.",
        )

    if not data.can_read and not data.can_edit:
        raise HTTPException(
            status_code=400,
            detail="Grant read or edit permission.",
        )

    permission = (
        db.query(DocumentPermission)
        .filter_by(
            document_id=document_id,
            user_id=target_user.id,
        )
        .first()
    )

    if permission is None:
        permission = DocumentPermission(
            document_id=document_id,
            user_id=target_user.id,
            granted_by_id=current_user.id,
        )
        db.add(permission)

    # Edit permission also allows reading.
    permission.can_edit = data.can_edit
    permission.can_read = data.can_read or data.can_edit

    record_audit_event(
        db=db,
        actor_id=current_user.id,
        action="PERMISSION_GRANT",
        resource_type="document",
        resource_id=str(document_id),
        outcome="SUCCESS",
        details=(
            f"Granted permissions to username={target_user.username}; "
            f"can_read={permission.can_read}; "
            f"can_edit={permission.can_edit}"
        ),
    )

    db.commit()
    db.refresh(permission)

    return {
        "message": "Document permissions updated successfully.",
        "document_id": document_id,
        "username": target_user.username,
        "can_read": permission.can_read,
        "can_edit": permission.can_edit,
    }


@router.delete("/{document_id}/permissions/{username}")
def revoke_document_permission(
    document_id: int,
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)

    # Only the document owner can revoke permissions.
    if document is None or document.owner_id != current_user.id:
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="PERMISSION_REVOKE",
            resource_type="document",
            resource_id=str(document_id),
            outcome="DENIED",
            details=(
                "Attempted to revoke permissions without "
                "document ownership."
            ),
        )
        db.commit()

        raise HTTPException(
            status_code=404,
            detail="Document not found.",
        )

    target_user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if target_user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    permission = (
        db.query(DocumentPermission)
        .filter_by(
            document_id=document_id,
            user_id=target_user.id,
        )
        .first()
    )

    if permission is None:
        raise HTTPException(
            status_code=404,
            detail="Permission not found.",
        )

    record_audit_event(
        db=db,
        actor_id=current_user.id,
        action="PERMISSION_REVOKE",
        resource_type="document",
        resource_id=str(document_id),
        outcome="SUCCESS",
        details=(
            f"Revoked permissions for username={target_user.username}"
        ),
    )

    db.delete(permission)
    db.commit()

    return {
        "message": "Document access revoked successfully.",
        "document_id": document_id,
        "username": target_user.username,
    }
