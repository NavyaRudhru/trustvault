
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import AuditLog, Document, DocumentPermission, User

router = APIRouter(prefix="/admin", tags=["Admin"])


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Allow these endpoints only to active admin accounts."""
    if not current_user.is_active or current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required.",
        )
    return current_user


@router.get("/audit")
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    action: str | None = None,
    outcome: str | None = None,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """List audit events for administrators, newest first."""
    query = select(AuditLog)

    if action and action.strip():
        query = query.where(AuditLog.action == action.strip())

    if outcome and outcome.strip():
        normalized_outcome = outcome.strip().upper()
        if normalized_outcome not in {"SUCCESS", "DENIED", "FAILURE"}:
            raise HTTPException(
                status_code=400,
                detail="Invalid outcome filter.",
            )
        query = query.where(AuditLog.outcome == normalized_outcome)

    total = db.scalar(
        select(func.count()).select_from(query.subquery())
    ) or 0

    entries = db.scalars(
        query.order_by(AuditLog.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": entry.id,
                "actor_id": entry.actor_id,
                "action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "outcome": entry.outcome,
                "details": entry.details,
                "ip_address": entry.ip_address,
                "created_at": entry.created_at,
            }
            for entry in entries
        ],
    }


@router.get("/permissions")
def list_document_permissions(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Review document access grants without exposing file contents."""
    base_query = (
        select(DocumentPermission, Document, User)
        .join(
            Document,
            DocumentPermission.document_id == Document.id,
        )
        .join(
            User,
            DocumentPermission.user_id == User.id,
        )
    )

    total = db.scalar(
        select(func.count()).select_from(
            base_query.with_only_columns(
                DocumentPermission.id
            ).subquery()
        )
    ) or 0

    rows = db.execute(
        base_query
        .order_by(DocumentPermission.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "permission_id": permission.id,
                "document_id": document.id,
                "document_title": document.title,
                "owner_id": document.owner_id,
                "username": user.username,
                "user_id": user.id,
                "can_read": permission.can_read,
                "can_edit": permission.can_edit,
                "granted_by_id": permission.granted_by_id,
                "created_at": permission.created_at,
            }
            for permission, document, user in rows
        ],
    }
