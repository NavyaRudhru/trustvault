
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.auth import get_current_user
from app.database import get_db
from app.models import (
    Document,
    DocumentAccessRequest,
    DocumentPermission,
    User,
)

router = APIRouter(prefix="/access-requests", tags=["Access Requests"])


class CreateAccessRequest(BaseModel):
    document_id: int = Field(gt=0)
    requested_access: str
    reason: str = Field(default="", max_length=500)


def audit(
    db: Session,
    user_id: int,
    action: str,
    request_id: int | None,
    outcome: str,
    details: str,
) -> None:
    record_audit_event(
        db=db,
        actor_id=user_id,
        action=action,
        resource_type="document_access_request",
        resource_id=str(request_id) if request_id is not None else None,
        outcome=outcome,
        details=details,
    )


def request_dict(item: DocumentAccessRequest, db: Session) -> dict:
    document = db.get(Document, item.document_id)
    requester = db.get(User, item.requester_id)
    owner = db.get(User, document.owner_id) if document else None
    reviewer = db.get(User, item.reviewed_by_id) if item.reviewed_by_id else None

    return {
        "id": item.id,
        "document_id": item.document_id,
        "document_title": document.title if document else "[Deleted document]",
        "owner_id": document.owner_id if document else None,
        "owner_username": owner.username if owner else None,
        "requester_id": item.requester_id,
        "requester_username": requester.username if requester else None,
        "requested_access": item.requested_access,
        "reason": item.reason,
        "status": item.status,
        "reviewed_by": reviewer.username if reviewer else None,
        "reviewed_at": item.reviewed_at,
        "created_at": item.created_at,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_access_request(
    data: CreateAccessRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    access = data.requested_access.strip().lower()

    if access not in {"read", "edit"}:
        raise HTTPException(400, "requested_access must be 'read' or 'edit'.")

    document = db.get(Document, data.document_id)

    if document is None:
        audit(
            db, current_user.id, "ACCESS_REQUEST_CREATE",
            None, "DENIED", "Requested document does not exist."
        )
        db.commit()
        raise HTTPException(404, "Document not found.")

    if document.owner_id == current_user.id:
        raise HTTPException(400, "You already own this document.")

    existing_permission = (
        db.query(DocumentPermission)
        .filter_by(
            document_id=document.id,
            user_id=current_user.id,
        )
        .first()
    )

    if existing_permission and (
        existing_permission.can_edit
        or (access == "read" and existing_permission.can_read)
    ):
        raise HTTPException(409, "You already have this access.")

    pending = (
        db.query(DocumentAccessRequest)
        .filter_by(
            document_id=document.id,
            requester_id=current_user.id,
            status="pending",
        )
        .first()
    )

    if pending:
        raise HTTPException(409, "You already have a pending request for this document.")

    item = DocumentAccessRequest(
        document_id=document.id,
        requester_id=current_user.id,
        requested_access=access,
        reason=data.reason.strip(),
        status="pending",
    )

    try:
        db.add(item)
        db.flush()

        audit(
            db, current_user.id, "ACCESS_REQUEST_CREATE",
            item.id, "SUCCESS",
            f"document_id={document.id}; requested_access={access}",
        )
        db.commit()
        db.refresh(item)
        return request_dict(item, db)

    except Exception:
        db.rollback()
        raise HTTPException(500, "Access request could not be saved.") from None


@router.get("/mine")
def my_access_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    items = (
        db.query(DocumentAccessRequest)
        .filter_by(requester_id=current_user.id)
        .order_by(DocumentAccessRequest.created_at.desc())
        .all()
    )
    return {"items": [request_dict(x, db) for x in items]}


@router.get("/received")
def received_access_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Only requests for documents owned by the current user are returned.
    items = (
        db.query(DocumentAccessRequest)
        .join(Document, Document.id == DocumentAccessRequest.document_id)
        .filter(
            Document.owner_id == current_user.id,
            DocumentAccessRequest.status == "pending",
        )
        .order_by(DocumentAccessRequest.created_at.asc())
        .all()
    )
    return {"items": [request_dict(x, db) for x in items]}


def review_request(
    request_id: int,
    decision: str,
    current_user: User,
    db: Session,
):
    item = db.get(DocumentAccessRequest, request_id)

    if item is None:
        raise HTTPException(404, "Access request not found.")

    document = db.get(Document, item.document_id)

    if document is None or document.owner_id != current_user.id:
        try:
            audit(
                db, current_user.id, f"ACCESS_REQUEST_{decision.upper()}",
                request_id, "DENIED",
                "Only the document owner may review this request.",
            )
            db.commit()
        except Exception:
            db.rollback()
            raise HTTPException(500, "Denied action could not be audited.") from None

        raise HTTPException(404, "Access request not found.")

    if item.status != "pending":
        raise HTTPException(409, "This request has already been reviewed.")

    try:
        if decision == "approve":
            permission = (
                db.query(DocumentPermission)
                .filter_by(
                    document_id=document.id,
                    user_id=item.requester_id,
                )
                .first()
            )

            if permission is None:
                permission = DocumentPermission(
                    document_id=document.id,
                    user_id=item.requester_id,
                    can_read=True,
                    can_edit=(item.requested_access == "edit"),
                    granted_by_id=current_user.id,
                )
                db.add(permission)
            else:
                permission.can_read = True
                permission.can_edit = (
                    permission.can_edit or item.requested_access == "edit"
                )
                permission.granted_by_id = current_user.id

            item.status = "approved"
        else:
            item.status = "rejected"

        item.reviewed_by_id = current_user.id
        item.reviewed_at = datetime.now(timezone.utc)

        audit(
            db, current_user.id, f"ACCESS_REQUEST_{decision.upper()}",
            item.id, "SUCCESS",
            f"document_id={document.id}; requester_id={item.requester_id}; "
            f"requested_access={item.requested_access}",
        )
        db.commit()
        db.refresh(item)
        return request_dict(item, db)

    except Exception:
        db.rollback()
        raise HTTPException(500, "Access request review failed.") from None


@router.post("/{request_id}/approve")
def approve_access_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return review_request(request_id, "approve", current_user, db)


@router.post("/{request_id}/reject")
def reject_access_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return review_request(request_id, "reject", current_user, db)
