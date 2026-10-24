
import os
import uuid
from datetime import date, datetime, time, timedelta
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.auth import get_current_user
from app.database import get_db
from app.models import Document, DocumentPermission, User
from app.permissions import require_document_read, require_document_edit


router = APIRouter(prefix="/documents", tags=["Documents"])

BASE_DIR = Path(__file__).resolve().parent.parent

STORAGE_DIR = Path(
    os.getenv(
        "TRUSTVAULT_STORAGE_DIR",
        str(BASE_DIR / "storage"),
    )
).resolve()

MAX_UPLOAD_BYTES = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SIGNATURE = b"\xff\xd8\xff"


class DocumentUpdateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=100)


def audit_rejected_upload(
    db: Session,
    current_user: User,
    reason: str,
) -> None:
    """Record rejected uploads; fail closed if the audit cannot be saved."""
    try:
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_UPLOAD",
            resource_type="DOCUMENT",
            resource_id=None,
            outcome="DENIED",
            details=f"Upload rejected: {reason}",
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Upload rejection could not be audited.",
        ) from None


def validate_file_content(extension: str, content: bytes) -> bool:
    """Check basic file signatures and reject obvious extension mismatches."""
    if not content:
        return False

    if extension == ".pdf":
        return content.startswith(b"%PDF-")

    if extension == ".png":
        return content.startswith(PNG_SIGNATURE)

    if extension in {".jpg", ".jpeg"}:
        return content.startswith(JPEG_SIGNATURE)

    if extension == ".txt":
        if b"\x00" in content:
            return False

        try:
            content.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    return False


def document_response(
    document: Document,
    user: User,
    db: Session,
) -> dict:
    """Return safe document metadata and the current user's permissions."""

    can_edit = document.owner_id == user.id

    if not can_edit:
        permission = (
            db.query(DocumentPermission)
            .filter_by(
                document_id=document.id,
                user_id=user.id,
            )
            .first()
        )
        can_edit = bool(permission and permission.can_edit)

    return {
        "id": document.id,
        "title": document.title,
        "category": document.category,
        "original_filename": document.original_filename,
        "size_bytes": document.size_bytes,
        "owner_id": document.owner_id,
        "created_at": document.created_at,
        "can_edit": can_edit,
    }

def get_safe_storage_path(storage_key: str) -> Path:
    """
    Resolve a storage key and ensure it points directly inside STORAGE_DIR.
    Reject traversal, directory paths, and paths resolving outside the root.
    """
    storage_root = STORAGE_DIR.resolve()
    storage_path = (storage_root / storage_key).resolve()

    if (
        storage_path == storage_root
        or storage_path.parent != storage_root
    ):
        raise HTTPException(
            status_code=500,
            detail="Invalid document storage path.",
        )

    return storage_path


def record_denied_document_action(
    db: Session,
    current_user: User,
    action: str,
    document_id: int,
    details: str,
) -> None:
    """Persist a denied document action before returning an error."""
    try:
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action=action,
            resource_type="DOCUMENT",
            resource_id=str(document_id),
            outcome="DENIED",
            details=details,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Denied action could not be audited.",
        ) from None


@router.post("/", status_code=201)
def upload_document(
    title: str = Form(..., min_length=1, max_length=255),
    category: str = Form(..., min_length=1, max_length=100),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Validate, store, and audit a document upload."""

    storage_path = None
    file_created = False
    transaction_committed = False

    try:
        title = title.strip()
        category = category.strip()

        if not title or not category:
            raise HTTPException(
                status_code=400,
                detail="Title and category cannot be empty.",
            )

        raw_filename = (file.filename or "").replace("\\", "/")
        original_name = Path(raw_filename).name

        if (
            not original_name
            or original_name in {".", ".."}
            or "\x00" in original_name
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid filename.",
            )

        extension = Path(original_name).suffix.lower()

        if extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail="File type is not allowed.",
            )

        content = file.file.read(MAX_UPLOAD_BYTES + 1)

        if not content:
            raise HTTPException(
                status_code=400,
                detail="Empty files are not allowed.",
            )

        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail="File exceeds the 10 MB limit.",
            )

        if not validate_file_content(extension, content):
            raise HTTPException(
                status_code=400,
                detail="File content does not match its extension.",
            )

        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

        storage_key = f"{uuid.uuid4().hex}{extension}"
        storage_path = get_safe_storage_path(storage_key)

        # Exclusive creation prevents accidental overwrite.
        with storage_path.open("xb") as stored_file:
            file_created = True
            stored_file.write(content)

        document = Document(
            title=title,
            category=category,
            original_filename=original_name,
            storage_key=storage_key,
            content_type=file.content_type or "application/octet-stream",
            size_bytes=len(content),
            owner_id=current_user.id,
        )

        db.add(document)
        db.flush()
        db.refresh(document)

        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_UPLOAD",
            resource_type="DOCUMENT",
            resource_id=str(document.id),
            outcome="SUCCESS",
            details=f"Uploaded document: {original_name}",
        )

        db.commit()
        transaction_committed = True

        return document_response(document, current_user, db)

    except HTTPException as exc:
        db.rollback()

        if file_created and storage_path is not None:
            try:
                storage_path.unlink(missing_ok=True)
            except OSError:
                pass

        audit_rejected_upload(db, current_user, str(exc.detail))
        raise

    except Exception:
        db.rollback()

        if (
            not transaction_committed
            and file_created
            and storage_path is not None
        ):
            try:
                storage_path.unlink(missing_ok=True)
            except OSError:
                pass

        audit_rejected_upload(
            db,
            current_user,
            "Upload failed during storage or database processing.",
        )

        raise HTTPException(
            status_code=500,
            detail="Document upload failed.",
        ) from None

    finally:
        file.file.close()


@router.get("/")
def list_documents(
    search: str | None = None,
    category: str | None = None,
    owner: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List only owned or explicitly shared documents, with search filters."""

    if date_from and date_to and date_from > date_to:
        raise HTTPException(
            status_code=400,
            detail="date_from must not be after date_to.",
        )

    permitted_ids = (
        db.query(DocumentPermission.document_id)
        .filter(
            DocumentPermission.user_id == current_user.id,
            or_(
                DocumentPermission.can_read.is_(True),
                DocumentPermission.can_edit.is_(True),
            ),
        )
    )

    query = db.query(Document).filter(
        or_(
            Document.owner_id == current_user.id,
            Document.id.in_(permitted_ids),
        )
    )

    if search and search.strip():
        term = (
            search.strip()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = f"%{term}%"

        query = query.filter(
            or_(
                Document.title.ilike(pattern, escape="\\"),
                Document.original_filename.ilike(pattern, escape="\\"),
            )
        )

    if category and category.strip():
        term = (
            category.strip()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )

        query = query.filter(
            Document.category.ilike(
                f"%{term}%",
                escape="\\",
            )
        )

    if owner and owner.strip():
        owner_ids = db.query(User.id).filter(
            User.username.ilike(owner.strip())
        )
        query = query.filter(Document.owner_id.in_(owner_ids))

    if date_from:
        query = query.filter(
            Document.created_at >= datetime.combine(date_from, time.min)
        )

    if date_to:
        query = query.filter(
            Document.created_at
            < datetime.combine(date_to + timedelta(days=1), time.min)
        )

    documents = query.order_by(Document.created_at.desc()).all()

    return [
    document_response(doc, current_user, db)
    for doc in documents
]

@router.get("/{document_id}")
def get_document_metadata(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return metadata only when the user has read permission."""
    document = require_document_read(
        document_id,
        current_user,
        db,
    )
    return document_response(document, current_user, db)


@router.patch("/{document_id}")
def update_document(
    document_id: int,
    data: DocumentUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update metadata only when the user has edit permission."""

    document = require_document_edit(
        document_id,
        current_user,
        db,
    )

    title = data.title.strip()
    category = data.category.strip()

    if not title or not category:
        raise HTTPException(
            status_code=400,
            detail="Title and category cannot be empty.",
        )

    old_title = document.title

    try:
        document.title = title
        document.category = category

        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_UPDATE",
            resource_type="DOCUMENT",
            resource_id=str(document.id),
            outcome="SUCCESS",
            details=(
                f"Updated document {document.id}; "
                f"previous title={old_title}"
            ),
        )

        db.commit()
        db.refresh(document)

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Document update failed.",
        ) from None

    return document_response(document, current_user, db)


@router.delete("/{document_id}")
def delete_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Delete only an owner's document.
    Stage the physical file until the database transaction commits.
    """
    document = db.get(Document, document_id)

    if document is None or document.owner_id != current_user.id:
        record_denied_document_action(
            db=db,
            current_user=current_user,
            action="DOCUMENT_DELETE",
            document_id=document_id,
            details="Document deletion denied: requester is not the owner.",
        )

        raise HTTPException(
            status_code=404,
            detail="Document not found.",
        )

    storage_path = get_safe_storage_path(document.storage_key)
    storage_root = STORAGE_DIR.resolve()

    staged_path = storage_root / (
        f".{storage_path.name}.deleting-{uuid.uuid4().hex}"
    )

    file_staged = False

    try:
        if storage_path.exists():
            if not storage_path.is_file():
                raise HTTPException(
                    status_code=500,
                    detail="Document storage entry is not a regular file.",
                )

            # Move the file aside so it can be restored if DB commit fails.
            os.replace(storage_path, staged_path)
            file_staged = True

        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_DELETE",
            resource_type="DOCUMENT",
            resource_id=str(document.id),
            outcome="SUCCESS",
            details=f"Deleted document titled: {document.title}",
        )

        db.query(DocumentPermission).filter(
            DocumentPermission.document_id == document.id
        ).delete(synchronize_session=False)

        db.delete(document)
        db.commit()

    except Exception as exc:
        db.rollback()

        if file_staged:
            try:
                os.replace(staged_path, storage_path)
            except OSError:
                # Keep the staged file for manual recovery if restoration fails.
                pass

        if isinstance(exc, HTTPException):
            raise

        raise HTTPException(
            status_code=500,
            detail="Document deletion failed.",
        ) from None

    # Database deletion succeeded. Remove the staged file afterward.
    if file_staged:
        try:
            staged_path.unlink()
        except OSError:
            # The database record is gone; a staged file may need cleanup.
            pass

    return {
        "message": "Document deleted successfully.",
        "document_id": document_id,
    }


@router.get("/{document_id}/download")
def download_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download only after verifying document read permission."""

    document = require_document_read(
        document_id,
        current_user,
        db,
        audit_action="DOCUMENT_DOWNLOAD",
    )

    try:
        storage_path = get_safe_storage_path(document.storage_key)
    except HTTPException:
        record_denied_document_action(
            db=db,
            current_user=current_user,
            action="DOCUMENT_DOWNLOAD",
            document_id=document_id,
            details="Stored file path is invalid.",
        )
        raise

    if not storage_path.is_file():
        record_denied_document_action(
            db=db,
            current_user=current_user,
            action="DOCUMENT_DOWNLOAD",
            document_id=document_id,
            details="Stored document file is missing.",
        )

        raise HTTPException(
            status_code=404,
            detail="Document file not found.",
        )

    try:
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_DOWNLOAD",
            resource_type="DOCUMENT",
            resource_id=str(document.id),
            outcome="SUCCESS",
            details=f"Download authorized for document: {document.title}",
        )
        db.commit()

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Download could not be recorded.",
        ) from None

    return FileResponse(
        path=storage_path,
        filename=document.original_filename,
        media_type="application/octet-stream",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )
