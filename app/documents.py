
import uuid
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
STORAGE_DIR = BASE_DIR / "storage"
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
    """Attempt to record a rejected upload."""
    try:
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_UPLOAD",
            resource_type="document",
            resource_id=None,
            outcome="DENIED",
            details=f"Upload rejected: {reason}",
        )
        db.commit()
    except Exception:
        db.rollback()


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


def document_response(document: Document) -> dict:
    """Return metadata without exposing the internal storage key."""
    return {
        "id": document.id,
        "title": document.title,
        "category": document.category,
        "original_filename": document.original_filename,
        "size_bytes": document.size_bytes,
        "owner_id": document.owner_id,
        "created_at": document.created_at,
    }


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
        # Validate form values.
        title = title.strip()
        category = category.strip()

        if not title or not category:
            raise HTTPException(
                status_code=400,
                detail="Title and category cannot be empty.",
            )

        # Normalize Windows and Unix-style filenames.
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

        # Validate the extension.
        extension = Path(original_name).suffix.lower()

        if extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail="File type is not allowed.",
            )

        # Read at most one byte beyond the limit.
        # This avoids loading an arbitrarily large upload into memory.
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

        # Check the file signature/content.
        if not validate_file_content(extension, content):
            raise HTTPException(
                status_code=400,
                detail="File content does not match its extension.",
            )

        # Store files under generated names, never user-supplied paths.
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

        storage_key = f"{uuid.uuid4().hex}{extension}"
        storage_path = STORAGE_DIR / storage_key

        with storage_path.open("xb") as stored_file:
            file_created = True
            stored_file.write(content)

        # Create the document record.
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

        # Record success in the same database transaction.
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_UPLOAD",
            resource_type="document",
            resource_id=document.id,
            outcome="SUCCESS",
            details=f"Uploaded document: {original_name}",
        )

        db.commit()
        transaction_committed = True

        return document_response(document)

    except HTTPException as exc:
        db.rollback()

        # Remove a file created by this failed upload.
        if file_created and storage_path is not None:
            try:
                storage_path.unlink(missing_ok=True)
            except OSError:
                pass

        audit_rejected_upload(db, current_user, str(exc.detail))
        raise

    except Exception:
        db.rollback()

        # Do not delete a file after the DB transaction has committed.
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List documents owned by or explicitly shared with the user."""

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
        escaped_search = (
            search.strip()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        query = query.filter(
            Document.title.ilike(
                f"%{escaped_search}%",
                escape="\\",
            )
        )

    if category and category.strip():
        query = query.filter(
            Document.category.ilike(category.strip())
        )

    documents = query.order_by(Document.created_at.desc()).all()
    return [document_response(doc) for doc in documents]


@router.get("/{document_id}")
def get_document_metadata(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return metadata only when the user has read permission."""
    document = require_document_read(document_id, current_user, db)
    return document_response(document)


@router.patch("/{document_id}")
def update_document(
    document_id: int,
    data: DocumentUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update metadata only when the user has edit permission."""

    document = require_document_edit(document_id, current_user, db)

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
            resource_type="document",
            resource_id=str(document.id),
            outcome="SUCCESS",
            details=f"Updated document {document.id}; previous title={old_title}",
        )

        db.commit()
        db.refresh(document)

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Document update failed.",
        ) from None

    return document_response(document)


@router.delete("/{document_id}")
def delete_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Only the owner can delete a document."""

    document = db.get(Document, document_id)

    if document is None or document.owner_id != current_user.id:
        try:
            record_audit_event(
                db=db,
                actor_id=current_user.id,
                action="DOCUMENT_DELETE",
                resource_type="document",
                resource_id=str(document_id),
                outcome="DENIED",
                details="Document deletion denied: requester is not the owner.",
            )
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(status_code=404, detail="Document not found.")

    storage_root = STORAGE_DIR.resolve()
    storage_path = (storage_root / document.storage_key).resolve()

    if storage_path.parent != storage_root:
        raise HTTPException(
            status_code=500,
            detail="Invalid document storage path.",
        )

    try:
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_DELETE",
            resource_type="document",
            resource_id=str(document.id),
            outcome="SUCCESS",
            details=f"Deleted document titled: {document.title}",
        )

        db.query(DocumentPermission).filter(
            DocumentPermission.document_id == document.id
        ).delete(synchronize_session=False)

        db.delete(document)
        db.commit()

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Document deletion failed.",
        ) from None

    # Delete the physical file only after the DB transaction succeeds.
    if storage_path.is_file():
        try:
            storage_path.unlink()
        except OSError:
            # A separate cleanup task should handle orphaned files.
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

    try:
        document = require_document_read(
            document_id, current_user, db
        )
    except HTTPException as exc:
        if exc.status_code in (403, 404):
            try:
                record_audit_event(
                    db=db,
                    actor_id=current_user.id,
                    action="DOCUMENT_DOWNLOAD",
                    resource_type="document",
                    resource_id=str(document_id),
                    outcome="DENIED",
                    details="Download denied by document read authorization.",
                )
                db.commit()
            except Exception:
                db.rollback()
        raise

    storage_root = STORAGE_DIR.resolve()
    storage_path = (storage_root / document.storage_key).resolve()

    if (
        storage_path.parent != storage_root
        or not storage_path.is_file()
    ):
        try:
            record_audit_event(
                db=db,
                actor_id=current_user.id,
                action="DOCUMENT_DOWNLOAD",
                resource_type="document",
                resource_id=str(document_id),
                outcome="DENIED",
                details="Stored file is missing or its path is invalid.",
            )
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(
            status_code=404,
            detail="Document file not found.",
        )

    # Fail closed if the successful download cannot be audited.
    try:
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_DOWNLOAD",
            resource_type="document",
            resource_id=str(document.id),
            outcome="SUCCESS",
            details=f"Downloaded document titled: {document.title}",
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
