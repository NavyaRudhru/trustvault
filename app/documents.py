
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
from sqlalchemy import or_
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.auth import get_current_user
from app.database import get_db
from app.models import Document, DocumentPermission, User
from app.permissions import require_document_read, require_document_edit
from app.audit import record_audit_event


router = APIRouter(prefix="/documents", tags=["Documents"])


class DocumentUpdateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=100)


BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}


def document_response(document: Document) -> dict:
    """Return document metadata without exposing its storage key."""
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
async def upload_document(
    title: str = Form(..., min_length=1, max_length=255),
    category: str = Form("General", max_length=100),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Upload a document to private server-side storage."""
    original_name = Path(file.filename or "").name
    extension = Path(original_name).suffix.lower()

    if not original_name or extension not in ALLOWED_EXTENSIONS:
        await file.close()
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type.",
        )

    content = await file.read(MAX_UPLOAD_BYTES + 1)

    if not content:
        await file.close()
        raise HTTPException(
            status_code=400,
            detail="Empty files are not allowed.",
        )

    if len(content) > MAX_UPLOAD_BYTES:
        await file.close()
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 10 MB limit.",
        )

    expected_signatures = {
        ".pdf": content.startswith(b"%PDF-"),
        ".png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": content.startswith(b"\xff\xd8\xff"),
        ".jpeg": content.startswith(b"\xff\xd8\xff"),
        ".txt": b"\x00" not in content,
    }

    if not expected_signatures[extension]:
        await file.close()
        raise HTTPException(
            status_code=400,
            detail="File content does not match the allowed file type.",
        )

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    storage_key = uuid.uuid4().hex
    storage_path = STORAGE_DIR / storage_key

    document = Document(
        title=title.strip(),
        category=category.strip() or "General",
        original_filename=original_name,
        storage_key=storage_key,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=len(content),
        owner_id=current_user.id,
    )

    try:
        with storage_path.open("xb") as stored_file:
            stored_file.write(content)

        db.add(document)
        db.flush()

        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_UPLOAD",
            resource_type="document",
            resource_id=str(document.id),
            outcome="SUCCESS",
            details=(
                f"Uploaded document titled: {document.title}; "
                f"filename={document.original_filename}; "
                f"size_bytes={document.size_bytes}"
            ),
        )

        # Save the document and its audit entry together.
        db.commit()
        db.refresh(document)

    except Exception:
        db.rollback()

        if storage_path.exists():
            storage_path.unlink()

        raise HTTPException(
            status_code=500,
            detail="Document upload failed.",
        ) from None

    finally:
        await file.close()

    return document_response(document)


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
        # Treat user input as a literal search string.
        escaped_search = (
            search.strip()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        query = query.filter(
            Document.title.ilike(f"%{escaped_search}%", escape="\\")
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
    """Return metadata only when the user can read the document."""
    document = require_document_read(document_id, current_user, db)
    return document_response(document)


@router.patch("/{document_id}")
def update_document(
    document_id: int,
    data: DocumentUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = require_document_edit(document_id, current_user, db)

    if not data.title.strip() or not data.category.strip():
        raise HTTPException(
            status_code=400,
            detail="Title and category cannot be empty.",
        )

    old_title = document.title
    document.title = data.title.strip()
    document.category = data.category.strip()

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

    return document_response(document)


@router.delete("/{document_id}")
def delete_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)

    # Only the document owner can delete it.
    if document is None or document.owner_id != current_user.id:
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
        raise HTTPException(status_code=404, detail="Document not found.")

    # Resolve the storage path and prevent path traversal.
    storage_root = STORAGE_DIR.resolve()
    storage_path = (storage_root / document.storage_key).resolve()

    if storage_path.parent != storage_root:
        raise HTTPException(
            status_code=500,
            detail="Invalid document storage path.",
        )

    # Record the successful deletion in the audit log.
    record_audit_event(
        db=db,
        actor_id=current_user.id,
        action="DOCUMENT_DELETE",
        resource_type="document",
        resource_id=str(document.id),
        outcome="SUCCESS",
        details=f"Deleted document titled: {document.title}",
    )

    # Remove associated permissions and the document record.
    db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document.id
    ).delete(synchronize_session=False)

    db.delete(document)
    db.commit()

    # Remove the stored file after the database commit.
    if storage_path.is_file():
        try:
            storage_path.unlink()
        except OSError:
            # The document record is deleted, so the file is
            # no longer accessible through the document API.
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
    """Download a document only after checking read permission."""
    document = require_document_read(document_id, current_user, db)

    # Resolve and verify the path stays inside private storage.
    storage_root = STORAGE_DIR.resolve()
    storage_path = (storage_root / document.storage_key).resolve()

    if storage_path.parent != storage_root or not storage_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Document file not found.",
        )

    return FileResponse(
        path=storage_path,
        filename=document.original_filename,
        media_type="application/octet-stream",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )
