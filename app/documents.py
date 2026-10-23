
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


class DocumentUpdateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=100)


def audit_rejected_upload(
    db: Session,
    current_user: User,
    reason: str,
) -> None:
    """Record a rejected upload attempt."""
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
async def upload_document(
    title: str = Form(..., min_length=1, max_length=255),
    category: str = Form("General", max_length=100),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Validate and save an uploaded document in private storage."""

    raw_filename = (file.filename or "").replace("\\", "/")
    original_name = Path(raw_filename).name
    extension = Path(original_name).suffix.lower()

    try:
        # Validate filename and extension.
        if (
            not original_name
            or original_name in {".", ".."}
            or extension not in ALLOWED_EXTENSIONS
        ):
            audit_rejected_upload(
                db, current_user, "Unsupported file type or filename."
            )
            raise HTTPException(
                status_code=400,
                detail="Unsupported file type.",
            )

        # Reject whitespace-only titles and invalid categories.
        if not title.strip():
            audit_rejected_upload(
                db, current_user, "Document title cannot be empty."
            )
            raise HTTPException(
                status_code=400,
                detail="Document title cannot be empty.",
            )

        if len(category) > 100:
            audit_rejected_upload(
                db, current_user, "Category exceeds the allowed length."
            )
            raise HTTPException(
                status_code=400,
                detail="Category is too long.",
            )

        # Read at most one byte above the upload limit.
        content = await file.read(MAX_UPLOAD_BYTES + 1)

        if not content:
            audit_rejected_upload(
                db, current_user, "Empty files are not allowed."
            )
            raise HTTPException(
                status_code=400,
                detail="Empty files are not allowed.",
            )

        if len(content) > MAX_UPLOAD_BYTES:
            audit_rejected_upload(
                db, current_user, "File exceeds the 10 MB limit."
            )
            raise HTTPException(
                status_code=413,
                detail="File exceeds the 10 MB limit.",
            )

        # Check basic file signatures. These checks do not fully validate
        # or scan the contents of a file.
        expected_signatures = {
            ".pdf": content.startswith(b"%PDF-"),
            ".png": content.startswith(b"\x89PNG\r\n\x1a\n"),
            ".jpg": content.startswith(b"\xff\xd8\xff"),
            ".jpeg": content.startswith(b"\xff\xd8\xff"),
            ".txt": b"\x00" not in content,
        }

        if not expected_signatures[extension]:
            audit_rejected_upload(
                db,
                current_user,
                "File content does not match its extension.",
            )
            raise HTTPException(
                status_code=400,
                detail="File content does not match the allowed file type.",
            )

        # Generate a server-controlled storage name.
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

        file_created = False

        try:
            # Exclusive creation avoids overwriting an existing file.
            with storage_path.open("xb") as stored_file:
                file_created = True
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

            # Save the document and audit entry in one transaction.
            db.commit()
            db.refresh(document)

        except Exception:
            db.rollback()

            # Remove a partially written file if the database operation fails.
            if file_created:
                try:
                    storage_path.unlink(missing_ok=True)
                except OSError:
                    # Avoid exposing filesystem details to the caller.
                    pass

            raise HTTPException(
                status_code=500,
                detail="Document upload failed.",
            ) from None

        return document_response(document)

    finally:
        await file.close()


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
    """Return metadata only if the user has read permission."""
    document = require_document_read(document_id, current_user, db)
    return document_response(document)


@router.patch("/{document_id}")
def update_document(
    document_id: int,
    data: DocumentUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update document metadata only if the user has edit permission."""

    document = require_document_edit(document_id, current_user, db)

    if not data.title.strip() or not data.category.strip():
        raise HTTPException(
            status_code=400,
            detail="Title and category cannot be empty.",
        )

    old_title = document.title

    try:
        document.title = data.title.strip()
        document.category = data.category.strip()

        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_UPDATE",
            resource_type="document",
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

    return document_response(document)


@router.delete("/{document_id}")
def delete_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Allow only the document owner to delete a document."""

    document = db.get(Document, document_id)

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

    # Remove the physical file after the database transaction succeeds.
    if storage_path.is_file():
        try:
            storage_path.unlink()
        except OSError:
            # The database record is gone; monitor for orphaned files.
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

    if storage_path.parent != storage_root or not storage_path.is_file():
        record_audit_event(
            db=db,
            actor_id=current_user.id,
            action="DOCUMENT_DOWNLOAD",
            resource_type="document",
            resource_id=str(document_id),
            outcome="DENIED",
            details=(
                "Download denied because the stored file is missing "
                "or its path is invalid."
            ),
        )
        db.commit()
        raise HTTPException(
            status_code=404,
            detail="Document file not found.",
        )

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
