
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse
from app.auth import get_current_user
from app.database import get_db
from app.models import Document, User
from app.permissions import require_document_read

router = APIRouter(prefix="/documents", tags=["Documents"])

BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

# Initial allowlist. We will validate actual file content too.
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}


@router.post("/", status_code=201)
async def upload_document(
    title: str = Form(..., min_length=1, max_length=255),
    category: str = Form("General", max_length=100),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    original_name = Path(file.filename or "").name
    extension = Path(original_name).suffix.lower()

    if not original_name or extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported file type.")

    content = await file.read(MAX_UPLOAD_BYTES + 1)

    if not content:
        raise HTTPException(status_code=400, detail="Empty files are not allowed.")

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 10 MB limit.")

    # Do not trust the client-supplied MIME type alone.
    expected_signatures = {
        ".pdf": content.startswith(b"%PDF-"),
        ".png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": content.startswith(b"\xff\xd8\xff"),
        ".jpeg": content.startswith(b"\xff\xd8\xff"),
        ".txt": b"\x00" not in content,
    }

    if not expected_signatures[extension]:
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

    # Store the file under a random server-generated name.
    # If database persistence fails, remove the stored file.
    try:
        with storage_path.open("xb") as stored_file:
            stored_file.write(content)

        db.add(document)
        db.commit()
        db.refresh(document)
    except Exception:
        db.rollback()
        if storage_path.exists():
            storage_path.unlink()
        raise HTTPException(status_code=500, detail="Document upload failed.")
    finally:
        await file.close()

    return {
        "id": document.id,
        "title": document.title,
        "category": document.category,
        "original_filename": document.original_filename,
        "size_bytes": document.size_bytes,
        "owner_id": document.owner_id,
        "created_at": document.created_at,
    }


@router.get("/{document_id}")
def get_document_metadata(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = require_document_read(document_id, current_user, db)

    return {
        "id": document.id,
        "title": document.title,
        "category": document.category,
        "original_filename": document.original_filename,
        "size_bytes": document.size_bytes,
        "owner_id": document.owner_id,
        "created_at": document.created_at,
    }

@router.get("/{document_id}/download")
def download_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = require_document_read(document_id, current_user, db)

    storage_path = STORAGE_DIR / document.storage_key

    if not storage_path.is_file():
        raise HTTPException(status_code=404, detail="Document file not found.")

    return FileResponse(
        path=storage_path,
        filename=document.original_filename,
        media_type="application/octet-stream",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )

