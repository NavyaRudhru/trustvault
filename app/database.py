
import os
import logging
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = Path(
    os.getenv("TRUSTVAULT_DATA_DIR", str(BASE_DIR))
).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = DATA_DIR / "trustvault.db"
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{DATABASE_PATH.as_posix()}",
)

connect_args = (
    {"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    checkpoint_pending = False

    try:
        yield db
    finally:
        # Capture the marker before closing the request session.
        checkpoint_pending = db.info.pop(
            "audit_checkpoint_pending", False
        )

        # Closing rolls back any transaction that was not committed.
        db.close()

        # Read only the state visible to a separate database session.
        if checkpoint_pending:
            checkpoint_db = SessionLocal()

            try:
                from app.audit import verify_audit_chain
                from app.audit_checkpoint import (
                    create_checkpoint,
                    save_checkpoint,
                )
                from app.models import AuditLog

                is_valid, message = verify_audit_chain(checkpoint_db)

                if not is_valid:
                    logger.error(
                        "Audit checkpoint skipped: %s", message
                    )
                else:
                    latest = checkpoint_db.scalar(
                        select(AuditLog)
                        .order_by(AuditLog.id.desc())
                        .limit(1)
                    )

                    if latest is not None:
                        checkpoint = create_checkpoint(
                            latest.id,
                            latest.entry_hash,
                        )
                        save_checkpoint(checkpoint)

            except Exception:
                # Do not hide the original request result.
                logger.exception("Audit checkpoint update failed.")
            finally:
                checkpoint_db.close()
