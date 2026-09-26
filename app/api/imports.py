import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.auth import Principal, get_current_principal, require_engagement_access
from app.config import get_settings
from app.database import get_db
from app.models import Engagement, ImportBatch
from app.schemas import ImportBatchOut, ImportResult
from app.uploads import save_upload_capped
from services.import_service import import_scanner_file

router = APIRouter(prefix="/api/imports", tags=["imports"])


@router.post("", response_model=ImportResult, status_code=201)
async def upload_import(
    engagement_id: int = Form(...),
    tool: str | None = Form(None),
    is_retest: bool = Form(False),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)

    settings = get_settings()
    suffix = Path(file.filename or "upload.xml").suffix or ".xml"
    tmp_path = await save_upload_capped(
        file, max_bytes=settings.max_upload_bytes, suffix=suffix
    )

    try:
        result = import_scanner_file(
            db,
            engagement_id=engagement_id,
            source_path=tmp_path,
            original_filename=file.filename or tmp_path.name,
            tool=tool,
            is_retest=is_retest,
        )
        return result
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        tmp_path.unlink(missing_ok=True)


@router.get("/engagement/{engagement_id}", response_model=list[ImportBatchOut])
def list_imports(
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    require_engagement_access(engagement_id, principal)
    return (
        db.query(ImportBatch)
        .filter(ImportBatch.engagement_id == engagement_id)
        .order_by(ImportBatch.id.desc())
        .all()
    )


@router.get("/{import_id}", response_model=ImportBatchOut)
def get_import(
    import_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    batch = db.get(ImportBatch, import_id)
    if not batch:
        raise HTTPException(404, "Import batch not found")
    require_engagement_access(batch.engagement_id, principal)
    return batch
