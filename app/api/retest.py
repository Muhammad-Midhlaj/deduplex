from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import Principal, get_current_principal, require_engagement_access
from app.database import get_db
from app.models import Engagement, ImportBatch
from app.schemas import RetestCompareRequest, RetestCompareResult
from services.retest import compare_retest

router = APIRouter(prefix="/api/retest", tags=["retest"])


@router.post("/compare", response_model=RetestCompareResult)
def retest_compare(
    body: RetestCompareRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    if not db.get(Engagement, body.engagement_id):
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(body.engagement_id, principal)
    batch = db.get(ImportBatch, body.retest_import_batch_id)
    if not batch or batch.engagement_id != body.engagement_id:
        raise HTTPException(404, "Retest import batch not found for engagement")
    return compare_retest(
        db,
        engagement_id=body.engagement_id,
        retest_import_batch_id=body.retest_import_batch_id,
        baseline_import_batch_id=body.baseline_import_batch_id,
    )
