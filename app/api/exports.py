from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.auth import Principal, get_current_principal, require_engagement_access
from app.database import get_db
from app.models import Engagement
from services.export_report import (
    export_report_docx,
    export_tracker_csv,
    export_tracker_xlsx,
)

router = APIRouter(prefix="/api/exports", tags=["exports"])


@router.get("/{engagement_id}/tracker.csv")
def export_csv(
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    if not db.get(Engagement, engagement_id):
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    content = export_tracker_csv(db, engagement_id)
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="engagement_{engagement_id}_tracker.csv"'
        },
    )


@router.get("/{engagement_id}/tracker.xlsx")
def export_xlsx(
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    if not db.get(Engagement, engagement_id):
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    content = export_tracker_xlsx(db, engagement_id)
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="engagement_{engagement_id}_tracker.xlsx"'
        },
    )


@router.get("/{engagement_id}/report.docx")
def export_docx(
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    if not db.get(Engagement, engagement_id):
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    content = export_report_docx(db, engagement_id)
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={
            "Content-Disposition": f'attachment; filename="engagement_{engagement_id}_report.docx"'
        },
    )
