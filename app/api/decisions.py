from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import Principal, get_current_principal, require_engagement_access
from app.database import get_db
from app.models import AnalystDecision, FindingGroup
from app.schemas import DecisionCreate, DecisionOut

router = APIRouter(prefix="/api/finding-groups", tags=["decisions"])


@router.post("/{group_id}/decisions", response_model=DecisionOut, status_code=201)
def record_decision(
    group_id: int,
    body: DecisionCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    group = db.get(FindingGroup, group_id)
    if not group:
        raise HTTPException(404, "Finding group not found")
    require_engagement_access(group.engagement_id, principal)

    model_version = None
    if group.observations:
        model_version = group.observations[0].model_version

    decision = AnalystDecision(
        finding_group_id=group.id,
        decision=body.decision,
        reason=body.reason,
        analyst=body.analyst or principal.name,
        model_version_at_decision=model_version,
    )
    group.queue_status = body.decision
    db.add(decision)
    db.add(group)
    db.commit()
    db.refresh(decision)
    return decision


@router.get("/{group_id}/decisions", response_model=list[DecisionOut])
def list_decisions(
    group_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    group = db.get(FindingGroup, group_id)
    if not group:
        raise HTTPException(404, "Finding group not found")
    require_engagement_access(group.engagement_id, principal)
    return (
        db.query(AnalystDecision)
        .filter(AnalystDecision.finding_group_id == group_id)
        .order_by(AnalystDecision.created_at.desc())
        .all()
    )
