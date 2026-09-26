from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import (
    Principal,
    filter_engagement_ids,
    get_current_principal,
    grant_engagement_access,
    require_engagement_access,
)
from app.database import get_db
from app.models import Engagement
from app.schemas import EngagementCreate, EngagementOut

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


@router.post("", response_model=EngagementOut, status_code=201)
def create_engagement(
    body: EngagementCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    eng = Engagement(name=body.name, client=body.client, description=body.description)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    # Creator (non-admin with a real principal id) gets ACL membership automatically.
    if principal.id is not None and not principal.is_admin:
        grant_engagement_access(db, principal.id, eng.id)
    return eng


@router.get("", response_model=list[EngagementOut])
def list_engagements(
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    q = db.query(Engagement)
    allowed = filter_engagement_ids(principal)
    if allowed is not None:
        if not allowed:
            return []
        q = q.filter(Engagement.id.in_(allowed))
    return q.order_by(Engagement.id.desc()).all()


@router.get("/{engagement_id}", response_model=EngagementOut)
def get_engagement(
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    return eng
