from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.auth import Principal, filter_engagement_ids, get_current_principal, require_engagement_access
from app.database import get_db
from app.models import DecisionValue, FindingGroup, Observation
from app.schemas import (
    AssetOut,
    DecisionOut,
    FindingGroupDetail,
    FindingGroupOut,
    ObservationOut,
)

router = APIRouter(prefix="/api", tags=["queue"])


def _group_out(g: FindingGroup, observation_count: int | None = None) -> FindingGroupOut:
    count = observation_count
    if count is None:
        count = len(g.observations) if g.observations is not None else 0
    return FindingGroupOut(
        id=g.id,
        engagement_id=g.engagement_id,
        group_key=g.group_key,
        tool=g.tool,
        rule_id=g.rule_id,
        asset_id=g.asset_id,
        title=g.title,
        severity=g.severity,
        priority_score=g.priority_score,
        queue_status=g.queue_status,
        observation_count=count,
        asset=AssetOut.model_validate(g.asset) if g.asset else None,
    )


@router.get("/queue", response_model=list[FindingGroupOut])
def list_queue(
    engagement_id: int | None = Query(None),
    status: DecisionValue | None = Query(DecisionValue.PENDING),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    q = db.query(FindingGroup).options(
        joinedload(FindingGroup.asset),
        joinedload(FindingGroup.observations),
    )
    allowed = filter_engagement_ids(principal)
    if engagement_id is not None:
        require_engagement_access(engagement_id, principal)
        q = q.filter(FindingGroup.engagement_id == engagement_id)
    elif allowed is not None:
        if not allowed:
            return []
        q = q.filter(FindingGroup.engagement_id.in_(allowed))
    if status is not None:
        q = q.filter(FindingGroup.queue_status == status)
    groups = q.order_by(
        FindingGroup.priority_score.desc(), FindingGroup.id.asc()
    ).all()
    return [_group_out(g) for g in groups]


@router.get("/finding-groups/{group_id}", response_model=FindingGroupDetail)
def get_finding_group(
    group_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    g = (
        db.query(FindingGroup)
        .options(
            joinedload(FindingGroup.asset),
            joinedload(FindingGroup.observations),
            joinedload(FindingGroup.decisions),
        )
        .filter(FindingGroup.id == group_id)
        .one_or_none()
    )
    if not g:
        raise HTTPException(404, "Finding group not found")
    require_engagement_access(g.engagement_id, principal)
    base = _group_out(g)
    return FindingGroupDetail(
        **base.model_dump(),
        observations=[ObservationOut.model_validate(o) for o in g.observations],
        decisions=[DecisionOut.model_validate(d) for d in g.decisions],
    )


@router.get("/observations/{observation_id}", response_model=ObservationOut)
def get_observation(
    observation_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    obs = db.get(Observation, observation_id)
    if not obs:
        raise HTTPException(404, "Observation not found")
    require_engagement_access(obs.engagement_id, principal)
    return obs
