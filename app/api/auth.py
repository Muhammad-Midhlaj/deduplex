"""Auth endpoints: login (session cookie), whoami, ACL grant (admin)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import (
    SESSION_COOKIE,
    Principal,
    ensure_bootstrap_principal,
    get_current_principal,
    grant_engagement_access,
    find_principal_row_by_api_key,
    hash_api_key,
    make_session_token,
)
from app.config import get_settings
from app.rate_limit import check_rate_limit, client_key
from app.database import get_db
from app.models import ApiPrincipal, Engagement

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginBody(BaseModel):
    api_key: str = Field(min_length=8)


class PrincipalOut(BaseModel):
    id: int | None
    name: str
    is_admin: bool
    engagement_ids: list[int]


class AclGrantBody(BaseModel):
    principal_name: str
    engagement_id: int


class CreatePrincipalBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    api_key: str = Field(min_length=16)
    is_admin: bool = False


@router.post("/login")
def login(
    body: LoginBody,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    check_rate_limit(client_key(request, "auth-login"), max_hits=20, window_seconds=60)
    settings = get_settings()
    if not settings.auth_enabled:
        raise HTTPException(400, "Auth is disabled (AUTH_ENABLED=false)")
    ensure_bootstrap_principal(db)
    row = find_principal_row_by_api_key(db, body.api_key)
    if not row:
        raise HTTPException(401, "Invalid API key")
    token = make_session_token(row.id, settings.session_secret)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        max_age=60 * 60 * 12,
    )
    return {"ok": True, "name": row.name, "is_admin": row.is_admin}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@router.get("/me", response_model=PrincipalOut)
def me(principal: Principal = Depends(get_current_principal)):
    ids = sorted(principal.engagement_ids) if not principal.is_admin else []
    return PrincipalOut(
        id=principal.id,
        name=principal.name,
        is_admin=principal.is_admin,
        engagement_ids=ids,
    )


@router.post("/principals", status_code=201)
def create_principal(
    body: CreatePrincipalBody,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    if not get_settings().auth_enabled:
        raise HTTPException(400, "Auth is disabled")
    if not principal.is_admin:
        raise HTTPException(403, "Admin only")
    if db.query(ApiPrincipal).filter(ApiPrincipal.name == body.name).one_or_none():
        raise HTTPException(409, "Principal name already exists")
    key_hash = hash_api_key(body.api_key)
    if db.query(ApiPrincipal).filter(ApiPrincipal.key_hash == key_hash).one_or_none():
        raise HTTPException(409, "API key already in use")
    row = ApiPrincipal(name=body.name, key_hash=key_hash, is_admin=body.is_admin)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name, "is_admin": row.is_admin}


@router.post("/acl", status_code=201)
def grant_acl(
    body: AclGrantBody,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    if not get_settings().auth_enabled:
        raise HTTPException(400, "Auth is disabled")
    if not principal.is_admin:
        raise HTTPException(403, "Admin only")
    target = db.query(ApiPrincipal).filter(ApiPrincipal.name == body.principal_name).one_or_none()
    if not target:
        raise HTTPException(404, "Principal not found")
    if not db.get(Engagement, body.engagement_id):
        raise HTTPException(404, "Engagement not found")
    grant_engagement_access(db, target.id, body.engagement_id)
    return {"ok": True, "principal": target.name, "engagement_id": body.engagement_id}
