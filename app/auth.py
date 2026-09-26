"""API-key + session auth with engagement-scoped ACLs.

First-cut MVP:
- AUTH_ENABLED=false (default): open access (current behaviour).
- AUTH_ENABLED=true: require X-API-Key or session cookie on /api/* (except health)
  and on /ui/* /evidence. Engagement list/detail/mutations are ACL-scoped.
- BOOTSTRAP_API_KEY seeds an admin principal on startup when auth is enabled.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import ApiPrincipal, EngagementAcl

SESSION_COOKIE = "vapt_session"
SESSION_TTL_SECONDS = 60 * 60 * 12  # 12h


@dataclass
class Principal:
    id: int | None
    name: str
    is_admin: bool
    engagement_ids: frozenset[int]

    def can_access(self, engagement_id: int) -> bool:
        if self.is_admin:
            return True
        return engagement_id in self.engagement_ids


def _pepper() -> bytes:
    settings = get_settings()
    pepper = (settings.api_key_pepper or settings.session_secret or "").strip()
    return pepper.encode("utf-8")


def hash_api_key(raw: str) -> str:
    """HMAC-SHA256 of the API key with a server pepper (not unsalted SHA-256)."""
    return hmac.new(_pepper(), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def _legacy_hash_api_key(raw: str) -> str:
    """Pre-pepper SHA-256 — accepted once, then upgraded on successful auth."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sign(payload_b64: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_token(principal_id: int, secret: str) -> str:
    import base64

    body = {"pid": principal_id, "exp": int(time.time()) + SESSION_TTL_SECONDS}
    raw = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{raw}.{_sign(raw, secret)}"


def parse_session_token(token: str, secret: str) -> int | None:
    import base64

    try:
        raw, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(_sign(raw, secret), sig):
        return None
    pad = "=" * (-len(raw) % 4)
    try:
        body = json.loads(base64.urlsafe_b64decode(raw + pad))
    except (json.JSONDecodeError, ValueError):
        return None
    if int(body.get("exp", 0)) < int(time.time()):
        return None
    return int(body["pid"])


def ensure_bootstrap_principal(db: Session) -> None:
    """Create/refresh admin from BOOTSTRAP_API_KEY when auth is enabled."""
    settings = get_settings()
    if not settings.auth_enabled:
        return
    key = (settings.bootstrap_api_key or "").strip()
    if not key:
        return
    key_hash = hash_api_key(key)
    existing = db.query(ApiPrincipal).filter(ApiPrincipal.key_hash == key_hash).one_or_none()
    if existing:
        existing.is_admin = True
        existing.name = existing.name or "bootstrap-admin"
        db.add(existing)
    else:
        # Demote any previous bootstrap by name; allow re-key.
        named = db.query(ApiPrincipal).filter(ApiPrincipal.name == "bootstrap-admin").one_or_none()
        if named:
            named.key_hash = key_hash
            named.is_admin = True
            db.add(named)
        else:
            db.add(
                ApiPrincipal(
                    name="bootstrap-admin",
                    key_hash=key_hash,
                    is_admin=True,
                )
            )
    db.commit()


def _load_principal(db: Session, principal: ApiPrincipal) -> Principal:
    if principal.is_admin:
        return Principal(
            id=principal.id,
            name=principal.name,
            is_admin=True,
            engagement_ids=frozenset(),
        )
    ids = {
        row.engagement_id
        for row in db.query(EngagementAcl)
        .filter(EngagementAcl.principal_id == principal.id)
        .all()
    }
    return Principal(
        id=principal.id,
        name=principal.name,
        is_admin=False,
        engagement_ids=frozenset(ids),
    )


def find_principal_row_by_api_key(db: Session, api_key: str) -> ApiPrincipal | None:
    """Return active principal for a raw API key, upgrading legacy hashes if needed."""
    key = api_key.strip()
    row = (
        db.query(ApiPrincipal)
        .filter(ApiPrincipal.key_hash == hash_api_key(key), ApiPrincipal.is_active.is_(True))
        .one_or_none()
    )
    if row is not None:
        return row
    legacy = (
        db.query(ApiPrincipal)
        .filter(
            ApiPrincipal.key_hash == _legacy_hash_api_key(key),
            ApiPrincipal.is_active.is_(True),
        )
        .one_or_none()
    )
    if legacy is None:
        return None
    legacy.key_hash = hash_api_key(key)
    db.add(legacy)
    db.commit()
    db.refresh(legacy)
    return legacy


def _principal_from_api_key(db: Session, api_key: str) -> Principal | None:
    row = find_principal_row_by_api_key(db, api_key)
    if not row:
        return None
    return _load_principal(db, row)


def get_current_principal(
    request: Request,
    db: Session = Depends(get_db),
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    vapt_session: Annotated[str | None, Cookie()] = None,
) -> Principal:
    settings = get_settings()
    if not settings.auth_enabled:
        return Principal(id=None, name="anonymous", is_admin=True, engagement_ids=frozenset())

    if x_api_key:
        principal = _principal_from_api_key(db, x_api_key.strip())
        if principal:
            return principal

    if vapt_session:
        pid = parse_session_token(vapt_session, settings.session_secret)
        if pid is not None:
            row = db.get(ApiPrincipal, pid)
            if row and row.is_active:
                return _load_principal(db, row)

    # Authorization: Bearer <key>
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        principal = _principal_from_api_key(db, auth[7:].strip())
        if principal:
            return principal

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (X-API-Key or session cookie)",
        headers={"WWW-Authenticate": "API-Key"},
    )


def require_engagement_access(engagement_id: int, principal: Principal) -> None:
    if not principal.can_access(engagement_id):
        raise HTTPException(status_code=403, detail="No access to this engagement")


def grant_engagement_access(db: Session, principal_id: int, engagement_id: int) -> None:
    exists = (
        db.query(EngagementAcl)
        .filter(
            EngagementAcl.principal_id == principal_id,
            EngagementAcl.engagement_id == engagement_id,
        )
        .one_or_none()
    )
    if exists:
        return
    db.add(EngagementAcl(principal_id=principal_id, engagement_id=engagement_id))
    db.commit()


def filter_engagement_ids(principal: Principal) -> frozenset[int] | None:
    """None means unrestricted (admin / auth off)."""
    if principal.is_admin:
        return None
    return principal.engagement_ids
