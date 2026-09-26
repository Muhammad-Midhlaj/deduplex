"""Double-submit CSRF cookie for HTML UI form POSTs."""

from __future__ import annotations

import hmac
import secrets
from typing import Annotated

from fastapi import Form, HTTPException, Request, Response

from app.config import get_settings

CSRF_COOKIE = "vapt_csrf"
CSRF_FORM_FIELD = "csrf_token"


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_csrf_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        httponly=False,
        samesite="lax",
        secure=settings.session_cookie_secure,
        max_age=60 * 60 * 12,
    )


def csrf_token_for_request(request: Request) -> str:
    existing = request.cookies.get(CSRF_COOKIE)
    if existing and len(existing) >= 16:
        return existing
    return new_csrf_token()


def validate_csrf(request: Request, form_token: str | None) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    if not cookie or not form_token:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    if not hmac.compare_digest(cookie, form_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")


async def require_csrf(
    request: Request,
    csrf_token: Annotated[str | None, Form()] = None,
) -> None:
    validate_csrf(request, csrf_token)
