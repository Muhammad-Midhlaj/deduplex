"""FastAPI application entrypoint."""

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api import auth as auth_api
from app.api import decisions, engagements, exports, imports, observations, retest
from app.auth import ensure_bootstrap_principal
from app.config import get_settings, validate_security_settings
from app.database import SessionLocal, init_db
from app.web import routes as web_routes

logger = logging.getLogger("vapt")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    validate_security_settings(settings)
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    init_db()
    db = SessionLocal()
    try:
        ensure_bootstrap_principal(db)
    finally:
        db.close()
    if not settings.auth_enabled:
        logger.warning(
            "AUTH_ENABLED=false — API/UI are open. Bind to 127.0.0.1 only; "
            "set AUTH_ENABLED=true before any non-local exposure."
        )
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    validate_security_settings(settings)

    docs_url = "/docs" if (not settings.auth_enabled or settings.expose_api_docs) else None
    redoc_url = "/redoc" if docs_url else None
    openapi_url = "/openapi.json" if docs_url else None

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        description=(
            "Deduplex (VAPT Effort Reduction) — consolidate scanner results, "
            "group exact duplicates, analyst queue, exports, retest hooks. "
            "Laya triage is feature-flagged; rules fallback always available. "
            "API-key auth + engagement ACLs via AUTH_ENABLED (required for non-local use)."
        ),
    )

    app.include_router(auth_api.router)
    app.include_router(engagements.router)
    app.include_router(imports.router)
    app.include_router(observations.router)
    app.include_router(decisions.router)
    app.include_router(exports.router)
    app.include_router(retest.router)
    app.include_router(web_routes.router)

    # Evidence StaticFiles only with explicit insecure open-mode (never the default).
    if (not settings.auth_enabled) and settings.allow_insecure_open_mode:
        evidence_root = settings.evidence_dir
        evidence_root.mkdir(parents=True, exist_ok=True)
        app.mount(
            "/evidence",
            StaticFiles(directory=str(evidence_root)),
            name="evidence",
        )
        logger.warning("ALLOW_INSECURE_OPEN_MODE: /evidence is publicly mounted")

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "laya_enabled": settings.laya_enabled,
            "auth_enabled": settings.auth_enabled,
            "database_url_scheme": settings.database_url.split(":", 1)[0],
        }

    @app.exception_handler(Exception)
    async def unhandled(_request: Request, exc: Exception):
        logger.exception("Unhandled error: %s", exc)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return app


app = create_app()
