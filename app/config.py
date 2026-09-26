"""Application configuration via environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.paths import (
    get_app_data_dir,
    get_default_database_url,
    get_default_evidence_dir,
    get_project_root,
    get_templates_dir,
)

# Re-exported so existing imports (`from app.config import PROJECT_ROOT`) keep working.
# Resolved once at import — desktop_app sets VAPT_* env vars *before* importing app.
PROJECT_ROOT = get_project_root()
TEMPLATES_DIR = get_templates_dir()

# Known-insecure default — refused when AUTH_ENABLED=true.
DEFAULT_SESSION_SECRET = "dev-only-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env") if (PROJECT_ROOT / ".env").is_file() else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Deduplex"
    database_url: str = get_default_database_url()
    evidence_dir: Path = get_default_evidence_dir()
    # Feature flag: when True, call Laya (remote or local SDK); otherwise rules-only.
    laya_enabled: bool = False
    # Optional remote triage endpoint. Tried first when set and reachable.
    laya_service_url: str = "http://127.0.0.1:8090"
    # Hugging Face repo / subfolder for local SDK (typed-decisions = 1024 context).
    laya_repo: str = "convaiinnovations/laya"
    laya_subfolder: str = "typed-decisions"
    # cpu | cuda | auto (auto lets the SDK pick cuda/mps/cpu).
    laya_device: str = "auto"
    # If True, load the agent at first recommend_triage call (still lazy at import).
    laya_preload: bool = False
    # Model version string recorded with Laya recommendations.
    laya_model_version: str = "laya-typed-decisions"
    # Last-resort deterministic stub (off by default; real SDK path is preferred).
    laya_use_stub: bool = False
    # Rules fallback model version label.
    rules_model_version: str = "rules-v1"
    # Optional local fine-tuned checkpoint directory (laya.Agent(path)).
    # When set, inference loads this instead of Hub repo/subfolder.
    laya_local_checkpoint: str = ""
    # Auth (API key / session + engagement ACLs). Default off for local lab only.
    auth_enabled: bool = False
    # When auth_enabled, seed/refresh an admin principal with this raw key (never log it).
    bootstrap_api_key: str = ""
    # HMAC secret for signed session cookies (must not be the default when auth is on).
    session_secret: str = DEFAULT_SESSION_SECRET
    # Explicit opt-in: allow unauthenticated /evidence StaticFiles when auth is off.
    # Without this, evidence is never publicly mounted (fail-closed for C-1).
    allow_insecure_open_mode: bool = False
    # When auth is on, OpenAPI /docs is hidden unless this is true.
    expose_api_docs: bool = False
    # Max scanner upload size (bytes) for API/UI imports.
    max_upload_bytes: int = 32 * 1024 * 1024
    # Set Secure flag on session cookies (enable behind HTTPS).
    session_cookie_secure: bool = False
    # Pepper for API-key HMAC (defaults to SESSION_SECRET when empty).
    api_key_pepper: str = ""


class InsecureConfigError(RuntimeError):
    """Raised when AUTH_ENABLED is on with weak/missing secrets."""


def validate_security_settings(settings: Settings) -> None:
    """Fail closed for auth misconfiguration (code review C-1 / C-2)."""
    if not settings.auth_enabled:
        return
    secret = (settings.session_secret or "").strip()
    if not secret or secret == DEFAULT_SESSION_SECRET:
        raise InsecureConfigError(
            "AUTH_ENABLED=true requires a non-default SESSION_SECRET "
            "(do not use the built-in dev placeholder)."
        )
    if len(secret) < 32:
        raise InsecureConfigError("SESSION_SECRET must be at least 32 characters when AUTH_ENABLED=true.")
    key = (settings.bootstrap_api_key or "").strip()
    if len(key) < 16:
        raise InsecureConfigError(
            "AUTH_ENABLED=true requires BOOTSTRAP_API_KEY with at least 16 characters."
        )


def _ensure_sqlite_parent(database_url: str) -> None:
    if not database_url.startswith("sqlite:///"):
        return
    raw = database_url[len("sqlite:///") :]
    # Ignore sqlite:///:memory: and empty
    if not raw or raw == ":memory:":
        return
    Path(raw).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    _ensure_sqlite_parent(settings.database_url)
    # Lab convenience: keep <project>/data when not using a custom app-data dir.
    try:
        get_app_data_dir().mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return settings
