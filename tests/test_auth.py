"""API-key auth + engagement ACL smoke tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ADMIN_KEY = "bootstrap-secret-key-32charsXX"


@pytest.fixture()
def auth_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("BOOTSTRAP_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-not-for-prod-xx")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'auth.db'}")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))

    from app.config import get_settings

    get_settings.cache_clear()

    import app.database as database
    from app import models  # noqa: F401 — register metadata
    from app.auth import ensure_bootstrap_principal
    from app.database import Base, init_db

    database.engine = database._make_engine()
    database.SessionLocal = sessionmaker(
        bind=database.engine, autoflush=False, autocommit=False, future=True
    )
    init_db()
    db = database.SessionLocal()
    try:
        ensure_bootstrap_principal(db)
    finally:
        db.close()

    from app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client

    get_settings.cache_clear()


def _admin_headers():
    return {"X-API-Key": ADMIN_KEY}


def test_health_open_when_auth_on(auth_client):
    r = auth_client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["auth_enabled"] is True


def test_engagements_require_key(auth_client):
    r = auth_client.get("/api/engagements")
    assert r.status_code == 401


def test_admin_bootstrap_lists_and_creates(auth_client):
    headers = _admin_headers()
    r = auth_client.get("/api/engagements", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []

    created = auth_client.post(
        "/api/engagements",
        headers=headers,
        json={"name": "ACL Demo", "client": "Lab"},
    )
    assert created.status_code == 201, created.text
    eng_id = created.json()["id"]

    listed = auth_client.get("/api/engagements", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["id"] == eng_id


def test_non_admin_acl_scopes_engagements(auth_client):
    admin = _admin_headers()
    e1 = auth_client.post("/api/engagements", headers=admin, json={"name": "E1"}).json()["id"]
    e2 = auth_client.post("/api/engagements", headers=admin, json={"name": "E2"}).json()["id"]

    create = auth_client.post(
        "/api/auth/principals",
        headers=admin,
        json={"name": "alice", "api_key": "alice-api-key-16chars", "is_admin": False},
    )
    assert create.status_code == 201, create.text

    grant = auth_client.post(
        "/api/auth/acl",
        headers=admin,
        json={"principal_name": "alice", "engagement_id": e1},
    )
    assert grant.status_code == 201, grant.text

    alice = {"X-API-Key": "alice-api-key-16chars"}
    listed = auth_client.get("/api/engagements", headers=alice)
    assert listed.status_code == 200
    ids = {row["id"] for row in listed.json()}
    assert ids == {e1}

    denied = auth_client.get(f"/api/engagements/{e2}", headers=alice)
    assert denied.status_code == 403

    ok = auth_client.get(f"/api/engagements/{e1}", headers=alice)
    assert ok.status_code == 200


def test_session_login_cookie(auth_client):
    r = auth_client.post("/api/auth/login", json={"api_key": ADMIN_KEY})
    assert r.status_code == 200, r.text
    assert "vapt_session" in r.cookies
    me = auth_client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["is_admin"] is True


def test_refuses_default_session_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("BOOTSTRAP_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("SESSION_SECRET", "dev-only-change-me")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'bad.db'}")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))

    from app.config import get_settings, validate_security_settings, InsecureConfigError

    get_settings.cache_clear()
    settings = get_settings()
    try:
        validate_security_settings(settings)
        assert False, "expected InsecureConfigError"
    except InsecureConfigError:
        pass
    finally:
        get_settings.cache_clear()
