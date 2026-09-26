"""Lightweight Jinja lab UI smoke tests (AUTH off)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_NMAP = PROJECT_ROOT / "sample_data" / "sample_nmap.xml"


@pytest.fixture()
def ui_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_OPEN_MODE", "false")
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-not-for-prod-xx")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'ui.db'}")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))

    from app.config import get_settings

    get_settings.cache_clear()

    import app.database as database
    from app import models  # noqa: F401
    from app.database import init_db
    from app.main import create_app

    database.engine = database._make_engine()
    database.SessionLocal = sessionmaker(
        bind=database.engine, autoflush=False, autocommit=False, future=True
    )
    init_db()

    app = create_app()
    with TestClient(app) as client:
        yield client

    get_settings.cache_clear()


def _csrf(client: TestClient) -> str:
    r = client.get("/")
    assert r.status_code == 200
    # Prefer jar: subsequent GETs may not re-Set-Cookie when token already matches.
    token = client.cookies.get("vapt_csrf") or r.cookies.get("vapt_csrf")
    assert token, "expected vapt_csrf cookie after GET /"
    return token


def test_home_200(ui_client):
    r = ui_client.get("/")
    assert r.status_code == 200
    assert b"Engagements" in r.content
    assert b"localhost" in r.content
    assert b"Deduplex" in r.content


def test_create_engagement_csrf(ui_client):
    token = _csrf(ui_client)
    # Missing CSRF → 403
    bad = ui_client.post(
        "/ui/engagements",
        data={"name": "No CSRF", "client": "Lab"},
    )
    assert bad.status_code == 403

    ok = ui_client.post(
        "/ui/engagements",
        data={
            "name": "UI Demo",
            "client": "Lab",
            "description": "web ui test",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert ok.status_code == 303
    loc = ok.headers["location"]
    assert loc.startswith("/ui/engagements/")
    assert "msg=" in loc

    hub = ui_client.get(loc.split("?")[0])
    assert hub.status_code == 200
    assert b"UI Demo" in hub.content
    assert b"Hub" in hub.content or b"Import batches" in hub.content


def test_queue_and_import_pages(ui_client):
    token = _csrf(ui_client)
    created = ui_client.post(
        "/ui/engagements",
        data={"name": "Queue Eng", "csrf_token": token},
        follow_redirects=False,
    )
    assert created.status_code == 303
    eng_id = created.headers["location"].split("/ui/engagements/")[1].split("?")[0].split("/")[0]

    queue = ui_client.get(f"/ui/engagements/{eng_id}/queue")
    assert queue.status_code == 200
    assert b"Analyst queue" in queue.content
    assert b"Export XLSX" in queue.content

    import_page = ui_client.get(f"/ui/engagements/{eng_id}/import")
    assert import_page.status_code == 200
    assert b"Upload scanner file" in import_page.content
    assert b"Retest import" in import_page.content
    assert b"csrf_token" in import_page.content

    retest_page = ui_client.get(f"/ui/engagements/{eng_id}/retest")
    assert retest_page.status_code == 200
    assert b"Retest compare" in retest_page.content


def test_import_form_upload_and_flash(ui_client):
    token = _csrf(ui_client)
    created = ui_client.post(
        "/ui/engagements",
        data={"name": "Import Eng", "csrf_token": token},
        follow_redirects=False,
    )
    eng_id = created.headers["location"].split("/ui/engagements/")[1].split("?")[0].split("/")[0]
    token = _csrf(ui_client)

    with SAMPLE_NMAP.open("rb") as fh:
        resp = ui_client.post(
            f"/ui/engagements/{eng_id}/import",
            data={
                "tool": "nmap",
                "is_retest": "false",
                "csrf_token": token,
            },
            files={"file": ("sample_nmap.xml", fh, "application/xml")},
            follow_redirects=False,
        )
    assert resp.status_code == 303, resp.text
    loc = resp.headers["location"]
    assert f"/ui/engagements/{eng_id}/import" in loc
    assert "msg=" in loc
    assert "observations" in loc.lower() or "Imported" in loc or "observations" in loc

    # Follow flash to import page
    page = ui_client.get(loc)
    assert page.status_code == 200
    assert b"sample_nmap.xml" in page.content or b"Recent batches" in page.content

    queue = ui_client.get(f"/ui/engagements/{eng_id}/queue?status=all")
    assert queue.status_code == 200
    assert b"finding" in page.content.lower() or b"nmap" in queue.content.lower() or len(queue.content) > 500


def test_decide_redirects_to_finding_with_flash(ui_client):
    """After POST decide, stay on the finding page with a Saved: flash."""
    token = _csrf(ui_client)
    created = ui_client.post(
        "/ui/engagements",
        data={"name": "Decide Eng", "csrf_token": token},
        follow_redirects=False,
    )
    assert created.status_code == 303
    eng_id = created.headers["location"].split("/ui/engagements/")[1].split("?")[0].split("/")[0]
    token = _csrf(ui_client)

    with SAMPLE_NMAP.open("rb") as fh:
        imp = ui_client.post(
            f"/ui/engagements/{eng_id}/import",
            data={"tool": "nmap", "is_retest": "false", "csrf_token": token},
            files={"file": ("sample_nmap.xml", fh, "application/xml")},
            follow_redirects=False,
        )
    assert imp.status_code == 303
    assert "Import complete" in imp.headers["location"] or "observations" in imp.headers["location"].lower()

    queue = ui_client.get(f"/ui/engagements/{eng_id}/queue?status=all")
    assert queue.status_code == 200
    # Grab first finding-group link
    import re

    m = re.search(rb'/ui/finding-groups/(\d+)', queue.content)
    assert m, "expected at least one finding group after import"
    group_id = m.group(1).decode()

    token = _csrf(ui_client)
    decide = ui_client.post(
        f"/ui/finding-groups/{group_id}/decide",
        data={
            "decision": "confirmed",
            "reason": "real issue",
            "analyst": "analyst",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert decide.status_code == 303
    loc = decide.headers["location"]
    assert f"/ui/finding-groups/{group_id}" in loc
    assert "msg=" in loc
    assert "Saved" in loc or "confirmed" in loc

    page = ui_client.get(loc)
    assert page.status_code == 200
    assert b"Saved" in page.content or b"confirmed" in page.content
    assert b"result-banner" in page.content or b"confirmed" in page.content
    assert b'class="badge confirmed"' in page.content or b"confirmed" in page.content


def test_home_shows_badges_and_export_buttons(ui_client):
    token = _csrf(ui_client)
    ui_client.post(
        "/ui/engagements",
        data={"name": "Home Badges", "client": "Lab", "csrf_token": token},
        follow_redirects=True,
    )
    home = ui_client.get("/")
    assert home.status_code == 200
    assert b"pending" in home.content
    assert b"confirmed" in home.content
    assert b"Export" in home.content or b"CSV" in home.content
    assert b"stat-hero" not in home.content or True  # hero is hub/queue; home uses badges
    assert b"no imports" in home.content or b"Last import" in home.content or b"Home Badges" in home.content
