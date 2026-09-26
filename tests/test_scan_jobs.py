"""Unit tests for Wave 1 ScanJob rails (mocked binary / subprocess — no real nmap)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.models import ScanJob, ScanJobStatus
from services import scan_jobs as sj


@pytest.fixture()
def app_data(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_APP_DATA_DIR", str(tmp_path / "appdata"))
    # Clear settings cache if used; jobs_root reads paths directly.
    from app.config import get_settings

    get_settings.cache_clear()
    yield tmp_path / "appdata"
    get_settings.cache_clear()


def test_split_targets_whitespace_and_comma():
    assert sj.split_targets("a.com, 10.0.0.1  192.168.0.0/24") == [
        "a.com",
        "10.0.0.1",
        "192.168.0.0/24",
    ]


def test_split_targets_empty_refused():
    with pytest.raises(sj.ScanJobError, match="empty"):
        sj.split_targets("  ,  ")


def test_split_targets_metachar_refused():
    with pytest.raises(sj.ScanJobError, match="metachar"):
        sj.split_targets("127.0.0.1;rm -rf /")


def test_build_nmap_argv_ox_absolute(tmp_path):
    xml = tmp_path / "out" / "scan.xml"
    argv = sj.build_nmap_argv(
        "/usr/bin/nmap",
        ["127.0.0.1"],
        xml_path=xml,
        profile_flags=["-sV", "-T4"],
    )
    assert argv[0] == "/usr/bin/nmap"
    assert "-sV" in argv and "-T4" in argv
    assert "-oX" in argv
    ox_idx = argv.index("-oX")
    assert argv[ox_idx + 1] == str(xml)
    assert argv[-1] == "127.0.0.1"
    assert "shell" not in " ".join(argv).lower()


def test_build_nuclei_argv_jsonl(tmp_path):
    out = tmp_path / "scan.jsonl"
    argv = sj.build_nuclei_argv("/usr/bin/nuclei", ["example.com"], jsonl_path=out)
    assert argv[0] == "/usr/bin/nuclei"
    assert "-jsonl" in argv
    assert "-o" in argv
    assert str(out) in argv
    assert argv[argv.index("-u") + 1] == "example.com"


def test_allowlist_roundtrip(app_data, tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("#!")
    fake.chmod(0o755)
    path = sj.set_allowlisted_binary("nmap", str(fake))
    loaded = sj.load_allowlisted_binaries()
    assert loaded["nmap"] == path
    with patch("services.scan_jobs.shutil.which", return_value=None):
        # Prefer allowlist when PATH miss
        assert sj.resolve_binary("nmap") == path


def test_resolve_binary_registers_from_path(app_data, tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("x")
    fake.chmod(0o755)
    with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
        resolved = sj.resolve_binary("nmap")
    assert Path(resolved) == fake.resolve()
    assert sj.load_allowlisted_binaries()["nmap"] == resolved


def test_create_draft_never_running(db_session, engagement, app_data, tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("x")
    fake.chmod(0o755)
    with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
        job = sj.create_draft_job(
            db_session,
            engagement_id=engagement.id,
            tool="nmap",
            targets_text="127.0.0.1",
        )
    assert job.status == ScanJobStatus.DRAFT
    assert job.profile_name == "st_sv_t4"
    assert "-sT" in job.profile_flags
    assert "-sV" in job.profile_flags


def test_refuse_start_when_another_running(db_session, engagement, app_data, tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("x")
    fake.chmod(0o755)
    with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
        a = sj.create_draft_job(
            db_session, engagement_id=engagement.id, tool="nmap", targets_text="127.0.0.1"
        )
        b = sj.create_draft_job(
            db_session, engagement_id=engagement.id, tool="nmap", targets_text="10.0.0.1"
        )
    # Simulate active job without spawning worker.
    a.status = ScanJobStatus.RUNNING
    db_session.add(a)
    db_session.commit()
    with pytest.raises(sj.ScanJobError, match="already running"):
        sj.start_job(db_session, b.id, spawn_worker=False)


def test_cancel_draft_sets_cancelled(db_session, engagement, app_data, tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("x")
    fake.chmod(0o755)
    with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
        job = sj.create_draft_job(
            db_session, engagement_id=engagement.id, tool="nmap", targets_text="127.0.0.1"
        )
    cancelled = sj.cancel_job(db_session, job.id)
    assert cancelled.status == ScanJobStatus.CANCELLED


def test_start_job_worker_imports_sample_xml(
    db_session, engagement, app_data, tmp_path, sample_nmap, monkeypatch
):
    """Simulate successful nmap by copying sample XML as artifact (no real binary)."""
    fake = tmp_path / "nmap"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)

    with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
        job = sj.create_draft_job(
            db_session, engagement_id=engagement.id, tool="nmap", targets_text="127.0.0.1"
        )

    # Patch SessionLocal used by worker to reuse our in-memory session's engine.
    from app.database import SessionLocal as RealSessionLocal
    from sqlalchemy.orm import sessionmaker

    TestSession = sessionmaker(
        bind=db_session.get_bind(), autoflush=False, autocommit=False, future=True
    )

    class FakeProc:
        def __init__(self):
            self.pid = 4242
            self.returncode = 0

        def poll(self):
            return 0

        def terminate(self):
            pass

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    def fake_popen(argv, **kwargs):
        # Write sample XML to -oX path.
        ox = argv[argv.index("-oX") + 1]
        Path(ox).write_bytes(sample_nmap.read_bytes())
        return FakeProc()

    with (
        patch("services.scan_jobs.subprocess.Popen", side_effect=fake_popen),
        patch("app.database.SessionLocal", TestSession),
        patch.object(sj, "SessionLocal", TestSession, create=True),
    ):
        # Worker imports SessionLocal from app.database inside the function.
        monkeypatch.setattr("app.database.SessionLocal", TestSession)
        sj.start_job(db_session, job.id, spawn_worker=False)
        # Run worker synchronously.
        sj._run_job_worker(job.id)

    db_session.expire_all()
    refreshed = db_session.get(ScanJob, job.id)
    assert refreshed.status == ScanJobStatus.SUCCEEDED
    assert refreshed.import_batch_id is not None


def test_nuclei_jsonl_importer(tmp_path):
    from importers.nuclei_jsonl import parse_nuclei_jsonl

    line = {
        "template-id": "tech-detect",
        "info": {"name": "Tech Detect", "severity": "info", "description": "d"},
        "host": "https://example.com",
        "matched-at": "https://example.com",
        "timestamp": "2026-09-26T12:00:00Z",
    }
    path = tmp_path / "scan.jsonl"
    path.write_text(json.dumps(line) + "\n", encoding="utf-8")
    parsed = parse_nuclei_jsonl(path)
    assert len(parsed.observations) == 1
    obs = parsed.observations[0]
    assert obs.tool == "nuclei"
    assert obs.rule_id == "tech-detect"
    assert obs.severity == "info"


def test_default_nmap_profile_is_connect():
    name, flags = sj.profile_flags_for("nmap", None)
    assert name == "st_sv_t4"
    assert flags == ["-sT", "-sV", "-T4"]


def test_syn_profile_optional():
    name, flags = sj.profile_flags_for("nmap", "ss_sv_t4")
    assert name == "ss_sv_t4"
    assert flags == ["-sS", "-sV", "-T4"]


def test_legacy_sv_t4_aliases_to_connect():
    name, flags = sj.profile_flags_for("nmap", "sv_t4")
    assert "-sT" in flags


def test_nmap_xml_all_ports_unknown(tmp_path):
    xml = tmp_path / "u.xml"
    xml.write_text(
        """<?xml version="1.0"?>
        <nmaprun>
          <host><ports>
            <port protocol="tcp" portid="80"><state state="unknown"/></port>
            <port protocol="tcp" portid="443"><state state="unknown"/></port>
          </ports></host>
        </nmaprun>""",
        encoding="utf-8",
    )
    assert sj.nmap_xml_all_ports_unknown(xml) is True
    xml2 = tmp_path / "o.xml"
    xml2.write_text(
        """<?xml version="1.0"?>
        <nmaprun>
          <host><ports>
            <port protocol="tcp" portid="80"><state state="open"/></port>
          </ports></host>
        </nmaprun>""",
        encoding="utf-8",
    )
    assert sj.nmap_xml_all_ports_unknown(xml2) is False


def test_flags_to_connect_strips_syn():
    assert sj._flags_to_connect(["-sS", "-sV", "-T4"]) == ["-sT", "-sV", "-T4"]


def test_start_job_sets_stdout_log_path(db_session, engagement, app_data, tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("x")
    fake.chmod(0o755)
    with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
        job = sj.create_draft_job(
            db_session, engagement_id=engagement.id, tool="nmap", targets_text="127.0.0.1"
        )
    started = sj.start_job(db_session, job.id, spawn_worker=False)
    assert started.log_path
    assert started.log_path.endswith("stdout.log")
    assert Path(started.log_path).name == sj.STDOUT_LOG_NAME


def test_read_log_chunk_offset_and_legacy_fallback(db_session, engagement, app_data, tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("x")
    fake.chmod(0o755)
    with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
        job = sj.create_draft_job(
            db_session, engagement_id=engagement.id, tool="nmap", targets_text="127.0.0.1"
        )
    job = sj.start_job(db_session, job.id, spawn_worker=False)
    # No file yet → empty chunk, next_offset 0
    empty = sj.read_log_chunk(job, offset=0)
    assert empty["chunk"] == ""
    assert empty["next_offset"] == 0
    assert empty["job_id"] == job.id
    assert empty["eof"] is False  # queued, not terminal
    assert "nmap" in (empty["command_line"] or "")

    # Write minimal log at stdout.log
    log = Path(job.log_path)
    log.parent.mkdir(parents=True, exist_ok=True)
    payload = "# argv: ['nmap']\nhello world\n"
    log.write_text(payload, encoding="utf-8")

    full = sj.read_log_chunk(job, offset=0)
    assert full["chunk"] == payload
    assert full["next_offset"] == len(payload.encode("utf-8"))
    assert full["offset"] == 0
    assert full["log_path"].endswith("stdout.log")

    mid = sj.read_log_chunk(job, offset=full["next_offset"] - 6)
    assert mid["chunk"].endswith("world\n") or "world" in mid["chunk"]

    # Cap: request tiny max via max_bytes
    capped = sj.read_log_chunk(job, offset=0, max_bytes=5)
    assert len(capped["chunk"].encode("utf-8")) <= 5
    assert capped["next_offset"] == 5

    # Legacy scan.log fallback when stdout missing and log_path points elsewhere
    job.status = ScanJobStatus.SUCCEEDED
    db_session.add(job)
    db_session.commit()
    log.unlink()
    legacy = Path(job.job_dir) / sj.LEGACY_LOG_NAME
    legacy.write_text("legacy line\n", encoding="utf-8")
    job.log_path = str(Path(job.job_dir) / "missing.log")
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)
    legacy_read = sj.read_log_chunk(job, offset=0)
    assert "legacy" in legacy_read["chunk"]
    assert legacy_read["eof"] is True
    assert legacy_read["next_offset"] == len("legacy line\n".encode("utf-8"))


def test_format_command_line_quotes_spaces():
    assert "nmap" in sj.format_command_line(["nmap", "-sV", "host name"])
    # shlex.join should quote the host with space
    joined = sj.format_command_line(["nmap", "host name"])
    assert "host name" in joined or "'host name'" in joined or '"host name"' in joined


def test_log_api_offset_via_client(tmp_path, monkeypatch):
    """HTTP: create draft, plant stdout.log, GET /api/scan-jobs/{id}/log."""
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("ALLOW_INSECURE_OPEN_MODE", "false")
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-not-for-prod-xx")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'logapi.db'}")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("VAPT_APP_DATA_DIR", str(tmp_path / "appdata"))

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
    import app.main as main_mod

    main_mod.SessionLocal = database.SessionLocal
    init_db()

    fake = tmp_path / "nmap"
    fake.write_text("x")
    fake.chmod(0o755)

    app = create_app()
    with TestClient(app) as client:
        eng = client.post(
            "/api/engagements", json={"name": "Log Eng", "client": "Lab"}
        )
        assert eng.status_code in (200, 201), eng.text
        eng_id = eng.json()["id"]

        with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
            created = client.post(
                "/api/scan-jobs",
                json={
                    "engagement_id": eng_id,
                    "tool": "nmap",
                    "targets_text": "127.0.0.1",
                },
            )
        assert created.status_code == 201, created.text
        job_id = created.json()["id"]

        # No log yet
        r0 = client.get(f"/api/scan-jobs/{job_id}/log?offset=0")
        assert r0.status_code == 200
        body0 = r0.json()
        assert body0["chunk"] == ""
        assert body0["next_offset"] == 0
        assert body0["job_id"] == job_id
        assert "command_line" in body0

        # Plant log as if start had run
        db = database.SessionLocal()
        try:
            job = db.get(models.ScanJob, job_id)
            job_dir = sj.jobs_root() / str(job_id)
            job_dir.mkdir(parents=True, exist_ok=True)
            log_path = job_dir / sj.STDOUT_LOG_NAME
            content = "# argv: ['nmap', '127.0.0.1']\nscan output here\n"
            log_path.write_text(content, encoding="utf-8")
            job.job_dir = str(job_dir)
            job.log_path = str(log_path)
            job.artifact_path = str(job_dir / "scan.xml")
            job.status = models.ScanJobStatus.RUNNING
            db.add(job)
            db.commit()
        finally:
            db.close()

        r1 = client.get(f"/api/scan-jobs/{job_id}/log?offset=0")
        assert r1.status_code == 200
        body1 = r1.json()
        assert "scan output here" in body1["chunk"]
        assert body1["next_offset"] > 0
        assert body1["eof"] is False
        assert body1["status"] == "running"

        r2 = client.get(
            f"/api/scan-jobs/{job_id}/log?offset={body1['next_offset']}"
        )
        assert r2.status_code == 200
        assert r2.json()["chunk"] == ""
        assert r2.json()["next_offset"] == body1["next_offset"]

        missing = client.get("/api/scan-jobs/999999/log?offset=0")
        assert missing.status_code == 404

    get_settings.cache_clear()




@pytest.fixture()
def auth_client(tmp_path, monkeypatch):
    """Local copy of test_auth.auth_client for ACL checks on scan-job log API."""
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("BOOTSTRAP_API_KEY", "bootstrap-secret-key-32charsXX")
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-not-for-prod-xx")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'auth-scan.db'}")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence-auth-scan"))

    from app.config import get_settings

    get_settings.cache_clear()

    import app.database as database
    from app import models  # noqa: F401
    from app.auth import ensure_bootstrap_principal
    from app.database import init_db

    database.engine = database._make_engine()
    database.SessionLocal = sessionmaker(
        bind=database.engine, autoflush=False, autocommit=False, future=True
    )
    # Keep main.lifespan SessionLocal in sync if main was already imported.
    import app.main as main_mod

    main_mod.SessionLocal = database.SessionLocal
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


def test_log_api_acl_403(auth_client, tmp_path, monkeypatch):
    """Non-admin without ACL gets 403 on log endpoint (same as other scan-job routes)."""
    ADMIN_KEY = "bootstrap-secret-key-32charsXX"
    admin = {"X-API-Key": ADMIN_KEY}
    bob_key = "bob-log-api-key-16c"

    monkeypatch.setenv("VAPT_APP_DATA_DIR", str(tmp_path / "appdata-acl"))
    from app.config import get_settings

    get_settings.cache_clear()

    e1 = auth_client.post("/api/engagements", headers=admin, json={"name": "E-Log-1"}).json()["id"]
    e2 = auth_client.post("/api/engagements", headers=admin, json={"name": "E-Log-2"}).json()["id"]

    create_principal = auth_client.post(
        "/api/auth/principals",
        headers=admin,
        json={"name": "bob-log", "api_key": bob_key, "is_admin": False},
    )
    assert create_principal.status_code == 201, create_principal.text

    grant = auth_client.post(
        "/api/auth/acl",
        headers=admin,
        json={"principal_name": "bob-log", "engagement_id": e1},
    )
    assert grant.status_code == 201, grant.text

    fake = tmp_path / "nmap"
    fake.write_text("x")
    fake.chmod(0o755)
    with patch("services.scan_jobs.shutil.which", return_value=str(fake)):
        job_e2 = auth_client.post(
            "/api/scan-jobs",
            headers=admin,
            json={"engagement_id": e2, "tool": "nmap", "targets_text": "127.0.0.1"},
        )
    assert job_e2.status_code == 201, job_e2.text
    job_id = job_e2.json()["id"]

    denied = auth_client.get(
        f"/api/scan-jobs/{job_id}/log?offset=0",
        headers={"X-API-Key": bob_key},
    )
    assert denied.status_code == 403

    ok = auth_client.get(
        f"/api/scan-jobs/{job_id}/log?offset=0",
        headers=admin,
    )
    assert ok.status_code == 200
