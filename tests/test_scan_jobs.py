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
    assert job.profile_name == "sv_t4"
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
