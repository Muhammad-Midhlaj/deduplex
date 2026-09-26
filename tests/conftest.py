"""Pytest fixtures — isolated SQLite DB per test session/function."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import Base  # noqa: E402
from app import models  # noqa: E402, F401
from app.models import Engagement  # noqa: E402


SAMPLE_DIR = PROJECT_ROOT / "sample_data"


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def engagement(db_session):
    eng = Engagement(name="Test Engagement", client="Lab")
    db_session.add(eng)
    db_session.commit()
    db_session.refresh(eng)
    return eng


@pytest.fixture()
def sample_nmap():
    return SAMPLE_DIR / "sample_nmap.xml"


@pytest.fixture()
def sample_nessus():
    return SAMPLE_DIR / "sample_nessus.nessus"


@pytest.fixture()
def sample_nmap_retest():
    return SAMPLE_DIR / "sample_nmap_retest.xml"
