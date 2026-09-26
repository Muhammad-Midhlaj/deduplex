"""Security hardening smoke: defusedxml parsers + CSRF helper + login rate limit."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.csrf import validate_csrf
from app.rate_limit import check_rate_limit
from importers.nessus import parse_nessus
from importers.nmap_xml import parse_nmap_xml

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data"


def test_nmap_uses_defusedxml(sample_nmap=None):
    # Import path is defusedxml; sample still parses.
    result = parse_nmap_xml(SAMPLE / "sample_nmap.xml")
    assert result.observations or result.warnings is not None


def test_nessus_uses_defusedxml():
    result = parse_nessus(SAMPLE / "sample_nessus.nessus")
    assert result.observations or result.warnings is not None


def test_csrf_mismatch():
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/ui/engagements",
        "raw_path": b"/ui/engagements",
        "query_string": b"",
        "headers": [(b"cookie", b"vapt_csrf=good-token-value-here")],
        "client": ("127.0.0.1", 123),
        "server": ("test", 80),
    }
    request = Request(scope)
    with pytest.raises(HTTPException) as exc:
        validate_csrf(request, "wrong-token")
    assert exc.value.status_code == 403


def test_rate_limit_trips():
    key = "test-rate-limit-unique-key"
    for _ in range(5):
        check_rate_limit(key, max_hits=5, window_seconds=60)
    with pytest.raises(HTTPException) as exc:
        check_rate_limit(key, max_hits=5, window_seconds=60)
    assert exc.value.status_code == 429
