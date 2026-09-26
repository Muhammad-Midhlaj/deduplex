"""Streaming upload cap + peppered API-key hash."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi import HTTPException, UploadFile
from starlette.datastructures import Headers

from app.auth import _legacy_hash_api_key, hash_api_key
from app.config import get_settings
from app.uploads import save_upload_capped


@pytest.mark.asyncio
async def test_streaming_upload_rejects_oversize(tmp_path, monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-not-for-prod-xx")
    get_settings.cache_clear()

    class _F:
        def __init__(self):
            self._data = b"x" * (1024 * 10)
            self._pos = 0
            self.filename = "big.xml"

        async def read(self, n: int = -1):
            if self._pos >= len(self._data):
                return b""
            if n < 0:
                n = len(self._data) - self._pos
            chunk = self._data[self._pos : self._pos + n]
            self._pos += len(chunk)
            return chunk

    upload = UploadFile(filename="big.xml", file=None)
    upload.file = type("F", (), {})()  # placeholder
    # Use a simple async file-like via UploadFile constructor with SpooledTemporaryFile
    import io
    from starlette.datastructures import UploadFile as SU

    bio = io.BytesIO(b"y" * 5000)
    uf = SU(file=bio, filename="big.xml")
    with pytest.raises(HTTPException) as exc:
        await save_upload_capped(uf, max_bytes=1000, suffix=".xml")
    assert exc.value.status_code == 413
    get_settings.cache_clear()


def test_api_key_hash_is_peppered(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-not-for-prod-xx")
    monkeypatch.setenv("API_KEY_PEPPER", "dedicated-pepper-value-here!!")
    get_settings.cache_clear()
    raw = "some-api-key-value-16"
    h = hash_api_key(raw)
    assert h != hashlib.sha256(raw.encode()).hexdigest()
    assert h != _legacy_hash_api_key(raw)
    assert len(h) == 64
    get_settings.cache_clear()
