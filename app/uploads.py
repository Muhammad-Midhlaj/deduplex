"""Stream uploads to a temp file with an early size cap (no full buffer first)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import HTTPException, UploadFile


CHUNK_SIZE = 64 * 1024


async def save_upload_capped(file: UploadFile, *, max_bytes: int, suffix: str) -> Path:
    """Write the upload to a temp path, aborting as soon as max_bytes is exceeded."""
    tmp_path: Path | None = None
    total = 0
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp_path = Path(tmp.name)
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds max size of {max_bytes} bytes",
                    )
                tmp.write(chunk)
        return tmp_path
    except Exception:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
        raise
