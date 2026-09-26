"""Simple in-process sliding-window rate limiter (MVP)."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request

_lock = Lock()
_hits: dict[str, deque[float]] = defaultdict(deque)


def check_rate_limit(
    key: str,
    *,
    max_hits: int,
    window_seconds: float,
) -> None:
    now = time.monotonic()
    with _lock:
        q = _hits[key]
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(q) >= max_hits:
            raise HTTPException(status_code=429, detail="Too many requests; try again later")
        q.append(now)


def client_key(request: Request, suffix: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{suffix}"
