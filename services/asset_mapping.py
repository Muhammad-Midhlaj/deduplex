"""Asset canonicalization and get-or-create within an engagement."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Asset


def build_canonical_key(
    *,
    ip_address: str | None,
    hostname: str | None,
    port: int | None,
    protocol: str | None,
) -> str:
    """Build a stable asset key for exact matching.

    Format: host|ip|proto|port  (empty segments allowed).
    Host-level (no port) assets omit port/proto trailing segments consistency:
    always four fields so keys remain comparable.
    """
    host = (hostname or "").strip().lower()
    ip = (ip_address or "").strip().lower()
    proto = (protocol or "").strip().lower() if port is not None else ""
    port_s = str(port) if port is not None else ""
    # Prefer IP as primary identity when present; keep hostname for display.
    return f"{host}|{ip}|{proto}|{port_s}"


def get_or_create_asset(
    db: Session,
    engagement_id: int,
    *,
    hostname: str | None,
    ip_address: str | None,
    port: int | None,
    protocol: str | None,
    service: str | None = None,
) -> tuple[Asset, bool]:
    """Return (asset, created)."""
    key = build_canonical_key(
        ip_address=ip_address,
        hostname=hostname,
        port=port,
        protocol=protocol,
    )
    existing = (
        db.query(Asset)
        .filter(Asset.engagement_id == engagement_id, Asset.canonical_key == key)
        .one_or_none()
    )
    if existing:
        # Enrich empty fields if later import has more detail.
        changed = False
        if hostname and not existing.hostname:
            existing.hostname = hostname
            changed = True
        if ip_address and not existing.ip_address:
            existing.ip_address = ip_address
            changed = True
        if service and not existing.service:
            existing.service = service
            changed = True
        if changed:
            db.add(existing)
        return existing, False

    asset = Asset(
        engagement_id=engagement_id,
        hostname=hostname,
        ip_address=ip_address,
        port=port,
        protocol=protocol,
        service=service,
        canonical_key=key,
    )
    db.add(asset)
    db.flush()
    return asset, True
