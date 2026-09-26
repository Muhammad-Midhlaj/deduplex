"""Orchestrate scanner file import: store evidence, parse, map assets, group, triage."""

from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import EvidenceFile, ImportBatch, ImportStatus, Observation
from app.schemas import ImportResult
from importers.nessus import parse_nessus
from importers.nmap_xml import parse_nmap_xml
from services.asset_mapping import get_or_create_asset
from services.grouping import attach_observation_to_group, build_duplicate_key
from services.laya_triage import recommend_triage


SUPPORTED_TOOLS = {"nmap", "nessus"}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_tool(filename: str, tool_hint: str | None) -> str:
    if tool_hint:
        t = tool_hint.lower().strip()
        if t in SUPPORTED_TOOLS:
            return t
        raise ValueError(f"Unsupported tool hint: {tool_hint}")
    lower = filename.lower()
    if lower.endswith(".nessus") or "nessus" in lower:
        return "nessus"
    if lower.endswith(".xml") or "nmap" in lower:
        return "nmap"
    raise ValueError(
        f"Cannot detect tool from filename '{filename}'. Pass tool=nmap|nessus."
    )


def store_evidence(
    source_path: Path,
    engagement_id: int,
    original_filename: str,
) -> tuple[Path, str, int]:
    """Copy raw scanner file under data/evidence/<engagement>/<uuid>_filename."""
    settings = get_settings()
    dest_dir = settings.evidence_dir / str(engagement_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(original_filename).name.replace(" ", "_")
    dest = dest_dir / f"{uuid.uuid4().hex}_{safe_name}"
    shutil.copy2(source_path, dest)
    digest = _sha256_file(dest)
    return dest, digest, dest.stat().st_size


def import_scanner_file(
    db: Session,
    *,
    engagement_id: int,
    source_path: Path,
    original_filename: str | None = None,
    tool: str | None = None,
    is_retest: bool = False,
) -> ImportResult:
    original_filename = original_filename or source_path.name
    detected_tool = _detect_tool(original_filename, tool)

    stored_path, digest, size_bytes = store_evidence(
        source_path, engagement_id, original_filename
    )

    batch = ImportBatch(
        engagement_id=engagement_id,
        tool=detected_tool,
        original_filename=original_filename,
        stored_path=str(stored_path),
        status=ImportStatus.PROCESSING,
    )
    db.add(batch)
    db.flush()

    evidence = EvidenceFile(
        import_batch_id=batch.id,
        relative_path=str(stored_path),
        content_type="application/xml",
        sha256=digest,
        size_bytes=size_bytes,
    )
    db.add(evidence)
    db.flush()

    try:
        if detected_tool == "nmap":
            parsed = parse_nmap_xml(stored_path)
        else:
            parsed = parse_nessus(stored_path)

        batch.scan_time = parsed.scan_time
        assets_created = 0
        assets_reused = 0
        groups_touched: set[int] = set()
        warnings = list(parsed.warnings)

        for item in parsed.observations:
            asset, created = get_or_create_asset(
                db,
                engagement_id,
                hostname=item.hostname,
                ip_address=item.ip_address,
                port=item.port,
                protocol=item.protocol,
                service=item.service,
            )
            if created:
                assets_created += 1
            else:
                assets_reused += 1

            triage = recommend_triage(
                severity=item.severity,
                cvss=item.cvss,
                cve=item.cve,
                plugin_output=item.plugin_output,
                description=item.description,
                title=item.title,
                rule_id=item.rule_id,
                hostname=item.hostname or asset.hostname,
                ip_address=item.ip_address or asset.ip_address,
                port=item.port if item.port is not None else asset.port,
                protocol=item.protocol or asset.protocol,
                service=item.service or asset.service,
            )

            dup_key = build_duplicate_key(
                item.tool, item.rule_id, asset.canonical_key
            )
            obs = Observation(
                engagement_id=engagement_id,
                asset_id=asset.id,
                import_batch_id=batch.id,
                evidence_id=evidence.id,
                tool=item.tool,
                rule_id=item.rule_id,
                title=item.title,
                severity=item.severity,
                description=item.description,
                plugin_output=item.plugin_output,
                cve=item.cve,
                cvss=item.cvss,
                original_finding_id=item.original_finding_id,
                scan_time=item.scan_time or parsed.scan_time,
                duplicate_key=dup_key,
                proposed_classification=triage.proposed_classification,
                triage_score=triage.score,
                triage_source=triage.source,
                model_version=triage.model_version,
                is_retest=is_retest,
            )
            db.add(obs)
            db.flush()

            group = attach_observation_to_group(
                db, obs, asset, priority_score=triage.score or 0.0
            )
            groups_touched.add(group.id)

        batch.record_count = len(parsed.observations)
        batch.status = ImportStatus.COMPLETED
        db.add(batch)
        db.commit()
        db.refresh(batch)

        from app.schemas import ImportBatchOut

        return ImportResult(
            import_batch=ImportBatchOut.model_validate(batch),
            observations_created=len(parsed.observations),
            groups_touched=len(groups_touched),
            assets_created=assets_created,
            assets_reused=assets_reused,
            skipped_unparseable=parsed.skipped_unparseable,
            warnings=warnings,
        )
    except Exception as exc:
        batch.status = ImportStatus.FAILED
        batch.error_message = str(exc)
        db.add(batch)
        db.commit()
        raise
