"""Exact duplicate grouping by tool + rule + asset.

Reimport / retest identity (DefectDojo-inspired field pattern, reimplemented):
  - duplicate_key / group_key: tool|rule_id|asset.canonical_key
  - finding_hash: sha256 of that key (compact stable hash for APIs/exports)
  - Nessus also sets original_finding_id = nessus:plugin:host:proto:port

Re-importing the same findings creates new Observation rows (evidence trail)
but attaches them to the existing FindingGroup via group_key — groups stay
stable; observation count grows.
"""

from __future__ import annotations

import hashlib

from sqlalchemy.orm import Session

from app.models import Asset, FindingGroup, Observation


def build_duplicate_key(tool: str, rule_id: str, asset_canonical_key: str) -> str:
    """Exact duplicate key used for grouping. Must match across imports."""
    return f"{tool}|{rule_id}|{asset_canonical_key}"


def build_finding_hash(tool: str, rule_id: str, asset_canonical_key: str) -> str:
    """Stable reimport hash over the same fields as duplicate_key.

    Inspired by DefectDojo's hash_code idea (hash of selected finding fields);
    we reimplement under our own license rather than vendoring their code.
    Material is UTF-8 of build_duplicate_key(...).
    """
    material = build_duplicate_key(tool, rule_id, asset_canonical_key)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def get_or_create_group(
    db: Session,
    *,
    engagement_id: int,
    tool: str,
    rule_id: str,
    asset: Asset,
    title: str | None,
    severity: str | None,
    priority_score: float = 0.0,
) -> tuple[FindingGroup, bool]:
    group_key = build_duplicate_key(tool, rule_id, asset.canonical_key)
    existing = (
        db.query(FindingGroup)
        .filter(
            FindingGroup.engagement_id == engagement_id,
            FindingGroup.group_key == group_key,
        )
        .one_or_none()
    )
    if existing:
        if priority_score > (existing.priority_score or 0):
            existing.priority_score = priority_score
        if title and not existing.title:
            existing.title = title
        if severity and not existing.severity:
            existing.severity = severity
        db.add(existing)
        return existing, False

    group = FindingGroup(
        engagement_id=engagement_id,
        group_key=group_key,
        tool=tool,
        rule_id=rule_id,
        asset_id=asset.id,
        title=title,
        severity=severity,
        priority_score=priority_score,
    )
    db.add(group)
    db.flush()
    return group, True


def attach_observation_to_group(
    db: Session,
    observation: Observation,
    asset: Asset,
    priority_score: float = 0.0,
) -> FindingGroup:
    group, _ = get_or_create_group(
        db,
        engagement_id=observation.engagement_id,
        tool=observation.tool,
        rule_id=observation.rule_id,
        asset=asset,
        title=observation.title,
        severity=observation.severity,
        priority_score=priority_score,
    )
    observation.finding_group_id = group.id
    observation.duplicate_key = group.group_key
    db.add(observation)
    return group
