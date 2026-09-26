"""Pydantic schemas for API request/response bodies."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models import DecisionValue, ImportStatus, ScanJobStatus


class EngagementCreate(BaseModel):
    name: str
    client: str | None = None
    description: str | None = None


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    client: str | None
    description: str | None
    created_at: datetime


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    hostname: str | None
    ip_address: str | None
    port: int | None
    protocol: str | None
    service: str | None
    canonical_key: str


class ObservationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    asset_id: int
    finding_group_id: int | None
    tool: str
    rule_id: str
    title: str | None
    severity: str | None
    description: str | None
    plugin_output: str | None
    cve: str | None
    cvss: float | None
    original_finding_id: str | None
    scan_time: datetime | None
    duplicate_key: str
    proposed_classification: str | None
    triage_score: float | None
    triage_source: str | None
    model_version: str | None
    is_retest: bool
    retest_of_observation_id: int | None
    evidence_id: int | None


class DecisionCreate(BaseModel):
    decision: DecisionValue
    reason: str | None = None
    analyst: str | None = "analyst"


class DecisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_group_id: int
    decision: DecisionValue
    reason: str | None
    analyst: str | None
    model_version_at_decision: str | None
    created_at: datetime


class FindingGroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    group_key: str
    tool: str
    rule_id: str
    asset_id: int
    title: str | None
    severity: str | None
    priority_score: float
    queue_status: DecisionValue
    observation_count: int = 0
    asset: AssetOut | None = None


class FindingGroupDetail(FindingGroupOut):
    observations: list[ObservationOut] = Field(default_factory=list)
    decisions: list[DecisionOut] = Field(default_factory=list)


class ImportBatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    tool: str
    original_filename: str
    stored_path: str
    status: ImportStatus
    record_count: int
    error_message: str | None
    scan_time: datetime | None
    created_at: datetime


class ImportResult(BaseModel):
    import_batch: ImportBatchOut
    observations_created: int
    groups_touched: int
    assets_created: int
    assets_reused: int
    skipped_unparseable: int = 0
    warnings: list[str] = Field(default_factory=list)


class RetestCompareRequest(BaseModel):
    engagement_id: int
    retest_import_batch_id: int
    baseline_import_batch_id: int | None = None


class RetestMatchOut(BaseModel):
    retest_observation_id: int
    matched_observation_id: int | None
    match_method: str | None
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class RetestCompareResult(BaseModel):
    matches: list[RetestMatchOut]
    summary: dict[str, int]


class ScanJobCreate(BaseModel):
    engagement_id: int
    tool: str = "nmap"
    targets_text: str
    profile_name: str | None = None
    binary_path: str | None = None
    timeout_seconds: int = 3600


class ScanJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    engagement_id: int
    tool: str
    status: ScanJobStatus
    targets_text: str
    profile_name: str
    profile_flags: str
    binary_path: str | None
    job_dir: str | None
    artifact_path: str | None
    log_path: str | None
    pid: int | None
    timeout_seconds: int
    error_message: str | None
    import_batch_id: int | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
