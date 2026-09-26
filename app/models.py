"""SQLAlchemy models for engagements, assets, observations, evidence, decisions, imports."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DecisionValue(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    DEFER = "defer"
    INFORMATIONAL = "informational"


class ImportStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    client: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    assets: Mapped[list[Asset]] = relationship(back_populates="engagement")
    observations: Mapped[list[Observation]] = relationship(back_populates="engagement")
    imports: Mapped[list[ImportBatch]] = relationship(back_populates="engagement")
    finding_groups: Mapped[list[FindingGroup]] = relationship(back_populates="engagement")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="engagement")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("engagement_id", "canonical_key", name="uq_asset_engagement_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(32))
    service: Mapped[str | None] = mapped_column(String(128))
    # Normalized key used for exact asset matching within an engagement.
    canonical_key: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="assets")
    observations: Mapped[list[Observation]] = relationship(back_populates="asset")


class ImportBatch(Base):
    __tablename__ = "import_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)  # nmap | nessus
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[ImportStatus] = mapped_column(
        Enum(ImportStatus), default=ImportStatus.PENDING, nullable=False
    )
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    scan_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="imports")
    evidence_files: Mapped[list[EvidenceFile]] = relationship(back_populates="import_batch")
    observations: Mapped[list[Observation]] = relationship(back_populates="import_batch")


class EvidenceFile(Base):
    __tablename__ = "evidence_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    import_batch_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id"), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(128))
    sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    import_batch: Mapped[ImportBatch] = relationship(back_populates="evidence_files")
    observations: Mapped[list[Observation]] = relationship(back_populates="evidence")


class FindingGroup(Base):
    """Exact-duplicate group keyed by tool + rule + asset within an engagement."""

    __tablename__ = "finding_groups"
    __table_args__ = (
        UniqueConstraint("engagement_id", "group_key", name="uq_finding_group_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    group_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[str | None] = mapped_column(String(32))
    # Highest prioritization score among members (rules / Laya stub).
    priority_score: Mapped[float] = mapped_column(Float, default=0.0)
    queue_status: Mapped[DecisionValue] = mapped_column(
        Enum(DecisionValue), default=DecisionValue.PENDING, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    engagement: Mapped[Engagement] = relationship(back_populates="finding_groups")
    asset: Mapped[Asset] = relationship()
    observations: Mapped[list[Observation]] = relationship(back_populates="finding_group")
    decisions: Mapped[list[AnalystDecision]] = relationship(back_populates="finding_group")


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    import_batch_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id"), nullable=False)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence_files.id"))
    finding_group_id: Mapped[int | None] = mapped_column(ForeignKey("finding_groups.id"))

    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[str | None] = mapped_column(String(32))
    description: Mapped[str | None] = mapped_column(Text)
    plugin_output: Mapped[str | None] = mapped_column(Text)
    cve: Mapped[str | None] = mapped_column(String(128))
    cvss: Mapped[float | None] = mapped_column(Float)
    # Scanner-native finding identifier (used for retest matching).
    original_finding_id: Mapped[str | None] = mapped_column(String(255))
    scan_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Exact duplicate key: tool|rule_id|asset.canonical_key
    duplicate_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    proposed_classification: Mapped[str | None] = mapped_column(String(64))
    triage_score: Mapped[float | None] = mapped_column(Float)
    triage_source: Mapped[str | None] = mapped_column(String(64))  # rules | laya | abstain
    model_version: Mapped[str | None] = mapped_column(String(64))
    # Link to a prior finding this retest observation is compared against.
    retest_of_observation_id: Mapped[int | None] = mapped_column(ForeignKey("observations.id"))
    is_retest: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="observations")
    asset: Mapped[Asset] = relationship(back_populates="observations")
    import_batch: Mapped[ImportBatch] = relationship(back_populates="observations")
    evidence: Mapped[EvidenceFile | None] = relationship(back_populates="observations")
    finding_group: Mapped[FindingGroup | None] = relationship(back_populates="observations")
    retest_of: Mapped[Observation | None] = relationship(remote_side="Observation.id")


class AnalystDecision(Base):
    __tablename__ = "analyst_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_group_id: Mapped[int] = mapped_column(
        ForeignKey("finding_groups.id"), nullable=False
    )
    decision: Mapped[DecisionValue] = mapped_column(Enum(DecisionValue), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    analyst: Mapped[str | None] = mapped_column(String(128))
    model_version_at_decision: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding_group: Mapped[FindingGroup] = relationship(back_populates="decisions")


class ApiPrincipal(Base):
    """API principal authenticated by hashed API key (first-cut auth)."""

    __tablename__ = "api_principals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    acls: Mapped[list[EngagementAcl]] = relationship(back_populates="principal")


class EngagementAcl(Base):
    """Engagement-scoped access for a non-admin principal."""

    __tablename__ = "engagement_acls"
    __table_args__ = (
        UniqueConstraint("principal_id", "engagement_id", name="uq_principal_engagement"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal_id: Mapped[int] = mapped_column(ForeignKey("api_principals.id"), nullable=False)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    principal: Mapped[ApiPrincipal] = relationship(back_populates="acls")


class ScanJobStatus(str, enum.Enum):
    DRAFT = "draft"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanJob(Base):
    """User-started local scanner run (Nmap Wave 1; Nuclei Wave 1b). Never auto-starts."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)  # nmap | nuclei
    status: Mapped[ScanJobStatus] = mapped_column(
        Enum(ScanJobStatus), default=ScanJobStatus.DRAFT, nullable=False
    )
    targets_text: Mapped[str] = mapped_column(Text, nullable=False)
    profile_name: Mapped[str] = mapped_column(String(64), default="sv_t4", nullable=False)
    profile_flags: Mapped[str] = mapped_column(String(512), default="-sV -T4", nullable=False)
    binary_path: Mapped[str | None] = mapped_column(String(1024))
    job_dir: Mapped[str | None] = mapped_column(String(1024))
    artifact_path: Mapped[str | None] = mapped_column(String(1024))
    log_path: Mapped[str | None] = mapped_column(String(1024))
    pid: Mapped[int | None] = mapped_column(Integer)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    import_batch_id: Mapped[int | None] = mapped_column(ForeignKey("import_batches.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    engagement: Mapped[Engagement] = relationship(back_populates="scan_jobs")
    import_batch: Mapped[ImportBatch | None] = relationship()
