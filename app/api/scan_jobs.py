"""API for local scanner ScanJobs (Nmap Wave 1 / Nuclei Wave 1b)."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import Principal, get_current_principal, require_engagement_access
from app.database import get_db
from app.models import Engagement, ScanJob
from app.schemas import ScanJobCreate, ScanJobOut
from services.scan_jobs import (
    ScanJobError,
    binary_on_path,
    cancel_job,
    create_draft_job,
    list_jobs_for_engagement,
    start_job,
)

router = APIRouter(prefix="/api/scan-jobs", tags=["scan-jobs"])


@router.get("/binaries")
def scanner_binaries_status(
    principal: Principal = Depends(get_current_principal),
):
    """Report whether nmap/nuclei resolve on PATH (no secrets)."""
    _ = principal
    return {
        "nmap": binary_on_path("nmap"),
        "nuclei": binary_on_path("nuclei"),
    }


@router.post("", response_model=ScanJobOut, status_code=201)
def create_scan_job(
    body: ScanJobCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    eng = db.get(Engagement, body.engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(body.engagement_id, principal)
    try:
        job = create_draft_job(
            db,
            engagement_id=body.engagement_id,
            tool=body.tool,
            targets_text=body.targets_text,
            profile_name=body.profile_name,
            binary_override=body.binary_path,
            timeout_seconds=body.timeout_seconds,
        )
    except ScanJobError as exc:
        raise HTTPException(400, str(exc)) from exc
    return job


@router.get("/engagement/{engagement_id}", response_model=list[ScanJobOut])
def list_scan_jobs(
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    require_engagement_access(engagement_id, principal)
    return list_jobs_for_engagement(db, engagement_id)


@router.get("/{job_id}", response_model=ScanJobOut)
def get_scan_job(
    job_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, "Scan job not found")
    require_engagement_access(job.engagement_id, principal)
    return job


@router.post("/{job_id}/start", response_model=ScanJobOut)
def start_scan_job(
    job_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, "Scan job not found")
    require_engagement_access(job.engagement_id, principal)
    try:
        return start_job(db, job_id)
    except ScanJobError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/{job_id}/cancel", response_model=ScanJobOut)
def cancel_scan_job(
    job_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, "Scan job not found")
    require_engagement_access(job.engagement_id, principal)
    try:
        return cancel_job(db, job_id)
    except ScanJobError as exc:
        raise HTTPException(400, str(exc)) from exc
