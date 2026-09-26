from collections import defaultdict
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.auth import Principal, filter_engagement_ids, get_current_principal, require_engagement_access
from app.config import get_settings
from app.csrf import CSRF_COOKIE, csrf_token_for_request, require_csrf, set_csrf_cookie
from app.database import get_db
from app.models import AnalystDecision, DecisionValue, Engagement, FindingGroup, ImportBatch, Observation, ScanJob
from app.paths import get_project_root, get_templates_dir
from app.uploads import save_upload_capped

PROJECT_ROOT = get_project_root()
templates = Jinja2Templates(directory=str(get_templates_dir()))

router = APIRouter(tags=["web"])


def _flash(request: Request) -> dict:
    """Session-less flash via query params ?msg= & ?msg_type= (ok|warn|error)."""
    msg = request.query_params.get("msg") or ""
    msg_type = request.query_params.get("msg_type") or "ok"
    if msg_type not in ("ok", "warn", "error"):
        msg_type = "ok"
    return {"flash_msg": msg, "flash_type": msg_type} if msg else {"flash_msg": None, "flash_type": None}


def _html(request: Request, name: str, context: dict):
    token = csrf_token_for_request(request)
    settings = get_settings()
    context = {
        **context,
        "csrf_token": token,
        "auth_enabled": settings.auth_enabled,
        "app_name": settings.app_name,
        "app_version": "0.1.0-spike",
        **_flash(request),
    }
    response = templates.TemplateResponse(request, name, context)
    if CSRF_COOKIE not in request.cookies or request.cookies.get(CSRF_COOKIE) != token:
        set_csrf_cookie(response, token)
    return response


def _redirect(path: str, *, msg: str | None = None, msg_type: str = "ok") -> RedirectResponse:
    if msg:
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}msg={quote(msg)}&msg_type={quote(msg_type)}"
    return RedirectResponse(path, status_code=303)


def _batch_rows(db: Session, engagement_id: int) -> list[dict]:
    batches = (
        db.query(ImportBatch)
        .filter(ImportBatch.engagement_id == engagement_id)
        .order_by(ImportBatch.id.desc())
        .all()
    )
    if not batches:
        return []
    ids = [b.id for b in batches]
    retest_flags = {
        row[0]
        for row in db.query(Observation.import_batch_id)
        .filter(Observation.import_batch_id.in_(ids), Observation.is_retest.is_(True))
        .distinct()
        .all()
    }
    rows = []
    for b in batches:
        rows.append(
            {
                "id": b.id,
                "tool": b.tool,
                "original_filename": b.original_filename,
                "status": b.status.value if hasattr(b.status, "value") else str(b.status),
                "created_at": b.created_at,
                "record_count": b.record_count,
                "is_retest": b.id in retest_flags,
            }
        )
    return rows


def _status_counts(db: Session, engagement_id: int) -> dict[str, int]:
    rows = (
        db.query(FindingGroup.queue_status, func.count(FindingGroup.id))
        .filter(FindingGroup.engagement_id == engagement_id)
        .group_by(FindingGroup.queue_status)
        .all()
    )
    counts: dict[str, int] = {s.value: 0 for s in DecisionValue}
    total = 0
    for status, n in rows:
        key = status.value if hasattr(status, "value") else str(status)
        counts[key] = n
        total += n
    counts["all"] = total
    return counts


def _next_pending_group_id(db: Session, engagement_id: int, after_id: int | None = None) -> int | None:
    """Return another pending finding-group id in the same engagement (prefer higher priority)."""
    q = (
        db.query(FindingGroup.id)
        .filter(
            FindingGroup.engagement_id == engagement_id,
            FindingGroup.queue_status == DecisionValue.PENDING,
        )
    )
    if after_id is not None:
        q = q.filter(FindingGroup.id != after_id)
    row = q.order_by(FindingGroup.priority_score.desc(), FindingGroup.id).first()
    return row[0] if row else None


@router.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    q = db.query(Engagement)
    allowed = filter_engagement_ids(principal)
    if allowed is not None:
        if not allowed:
            engagements = []
        else:
            engagements = q.filter(Engagement.id.in_(allowed)).order_by(Engagement.id.desc()).all()
    else:
        engagements = q.order_by(Engagement.id.desc()).all()

    counts: dict[int, dict[str, int]] = defaultdict(
        lambda: {"pending": 0, "confirmed": 0, "total": 0}
    )
    last_imports: dict[int, dict] = {}
    if engagements:
        eng_ids = [e.id for e in engagements]
        rows = (
            db.query(
                FindingGroup.engagement_id,
                FindingGroup.queue_status,
                func.count(FindingGroup.id),
            )
            .filter(FindingGroup.engagement_id.in_(eng_ids))
            .group_by(FindingGroup.engagement_id, FindingGroup.queue_status)
            .all()
        )
        for eng_id, status, n in rows:
            counts[eng_id]["total"] += n
            st = status.value if hasattr(status, "value") else str(status)
            if st == DecisionValue.PENDING.value:
                counts[eng_id]["pending"] += n
            elif st == DecisionValue.CONFIRMED.value:
                counts[eng_id]["confirmed"] += n

        # Latest import batch per engagement (one query, pick max id per eng)
        batches = (
            db.query(ImportBatch)
            .filter(ImportBatch.engagement_id.in_(eng_ids))
            .order_by(ImportBatch.id.desc())
            .all()
        )
        for b in batches:
            if b.engagement_id not in last_imports:
                last_imports[b.engagement_id] = {
                    "filename": b.original_filename,
                    "created_at": b.created_at,
                    "id": b.id,
                    "record_count": b.record_count,
                }

    return _html(
        request,
        "home.html",
        {
            "engagements": engagements,
            "counts": dict(counts),
            "last_imports": last_imports,
        },
    )


@router.post("/ui/engagements")
def ui_create_engagement(
    name: str = Form(...),
    client: str = Form(""),
    description: str = Form(""),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
    _csrf: None = Depends(require_csrf),
):
    eng = Engagement(name=name, client=client or None, description=description or None)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    if principal.id is not None and not principal.is_admin:
        from app.auth import grant_engagement_access

        grant_engagement_access(db, principal.id, eng.id)
    return _redirect(f"/ui/engagements/{eng.id}", msg=f"Created engagement #{eng.id}")


@router.get("/ui/engagements/{engagement_id}", response_class=HTMLResponse)
def ui_engagement_hub(
    request: Request,
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    batches = _batch_rows(db, engagement_id)
    last_import = batches[0] if batches else None
    return _html(
        request,
        "engagement.html",
        {
            "engagement": eng,
            "batches": batches,
            "last_import": last_import,
            "status_counts": _status_counts(db, engagement_id),
            "active_tab": "hub",
        },
    )


@router.get("/ui/engagements/{engagement_id}/queue", response_class=HTMLResponse)
def ui_queue(
    request: Request,
    engagement_id: int,
    status: str = "pending",
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    q = (
        db.query(FindingGroup)
        .options(joinedload(FindingGroup.asset), joinedload(FindingGroup.observations))
        .filter(FindingGroup.engagement_id == engagement_id)
    )
    if status and status != "all":
        try:
            q = q.filter(FindingGroup.queue_status == DecisionValue(status))
        except ValueError:
            pass
    groups = q.order_by(FindingGroup.priority_score.desc(), FindingGroup.id).all()
    return _html(
        request,
        "queue.html",
        {
            "engagement": eng,
            "groups": groups,
            "status": status,
            "statuses": [s.value for s in DecisionValue],
            "status_counts": _status_counts(db, engagement_id),
            "active_tab": "queue",
        },
    )


@router.get("/ui/finding-groups/{group_id}", response_class=HTMLResponse)
def ui_group_detail(
    request: Request,
    group_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    g = (
        db.query(FindingGroup)
        .options(
            joinedload(FindingGroup.asset),
            joinedload(FindingGroup.observations),
            joinedload(FindingGroup.decisions),
        )
        .filter(FindingGroup.id == group_id)
        .one_or_none()
    )
    if not g:
        raise HTTPException(404, "Finding group not found")
    require_engagement_access(g.engagement_id, principal)
    next_pending_id = _next_pending_group_id(db, g.engagement_id, after_id=g.id)
    return _html(
        request,
        "observation.html",
        {
            "group": g,
            "engagement": g.engagement if hasattr(g, "engagement") and g.engagement is not None else db.get(Engagement, g.engagement_id),
            "decisions_enum": [s.value for s in DecisionValue if s != DecisionValue.PENDING],
            "next_pending_id": next_pending_id,
            "active_tab": "decide",
        },
    )


@router.post("/ui/finding-groups/{group_id}/decide")
def ui_decide(
    group_id: int,
    decision: str = Form(...),
    reason: str = Form(""),
    analyst: str = Form("analyst"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
    _csrf: None = Depends(require_csrf),
):
    group = db.get(FindingGroup, group_id)
    if not group:
        raise HTTPException(404, "Finding group not found")
    require_engagement_access(group.engagement_id, principal)
    try:
        value = DecisionValue(decision)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid decision: {decision}") from exc

    model_version = None
    if group.observations:
        model_version = group.observations[0].model_version

    who = analyst or "analyst"
    rec = AnalystDecision(
        finding_group_id=group.id,
        decision=value,
        reason=reason or None,
        analyst=who,
        model_version_at_decision=model_version,
    )
    group.queue_status = value
    db.add(rec)
    db.add(group)
    db.commit()
    # Stay on the finding page so the new status is obvious; flash carries the result.
    label = value.value.replace("_", " ")
    msg = f"Saved: {label} by {who}"
    return _redirect(f"/ui/finding-groups/{group.id}", msg=msg)


@router.get("/ui/engagements/{engagement_id}/import", response_class=HTMLResponse)
def ui_import_form(
    request: Request,
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    return _html(
        request,
        "import.html",
        {
            "engagement": eng,
            "batches": _batch_rows(db, engagement_id),
            "active_tab": "import",
        },
    )


@router.post("/ui/engagements/{engagement_id}/import")
async def ui_import_upload(
    engagement_id: int,
    tool: str = Form(""),
    is_retest: str = Form("false"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
    _csrf: None = Depends(require_csrf),
):
    from pathlib import Path as P

    from services.import_service import import_scanner_file

    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)

    settings = get_settings()
    orig_name = file.filename or "upload.xml"
    suffix = P(orig_name).suffix or ".xml"
    tmp_path = await save_upload_capped(
        file, max_bytes=settings.max_upload_bytes, suffix=suffix
    )
    retest_flag = is_retest.lower() in ("1", "true", "yes", "on")
    try:
        result = import_scanner_file(
            db,
            engagement_id=engagement_id,
            source_path=tmp_path,
            original_filename=orig_name,
            tool=tool or None,
            is_retest=retest_flag,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    tag = " (retest)" if retest_flag else ""
    # Prominent flash: obs + groups + batch id (+ filename)
    msg = (
        f"Import complete{tag}: {result.observations_created} observations, "
        f"{result.groups_touched} groups · batch #{result.import_batch.id} · {orig_name}"
    )
    return _redirect(f"/ui/engagements/{engagement_id}/import", msg=msg)


@router.get("/ui/engagements/{engagement_id}/retest", response_class=HTMLResponse)
def ui_retest_form(
    request: Request,
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    return _html(
        request,
        "retest.html",
        {
            "engagement": eng,
            "batches": _batch_rows(db, engagement_id),
            "result": None,
            "active_tab": "retest",
        },
    )


@router.post("/ui/engagements/{engagement_id}/retest", response_class=HTMLResponse)
def ui_retest_compare(
    request: Request,
    engagement_id: int,
    retest_import_batch_id: int = Form(...),
    baseline_import_batch_id: str = Form(""),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
    _csrf: None = Depends(require_csrf),
):
    from services.retest import compare_retest

    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)

    batch = db.get(ImportBatch, retest_import_batch_id)
    if not batch or batch.engagement_id != engagement_id:
        raise HTTPException(404, "Retest import batch not found for engagement")

    baseline_id: int | None = None
    if baseline_import_batch_id.strip():
        try:
            baseline_id = int(baseline_import_batch_id.strip())
        except ValueError as exc:
            raise HTTPException(400, "Invalid baseline batch id") from exc
        base = db.get(ImportBatch, baseline_id)
        if not base or base.engagement_id != engagement_id:
            raise HTTPException(404, "Baseline import batch not found for engagement")

    result = compare_retest(
        db,
        engagement_id=engagement_id,
        retest_import_batch_id=retest_import_batch_id,
        baseline_import_batch_id=baseline_id,
    )
    fixed = [m for m in result.matches if m.status == "fixed"]
    still_open = [m for m in result.matches if m.status == "open"]
    new_findings = [m for m in result.matches if m.status == "new"]
    other = [m for m in result.matches if m.status not in ("fixed", "open", "new")]
    return _html(
        request,
        "retest.html",
        {
            "engagement": eng,
            "batches": _batch_rows(db, engagement_id),
            "result": result,
            "fixed": fixed,
            "still_open": still_open,
            "new_findings": new_findings,
            "other_matches": other,
            "selected_retest": retest_import_batch_id,
            "selected_baseline": baseline_id,
            "active_tab": "retest",
        },
    )


@router.get("/ui/engagements/{engagement_id}/scans", response_class=HTMLResponse)
def ui_scans(
    request: Request,
    engagement_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    from services.scan_jobs import binary_on_path, list_jobs_for_engagement

    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    jobs = list_jobs_for_engagement(db, engagement_id)
    job_rows = [
        {
            "id": j.id,
            "tool": j.tool,
            "status": j.status.value if hasattr(j.status, "value") else str(j.status),
            "targets_text": j.targets_text,
            "profile_name": j.profile_name,
            "profile_flags": j.profile_flags,
            "import_batch_id": j.import_batch_id,
            "started_at": j.started_at,
            "error_message": j.error_message,
        }
        for j in jobs
    ]
    return _html(
        request,
        "scans.html",
        {
            "engagement": eng,
            "jobs": job_rows,
            "nmap_path": binary_on_path("nmap"),
            "nuclei_path": binary_on_path("nuclei"),
            "active_tab": "scans",
        },
    )


@router.post("/ui/engagements/{engagement_id}/scans")
def ui_create_scan_draft(
    engagement_id: int,
    tool: str = Form("nmap"),
    targets_text: str = Form(...),
    profile_name: str = Form(""),
    binary_path: str = Form(""),
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
    _csrf: None = Depends(require_csrf),
):
    from services.scan_jobs import ScanJobError, create_draft_job

    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    try:
        job = create_draft_job(
            db,
            engagement_id=engagement_id,
            tool=tool,
            targets_text=targets_text,
            profile_name=profile_name or None,
            binary_override=binary_path.strip() or None,
        )
    except ScanJobError as exc:
        return _redirect(
            f"/ui/engagements/{engagement_id}/scans",
            msg=str(exc),
            msg_type="error",
        )
    return _redirect(
        f"/ui/engagements/{engagement_id}/scans",
        msg=f"Draft scan job #{job.id} created ({job.tool}). Click Start to run.",
    )


@router.post("/ui/engagements/{engagement_id}/scans/{job_id}/start")
def ui_start_scan(
    engagement_id: int,
    job_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
    _csrf: None = Depends(require_csrf),
):
    from services.scan_jobs import ScanJobError, start_job

    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    job = db.get(ScanJob, job_id)
    if not job or job.engagement_id != engagement_id:
        raise HTTPException(404, "Scan job not found")
    try:
        start_job(db, job_id)
    except ScanJobError as exc:
        return _redirect(
            f"/ui/engagements/{engagement_id}/scans",
            msg=str(exc),
            msg_type="error",
        )
    return _redirect(
        f"/ui/engagements/{engagement_id}/scans",
        msg=f"Started scan job #{job_id}",
    )


@router.post("/ui/engagements/{engagement_id}/scans/{job_id}/cancel")
def ui_cancel_scan(
    engagement_id: int,
    job_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
    _csrf: None = Depends(require_csrf),
):
    from services.scan_jobs import ScanJobError, cancel_job

    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    require_engagement_access(engagement_id, principal)
    job = db.get(ScanJob, job_id)
    if not job or job.engagement_id != engagement_id:
        raise HTTPException(404, "Scan job not found")
    try:
        cancel_job(db, job_id)
    except ScanJobError as exc:
        return _redirect(
            f"/ui/engagements/{engagement_id}/scans",
            msg=str(exc),
            msg_type="error",
        )
    return _redirect(
        f"/ui/engagements/{engagement_id}/scans",
        msg=f"Cancelled scan job #{job_id}",
        msg_type="warn",
    )
