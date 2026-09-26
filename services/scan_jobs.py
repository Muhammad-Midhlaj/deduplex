"""Scan job rails: draft → explicit Start → run → import → queue.

Wave 1: Nmap default -sT -sV -T4 -oX (Windows-friendly connect). Optional -sS -sV -T4 for elevated SYN. Auto-fallback to -sT if SYN yields all-unknown ports. Wave 1b: Nuclei (-jsonl). Nessus stays file-import only.
Safety: PATH resolve + binary allowlist, one job globally, timeout, cancel kill-tree,
never auto-start, no shell=True.
"""

from __future__ import annotations

import json
import shlex
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import ScanJob, ScanJobStatus, utcnow
from app.paths import get_app_data_dir, get_default_jobs_dir

logger = logging.getLogger("vapt.scan_jobs")

DEFAULT_TIMEOUT_SECONDS = 3600
ACTIVE_STATUSES = (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING)
TERMINAL_STATUSES = (
    ScanJobStatus.SUCCEEDED,
    ScanJobStatus.FAILED,
    ScanJobStatus.CANCELLED,
)
STDOUT_LOG_NAME = "stdout.log"
LEGACY_LOG_NAME = "scan.log"
LOG_CHUNK_MAX_BYTES = 256 * 1024

# Profiles: name → argv flag list (output path flags added by builder).
# Default is TCP connect (-sT): works without admin on Windows.
# SYN (-sS) needs elevation; kept as optional. Legacy name sv_t4 maps to connect.
NMAP_PROFILES: dict[str, list[str]] = {
    "st_sv_t4": ["-sT", "-sV", "-T4"],
    "ss_sv_t4": ["-sS", "-sV", "-T4"],
    "sv_t4": ["-sT", "-sV", "-T4"],  # legacy alias → connect (not bare -sV)
}
DEFAULT_NMAP_PROFILE = "st_sv_t4"
NUCLEI_PROFILES: dict[str, list[str]] = {
    "default": [],
}

# Shell / injection metacharacters refused in targets (args are list-based anyway).
_TARGET_FORBIDDEN = re.compile(r"[;|&$`<>(){}\[\]!?\\*~'\"\n\r\t]")
# Light allow: hostname, IPv4, IPv6-ish, CIDR, optional trailing port for nuclei URLs later.
_TARGET_OK = re.compile(
    r"^(?:"
    r"(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"
    r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])"
    r"|(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"|(?:[0-9a-fA-F:]+(?:/\d{1,3})?)"
    r"|localhost"
    r")$"
)

_BINARIES_FILENAME = "scanner_binaries.json"
_worker_lock = threading.Lock()
_cancel_requested: dict[int, bool] = {}
_active_procs: dict[int, subprocess.Popen] = {}


class ScanJobError(ValueError):
    """User-facing validation / state error for scan jobs."""


def jobs_root() -> Path:
    root = get_default_jobs_dir()
    root.mkdir(parents=True, exist_ok=True)
    return root


def binaries_store_path() -> Path:
    return get_app_data_dir() / _BINARIES_FILENAME


def load_allowlisted_binaries() -> dict[str, str]:
    path = binaries_store_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in data.items() if v}


def save_allowlisted_binaries(mapping: dict[str, str]) -> None:
    path = binaries_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cleaned = {str(k).lower(): str(v) for k, v in mapping.items() if v}
    path.write_text(json.dumps(cleaned, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def set_allowlisted_binary(tool: str, path: str) -> str:
    tool = tool.lower().strip()
    resolved = str(Path(path).expanduser().resolve())
    mapping = load_allowlisted_binaries()
    mapping[tool] = resolved
    save_allowlisted_binaries(mapping)
    return resolved


def resolve_binary(name: str, *, override: str | None = None) -> str:
    """Resolve scanner binary via override, allowlist, or PATH; register allowlist on first use."""
    name = name.lower().strip()
    if override and override.strip():
        p = Path(override.strip()).expanduser()
        if not p.is_file():
            raise ScanJobError(f"Binary override not found: {override}")
        resolved = str(p.resolve())
        set_allowlisted_binary(name, resolved)
        return resolved

    allow = load_allowlisted_binaries()
    if name in allow:
        p = Path(allow[name])
        if p.is_file():
            return str(p.resolve())
        # Stale allowlist entry — fall through to PATH.

    found = shutil.which(name)
    if not found:
        # Windows: try .exe explicitly if which missed it.
        found = shutil.which(f"{name}.exe")
    if not found:
        raise ScanJobError(
            f"Scanner binary '{name}' not found on PATH. "
            f"Install it or set an allowlisted path in app data ({_BINARIES_FILENAME})."
        )
    resolved = str(Path(found).resolve())
    set_allowlisted_binary(name, resolved)
    return resolved


def split_targets(targets_text: str) -> list[str]:
    raw = (targets_text or "").strip()
    if not raw:
        raise ScanJobError("Targets must not be empty")
    parts = re.split(r"[\s,]+", raw)
    targets = [p.strip() for p in parts if p.strip()]
    if not targets:
        raise ScanJobError("Targets must not be empty")
    for t in targets:
        if _TARGET_FORBIDDEN.search(t):
            raise ScanJobError(f"Refusing target with shell metacharacters: {t!r}")
        if not _TARGET_OK.match(t):
            raise ScanJobError(
                f"Invalid target (expected hostname, IP, or CIDR): {t!r}"
            )
    return targets


def profile_flags_for(tool: str, profile_name: str | None) -> tuple[str, list[str]]:
    tool = tool.lower().strip()
    if tool == "nmap":
        name = (profile_name or DEFAULT_NMAP_PROFILE).strip() or DEFAULT_NMAP_PROFILE
        flags = NMAP_PROFILES.get(name)
        if flags is None:
            raise ScanJobError(f"Unknown nmap profile: {name}")
        return name, list(flags)
    if tool == "nuclei":
        name = (profile_name or "default").strip() or "default"
        flags = NUCLEI_PROFILES.get(name)
        if flags is None:
            raise ScanJobError(f"Unknown nuclei profile: {name}")
        return name, list(flags)
    raise ScanJobError(f"Unsupported tool for execution: {tool}")


def build_nmap_argv(
    binary: str,
    targets: list[str],
    *,
    xml_path: Path,
    profile_flags: list[str] | None = None,
) -> list[str]:
    flags = list(profile_flags if profile_flags is not None else NMAP_PROFILES[DEFAULT_NMAP_PROFILE])
    # -oX writes absolute path so cwd is irrelevant.
    return [binary, *flags, "-oX", str(xml_path), *targets]




def nmap_xml_all_ports_unknown(path: Path) -> bool:
    """True when XML has port entries but none open/closed/filtered — typical non-elevated SYN on Windows."""
    try:
        import xml.etree.ElementTree as ET

        root = ET.parse(path).getroot()
    except Exception:  # noqa: BLE001
        return False
    states: set[str] = set()
    for port in root.iter("port"):
        state_el = port.find("state")
        if state_el is None:
            continue
        st = (state_el.get("state") or "").lower()
        if st:
            states.add(st)
    if not states:
        return False
    useful = {"open", "closed", "filtered", "unfiltered", "open|filtered"}
    return states.isdisjoint(useful) and "unknown" in states


def _flags_use_connect(flags: list[str]) -> bool:
    return "-sT" in flags


def _flags_to_connect(flags: list[str]) -> list[str]:
    out = [f for f in flags if f not in ("-sS", "-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX")]
    # Keep -sV / -T* etc.; insert -sT near front
    return ["-sT", *[f for f in out if f != "-sT"]]

def build_nuclei_argv(
    binary: str,
    targets: list[str],
    *,
    jsonl_path: Path,
    profile_flags: list[str] | None = None,
) -> list[str]:
    flags = list(profile_flags if profile_flags is not None else NUCLEI_PROFILES["default"])
    # -jsonl -o <path>; targets via -u (one) or repeated -u
    argv = [binary, *flags, "-jsonl", "-o", str(jsonl_path)]
    for t in targets:
        argv.extend(["-u", t])
    return argv


def _active_job(db: Session) -> ScanJob | None:
    return (
        db.query(ScanJob)
        .filter(ScanJob.status.in_(ACTIVE_STATUSES))
        .order_by(ScanJob.id.asc())
        .first()
    )


def create_draft_job(
    db: Session,
    *,
    engagement_id: int,
    tool: str,
    targets_text: str,
    profile_name: str | None = None,
    binary_override: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ScanJob:
    tool = tool.lower().strip()
    if tool not in ("nmap", "nuclei"):
        raise ScanJobError("tool must be nmap or nuclei")
    targets = split_targets(targets_text)
    pname, pflags = profile_flags_for(tool, profile_name)
    # Resolve + allowlist now so draft shows path; Start re-checks.
    binary = resolve_binary(tool, override=binary_override)
    if timeout_seconds < 30 or timeout_seconds > 86400:
        raise ScanJobError("timeout_seconds must be between 30 and 86400")

    job = ScanJob(
        engagement_id=engagement_id,
        tool=tool,
        status=ScanJobStatus.DRAFT,
        targets_text=" ".join(targets),
        profile_name=pname,
        profile_flags=" ".join(pflags),
        binary_path=binary,
        timeout_seconds=timeout_seconds,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def start_job(db: Session, job_id: int, *, spawn_worker: bool = True) -> ScanJob:
    """Promote draft/queued → running and spawn background worker. Globally one at a time."""
    job = db.get(ScanJob, job_id)
    if not job:
        raise ScanJobError("Scan job not found")
    if job.status not in (ScanJobStatus.DRAFT, ScanJobStatus.QUEUED):
        raise ScanJobError(f"Cannot start job in status {job.status.value}")

    other = _active_job(db)
    if other is not None and other.id != job.id:
        raise ScanJobError(
            f"Another scan job is already {other.status.value} (job #{other.id}). "
            "Only one job may run at a time."
        )

    # Re-validate targets + binary before start (resolve_binary always allowlists).
    targets = split_targets(job.targets_text)
    binary = resolve_binary(job.tool, override=job.binary_path)
    allow = load_allowlisted_binaries()
    allowed_path = allow.get(job.tool)
    if not allowed_path or Path(allowed_path).resolve() != Path(binary).resolve():
        raise ScanJobError(f"Binary for {job.tool} is not allowlisted: {binary}")

    job_dir = jobs_root() / str(job.id)
    job_dir.mkdir(parents=True, exist_ok=True)
    if job.tool == "nmap":
        artifact = job_dir / "scan.xml"
    else:
        artifact = job_dir / "scan.jsonl"
    log_path = job_dir / STDOUT_LOG_NAME

    job.binary_path = binary
    job.job_dir = str(job_dir)
    job.artifact_path = str(artifact)
    job.log_path = str(log_path)
    job.status = ScanJobStatus.QUEUED
    job.error_message = None
    job.started_at = utcnow()
    job.finished_at = None
    db.add(job)
    db.commit()
    db.refresh(job)

    with _worker_lock:
        _cancel_requested[job.id] = False

    if spawn_worker:
        t = threading.Thread(
            target=_run_job_worker,
            args=(job.id,),
            name=f"scan-job-{job.id}",
            daemon=True,
        )
        t.start()
    return job


def cancel_job(db: Session, job_id: int) -> ScanJob:
    job = db.get(ScanJob, job_id)
    if not job:
        raise ScanJobError("Scan job not found")
    if job.status not in (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING, ScanJobStatus.DRAFT):
        raise ScanJobError(f"Cannot cancel job in status {job.status.value}")

    if job.status == ScanJobStatus.DRAFT:
        job.status = ScanJobStatus.CANCELLED
        job.finished_at = utcnow()
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    with _worker_lock:
        _cancel_requested[job.id] = True
        proc = _active_procs.get(job.id)

    if proc is not None and proc.poll() is None:
        _kill_process_tree(proc)

    # If still queued (worker not yet started), mark cancelled immediately.
    db.refresh(job)
    if job.status in (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING):
        job.status = ScanJobStatus.CANCELLED
        job.finished_at = utcnow()
        job.error_message = job.error_message or "Cancelled by user"
        db.add(job)
        db.commit()
        db.refresh(job)
    return job


def _kill_process_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    pid = proc.pid
    try:
        if os.name == "nt":
            # Kill process tree on Windows.
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                check=False,
            )
        else:
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
    except Exception as exc:  # noqa: BLE001 — best-effort cancel
        logger.warning("kill-tree failed for pid=%s: %s", pid, exc)


def _popen_kwargs() -> dict:
    kwargs: dict = {}
    if os.name == "nt":
        # CREATE_NEW_PROCESS_GROUP = 0x00000200
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    return kwargs


def _run_job_worker(job_id: int) -> None:
    from app.database import SessionLocal
    from services.import_service import import_scanner_file

    db = SessionLocal()
    proc: subprocess.Popen | None = None
    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return
        if _cancel_requested.get(job_id):
            job.status = ScanJobStatus.CANCELLED
            job.finished_at = utcnow()
            job.error_message = "Cancelled by user"
            db.add(job)
            db.commit()
            return

        targets = split_targets(job.targets_text)
        binary = job.binary_path or resolve_binary(job.tool)
        artifact = Path(job.artifact_path)  # type: ignore[arg-type]
        log_path = Path(job.log_path)  # type: ignore[arg-type]
        profile_flags = (job.profile_flags or "").split()

        if job.tool == "nmap":
            argv = build_nmap_argv(
                binary, targets, xml_path=artifact, profile_flags=profile_flags
            )
        elif job.tool == "nuclei":
            argv = build_nuclei_argv(
                binary, targets, jsonl_path=artifact, profile_flags=profile_flags
            )
        else:
            job.status = ScanJobStatus.FAILED
            job.error_message = f"Unsupported tool: {job.tool}"
            job.finished_at = utcnow()
            db.add(job)
            db.commit()
            return

        job.status = ScanJobStatus.RUNNING
        db.add(job)
        db.commit()

        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w", encoding="utf-8", buffering=1) as logf:
            logf.write(f"# argv: {argv!r}\n")
            logf.flush()
            proc = subprocess.Popen(
                argv,
                stdout=logf,
                stderr=subprocess.STDOUT,
                shell=False,
                **_popen_kwargs(),
            )
            with _worker_lock:
                _active_procs[job_id] = proc
            job.pid = proc.pid
            db.add(job)
            db.commit()

            deadline = time.monotonic() + max(30, int(job.timeout_seconds or DEFAULT_TIMEOUT_SECONDS))
            while proc.poll() is None:
                if _cancel_requested.get(job_id):
                    _kill_process_tree(proc)
                    break
                if time.monotonic() > deadline:
                    _kill_process_tree(proc)
                    job = db.get(ScanJob, job_id)
                    if job:
                        job.status = ScanJobStatus.FAILED
                        job.error_message = f"Timed out after {job.timeout_seconds}s"
                        job.finished_at = utcnow()
                        db.add(job)
                        db.commit()
                    return
                time.sleep(0.25)

        rc = proc.returncode if proc is not None else -1
        job = db.get(ScanJob, job_id)
        if not job:
            return

        if _cancel_requested.get(job_id) or job.status == ScanJobStatus.CANCELLED:
            job.status = ScanJobStatus.CANCELLED
            job.finished_at = utcnow()
            job.error_message = job.error_message or "Cancelled by user"
            db.add(job)
            db.commit()
            return

        if rc != 0:
            job.status = ScanJobStatus.FAILED
            job.error_message = f"Scanner exited with code {rc}"
            job.finished_at = utcnow()
            db.add(job)
            db.commit()
            return

        if not artifact.is_file():
            job.status = ScanJobStatus.FAILED
            job.error_message = f"Expected artifact missing: {artifact}"
            job.finished_at = utcnow()
            db.add(job)
            db.commit()
            return

        # Non-elevated Windows SYN often yields ports state=unknown and 0 observations.
        # One automatic reconnect with -sT when the first pass was not already connect-scan.
        if (
            job.tool == "nmap"
            and not _flags_use_connect(profile_flags)
            and nmap_xml_all_ports_unknown(artifact)
            and not _cancel_requested.get(job_id)
        ):
            connect_flags = _flags_to_connect(profile_flags)
            fallback_xml = artifact.with_name("scan_connect.xml")
            argv2 = build_nmap_argv(
                binary, targets, xml_path=fallback_xml, profile_flags=connect_flags
            )
            with log_path.open("a", encoding="utf-8", buffering=1) as logf:
                logf.write(
                    "\n# auto-fallback: SYN/unknown ports → retry with -sT\n"
                    f"# argv: {argv2!r}\n"
                )
                logf.flush()
                proc2 = subprocess.Popen(
                    argv2,
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    **_popen_kwargs(),
                )
                with _worker_lock:
                    _active_procs[job_id] = proc2
                job.pid = proc2.pid
                db.add(job)
                db.commit()
                deadline2 = time.monotonic() + max(
                    30, int(job.timeout_seconds or DEFAULT_TIMEOUT_SECONDS)
                )
                while proc2.poll() is None:
                    if _cancel_requested.get(job_id):
                        _kill_process_tree(proc2)
                        break
                    if time.monotonic() > deadline2:
                        _kill_process_tree(proc2)
                        break
                    time.sleep(0.25)
            if _cancel_requested.get(job_id):
                job = db.get(ScanJob, job_id)
                if job:
                    job.status = ScanJobStatus.CANCELLED
                    job.finished_at = utcnow()
                    job.error_message = "Cancelled by user"
                    db.add(job)
                    db.commit()
                return
            if proc2.returncode == 0 and fallback_xml.is_file():
                try:
                    fallback_xml.replace(artifact)
                except OSError:
                    import shutil as _shutil

                    _shutil.copy2(fallback_xml, artifact)
                profile_flags = connect_flags
                job.profile_flags = " ".join(connect_flags)
                job.error_message = None
                db.add(job)
                db.commit()

        # Feed existing import pipeline.
        try:
            result = import_scanner_file(
                db,
                engagement_id=job.engagement_id,
                source_path=artifact,
                original_filename=artifact.name,
                tool=job.tool,
            )
            job.import_batch_id = result.import_batch.id
            job.status = ScanJobStatus.SUCCEEDED
            job.finished_at = utcnow()
            job.error_message = None
            db.add(job)
            db.commit()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Import after scan failed for job %s", job_id)
            job.status = ScanJobStatus.FAILED
            job.error_message = f"Scan ok but import failed: {exc}"
            job.finished_at = utcnow()
            db.add(job)
            db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan job worker failed for %s", job_id)
        try:
            job = db.get(ScanJob, job_id)
            if job and job.status not in (
                ScanJobStatus.SUCCEEDED,
                ScanJobStatus.CANCELLED,
            ):
                job.status = ScanJobStatus.FAILED
                job.error_message = str(exc)
                job.finished_at = utcnow()
                db.add(job)
                db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("Failed to persist worker error for job %s", job_id)
    finally:
        with _worker_lock:
            _active_procs.pop(job_id, None)
            _cancel_requested.pop(job_id, None)
        db.close()



def format_command_line(argv: list[str]) -> str:
    """Shell-join argv for display only — never re-execute the result."""
    try:
        return shlex.join(argv)
    except Exception:  # noqa: BLE001
        return " ".join(str(a) for a in argv)


def command_line_for_job(job: ScanJob) -> str:
    """Human-readable command line reconstructed from job fields (display only)."""
    binary = (job.binary_path or "").strip()
    if not binary:
        return ""
    targets = (job.targets_text or "").split()
    flags = (job.profile_flags or "").split()
    try:
        if job.tool == "nmap":
            artifact = Path(job.artifact_path) if job.artifact_path else Path("scan.xml")
            argv = build_nmap_argv(
                binary, targets or ["…"], xml_path=artifact, profile_flags=flags
            )
        elif job.tool == "nuclei":
            artifact = Path(job.artifact_path) if job.artifact_path else Path("scan.jsonl")
            argv = build_nuclei_argv(
                binary, targets or ["…"], jsonl_path=artifact, profile_flags=flags
            )
        else:
            argv = [binary, *flags, *targets]
        return format_command_line(argv)
    except Exception:  # noqa: BLE001
        return format_command_line([binary, *flags, *targets])


def resolve_existing_log_path(job: ScanJob) -> Path | None:
    """Prefer job.log_path, then stdout.log, then legacy scan.log under job_dir."""
    candidates: list[Path] = []
    if job.log_path:
        candidates.append(Path(job.log_path))
    if job.job_dir:
        d = Path(job.job_dir)
        candidates.append(d / STDOUT_LOG_NAME)
        candidates.append(d / LEGACY_LOG_NAME)
    seen: set[str] = set()
    for p in candidates:
        key = str(p)
        if key in seen:
            continue
        seen.add(key)
        try:
            if p.is_file():
                return p
        except OSError:
            continue
    return None


def read_log_chunk(
    job: ScanJob,
    *,
    offset: int = 0,
    max_bytes: int = LOG_CHUNK_MAX_BYTES,
) -> dict:
    """Read a UTF-8 log slice from byte offset for live tail / scrollback.

    Returns keys: job_id, status, command_line, offset, next_offset, chunk, eof, log_path.
    Undecodable bytes are replaced. Cap max_bytes (default 256KiB).
    """
    status_val = job.status.value if hasattr(job.status, "value") else str(job.status)
    cmd = command_line_for_job(job)
    terminal = job.status in TERMINAL_STATUSES
    try:
        off = max(0, int(offset or 0))
    except (TypeError, ValueError):
        off = 0
    try:
        cap = max(1, min(int(max_bytes or LOG_CHUNK_MAX_BYTES), LOG_CHUNK_MAX_BYTES))
    except (TypeError, ValueError):
        cap = LOG_CHUNK_MAX_BYTES

    path = resolve_existing_log_path(job)
    if path is None:
        return {
            "job_id": job.id,
            "status": status_val,
            "command_line": cmd,
            "offset": off,
            "next_offset": 0,
            "chunk": "",
            "eof": terminal,
            "log_path": job.log_path,
        }

    try:
        # Treat offsets as bytes in the LF-normalized stream so CRLF files
        # behave exactly like LF files on every platform.
        normalized = (
            path.read_bytes()
            .replace(b"\r\n", b"\n")
            .replace(b"\r", b"\n")
        )
    except OSError:
        normalized = b""

    size = len(normalized)
    if off > size:
        off = size

    raw = normalized[off : off + cap]
    chunk = raw.decode("utf-8", errors="replace")
    next_off = off + len(raw)
    eof = terminal and next_off >= size
    return {
        "job_id": job.id,
        "status": status_val,
        "command_line": cmd,
        "offset": off,
        "next_offset": next_off,
        "chunk": chunk,
        "eof": eof,
        "log_path": str(path),
    }


def list_jobs_for_engagement(db: Session, engagement_id: int) -> list[ScanJob]:
    return (
        db.query(ScanJob)
        .filter(ScanJob.engagement_id == engagement_id)
        .order_by(ScanJob.id.desc())
        .all()
    )


def binary_on_path(name: str) -> str | None:
    found = shutil.which(name) or shutil.which(f"{name}.exe")
    return str(Path(found).resolve()) if found else None
