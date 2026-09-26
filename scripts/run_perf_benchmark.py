#!/usr/bin/env python3
"""Wall-time + count + peak-RSS benchmark for import/queue/triage/export.

Uses a dedicated SQLite DB under data/perf_dummy/ so the main lab DB is untouched.
AUTH_ENABLED/LAYA_ENABLED should stay off (defaults). Does not invent model metrics.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Configure env BEFORE importing app.*
PERF_DIR = PROJECT_ROOT / "data" / "perf_dummy"
PERF_DIR.mkdir(parents=True, exist_ok=True)
PERF_DB = PERF_DIR / "perf.db"
os.environ.setdefault("AUTH_ENABLED", "false")
os.environ.setdefault("LAYA_ENABLED", "false")
os.environ["DATABASE_URL"] = f"sqlite:///{PERF_DB.as_posix()}"
# Keep evidence under perf_dummy to avoid flooding lab evidence tree
os.environ["EVIDENCE_DIR"] = str(PERF_DIR / "evidence")


def _rss_mb() -> float | None:
    try:
        import psutil

        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except Exception:
        return None


class PeakTracker:
    def __init__(self) -> None:
        self.peak: float | None = _rss_mb()
        self.samples: list[float] = []

    def sample(self) -> None:
        v = _rss_mb()
        if v is None:
            return
        self.samples.append(v)
        if self.peak is None or v > self.peak:
            self.peak = v


def timed(label: str, fn, tracker: PeakTracker) -> tuple[float, object]:
    tracker.sample()
    t0 = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - t0
    tracker.sample()
    print(f"  {label}: {elapsed:.3f}s")
    return elapsed, result


def main() -> int:
    parser = argparse.ArgumentParser(description="Perf benchmark for VAPT MVP pipeline")
    parser.add_argument(
        "--nmap",
        type=Path,
        default=PROJECT_ROOT / "sample_data" / "perf" / "perf_nmap.xml",
    )
    parser.add_argument(
        "--nessus",
        type=Path,
        default=PROJECT_ROOT / "sample_data" / "perf" / "perf_nessus.nessus",
    )
    parser.add_argument("--reset-db", action="store_true", default=True)
    args = parser.parse_args()

    if not args.nmap.exists() or not args.nessus.exists():
        print("Missing dummy files. Run scripts/generate_perf_dummy.py first.", file=sys.stderr)
        return 1

    if args.reset_db and PERF_DB.exists():
        PERF_DB.unlink()

    # Clear settings cache if already imported somehow
    from app.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    assert "perf.db" in settings.database_url, settings.database_url
    assert settings.auth_enabled is False
    assert settings.laya_enabled is False

    from app.database import SessionLocal, init_db
    from app.models import Engagement, FindingGroup, Observation
    from services.export_report import (
        export_report_docx,
        export_tracker_csv,
        export_tracker_xlsx,
    )
    from services.import_service import import_scanner_file
    from services.prioritization import rules_prioritize

    tracker = PeakTracker()
    timings: dict[str, float] = {}
    counts: dict[str, int] = {}

    init_db()
    db = SessionLocal()
    try:
        def create_eng():
            eng = Engagement(name="Perf Benchmark 2026-09-26", client="PerfLab")
            db.add(eng)
            db.commit()
            db.refresh(eng)
            return eng

        t, eng = timed("create_engagement", create_eng, tracker)
        timings["create_engagement_s"] = round(t, 4)
        engagement_id = eng.id
        print(f"  engagement_id={engagement_id}")

        def import_nmap():
            return import_scanner_file(
                db,
                engagement_id=engagement_id,
                source_path=args.nmap,
                original_filename=args.nmap.name,
                tool="nmap",
            )

        t, nmap_res = timed("import_nmap", import_nmap, tracker)
        timings["import_nmap_s"] = round(t, 4)
        counts["nmap_observations_created"] = nmap_res.observations_created
        counts["nmap_groups_touched"] = nmap_res.groups_touched
        counts["nmap_assets_created"] = nmap_res.assets_created
        print(
            f"    obs={nmap_res.observations_created} groups={nmap_res.groups_touched} "
            f"assets_new={nmap_res.assets_created}"
        )

        def import_nessus():
            return import_scanner_file(
                db,
                engagement_id=engagement_id,
                source_path=args.nessus,
                original_filename=args.nessus.name,
                tool="nessus",
            )

        t, nessus_res = timed("import_nessus", import_nessus, tracker)
        timings["import_nessus_s"] = round(t, 4)
        counts["nessus_observations_created"] = nessus_res.observations_created
        counts["nessus_groups_touched"] = nessus_res.groups_touched
        counts["nessus_assets_created"] = nessus_res.assets_created
        print(
            f"    obs={nessus_res.observations_created} groups={nessus_res.groups_touched} "
            f"assets_new={nessus_res.assets_created}"
        )

        def list_queue():
            groups = (
                db.query(FindingGroup)
                .filter(FindingGroup.engagement_id == engagement_id)
                .order_by(FindingGroup.priority_score.desc(), FindingGroup.id.asc())
                .all()
            )
            return groups

        t, groups = timed("list_queue", list_queue, tracker)
        timings["list_queue_s"] = round(t, 4)
        counts["queue_groups"] = len(groups)
        counts["total_observations"] = (
            db.query(Observation)
            .filter(Observation.engagement_id == engagement_id)
            .count()
        )
        print(f"    groups={len(groups)} total_obs={counts['total_observations']}")

        def rules_triage_pass():
            """Re-run rules_prioritize over each group's lead observation (explicit step)."""
            updated = 0
            for g in groups:
                obs = g.observations[0] if g.observations else None
                if not obs:
                    continue
                rec = rules_prioritize(
                    severity=obs.severity,
                    cvss=obs.cvss,
                    cve=obs.cve,
                    plugin_output=obs.plugin_output,
                    description=obs.description,
                    title=obs.title or g.title,
                )
                g.priority_score = rec.score
                updated += 1
            db.commit()
            return updated

        t, n_updated = timed("rules_triage_pass", rules_triage_pass, tracker)
        timings["rules_triage_pass_s"] = round(t, 4)
        counts["rules_triage_groups"] = n_updated
        print(f"    rescored_groups={n_updated}")

        # Mark all groups confirmed so exports contain rows (export filters confirmed-only).
        from app.models import AnalystDecision, DecisionValue

        def confirm_all_for_export():
            n = 0
            for g in groups:
                g.queue_status = DecisionValue.CONFIRMED
                db.add(
                    AnalystDecision(
                        finding_group_id=g.id,
                        decision=DecisionValue.CONFIRMED,
                        reason="perf benchmark bulk confirm for export sizing",
                        analyst="perf",
                    )
                )
                n += 1
            db.commit()
            return n

        t, n_conf = timed("confirm_all_for_export", confirm_all_for_export, tracker)
        timings["confirm_all_for_export_s"] = round(t, 4)
        counts["confirmed_for_export"] = n_conf
        print(f"    confirmed={n_conf}")

        export_dir = PERF_DIR / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)

        def export_csv():
            data = export_tracker_csv(db, engagement_id)
            path = export_dir / "tracker.csv"
            path.write_bytes(data if isinstance(data, (bytes, bytearray)) else data.encode("utf-8"))
            return path, len(data)

        t, (csv_path, csv_len) = timed("export_csv", export_csv, tracker)
        timings["export_csv_s"] = round(t, 4)
        counts["export_csv_bytes"] = csv_len
        print(f"    -> {csv_path} ({csv_len} bytes)")

        def export_xlsx():
            data = export_tracker_xlsx(db, engagement_id)
            path = export_dir / "tracker.xlsx"
            path.write_bytes(data)
            return path, len(data)

        t, (xlsx_path, xlsx_len) = timed("export_xlsx", export_xlsx, tracker)
        timings["export_xlsx_s"] = round(t, 4)
        counts["export_xlsx_bytes"] = xlsx_len
        print(f"    -> {xlsx_path} ({xlsx_len} bytes)")

        def export_docx():
            data = export_report_docx(db, engagement_id)
            path = export_dir / "report.docx"
            path.write_bytes(data)
            return path, len(data)

        t, (docx_path, docx_len) = timed("export_docx", export_docx, tracker)
        timings["export_docx_s"] = round(t, 4)
        counts["export_docx_bytes"] = docx_len
        print(f"    -> {docx_path} ({docx_len} bytes)")

    finally:
        db.close()

    tracker.sample()
    total = sum(v for k, v in timings.items() if k.endswith("_s"))
    timings["total_pipeline_s"] = round(total, 4)

    result = {
        "auth_enabled": settings.auth_enabled,
        "laya_enabled": settings.laya_enabled,
        "database_url": settings.database_url,
        "evidence_dir": str(settings.evidence_dir),
        "nmap_file": str(args.nmap),
        "nessus_file": str(args.nessus),
        "nmap_file_bytes": args.nmap.stat().st_size,
        "nessus_file_bytes": args.nessus.stat().st_size,
        "timings_s": timings,
        "counts": counts,
        "peak_rss_mb": round(tracker.peak, 2) if tracker.peak is not None else None,
        "rss_samples_mb": [round(x, 2) for x in tracker.samples],
    }
    out_json = PERF_DIR / "perf_results.json"
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nWrote {out_json}")
    print(f"Peak RSS MB: {result['peak_rss_mb']}")
    print(f"Total pipeline s: {timings['total_pipeline_s']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

