#!/usr/bin/env python3
"""QA-only: time queue list + confirm + csv/xlsx/docx export on an existing engagement."""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _peek(argv: list[str], name: str) -> str | None:
    flag = f"--{name}"
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return None


_early_url = _peek(sys.argv[1:], "database-url")
if _early_url:
    os.environ["DATABASE_URL"] = _early_url
_early_evidence = _peek(sys.argv[1:], "evidence-dir")
if _early_evidence:
    os.environ["EVIDENCE_DIR"] = _early_evidence
os.environ.setdefault("AUTH_ENABLED", "false")
os.environ.setdefault("LAYA_ENABLED", "false")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engagement-id", type=int, required=True)
    parser.add_argument("--database-url", type=str, default=None)
    parser.add_argument("--evidence-dir", type=str, default=None)
    parser.add_argument(
        "--export-dir",
        type=Path,
        default=PROJECT_ROOT / "data" / "evidence_perf" / "exports_qa",
    )
    args = parser.parse_args()

    from app.config import get_settings
    from app.database import SessionLocal, init_db
    from app.models import AnalystDecision, DecisionValue, FindingGroup, Observation
    from services.export_report import (
        export_report_docx,
        export_tracker_csv,
        export_tracker_xlsx,
    )

    get_settings.cache_clear()
    settings = get_settings()
    print(f"DATABASE_URL={settings.database_url}")
    print(f"EVIDENCE_DIR={settings.evidence_dir}")
    print(f"auth={settings.auth_enabled} laya={settings.laya_enabled}")

    init_db()
    db = SessionLocal()
    eid = args.engagement_id
    export_dir = args.export_dir
    if not export_dir.is_absolute():
        export_dir = PROJECT_ROOT / export_dir
    export_dir.mkdir(parents=True, exist_ok=True)

    try:
        t0 = time.perf_counter()
        groups = (
            db.query(FindingGroup)
            .filter(FindingGroup.engagement_id == eid)
            .order_by(FindingGroup.priority_score.desc(), FindingGroup.id.asc())
            .all()
        )
        list_s = time.perf_counter() - t0
        obs = (
            db.query(Observation)
            .filter(Observation.engagement_id == eid)
            .count()
        )
        print(f"list_queue_s={list_s:.3f} groups={len(groups)} observations={obs}")

        t1 = time.perf_counter()
        n_conf = 0
        for g in groups:
            g.queue_status = DecisionValue.CONFIRMED
            db.add(
                AnalystDecision(
                    finding_group_id=g.id,
                    decision=DecisionValue.CONFIRMED,
                    reason="qa timing bulk confirm",
                    analyst="qa",
                )
            )
            n_conf += 1
        db.commit()
        confirm_s = time.perf_counter() - t1
        print(f"confirm_all_for_export_s={confirm_s:.3f} confirmed={n_conf}")

        t2 = time.perf_counter()
        csv_data = export_tracker_csv(db, eid)
        csv_path = export_dir / "tracker.csv"
        csv_bytes = csv_data if isinstance(csv_data, (bytes, bytearray)) else csv_data.encode("utf-8")
        csv_path.write_bytes(csv_bytes)
        csv_s = time.perf_counter() - t2
        print(f"export_csv_s={csv_s:.3f} bytes={len(csv_bytes)} path={csv_path}")

        t3 = time.perf_counter()
        xlsx_data = export_tracker_xlsx(db, eid)
        xlsx_path = export_dir / "tracker.xlsx"
        xlsx_path.write_bytes(xlsx_data)
        xlsx_s = time.perf_counter() - t3
        print(f"export_xlsx_s={xlsx_s:.3f} bytes={len(xlsx_data)} path={xlsx_path}")

        t4 = time.perf_counter()
        docx_data = export_report_docx(db, eid)
        docx_path = export_dir / "report.docx"
        docx_path.write_bytes(docx_data)
        docx_s = time.perf_counter() - t4
        print(f"export_docx_s={docx_s:.3f} bytes={len(docx_data)} path={docx_path}")

        total = list_s + confirm_s + csv_s + xlsx_s + docx_s
        print(f"queue_export_wall_s={total:.3f}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
