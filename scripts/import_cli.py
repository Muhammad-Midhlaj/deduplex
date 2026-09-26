#!/usr/bin/env python3
"""CLI helper: create engagement (optional) and import a scanner file.

Usage:
  python scripts/import_cli.py --engagement-id 1 sample_data/sample_nmap.xml
  python scripts/import_cli.py --create-engagement "Lab Demo" --tool nmap sample_data/sample_nmap.xml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.database import SessionLocal, init_db  # noqa: E402
from app.models import Engagement  # noqa: E402
from services.import_service import import_scanner_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Nmap/Nessus into VAPT MVP")
    parser.add_argument("file", type=Path, help="Path to scanner export")
    parser.add_argument("--engagement-id", type=int, default=None)
    parser.add_argument("--create-engagement", type=str, default=None, help="Create engagement by name")
    parser.add_argument("--client", type=str, default=None)
    parser.add_argument("--tool", choices=["nmap", "nessus"], default=None)
    parser.add_argument("--retest", action="store_true")
    args = parser.parse_args()

    if not args.file.exists():
        print(f"File not found: {args.file}", file=sys.stderr)
        return 1

    init_db()
    db = SessionLocal()
    try:
        engagement_id = args.engagement_id
        if args.create_engagement:
            eng = Engagement(
                name=args.create_engagement,
                client=args.client,
            )
            db.add(eng)
            db.commit()
            db.refresh(eng)
            engagement_id = eng.id
            print(f"Created engagement id={engagement_id} name={eng.name}")

        if engagement_id is None:
            print("Provide --engagement-id or --create-engagement", file=sys.stderr)
            return 1

        eng = db.get(Engagement, engagement_id)
        if not eng:
            print(f"Engagement {engagement_id} not found", file=sys.stderr)
            return 1

        result = import_scanner_file(
            db,
            engagement_id=engagement_id,
            source_path=args.file,
            original_filename=args.file.name,
            tool=args.tool,
            is_retest=args.retest,
        )
        print(
            f"Import batch {result.import_batch.id} ({result.import_batch.status.value}): "
            f"{result.observations_created} observations, "
            f"{result.groups_touched} groups, "
            f"{result.assets_created} new assets, "
            f"{result.assets_reused} reused assets"
        )
        if result.warnings:
            print("Warnings:")
            for w in result.warnings:
                print(f"  - {w}")
        if result.skipped_unparseable:
            print(f"Skipped unparseable records: {result.skipped_unparseable}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
