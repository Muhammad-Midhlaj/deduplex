#!/usr/bin/env python3
"""Export labeled fine-tune JSONL from the local SQLite DB."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    p = argparse.ArgumentParser(description="Export analyst-labeled cases for Laya fine-tune")
    p.add_argument(
        "--out",
        type=Path,
        default=ROOT / "data" / "finetune" / "datasets" / "export.jsonl",
    )
    p.add_argument("--engagement-id", type=int, action="append", default=None)
    p.add_argument("--database-url", default=None, help="Override DATABASE_URL")
    args = p.parse_args()

    if args.database_url:
        import os

        os.environ["DATABASE_URL"] = args.database_url

    from app.database import SessionLocal
    from finetune.dataset import coverage_report, engagement_aware_split, write_split_jsonl
    from finetune.export_labels import case_to_jsonable, export_cases_from_session, write_jsonl

    session = SessionLocal()
    try:
        cases = export_cases_from_session(session, engagement_ids=args.engagement_id)
    finally:
        session.close()

    n = write_jsonl(cases, args.out)
    rows = [case_to_jsonable(c) for c in cases]
    cov = coverage_report(rows)
    cov_path = args.out.with_suffix(".coverage.json")
    cov_path.write_text(json.dumps(cov, indent=2), encoding="utf-8")

    if rows:
        splits = engagement_aware_split(rows)
        split_dir = args.out.parent / (args.out.stem + "_splits")
        write_split_jsonl(splits, split_dir)
        print(f"Wrote splits under {split_dir}")

    print(f"Exported {n} cases -> {args.out}")
    print(json.dumps(cov, indent=2))
    if n == 0:
        print(
            "NOTE: No analyst decisions found. Use synthetic data for pipeline testing:\n"
            "  python scripts/run_finetune_experiment.py --synthetic"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
