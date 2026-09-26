#!/usr/bin/env python3
"""Create a perf engagement, generate fixtures if needed, import Nmap then Nessus.

Prints wall-clock timing per import and totals (observations, groups, assets).
Dummy scanner XML for Core import/group/queue load — not Laya labels.

Does not start/stop uvicorn. Works with AUTH_ENABLED=false lab posture.

Optional DB isolation (recommended so walkthrough data is untouched)::

  DATABASE_URL=sqlite:////absolute/path/to/data/vapt_perf.db \\
    python scripts/seed_perf_load.py --hosts 50

  # or:
  python scripts/seed_perf_load.py --database-url sqlite:///./data/vapt_perf.db \
    --evidence-dir ./data/evidence_perf --hosts 5
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _peek_arg(argv: list[str], name: str) -> str | None:
    """Read --name VALUE or --name=VALUE before importing app settings."""
    flag = f"--{name}"
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return None


_early_url = _peek_arg(sys.argv[1:], "database-url")
if _early_url:
    os.environ["DATABASE_URL"] = _early_url
_early_evidence = _peek_arg(sys.argv[1:], "evidence-dir")
if _early_evidence:
    os.environ["EVIDENCE_DIR"] = _early_evidence

from app.config import get_settings  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.models import Asset, Engagement, FindingGroup, Observation  # noqa: E402
from services.import_service import import_scanner_file  # noqa: E402

DEFAULT_PERF_DIR = PROJECT_ROOT / "sample_data" / "perf"
NMAP_NAME = "perf_nmap.xml"
NESSUS_NAME = "perf_nessus.nessus"


def _load_generator():
    gen_mod_path = PROJECT_ROOT / "scripts" / "generate_perf_fixtures.py"
    spec = importlib.util.spec_from_file_location("generate_perf_fixtures", gen_mod_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load generator from {gen_mod_path}")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


def _ensure_fixtures(
    *,
    outdir: Path,
    hosts: int,
    ports_per_host: int,
    nessus_items_per_host: int,
    skip_generate: bool,
    regenerate: bool,
) -> tuple[Path, Path]:
    nmap_path = outdir / NMAP_NAME
    nessus_path = outdir / NESSUS_NAME
    missing = not nmap_path.exists() or not nessus_path.exists()
    if skip_generate and missing:
        absent = [str(p) for p in (nmap_path, nessus_path) if not p.exists()]
        raise FileNotFoundError(
            f"--skip-generate set but fixtures missing: {', '.join(absent)}"
        )
    if regenerate or missing:
        if skip_generate:
            # unreachable when missing due to check above; keep for clarity
            pass
        else:
            gen = _load_generator()
            outdir.mkdir(parents=True, exist_ok=True)
            nmap_path.write_text(
                gen.generate_nmap_xml(hosts, ports_per_host), encoding="utf-8"
            )
            nessus_path.write_text(
                gen.generate_nessus_xml(hosts, nessus_items_per_host), encoding="utf-8"
            )
            print(f"Generated fixtures under {outdir} (hosts={hosts})")
    else:
        print(f"Using existing fixtures under {outdir}")
    return nmap_path, nessus_path


def _counts(db, engagement_id: int) -> dict[str, int]:
    obs = (
        db.query(Observation)
        .filter(Observation.engagement_id == engagement_id)
        .count()
    )
    groups = (
        db.query(FindingGroup)
        .filter(FindingGroup.engagement_id == engagement_id)
        .count()
    )
    assets = db.query(Asset).filter(Asset.engagement_id == engagement_id).count()
    return {"observations": obs, "groups": groups, "assets": assets}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed a perf-load engagement with generated Nmap/Nessus fixtures"
    )
    parser.add_argument(
        "--name",
        type=str,
        default=None,
        help="Engagement name (default: Perf Load <timestamp>)",
    )
    parser.add_argument(
        "--engagement-id",
        type=int,
        default=None,
        help="Reuse an existing engagement id instead of creating one",
    )
    parser.add_argument(
        "--hosts",
        type=int,
        default=50,
        help="Host count when generating fixtures (default 50)",
    )
    parser.add_argument("--ports-per-host", type=int, default=4)
    parser.add_argument("--nessus-items-per-host", type=int, default=6)
    parser.add_argument(
        "--outdir",
        type=Path,
        default=DEFAULT_PERF_DIR,
        help="Fixture directory (default sample_data/perf)",
    )
    parser.add_argument(
        "--skip-generate",
        action="store_true",
        help="Do not generate; require existing files in outdir",
    )
    parser.add_argument(
        "--database-url",
        type=str,
        default=None,
        help="Override DATABASE_URL (applied before Settings/engine load)",
    )
    parser.add_argument(
        "--evidence-dir",
        type=str,
        default=None,
        help="Override EVIDENCE_DIR (applied before Settings load; isolates raw uploads)",
    )
    parser.add_argument(
        "--client",
        type=str,
        default="Perf Lab",
        help="Engagement client label",
    )
    args = parser.parse_args()

    outdir = args.outdir
    if not outdir.is_absolute():
        outdir = PROJECT_ROOT / outdir

    settings = get_settings()
    print(f"DATABASE_URL={settings.database_url}")
    print(f"EVIDENCE_DIR={settings.evidence_dir}")

    try:
        # Regenerate by default unless --skip-generate (keeps --hosts meaningful).
        nmap_path, nessus_path = _ensure_fixtures(
            outdir=outdir,
            hosts=args.hosts,
            ports_per_host=args.ports_per_host,
            nessus_items_per_host=args.nessus_items_per_host,
            skip_generate=args.skip_generate,
            regenerate=not args.skip_generate,
        )
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if not nmap_path.exists() or not nessus_path.exists():
        print("Fixture files missing after generate step", file=sys.stderr)
        return 1

    init_db()
    db = SessionLocal()
    try:
        engagement_id = args.engagement_id
        if engagement_id is None:
            name = args.name or f"Perf Load {datetime.now().strftime('%Y%m%d-%H%M%S')}"
            eng = Engagement(name=name, client=args.client)
            db.add(eng)
            db.commit()
            db.refresh(eng)
            engagement_id = eng.id
            print(f"Created engagement id={engagement_id} name={eng.name!r}")
        else:
            eng = db.get(Engagement, engagement_id)
            if not eng:
                print(f"Engagement {engagement_id} not found", file=sys.stderr)
                return 1
            print(f"Reusing engagement id={engagement_id} name={eng.name!r}")

        t0 = time.perf_counter()

        print(f"\nImporting Nmap: {nmap_path}")
        t_nmap = time.perf_counter()
        nmap_result = import_scanner_file(
            db,
            engagement_id=engagement_id,
            source_path=nmap_path,
            original_filename=nmap_path.name,
            tool="nmap",
        )
        nmap_secs = time.perf_counter() - t_nmap
        print(
            f"  Nmap done in {nmap_secs:.3f}s — "
            f"obs={nmap_result.observations_created} "
            f"groups_touched={nmap_result.groups_touched} "
            f"assets_new={nmap_result.assets_created} "
            f"assets_reused={nmap_result.assets_reused} "
            f"batch={nmap_result.import_batch.id} "
            f"status={nmap_result.import_batch.status.value}"
        )
        if nmap_result.warnings:
            for w in nmap_result.warnings[:5]:
                print(f"  warning: {w}")

        print(f"\nImporting Nessus: {nessus_path}")
        t_nessus = time.perf_counter()
        nessus_result = import_scanner_file(
            db,
            engagement_id=engagement_id,
            source_path=nessus_path,
            original_filename=nessus_path.name,
            tool="nessus",
        )
        nessus_secs = time.perf_counter() - t_nessus
        print(
            f"  Nessus done in {nessus_secs:.3f}s — "
            f"obs={nessus_result.observations_created} "
            f"groups_touched={nessus_result.groups_touched} "
            f"assets_new={nessus_result.assets_created} "
            f"assets_reused={nessus_result.assets_reused} "
            f"batch={nessus_result.import_batch.id} "
            f"status={nessus_result.import_batch.status.value}"
        )
        if nessus_result.warnings:
            for w in nessus_result.warnings[:5]:
                print(f"  warning: {w}")

        totals = _counts(db, engagement_id)
        elapsed = time.perf_counter() - t0
        print("\n=== Perf seed summary ===")
        print(f"engagement_id={engagement_id}")
        print(f"nmap_import_s={nmap_secs:.3f}")
        print(f"nessus_import_s={nessus_secs:.3f}")
        print(f"total_wall_s={elapsed:.3f}")
        print(
            f"observations={totals['observations']} "
            f"groups={totals['groups']} "
            f"assets={totals['assets']}"
        )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
