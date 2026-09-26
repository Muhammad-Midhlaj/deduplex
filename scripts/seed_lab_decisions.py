#!/usr/bin/env python3
"""Seed lab analyst decisions on pending finding groups (Windows / midhlaj).

Use for pipeline smoke when real UI decisions are scarce. Marks analyst as
``lab-seed``. Prefer real analyst decisions before claiming pilot_ready.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.database import SessionLocal, init_db
from app.models import AnalystDecision, DecisionValue, FindingGroup


OVERRIDES: dict[int, tuple[DecisionValue, str]] = {
    4: (DecisionValue.CONFIRMED, "Slowloris check reported likely vulnerable — prioritize review"),
    6: (DecisionValue.CONFIRMED, "CCS injection CVE-2014-0224 flagged with VULNERABLE"),
    14: (DecisionValue.CONFIRMED, "Unsupported MySQL 5.7 — confirm upgrade path"),
    15: (DecisionValue.CONFIRMED, "Empty root password — confirm and remediate"),
    11: (DecisionValue.ACCEPTED_RISK, "TRACE enabled; accepted for lab until next change window"),
    13: (DecisionValue.DEFER, "CBC ciphers — defer to hardening sprint"),
    12: (DecisionValue.INFORMATIONAL, "Scan metadata only — not a finding"),
    1: (DecisionValue.INFORMATIONAL, "Open SSH port expected for this host"),
    2: (DecisionValue.INFORMATIONAL, "HTTP expected on web host"),
    3: (DecisionValue.FALSE_POSITIVE, "http-title info only — no actionable vuln"),
    5: (DecisionValue.INFORMATIONAL, "HTTPS expected"),
    7: (DecisionValue.INFORMATIONAL, "MySQL port open — track with version findings"),
    8: (DecisionValue.FALSE_POSITIVE, "mysql-info banner only"),
    9: (DecisionValue.INFORMATIONAL, "Duplicate SSH port observation class"),
}


def decide(group: FindingGroup) -> tuple[DecisionValue, str]:
    if group.id in OVERRIDES:
        return OVERRIDES[group.id]
    sev = (group.severity or "").lower()
    title = (group.title or "").lower()
    if sev in ("critical", "high"):
        return DecisionValue.CONFIRMED, f"Seeded confirm for {sev} finding: {group.rule_id}"
    if sev == "medium":
        return DecisionValue.CONFIRMED, f"Seeded confirm for medium: {group.rule_id}"
    if "scan information" in title or group.rule_id == "19506":
        return DecisionValue.INFORMATIONAL, "Scan metadata"
    if sev in ("info", "informational", "low"):
        return DecisionValue.FALSE_POSITIVE, f"Seeded FP/info triage for {group.rule_id}"
    return DecisionValue.DEFER, f"Seeded defer for {group.rule_id}"


def main() -> int:
    init_db()
    db = SessionLocal()
    created = skipped = 0
    try:
        for g in db.query(FindingGroup).order_by(FindingGroup.id).all():
            existing = [d for d in g.decisions if d.decision != DecisionValue.PENDING]
            if existing:
                skipped += 1
                continue
            dec_val, reason = decide(g)
            db.add(
                AnalystDecision(
                    finding_group_id=g.id,
                    decision=dec_val,
                    reason=reason,
                    analyst="lab-seed",
                    model_version_at_decision="seed-v1",
                )
            )
            g.queue_status = dec_val
            db.add(g)
            created += 1
        db.commit()
    finally:
        db.close()
    print(f"created_decisions={created} skipped_already_labeled={skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
