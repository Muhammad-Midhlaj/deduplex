"""Retest comparison hooks: match by original finding ID, then asset+rule."""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy.orm import Session

from app.models import Observation
from app.schemas import RetestCompareResult, RetestMatchOut


def compare_retest(
    db: Session,
    *,
    engagement_id: int,
    retest_import_batch_id: int,
    baseline_import_batch_id: int | None = None,
) -> RetestCompareResult:
    """Compare a retest import batch against prior observations.

    Matching order:
      1. original_finding_id (exact)
      2. asset_id + rule_id + tool (exact key components)
    Status meanings:
      - open: matched baseline still present in retest
      - fixed: baseline exists, no matching retest observation
      - new: retest observation with no baseline match
      - unmatched_retest: reserved (same as new for now)
    """
    retest_q = db.query(Observation).filter(
        Observation.engagement_id == engagement_id,
        Observation.import_batch_id == retest_import_batch_id,
    )
    retest_obs = list(retest_q.all())

    baseline_q = db.query(Observation).filter(
        Observation.engagement_id == engagement_id,
        Observation.import_batch_id != retest_import_batch_id,
        Observation.is_retest.is_(False),
    )
    if baseline_import_batch_id is not None:
        baseline_q = baseline_q.filter(
            Observation.import_batch_id == baseline_import_batch_id
        )
    baseline_obs = list(baseline_q.all())

    by_orig: dict[str, list[Observation]] = defaultdict(list)
    by_asset_rule: dict[tuple, list[Observation]] = defaultdict(list)
    for b in baseline_obs:
        if b.original_finding_id:
            by_orig[b.original_finding_id].append(b)
        by_asset_rule[(b.tool, b.rule_id, b.asset_id)].append(b)

    matches: list[RetestMatchOut] = []
    matched_baseline_ids: set[int] = set()

    for r in retest_obs:
        matched: Observation | None = None
        method: str | None = None

        if r.original_finding_id and r.original_finding_id in by_orig:
            candidates = by_orig[r.original_finding_id]
            matched = candidates[0]
            method = "original_finding_id"
        else:
            key = (r.tool, r.rule_id, r.asset_id)
            if key in by_asset_rule:
                matched = by_asset_rule[key][0]
                method = "asset_rule"

        if matched:
            matched_baseline_ids.add(matched.id)
            r.retest_of_observation_id = matched.id
            r.is_retest = True
            db.add(r)
            matches.append(
                RetestMatchOut(
                    retest_observation_id=r.id,
                    matched_observation_id=matched.id,
                    match_method=method,
                    status="open",
                    details={
                        "rule_id": r.rule_id,
                        "severity": r.severity,
                        "baseline_severity": matched.severity,
                    },
                )
            )
        else:
            matches.append(
                RetestMatchOut(
                    retest_observation_id=r.id,
                    matched_observation_id=None,
                    match_method=None,
                    status="new",
                    details={"rule_id": r.rule_id, "title": r.title},
                )
            )

    # Baselines not seen in retest → potentially fixed
    for b in baseline_obs:
        if b.id not in matched_baseline_ids:
            matches.append(
                RetestMatchOut(
                    retest_observation_id=0,
                    matched_observation_id=b.id,
                    match_method=None,
                    status="fixed",
                    details={"rule_id": b.rule_id, "title": b.title},
                )
            )

    db.commit()

    summary: dict[str, int] = defaultdict(int)
    for m in matches:
        summary[m.status] += 1

    return RetestCompareResult(matches=matches, summary=dict(summary))
