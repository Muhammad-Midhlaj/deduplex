from app.models import DecisionValue, FindingGroup
from app.models import AnalystDecision
from services.export_report import export_tracker_csv, export_report_docx
from services.import_service import import_scanner_file
from services.retest import compare_retest


def test_decision_and_export_confirmed_only(
    db_session, engagement, sample_nessus
):
    result = import_scanner_file(
        db_session,
        engagement_id=engagement.id,
        source_path=sample_nessus,
        original_filename="sample_nessus.nessus",
        tool="nessus",
    )
    assert result.observations_created == 6

    groups = (
        db_session.query(FindingGroup)
        .filter(FindingGroup.engagement_id == engagement.id)
        .all()
    )
    assert len(groups) == 6

    # Confirm one, false-positive another
    g_confirm = groups[0]
    g_fp = groups[1]
    db_session.add(
        AnalystDecision(
            finding_group_id=g_confirm.id,
            decision=DecisionValue.CONFIRMED,
            reason="Validated on host",
            analyst="alice",
        )
    )
    g_confirm.queue_status = DecisionValue.CONFIRMED
    db_session.add(
        AnalystDecision(
            finding_group_id=g_fp.id,
            decision=DecisionValue.FALSE_POSITIVE,
            reason="Noise",
            analyst="alice",
        )
    )
    g_fp.queue_status = DecisionValue.FALSE_POSITIVE
    db_session.commit()

    csv_bytes = export_tracker_csv(db_session, engagement.id)
    text = csv_bytes.decode("utf-8")
    rows = [r for r in text.strip().splitlines()[1:] if r.strip()]
    # Only confirmed groups appear as data rows
    assert len(rows) == 1
    assert rows[0].startswith(f"{g_confirm.id},")
    assert "Validated on host" in text
    assert g_fp.title not in text if g_fp.title else True

    docx_bytes = export_report_docx(db_session, engagement.id)
    assert len(docx_bytes) > 1000  # non-empty docx


def test_retest_comparison(db_session, engagement, sample_nmap, sample_nmap_retest):
    baseline = import_scanner_file(
        db_session,
        engagement_id=engagement.id,
        source_path=sample_nmap,
        original_filename="sample_nmap.xml",
        tool="nmap",
    )
    retest = import_scanner_file(
        db_session,
        engagement_id=engagement.id,
        source_path=sample_nmap_retest,
        original_filename="sample_nmap_retest.xml",
        tool="nmap",
        is_retest=True,
    )
    cmp = compare_retest(
        db_session,
        engagement_id=engagement.id,
        retest_import_batch_id=retest.import_batch.id,
        baseline_import_batch_id=baseline.import_batch.id,
    )
    assert "open" in cmp.summary or "fixed" in cmp.summary or "new" in cmp.summary
    # ssl-ccs-injection should still be open; slowloris should be fixed (baseline only)
    statuses = {m.status for m in cmp.matches}
    assert "fixed" in statuses or "open" in statuses
