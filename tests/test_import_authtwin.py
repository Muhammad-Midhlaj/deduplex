"""AuthTwin findings importer: findings.json / report.json / findings.csv (ingest only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import Asset, FindingGroup, Observation
from importers.authtwin_findings import looks_like_authtwin, parse_authtwin_findings
from services.grouping import build_duplicate_key
from services.import_service import SUPPORTED_TOOLS, _detect_tool, import_scanner_file

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = PROJECT_ROOT / "sample_data" / "sample_authtwin_findings.json"


@pytest.fixture()
def findings_doc() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_parse_findings_json_mapping():
    result = parse_authtwin_findings(FIXTURE)
    assert result.skipped_unparseable == 0
    by_id = {o.original_finding_id: o for o in result.observations}
    assert set(by_id) == {"a1b2c3d4e5f6", "0f9e8d7c6b5a", "112233445566"}

    high = by_id["a1b2c3d4e5f6"]
    assert high.tool == "authtwin"
    assert high.rule_id == "BOLA/order"
    assert high.severity == "high"
    assert high.hostname == "shop.lab.local"
    assert high.port == 443 and high.protocol == "https"
    assert "bob → alice" in high.description
    assert "order_id:7777->1001" in high.description
    assert "sc-0007" in high.plugin_output
    # repro_chain (vault identity refs) kept out of the excerpt
    assert "repro_chain" not in high.raw_excerpt

    # No evidence URL / repro host → res_type:object_id fallback asset
    low = by_id["112233445566"]
    assert low.severity == "low"
    assert low.hostname == "invoice:INV-9"
    assert low.port is None


def test_import_findings_json_creates_observations(db_session, engagement):
    result = import_scanner_file(
        db_session,
        engagement_id=engagement.id,
        source_path=FIXTURE,
        original_filename="findings.json",
    )
    assert result.import_batch.tool == "authtwin"
    assert result.observations_created == 3
    assert result.assets_created == 2  # shop.lab.local:443 + invoice:INV-9
    # Both order findings share rule + asset → one group; invoice → another.
    assert result.groups_touched == 2

    obs = db_session.query(Observation).filter_by(original_finding_id="a1b2c3d4e5f6").one()
    asset = db_session.get(Asset, obs.asset_id)
    assert obs.tool == "authtwin"
    assert asset.canonical_key == "shop.lab.local||https|443"
    assert obs.duplicate_key == build_duplicate_key("authtwin", "BOLA/order", asset.canonical_key)
    assert db_session.query(FindingGroup).filter_by(tool="authtwin").count() == 2


def test_report_json_with_remediations(tmp_path, findings_doc, db_session, engagement):
    rem = {
        "finding_id": "a1b2c3d4e5f6",
        "owasp": [{"standard": "OWASP-API", "identifier": "API1:2023", "name": "BOLA", "url": ""}],
        "cwe": [{"standard": "CWE", "identifier": "CWE-639", "name": "x", "url": ""}],
        "root_cause": {"summary": "No ownership check.", "contributing_factors": []},
    }
    report = {
        "tool": "AuthTwin",
        "version": "0.1.0",
        "findings": findings_doc,
        "remediations": {"version": 1, "remediations": [rem]},
        "warnings": [],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    assert _detect_tool("report.json", None, path) == "authtwin"
    result = import_scanner_file(
        db_session, engagement_id=engagement.id, source_path=path, original_filename="report.json"
    )
    assert result.observations_created == 3
    obs = db_session.query(Observation).filter_by(original_finding_id="a1b2c3d4e5f6").one()
    assert "API1:2023" in obs.description and "CWE-639" in obs.description
    assert obs.rule_id == "BOLA/order"  # stable across formats


def test_findings_csv_fallback(tmp_path, db_session, engagement):
    csv_text = (
        "finding_id,severity,classification,res_type,object_id,owner_identity,"
        "actor_identity,access_types,owasp,cwe,evidence_count,title,representative_url\n"
        "a1b2c3d4e5f6,high,confirmed-anomaly,order,1001,alice,bob,mutate,API1:2023,"
        "CWE-639;CWE-285,1,bob can modify order 1001 owned by alice,"
        "https://shop.lab.local/api/orders/1001\n"
    )
    path = tmp_path / "findings.csv"
    path.write_text(csv_text, encoding="utf-8")
    assert looks_like_authtwin(path)

    result = import_scanner_file(
        db_session, engagement_id=engagement.id, source_path=path, original_filename="findings.csv"
    )
    assert result.import_batch.tool == "authtwin"
    assert result.observations_created == 1
    obs = db_session.query(Observation).one()
    assert obs.original_finding_id == "a1b2c3d4e5f6"
    assert obs.duplicate_key == "authtwin|BOLA/order|shop.lab.local||https|443"
    assert "CWE-285" in obs.description


def test_detection_and_hint(tmp_path):
    assert "authtwin" in SUPPORTED_TOOLS
    assert _detect_tool("authtwin_findings.json", None, FIXTURE) == "authtwin"
    assert _detect_tool("whatever.bin", "authtwin", FIXTURE) == "authtwin"
    other = tmp_path / "findings.json"
    other.write_text(json.dumps({"results": [1, 2]}), encoding="utf-8")
    assert not looks_like_authtwin(other)
    with pytest.raises(ValueError):
        _detect_tool("findings.json", None, other)


def test_wrong_content_with_hint_rejected(tmp_path, db_session, engagement):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"results": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        import_scanner_file(
            db_session,
            engagement_id=engagement.id,
            source_path=path,
            original_filename="findings.json",
            tool="authtwin",
        )
