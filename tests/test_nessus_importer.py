"""Nessus importer: sample parse, streaming large-ish fixtures, XXE defense."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from defusedxml.common import EntitiesForbidden

from importers.nessus import (
    build_nessus_original_finding_id,
    parse_nessus,
)
from services.grouping import build_duplicate_key, build_finding_hash
from services.import_service import import_scanner_file
from app.models import FindingGroup, Observation

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_generator():
    path = PROJECT_ROOT / "scripts" / "generate_perf_fixtures.py"
    spec = importlib.util.spec_from_file_location("generate_perf_fixtures", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_parse_sample_nessus(sample_nessus):
    result = parse_nessus(sample_nessus)
    assert result.skipped_unparseable == 0
    assert len(result.observations) == 6

    by_plugin = {o.rule_id: o for o in result.observations}
    assert "104743" in by_plugin
    ccs = by_plugin["104743"]
    assert ccs.severity == "high"
    assert ccs.port == 443
    assert ccs.ip_address == "192.168.1.10"
    assert "CVE-2014-0224" in (ccs.cve or "")
    assert ccs.cvss == 7.4
    assert ccs.original_finding_id == "nessus:104743:192.168.1.10:tcp:443"

    mysql = by_plugin["55446"]
    assert mysql.ip_address == "192.168.1.11"
    assert mysql.port == 3306


def test_nessus_info_plugin_retained(sample_nessus):
    result = parse_nessus(sample_nessus)
    info = [o for o in result.observations if o.rule_id == "19506"]
    assert len(info) == 1
    assert info[0].severity == "info"


def test_nessus_original_finding_id_stable():
    a = build_nessus_original_finding_id("104743", "192.168.1.10", "tcp", 443)
    b = build_nessus_original_finding_id("104743", "192.168.1.10", "tcp", 443)
    assert a == b == "nessus:104743:192.168.1.10:tcp:443"


def test_finding_hash_stable_and_aligned_with_duplicate_key():
    key = build_duplicate_key(
        "nessus", "104743", "web.lab.local|192.168.1.10|tcp|443"
    )
    h1 = build_finding_hash(
        "nessus", "104743", "web.lab.local|192.168.1.10|tcp|443"
    )
    h2 = build_finding_hash(
        "nessus", "104743", "web.lab.local|192.168.1.10|tcp|443"
    )
    assert h1 == h2
    assert len(h1) == 64
    # Different fields → different hash
    h3 = build_finding_hash(
        "nessus", "104743", "web.lab.local|192.168.1.10|tcp|80"
    )
    assert h3 != h1
    assert key.startswith("nessus|104743|")


def test_streaming_parse_largeish_synthetic(tmp_path):
    """Streaming iterparse handles multi-host synthetic export (perf fixture)."""
    gen = _load_generator()
    hosts = 25
    items = 5
    xml = gen.generate_nessus_xml(hosts, items_per_host=items, duplicate_every=10)
    path = tmp_path / "largeish.nessus"
    path.write_text(xml, encoding="utf-8")

    result = parse_nessus(path)
    assert result.skipped_unparseable == 0
    # 25*5 + floor(25/10)=2 intentional dupes
    assert len(result.observations) == hosts * items + 2
    assert all(o.tool == "nessus" for o in result.observations)
    assert all(o.original_finding_id and o.original_finding_id.startswith("nessus:") for o in result.observations)
    ips = {o.ip_address for o in result.observations if o.ip_address}
    assert any(ip.startswith("10.50.") for ip in ips)


def test_nessus_reimport_groups_stable(db_session, engagement, sample_nessus):
    """Re-import same .nessus: observation count doubles; FindingGroup count stable."""
    r1 = import_scanner_file(
        db_session,
        engagement_id=engagement.id,
        source_path=sample_nessus,
        original_filename="sample_nessus.nessus",
        tool="nessus",
    )
    assert r1.observations_created == 6
    groups_after_first = r1.groups_touched

    r2 = import_scanner_file(
        db_session,
        engagement_id=engagement.id,
        source_path=sample_nessus,
        original_filename="sample_nessus_reimport.nessus",
        tool="nessus",
    )
    assert r2.observations_created == 6

    groups = (
        db_session.query(FindingGroup)
        .filter(FindingGroup.engagement_id == engagement.id)
        .all()
    )
    obs = (
        db_session.query(Observation)
        .filter(Observation.engagement_id == engagement.id)
        .all()
    )
    assert len(obs) == 12  # new observations each import (evidence trail)
    assert len(groups) == groups_after_first  # groups deduped by hash/key
    for g in groups:
        members = [o for o in obs if o.finding_group_id == g.id]
        assert len(members) == 2, f"Group {g.group_key} has {len(members)} members"


def test_xxe_entity_rejected(tmp_path):
    """defusedxml iterparse must reject external entity (XXE) — not weakened."""
    xxe = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<NessusClientData_v2>
  <Report name="x">
    <ReportHost name="1.2.3.4">
      <HostProperties>
        <tag name="host-ip">&xxe;</tag>
      </HostProperties>
      <ReportItem port="80" svc_name="www" protocol="tcp" severity="2"
        pluginID="99999" pluginName="XXE Probe" pluginFamily="Misc.">
        <description>should not parse</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""
    path = tmp_path / "xxe.nessus"
    path.write_text(xxe, encoding="utf-8")
    result = parse_nessus(path)
    # Security rejection surfaced as warning + no observations from the entity
    assert result.observations == []
    assert result.skipped_unparseable >= 1
    assert any("security" in w.lower() or "entit" in w.lower() for w in result.warnings)


def test_xxe_raises_at_iterparse_layer(tmp_path):
    """Direct iterparse still raises EntitiesForbidden (defense not bypassed)."""
    from defusedxml import ElementTree as ET

    path = tmp_path / "xxe2.nessus"
    path.write_text(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY e SYSTEM "file:///etc/hosts">]>'
        "<root>&e;</root>",
        encoding="utf-8",
    )
    with pytest.raises(EntitiesForbidden):
        list(ET.iterparse(path, events=("end",)))
