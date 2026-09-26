from services.asset_mapping import build_canonical_key, get_or_create_asset
from services.grouping import build_duplicate_key, get_or_create_group
from services.import_service import import_scanner_file
from app.models import FindingGroup, Observation


def test_canonical_key_stable():
    a = build_canonical_key(
        ip_address="192.168.1.10", hostname="Web.Lab.Local", port=443, protocol="TCP"
    )
    b = build_canonical_key(
        ip_address="192.168.1.10", hostname="web.lab.local", port=443, protocol="tcp"
    )
    assert a == b
    assert a == "web.lab.local|192.168.1.10|tcp|443"


def test_duplicate_key_format():
    key = build_duplicate_key("nessus", "104743", "web.lab.local|192.168.1.10|tcp|443")
    assert key == "nessus|104743|web.lab.local|192.168.1.10|tcp|443"


def test_exact_duplicate_grouping_on_reimport(db_session, engagement, sample_nmap, tmp_path):
    # Import twice — exact duplicates must land in the same finding group.
    r1 = import_scanner_file(
        db_session,
        engagement_id=engagement.id,
        source_path=sample_nmap,
        original_filename="sample_nmap.xml",
        tool="nmap",
    )
    assert r1.observations_created > 0

    # Copy again via same path (evidence stored separately each time)
    r2 = import_scanner_file(
        db_session,
        engagement_id=engagement.id,
        source_path=sample_nmap,
        original_filename="sample_nmap_again.xml",
        tool="nmap",
    )
    assert r2.observations_created == r1.observations_created

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
    # Twice the observations, same number of groups as first import's unique keys
    assert len(obs) == r1.observations_created * 2
    assert len(groups) == r1.groups_touched

    # Each group should have exactly 2 observations
    for g in groups:
        members = [o for o in obs if o.finding_group_id == g.id]
        assert len(members) == 2, f"Group {g.group_key} has {len(members)} members"


def test_asset_get_or_create(db_session, engagement):
    a1, created1 = get_or_create_asset(
        db_session,
        engagement.id,
        hostname="web.lab.local",
        ip_address="192.168.1.10",
        port=80,
        protocol="tcp",
        service="http",
    )
    db_session.commit()
    assert created1 is True

    a2, created2 = get_or_create_asset(
        db_session,
        engagement.id,
        hostname="web.lab.local",
        ip_address="192.168.1.10",
        port=80,
        protocol="tcp",
    )
    db_session.commit()
    assert created2 is False
    assert a1.id == a2.id


def test_group_get_or_create(db_session, engagement):
    asset, _ = get_or_create_asset(
        db_session,
        engagement.id,
        hostname="web.lab.local",
        ip_address="192.168.1.10",
        port=443,
        protocol="tcp",
    )
    db_session.flush()
    g1, c1 = get_or_create_group(
        db_session,
        engagement_id=engagement.id,
        tool="nmap",
        rule_id="ssl-ccs-injection",
        asset=asset,
        title="CCS",
        severity="high",
        priority_score=0.8,
    )
    db_session.flush()
    g2, c2 = get_or_create_group(
        db_session,
        engagement_id=engagement.id,
        tool="nmap",
        rule_id="ssl-ccs-injection",
        asset=asset,
        title="CCS",
        severity="high",
        priority_score=0.9,
    )
    assert c1 is True and c2 is False
    assert g1.id == g2.id
    assert g2.priority_score == 0.9
