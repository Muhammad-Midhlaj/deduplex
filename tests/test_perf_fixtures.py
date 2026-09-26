"""Smoke: generate_perf_fixtures writes parseable Nmap/Nessus for a tiny host count."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from importers.nessus import parse_nessus
from importers.nmap_xml import parse_nmap_xml

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_generator():
    path = PROJECT_ROOT / "scripts" / "generate_perf_fixtures.py"
    spec = importlib.util.spec_from_file_location("generate_perf_fixtures", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def tiny_perf_dir(tmp_path: Path) -> Path:
    gen = _load_generator()
    hosts = 3
    nmap_xml = gen.generate_nmap_xml(hosts, ports_per_host=2, duplicate_every=2)
    nessus_xml = gen.generate_nessus_xml(
        hosts, items_per_host=3, duplicate_every=2
    )
    nmap_path = tmp_path / "perf_nmap.xml"
    nessus_path = tmp_path / "perf_nessus.nessus"
    nmap_path.write_text(nmap_xml, encoding="utf-8")
    nessus_path.write_text(nessus_xml, encoding="utf-8")
    return tmp_path


def test_generate_perf_fixtures_parseable(tiny_perf_dir: Path):
    nmap_path = tiny_perf_dir / "perf_nmap.xml"
    nessus_path = tiny_perf_dir / "perf_nessus.nessus"
    assert nmap_path.exists() and nmap_path.stat().st_size > 100
    assert nessus_path.exists() and nessus_path.stat().st_size > 100

    nmap = parse_nmap_xml(nmap_path)
    assert nmap.skipped_unparseable == 0
    assert len(nmap.observations) > 0
    assert any(o.tool == "nmap" for o in nmap.observations)
    ips = {o.ip_address for o in nmap.observations if o.ip_address}
    assert any(ip.startswith("10.50.") for ip in ips)

    nessus = parse_nessus(nessus_path)
    assert nessus.skipped_unparseable == 0
    assert len(nessus.observations) > 0
    assert any(o.tool == "nessus" for o in nessus.observations)
    plugin_ids = {o.rule_id for o in nessus.observations}
    assert len(plugin_ids) >= 2  # varied plugins, not one blob


def test_generate_cli_writes_outdir(tmp_path: Path):
    """CLI entry writes expected filenames and prints counts."""
    gen = _load_generator()
    # Exercise CLI main via argv
    import sys

    argv = [
        "generate_perf_fixtures.py",
        "--hosts",
        "2",
        "--ports-per-host",
        "2",
        "--nessus-items-per-host",
        "2",
        "--outdir",
        str(tmp_path),
        "--duplicate-every",
        "0",
    ]
    old = sys.argv
    try:
        sys.argv = argv
        rc = gen.main()
    finally:
        sys.argv = old
    assert rc == 0
    assert (tmp_path / "perf_nmap.xml").exists()
    assert (tmp_path / "perf_nessus.nessus").exists()
    nmap = parse_nmap_xml(tmp_path / "perf_nmap.xml")
    nessus = parse_nessus(tmp_path / "perf_nessus.nessus")
    assert len(nmap.observations) > 0
    assert len(nessus.observations) > 0
