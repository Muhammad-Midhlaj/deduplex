from importers.nmap_xml import parse_nmap_xml


def test_parse_sample_nmap(sample_nmap):
    result = parse_nmap_xml(sample_nmap)
    assert result.skipped_unparseable == 0
    assert len(result.observations) >= 6  # ports + scripts

    tools = {o.tool for o in result.observations}
    assert tools == {"nmap"}

    ips = {o.ip_address for o in result.observations}
    assert "192.168.1.10" in ips
    assert "192.168.1.11" in ips

    rule_ids = {o.rule_id for o in result.observations}
    assert "ssl-ccs-injection" in rule_ids
    assert "http-slowloris-check" in rule_ids
    assert "port-tcp-22" in rule_ids

    ccs = next(o for o in result.observations if o.rule_id == "ssl-ccs-injection")
    assert ccs.port == 443
    assert ccs.hostname == "web.lab.local"
    assert ccs.original_finding_id is not None
    assert "VULNERABLE" in (ccs.plugin_output or "")


def test_nmap_retains_host_without_dropping(sample_nmap):
    result = parse_nmap_xml(sample_nmap)
    # Every open port should produce at least a port-* observation
    port_obs = [o for o in result.observations if o.rule_id.startswith("port-")]
    assert len(port_obs) == 5  # 22,80,443 on .10 and 3306,22 on .11
