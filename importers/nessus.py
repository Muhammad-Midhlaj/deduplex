"""Nessus (.nessus XML) importer.

Parses ReportHost / ReportItem into normalized observation dicts via streaming
iterparse (pyTenable NessusReportv2-style ReportItem walk) so large exports do
not need a full DOM in memory. Uses defusedxml for XXE defense.

Retains every parseable ReportItem; unparseable items are counted, not dropped
silently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from importers.nmap_xml import ParsedObservation, ParseResult


SEVERITY_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}


def build_nessus_original_finding_id(
    plugin_id: str,
    host: str | None,
    protocol: str,
    port: int,
) -> str:
    """Stable scanner-native id for retest / reimport matching.

    Pattern (DefectDojo-inspired field set, not their code): host + port +
    protocol + plugin_id. Format kept stable across streaming and legacy paths.
    """
    host_part = (host or "").strip() or "unknown"
    return f"nessus:{plugin_id}:{host_part}:{protocol}:{port}"


def _text(el: ET.Element | None) -> str | None:
    if el is None or el.text is None:
        return None
    return el.text.strip() or None


def _local_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _host_property(host: ET.Element, name: str) -> str | None:
    for child in host:
        if _local_tag(child.tag) != "HostProperties":
            continue
        for tag in child:
            if _local_tag(tag.tag) == "tag" and tag.get("name") == name:
                return (tag.text or "").strip() or None
    return None


def _parse_nessus_time(value: str | None) -> datetime | None:
    if not value:
        return None
    # Common formats: "Tue Sep 23 10:00:00 2026" or epoch
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        pass
    for fmt in (
        "%a %b %d %H:%M:%S %Y",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _observation_from_report_item(
    item: ET.Element,
    *,
    hostname: str | None,
    ip_address: str | None,
    dns: str | None,
    scan_time: datetime | None,
    result: ParseResult,
) -> ParsedObservation | None:
    plugin_id = item.get("pluginID")
    if not plugin_id:
        result.skipped_unparseable += 1
        result.warnings.append(
            f"ReportItem missing pluginID on host {hostname or ip_address}"
        )
        return None

    try:
        port = int(item.get("port") or "0")
    except ValueError:
        port = 0
        result.warnings.append(
            f"Unparseable port for plugin {plugin_id}; stored as 0"
        )

    protocol = item.get("protocol") or "tcp"
    service = item.get("svc_name")
    severity_code = item.get("severity", "0")
    severity = SEVERITY_MAP.get(severity_code, "info")
    plugin_name = item.get("pluginName") or f"Plugin {plugin_id}"

    description = _text(item.find("description"))
    plugin_output = _text(item.find("plugin_output"))
    synopsis = _text(item.find("synopsis"))
    # Multiple CVEs possible — join first few
    cves = [_text(c) for c in item.findall("cve")]
    cves = [c for c in cves if c]
    cve = ", ".join(cves[:5]) if cves else None

    cvss_raw = _text(item.find("cvss3_base_score")) or _text(
        item.find("cvss_base_score")
    )
    cvss = None
    if cvss_raw:
        try:
            cvss = float(cvss_raw)
        except ValueError:
            result.warnings.append(
                f"Unparseable CVSS '{cvss_raw}' for plugin {plugin_id}"
            )

    original_finding_id = build_nessus_original_finding_id(
        str(plugin_id),
        ip_address or hostname,
        protocol,
        port,
    )

    return ParsedObservation(
        tool="nessus",
        rule_id=str(plugin_id),
        title=plugin_name,
        severity=severity,
        description=description or synopsis,
        plugin_output=plugin_output,
        cve=cve,
        cvss=cvss,
        original_finding_id=original_finding_id,
        scan_time=scan_time,
        hostname=hostname if hostname != ip_address else dns,
        ip_address=ip_address,
        port=port if port != 0 else None,
        protocol=protocol if port != 0 else None,
        service=service if service and service != "general" else None,
        raw_excerpt=ET.tostring(item, encoding="unicode")[:4000],
    )


def _process_report_host(host: ET.Element, result: ParseResult) -> None:
    hostname = host.get("name")
    ip_address = _host_property(host, "host-ip") or hostname
    dns = _host_property(host, "host-fqdn") or _host_property(host, "hostname")
    if dns:
        hostname = dns
    host_start = _host_property(host, "HOST_START")
    scan_time = _parse_nessus_time(host_start)
    if scan_time and (result.scan_time is None or scan_time < result.scan_time):
        result.scan_time = scan_time

    for child in host:
        if _local_tag(child.tag) != "ReportItem":
            continue
        obs = _observation_from_report_item(
            child,
            hostname=hostname,
            ip_address=ip_address,
            dns=dns,
            scan_time=scan_time,
            result=result,
        )
        if obs is not None:
            result.observations.append(obs)


def parse_nessus(path: str | Path) -> ParseResult:
    """Parse a .nessus XML export into normalized observations.

    Uses defusedxml iterparse (forbid_entities=True by default) and clears each
    ReportHost after processing so peak memory stays proportional to one host
    subtree rather than the full document.
    """
    path = Path(path)
    result = ParseResult()
    try:
        # events=("end",) only: process a host when its closing tag is seen,
        # then clear that subtree (NessusReportv2-style incremental walk).
        for _event, elem in ET.iterparse(path, events=("end",)):
            if _local_tag(elem.tag) != "ReportHost":
                continue
            _process_report_host(elem, result)
            # Free memory for this host and descendants.
            elem.clear()
    except DefusedXmlException as exc:
        result.warnings.append(f"XML security rejection: {exc}")
        result.skipped_unparseable += 1
        return result
    except ET.ParseError as exc:
        result.warnings.append(f"XML parse error: {exc}")
        result.skipped_unparseable += 1
        return result

    if not result.observations and result.skipped_unparseable == 0:
        # Empty but valid file — not a silent loss; surface a warning.
        result.warnings.append("No ReportItem elements found in Nessus file")

    return result


def observations_as_dicts(result: ParseResult) -> list[dict[str, Any]]:
    return [
        {
            "tool": o.tool,
            "rule_id": o.rule_id,
            "title": o.title,
            "severity": o.severity,
            "description": o.description,
            "plugin_output": o.plugin_output,
            "cve": o.cve,
            "cvss": o.cvss,
            "original_finding_id": o.original_finding_id,
            "scan_time": o.scan_time,
            "hostname": o.hostname,
            "ip_address": o.ip_address,
            "port": o.port,
            "protocol": o.protocol,
            "service": o.service,
        }
        for o in result.observations
    ]
