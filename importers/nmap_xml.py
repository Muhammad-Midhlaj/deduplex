"""Nmap XML importer.

Parses host/port/service and script findings into normalized observation dicts.
Raw file retention is handled by the import service; this module only parses.
Never silently drops parseable host/port records — unparseable nodes are counted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from defusedxml import ElementTree as ET


@dataclass
class ParsedObservation:
    tool: str
    rule_id: str
    title: str | None
    severity: str | None
    description: str | None
    plugin_output: str | None
    cve: str | None
    cvss: float | None
    original_finding_id: str | None
    scan_time: datetime | None
    hostname: str | None
    ip_address: str | None
    port: int | None
    protocol: str | None
    service: str | None
    raw_excerpt: str | None = None


@dataclass
class ParseResult:
    observations: list[ParsedObservation] = field(default_factory=list)
    scan_time: datetime | None = None
    warnings: list[str] = field(default_factory=list)
    skipped_unparseable: int = 0


def _parse_nmap_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # Nmap timestr like "Wed Sep 23 10:00:00 2026" or unix timestamp attr
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        pass
    for fmt in (
        "%a %b %d %H:%M:%S %Y",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _host_addrs(host: ET.Element) -> tuple[str | None, str | None]:
    ip_address = None
    hostname = None
    for addr in host.findall("address"):
        addrtype = addr.get("addrtype", "")
        if addrtype in ("ipv4", "ipv6") and not ip_address:
            ip_address = addr.get("addr")
    hostnames = host.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            if hn.get("name"):
                hostname = hn.get("name")
                break
    return ip_address, hostname


def _severity_from_script(script_id: str, output: str | None) -> str:
    text = f"{script_id} {output or ''}".lower()
    if any(k in text for k in ("critical", "vuln", "exploit", "cve-")):
        return "high"
    if "ssl" in text or "weak" in text:
        return "medium"
    return "info"


def parse_nmap_xml(path: str | Path) -> ParseResult:
    """Parse an Nmap XML file into normalized observations."""
    path = Path(path)
    result = ParseResult()
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        result.warnings.append(f"XML parse error: {exc}")
        result.skipped_unparseable += 1
        return result

    root = tree.getroot()
    start_time = root.get("start") or root.get("startstr")
    result.scan_time = _parse_nmap_time(start_time)

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue

        ip_address, hostname = _host_addrs(host)
        host_scan_time = result.scan_time
        endtime = host.get("endtime")
        if endtime:
            host_scan_time = _parse_nmap_time(endtime) or host_scan_time

        # Host-level scripts
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                script_id = script.get("id") or "unknown-script"
                output = script.get("output")
                result.observations.append(
                    ParsedObservation(
                        tool="nmap",
                        rule_id=script_id,
                        title=f"Nmap script: {script_id}",
                        severity=_severity_from_script(script_id, output),
                        description=f"Host script {script_id}",
                        plugin_output=output,
                        cve=None,
                        cvss=None,
                        original_finding_id=f"nmap:{script_id}:{ip_address or hostname or 'unknown'}",
                        scan_time=host_scan_time,
                        hostname=hostname,
                        ip_address=ip_address,
                        port=None,
                        protocol=None,
                        service=None,
                        raw_excerpt=ET.tostring(script, encoding="unicode")[:4000],
                    )
                )

        ports = host.find("ports")
        if ports is None:
            # Still record a host-up observation so the asset is not lost.
            if ip_address or hostname:
                result.observations.append(
                    ParsedObservation(
                        tool="nmap",
                        rule_id="host-up",
                        title="Host discovered",
                        severity="info",
                        description="Host was reported up with no open ports listed",
                        plugin_output=None,
                        cve=None,
                        cvss=None,
                        original_finding_id=f"nmap:host-up:{ip_address or hostname}",
                        scan_time=host_scan_time,
                        hostname=hostname,
                        ip_address=ip_address,
                        port=None,
                        protocol=None,
                        service=None,
                    )
                )
            continue

        for port_el in ports.findall("port"):
            try:
                portid = int(port_el.get("portid", "0"))
            except ValueError:
                result.skipped_unparseable += 1
                result.warnings.append(
                    f"Unparseable portid on host {ip_address or hostname}"
                )
                continue
            protocol = port_el.get("protocol")
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else None
            if state and state not in ("open", "open|filtered"):
                continue

            service_el = port_el.find("service")
            service_name = None
            product = None
            if service_el is not None:
                service_name = service_el.get("name")
                product = service_el.get("product")
                version = service_el.get("version")
                if product and version:
                    product = f"{product} {version}"

            # Port/service observation
            result.observations.append(
                ParsedObservation(
                    tool="nmap",
                    rule_id=f"port-{protocol or 'tcp'}-{portid}",
                    title=f"Open port {portid}/{protocol or 'tcp'}"
                    + (f" ({service_name})" if service_name else ""),
                    severity="info",
                    description=product or service_name,
                    plugin_output=None,
                    cve=None,
                    cvss=None,
                    original_finding_id=(
                        f"nmap:port:{ip_address or hostname}:{protocol or 'tcp'}:{portid}"
                    ),
                    scan_time=host_scan_time,
                    hostname=hostname,
                    ip_address=ip_address,
                    port=portid,
                    protocol=protocol,
                    service=service_name,
                )
            )

            # Port-level scripts (potential vulns)
            for script in port_el.findall("script"):
                script_id = script.get("id") or "unknown-script"
                output = script.get("output")
                result.observations.append(
                    ParsedObservation(
                        tool="nmap",
                        rule_id=script_id,
                        title=f"Nmap script: {script_id}",
                        severity=_severity_from_script(script_id, output),
                        description=f"Script {script_id} on {portid}/{protocol}",
                        plugin_output=output,
                        cve=None,
                        cvss=None,
                        original_finding_id=(
                            f"nmap:{script_id}:{ip_address or hostname}:"
                            f"{protocol or 'tcp'}:{portid}"
                        ),
                        scan_time=host_scan_time,
                        hostname=hostname,
                        ip_address=ip_address,
                        port=portid,
                        protocol=protocol,
                        service=service_name,
                        raw_excerpt=ET.tostring(script, encoding="unicode")[:4000],
                    )
                )

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
