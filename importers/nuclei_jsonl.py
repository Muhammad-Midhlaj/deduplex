"""Nuclei JSONL (-jsonl) importer for Wave 1b scan jobs.

Each line is one Nuclei result object. Maps into the same ParsedObservation
shape used by nmap/nessus importers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Reuse nmap dataclass shapes so import_service stays uniform.
from importers.nmap_xml import ParsedObservation, ParseResult


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # ISO-8601 with optional Z
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _host_port_from_url(url: str | None) -> tuple[str | None, str | None, int | None, str | None]:
    if not url:
        return None, None, None, None
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:  # noqa: BLE001
        return None, None, None, None
    host = parsed.hostname
    port = parsed.port
    scheme = parsed.scheme or None
    if port is None and scheme == "https":
        port = 443
    elif port is None and scheme == "http":
        port = 80
    return host, host, port, scheme


def _severity(info: dict) -> str | None:
    sev = info.get("severity") or info.get("Severity")
    if sev is None:
        return None
    return str(sev).lower()


def parse_nuclei_jsonl(path: Path | str) -> ParseResult:
    path = Path(path)
    result = ParseResult()
    scan_time: datetime | None = None

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.warnings.append(f"Cannot read nuclei jsonl: {exc}")
        return result

    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            result.skipped_unparseable += 1
            result.warnings.append(f"Line {line_no}: invalid JSON")
            continue
        if not isinstance(obj, dict):
            result.skipped_unparseable += 1
            continue

        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        template_id = (
            obj.get("template-id")
            or obj.get("templateID")
            or obj.get("template_id")
            or info.get("name")
            or "unknown"
        )
        template_id = str(template_id)
        matched = obj.get("matched-at") or obj.get("matched") or obj.get("host") or ""
        hostname, ip_guess, port, protocol = _host_port_from_url(str(matched) if matched else None)
        # Prefer explicit host/ip fields when present.
        host_field = obj.get("host") or obj.get("ip")
        if isinstance(host_field, str) and host_field.strip():
            # host may be URL or bare hostname
            h2, ip2, p2, proto2 = _host_port_from_url(host_field)
            hostname = hostname or h2 or host_field
            if ip2 and (ip_guess is None or ":" in str(ip_guess) or not ip_guess.replace(".", "").isdigit()):
                ip_guess = ip2
            port = port if port is not None else p2
            protocol = protocol or proto2
        ip_field = obj.get("ip")
        if isinstance(ip_field, str) and ip_field.strip():
            ip_guess = ip_field.strip()

        ts = _parse_ts(obj.get("timestamp") or obj.get("time"))
        if ts and (scan_time is None or ts > scan_time):
            scan_time = ts

        title = info.get("name") or template_id
        description = None
        if isinstance(info.get("description"), str):
            description = info["description"]
        plugin_bits = []
        for key in ("matcher-name", "matcher_name", "type", "curl-command"):
            if obj.get(key):
                plugin_bits.append(f"{key}: {obj[key]}")
        if obj.get("extracted-results"):
            plugin_bits.append(f"extracted: {obj['extracted-results']}")
        plugin_output = "\n".join(plugin_bits) if plugin_bits else (str(matched) if matched else None)

        cve = None
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cve_list = classification.get("cve-id") or classification.get("cve_id")
        if isinstance(cve_list, list) and cve_list:
            cve = str(cve_list[0])
        elif isinstance(cve_list, str):
            cve = cve_list

        result.observations.append(
            ParsedObservation(
                tool="nuclei",
                rule_id=template_id,
                title=str(title) if title else template_id,
                severity=_severity(info),
                description=description,
                plugin_output=plugin_output,
                cve=cve,
                cvss=None,
                original_finding_id=str(obj.get("template-path") or template_id),
                scan_time=ts,
                hostname=hostname,
                ip_address=ip_guess,
                port=port,
                protocol=protocol,
                service=None,
                raw_excerpt=line[:500],
            )
        )

    result.scan_time = scan_time
    return result
