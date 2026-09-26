#!/usr/bin/env python3
"""Generate large-ish dummy Nmap XML and Nessus exports for perf testing.

Writes under sample_data/perf/ by default. XML is valid-enough for project importers.
"""
from __future__ import annotations

import argparse
import html
import random
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

PORT_SERVICES = [
    (22, "ssh", "OpenSSH", "8.9p1"),
    (80, "http", "nginx", "1.24.0"),
    (443, "https", "nginx", "1.24.0"),
    (3306, "mysql", "MySQL", "5.7.40"),
    (5432, "postgresql", "PostgreSQL", "14.9"),
    (8080, "http-proxy", "Apache httpd", "2.4.57"),
    (3389, "ms-wbt-server", "Microsoft Terminal Services", None),
    (445, "microsoft-ds", "Samba", "4.17"),
    (25, "smtp", "Postfix", "3.7.0"),
    (53, "domain", "ISC BIND", "9.18"),
]

SCRIPTS = [
    ("http-title", "Welcome to lab host {host}"),
    ("http-slowloris-check", "LIKELY VULNERABLE: Slowloris DoS attack possible"),
    ("ssl-ccs-injection", "VULNERABLE: SSL/TLS CCS Injection (CVE-2014-0224)"),
    ("ssl-heartbleed", "VULNERABLE: Heartbleed (CVE-2014-0160)"),
    ("ssh2-enum-algos", "kex_algorithms: curve25519-sha256"),
    ("mysql-info", "Protocol: 10\\nVersion: 5.7.40"),
]

NESSUS_PLUGINS = [
    (104743, "SSL/TLS CCS Injection", "Service Detection", 3, 5.8, 7.4, "CVE-2014-0224", 443, "https"),
    (11213, "HTTP TRACE / TRACK Methods Allowed", "Web Servers", 2, 5.0, None, None, 80, "www"),
    (70658, "SSH Server CBC Mode Ciphers Enabled", "Misc.", 1, 2.6, None, None, 22, "ssh"),
    (55446, "MySQL Server Unsupported Version Detection", "Databases", 3, None, 7.5, None, 3306, "mysql"),
    (155155, "MySQL Empty Password", "Databases", 2, 7.5, None, "CVE-2002-1809", 3306, "mysql"),
    (19506, "Nessus Scan Information", "Settings", 0, None, None, None, 0, "general"),
    (51192, "SSL Certificate Cannot Be Trusted", "General", 2, 6.4, None, None, 443, "https"),
    (57582, "SSL Self-Signed Certificate", "General", 2, 6.4, None, None, 443, "https"),
    (26928, "SSL Medium Strength Cipher Suites Supported", "General", 1, 4.3, None, None, 443, "https"),
    (108797, "TLS Version 1.0 Protocol Detection", "Service Detection", 2, 5.0, None, None, 443, "https"),
    (42873, "SSL Certificate Expiry", "General", 1, 3.0, None, None, 443, "https"),
    (10107, "HTTP Server Type and Version", "Web Servers", 0, None, None, None, 80, "www"),
    (24260, "HyperText Transfer Protocol (HTTP) Information", "Web Servers", 0, None, None, None, 80, "www"),
    (10267, "SSH Protocol Versions Supported", "Misc.", 0, None, None, None, 22, "ssh"),
    (70657, "SSH Weak MAC Algorithms Enabled", "Misc.", 1, 2.6, None, None, 22, "ssh"),
    (33814, "OpenSSH X11 Forwarding Session Hijacking", "Misc.", 2, 5.0, "CVE-2008-1483", "CVE-2008-1483", 22, "ssh"),
    (34477, "Network Time Protocol (NTP) Mode 7 Detector", "RPC", 1, 5.0, None, None, 123, "ntp"),
    (18405, "Microsoft Windows SMB Shares Unprivileged Access", "Windows", 3, 7.5, None, None, 445, "cifs"),
    (57608, "SMB Signing not required", "Windows", 2, 5.0, None, None, 445, "cifs"),
    (22056, "Nessus SYN scanner", "Port scanners", 0, None, None, None, 0, "general"),
]


def _xml_escape(s: str) -> str:
    return html.escape(s, quote=True)


def generate_nmap(out: Path, n_hosts: int, seed: int) -> dict:
    rng = random.Random(seed)
    start = 1790157600
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<!DOCTYPE nmaprun>",
        f'<nmaprun scanner="nmap" args="nmap -sV -sC -oX perf_nmap.xml 10.20.0.0/24" '
        f'start="{start}" startstr="Tue Sep 23 10:00:00 2026" version="7.94" xmloutputversion="1.05">',
    ]
    host_count = 0
    port_count = 0
    script_count = 0
    for i in range(n_hosts):
        octet3 = (i // 250) % 256
        octet4 = (i % 250) + 1
        ip = f"10.20.{octet3}.{octet4}"
        hostname = f"host-{i:04d}.perf.lab.local"
        end = start + 60 + (i % 30)
        lines.append(f'  <host starttime="{start}" endtime="{end}">')
        lines.append('    <status state="up" reason="echo-reply"/>')
        lines.append(f'    <address addr="{ip}" addrtype="ipv4"/>')
        lines.append("    <hostnames>")
        lines.append(f'      <hostname name="{hostname}" type="PTR"/>')
        lines.append("    </hostnames>")
        lines.append("    <ports>")
        n_ports = rng.randint(3, 7)
        chosen = rng.sample(PORT_SERVICES, k=min(n_ports, len(PORT_SERVICES)))
        for portid, svc, product, version in chosen:
            port_count += 1
            ver_attr = f' version="{version}"' if version else ""
            lines.append(f'      <port protocol="tcp" portid="{portid}">')
            lines.append('        <state state="open" reason="syn-ack"/>')
            lines.append(
                f'        <service name="{svc}" product="{product}"{ver_attr} method="probed"/>'
            )
            # Attach 0-2 scripts on web/ssl/db-ish ports
            if portid in (80, 443, 22, 3306) and rng.random() < 0.7:
                script = rng.choice(SCRIPTS)
                # Prefer relevant scripts lightly
                if portid == 443:
                    script = rng.choice([s for s in SCRIPTS if "ssl" in s[0] or "http" in s[0]] or SCRIPTS)
                elif portid == 80:
                    script = rng.choice([s for s in SCRIPTS if "http" in s[0]] or SCRIPTS)
                elif portid == 22:
                    script = next((s for s in SCRIPTS if s[0].startswith("ssh")), SCRIPTS[0])
                output = script[1].format(host=hostname)
                lines.append(
                    f'        <script id="{script[0]}" output="{_xml_escape(output)}"/>'
                )
                script_count += 1
            lines.append("      </port>")
        lines.append("    </ports>")
        lines.append("  </host>")
        host_count += 1
    lines.append("</nmaprun>")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "path": str(out),
        "hosts": host_count,
        "open_ports": port_count,
        "scripts": script_count,
        "bytes": out.stat().st_size,
    }


def generate_nessus(out: Path, n_hosts: int, items_per_host: int, seed: int) -> dict:
    rng = random.Random(seed + 1)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<NessusClientData_v2>",
        "  <Policy>",
        "    <policyName>Perf Network Scan</policyName>",
        "  </Policy>",
        '  <Report name="Perf Lab Network Scan">',
    ]
    item_count = 0
    for i in range(n_hosts):
        octet3 = (i // 250) % 256
        octet4 = (i % 250) + 1
        ip = f"10.20.{octet3}.{octet4}"
        hostname = f"host-{i:04d}.perf.lab.local"
        lines.append(f'    <ReportHost name="{ip}">')
        lines.append("      <HostProperties>")
        lines.append(f'        <tag name="host-ip">{ip}</tag>')
        lines.append(f'        <tag name="host-fqdn">{hostname}</tag>')
        lines.append('        <tag name="HOST_START">Tue Sep 23 10:05:00 2026</tag>')
        lines.append('        <tag name="HOST_END">Tue Sep 23 10:40:00 2026</tag>')
        lines.append("      </HostProperties>")
        # Always include scan-info + a sample of plugins
        plugins = list(NESSUS_PLUGINS)
        rng.shuffle(plugins)
        selected = plugins[: max(1, min(items_per_host, len(plugins)))]
        # pad by repeating variants with unique-ish pluginID offsets if needed
        while len(selected) < items_per_host:
            base = rng.choice(NESSUS_PLUGINS)
            offset = 100000 + len(selected) + i
            selected.append(
                (
                    base[0] + offset % 9000,
                    f"{base[1]} (variant {len(selected)})",
                    base[2],
                    base[3],
                    base[4],
                    base[5],
                    base[6],
                    base[7],
                    base[8],
                )
            )
        for plugin in selected:
            (
                plugin_id,
                name,
                family,
                severity,
                cvss,
                cvss3,
                cve,
                port,
                svc,
            ) = plugin
            lines.append(
                f'      <ReportItem port="{port}" svc_name="{svc}" protocol="tcp" '
                f'severity="{severity}" pluginID="{plugin_id}" '
                f'pluginName="{_xml_escape(name)}" pluginFamily="{_xml_escape(family)}">'
            )
            lines.append(
                f"        <description>Synthetic finding for perf host {hostname}: {_xml_escape(name)}.</description>"
            )
            lines.append(f"        <synopsis>{_xml_escape(name)} detected.</synopsis>")
            lines.append(
                f"        <plugin_output>Host={hostname} IP={ip} port={port} plugin={plugin_id}</plugin_output>"
            )
            if cve:
                lines.append(f"        <cve>{cve}</cve>")
            if cvss is not None:
                lines.append(f"        <cvss_base_score>{cvss}</cvss_base_score>")
            if cvss3 is not None:
                lines.append(f"        <cvss3_base_score>{cvss3}</cvss3_base_score>")
            lines.append("      </ReportItem>")
            item_count += 1
        lines.append("    </ReportHost>")
    lines.append("  </Report>")
    lines.append("</NessusClientData_v2>")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "path": str(out),
        "hosts": n_hosts,
        "report_items": item_count,
        "bytes": out.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate perf dummy scanner files")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=PROJECT_ROOT / "sample_data" / "perf",
        help="Output directory (default: sample_data/perf)",
    )
    parser.add_argument("--nmap-hosts", type=int, default=200)
    parser.add_argument("--nessus-hosts", type=int, default=120)
    parser.add_argument("--nessus-items-per-host", type=int, default=18)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    out_dir = args.out_dir
    if not out_dir.is_absolute():
        out_dir = PROJECT_ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    nmap_meta = generate_nmap(out_dir / "perf_nmap.xml", args.nmap_hosts, args.seed)
    nessus_meta = generate_nessus(
        out_dir / "perf_nessus.nessus",
        args.nessus_hosts,
        args.nessus_items_per_host,
        args.seed,
    )
    print("Nmap:", nmap_meta)
    print("Nessus:", nessus_meta)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
