#!/usr/bin/env python3
"""Generate scaled dummy Nmap XML + Nessus XML for Core import/group/queue load tests.

These are synthetic scanner exports for VAPT Core performance fixtures — not Laya labels.
"""

from __future__ import annotations

import argparse
import html
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Varied ports/services so host×port assets multiply.
PORT_CATALOG: list[tuple[int, str, str, str]] = [
    (22, "ssh", "OpenSSH", "8.9p1"),
    (80, "http", "nginx", "1.24.0"),
    (443, "https", "nginx", "1.24.0"),
    (3306, "mysql", "MySQL", "8.0.36"),
    (8080, "http-proxy", "Apache httpd", "2.4.57"),
    (5432, "postgresql", "PostgreSQL", "15.4"),
    (25, "smtp", "Postfix smtpd", "3.8.1"),
    (445, "microsoft-ds", "Samba smbd", "4.18"),
    (3389, "ms-wbt-server", "xrdp", "0.9.22"),
    (6379, "redis", "Redis", "7.2.1"),
]

# Script ids vary so grouping creates many distinct finding groups.
SCRIPT_CATALOG: list[tuple[str, str]] = [
    ("http-title", "Welcome to perf host"),
    ("http-slowloris-check", "LIKELY VULNERABLE: Slowloris DoS attack possible"),
    ("ssl-ccs-injection", "VULNERABLE: SSL/TLS CCS Injection (CVE-2014-0224)"),
    ("ssl-dh-params", "WEAK: Diffie-Hellman parameters are vulnerable"),
    ("ssh2-enum-algos", "kex_algorithms: curve25519-sha256"),
    ("mysql-info", "Protocol: 10\nVersion: 8.0.36"),
    ("http-methods", "Supported Methods: GET HEAD POST OPTIONS TRACE"),
    ("ssl-cert", "Subject: CN=perf.lab.local"),
    ("vuln-ms17-010", "VULNERABLE: Remote Code Execution vulnerability in SMBv1"),
    ("redis-info", "redis_version:7.2.1"),
]

# Nessus plugins with severity 0-4; varied IDs for distinct groups.
NESSUS_PLUGINS: list[tuple[str, str, str, int, str, str | None, float | None]] = [
    # pluginID, pluginName, family, severity, description, cve, cvss3
    ("19506", "Nessus Scan Information", "Settings", 0, "Scan metadata for this host.", None, None),
    ("11213", "HTTP TRACE / TRACK Methods Allowed", "Web Servers", 2, "TRACE/TRACK methods are enabled.", None, 5.0),
    ("104743", "SSL/TLS CCS Injection", "Service Detection", 3, "OpenSSL CCS Injection (CVE-2014-0224).", "CVE-2014-0224", 7.4),
    ("70658", "SSH Server CBC Mode Ciphers Enabled", "Misc.", 1, "SSH supports CBC mode ciphers.", None, 2.6),
    ("55446", "MySQL Server Unsupported Version Detection", "Databases", 3, "Unsupported MySQL version detected.", None, 7.5),
    ("155155", "MySQL Empty Password", "Databases", 2, "MySQL accepts empty password for an account.", "CVE-2002-1809", 7.5),
    ("51192", "SSL Certificate Cannot Be Trusted", "General", 2, "The SSL certificate chain is not trusted.", None, 5.0),
    ("57582", "SSL Self-Signed Certificate", "General", 1, "The SSL certificate is self-signed.", None, 2.6),
    ("10079", "Anonymous FTP Enabled", "FTP", 2, "Anonymous FTP access is allowed.", None, 5.0),
    ("41028", "SSL Version 2 and 3 Protocol Detection", "Service Detection", 3, "SSLv2/SSLv3 is supported.", "CVE-2014-3566", 7.5),
    ("57608", "SMB Signing Disabled", "Windows", 2, "SMB signing is not required.", None, 5.3),
    ("10394", "Microsoft Windows SMB LsaQuerySecret User Enumeration", "Windows", 1, "SMB user enumeration possible.", None, 3.3),
    ("26928", "SSL Medium Strength Cipher Suites Supported", "Service Detection", 2, "Medium-strength SSL ciphers in use.", None, 5.0),
    ("42873", "SSL Certificate Expiry", "General", 1, "SSL certificate is expired or near expiry.", None, 2.6),
    ("20007", "SSL Version 2 (v2) Protocol Detection", "Service Detection", 4, "SSLv2 enables critical protocol attacks.", "CVE-2016-0800", 9.0),
    ("121010", "Redis Unauthenticated Access", "Databases", 4, "Redis accepts unauthenticated connections.", None, 9.8),
    ("84502", "PostgreSQL Default Unpassworded Account", "Databases", 3, "PostgreSQL has a default weak account.", None, 7.5),
    ("10107", "HTTP Server Type and Version", "Web Servers", 0, "Web server banner information.", None, None),
    ("22964", "Service Detection", "Service Detection", 0, "A network service was detected.", None, None),
    ("34277", "Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness", "Windows", 3, "RDP MitM weakness detected.", "CVE-2005-1794", 7.1),
]


def _host_ip(index: int) -> str:
    """Map host index to 10.50.x.y (avoids colliding with lab samples on 192.168.1.x)."""
    # index 0 -> 10.50.0.1 … wrap after .254
    third = (index // 254) % 256
    fourth = (index % 254) + 1
    return f"10.50.{third}.{fourth}"


def _hostname(index: int) -> str:
    return f"host-{index:04d}.perf.lab.local"


def _escape(text: str) -> str:
    return html.escape(text, quote=True)


def generate_nmap_xml(
    hosts: int,
    ports_per_host: int,
    *,
    duplicate_every: int = 10,
) -> str:
    """Build Nmap XML with open ports + scripts; intentional duplicates every N hosts."""
    start_ts = 1790157600
    lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<!DOCTYPE nmaprun>",
        (
            f'<nmaprun scanner="nmap" args="nmap -sV -sC -oX perf_nmap.xml 10.50.0.0/16" '
            f'start="{start_ts}" startstr="Tue Sep 23 10:00:00 2026" '
            f'version="7.94" xmloutputversion="1.05">'
        ),
    ]

    for i in range(hosts):
        ip = _host_ip(i)
        hn = _hostname(i)
        end_ts = start_ts + 60 + (i % 30)
        lines.append(f'  <host starttime="{start_ts}" endtime="{end_ts}">')
        lines.append('    <status state="up" reason="echo-reply"/>')
        lines.append(f'    <address addr="{ip}" addrtype="ipv4"/>')
        lines.append("    <hostnames>")
        lines.append(f'      <hostname name="{hn}" type="PTR"/>')
        lines.append("    </hostnames>")
        lines.append("    <ports>")

        # Rotate port catalog so different hosts get different port sets
        port_slice = [
            PORT_CATALOG[(i + j) % len(PORT_CATALOG)] for j in range(ports_per_host)
        ]
        for pidx, (portid, svc, product, version) in enumerate(port_slice):
            lines.append(f'      <port protocol="tcp" portid="{portid}">')
            lines.append('        <state state="open" reason="syn-ack"/>')
            lines.append(
                f'        <service name="{svc}" product="{_escape(product)}" '
                f'version="{_escape(version)}" method="probed"/>'
            )
            # Attach 1–2 scripts per port, rotated for variety
            script_a = SCRIPT_CATALOG[(i + pidx) % len(SCRIPT_CATALOG)]
            script_b = SCRIPT_CATALOG[(i + pidx + 3) % len(SCRIPT_CATALOG)]
            for sid, output in (script_a, script_b):
                lines.append(
                    f'        <script id="{_escape(sid)}" output="{_escape(output)}"/>'
                )
            lines.append("      </port>")

        lines.append("    </ports>")
        # Occasional host-level script
        if i % 7 == 0:
            hs = SCRIPT_CATALOG[i % len(SCRIPT_CATALOG)]
            lines.append("    <hostscript>")
            lines.append(
                f'      <script id="{_escape(hs[0])}" output="{_escape(hs[1])}"/>'
            )
            lines.append("    </hostscript>")
        lines.append("  </host>")

        # Intentional duplicate host block (same IP/ports/scripts) to exercise grouping
        if duplicate_every > 0 and (i + 1) % duplicate_every == 0:
            lines.append(
                f"  <!-- intentional duplicate of host {ip} for duplicate-grouping -->"
            )
            lines.append(f'  <host starttime="{start_ts}" endtime="{end_ts}">')
            lines.append('    <status state="up" reason="echo-reply"/>')
            lines.append(f'    <address addr="{ip}" addrtype="ipv4"/>')
            lines.append("    <hostnames>")
            lines.append(f'      <hostname name="{hn}" type="PTR"/>')
            lines.append("    </hostnames>")
            lines.append("    <ports>")
            # Duplicate first port + first script only (same rule_id + asset key)
            portid, svc, product, version = port_slice[0]
            sid, output = SCRIPT_CATALOG[(i) % len(SCRIPT_CATALOG)]
            lines.append(f'      <port protocol="tcp" portid="{portid}">')
            lines.append('        <state state="open" reason="syn-ack"/>')
            lines.append(
                f'        <service name="{svc}" product="{_escape(product)}" '
                f'version="{_escape(version)}" method="probed"/>'
            )
            lines.append(
                f'        <script id="{_escape(sid)}" output="{_escape(output)}"/>'
            )
            lines.append("      </port>")
            lines.append("    </ports>")
            lines.append("  </host>")

    lines.append("</nmaprun>")
    lines.append("")
    return "\n".join(lines)


def generate_nessus_xml(
    hosts: int,
    items_per_host: int,
    *,
    duplicate_every: int = 10,
) -> str:
    """Build NessusClientData_v2 with ReportHost/ReportItem; a few intentional dupes."""
    lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<NessusClientData_v2>",
        "  <Policy>",
        "    <policyName>Perf Load Scan</policyName>",
        "  </Policy>",
        '  <Report name="Perf Load Network Scan">',
    ]

    for i in range(hosts):
        ip = _host_ip(i)
        hn = _hostname(i)
        lines.append(f'    <ReportHost name="{ip}">')
        lines.append("      <HostProperties>")
        lines.append(f'        <tag name="host-ip">{ip}</tag>')
        lines.append(f'        <tag name="host-fqdn">{hn}</tag>')
        lines.append('        <tag name="HOST_START">Tue Sep 23 10:05:00 2026</tag>')
        lines.append('        <tag name="HOST_END">Tue Sep 23 10:40:00 2026</tag>')
        lines.append("      </HostProperties>")

        plugins = [
            NESSUS_PLUGINS[(i + j) % len(NESSUS_PLUGINS)] for j in range(items_per_host)
        ]
        for j, (pid, pname, family, sev, desc, cve, cvss) in enumerate(plugins):
            # Bind to a rotating port from PORT_CATALOG (0 for info/general)
            if sev == 0 and j == 0:
                port, svc = 0, "general"
            else:
                port, svc, _, _ = PORT_CATALOG[(i + j) % len(PORT_CATALOG)]
            lines.append(
                f'      <ReportItem port="{port}" svc_name="{svc}" protocol="tcp" '
                f'severity="{sev}" pluginID="{pid}" pluginName="{_escape(pname)}" '
                f'pluginFamily="{_escape(family)}">'
            )
            lines.append(f"        <description>{_escape(desc)}</description>")
            lines.append(f"        <synopsis>{_escape(pname)}</synopsis>")
            lines.append(
                f"        <plugin_output>Observed on {_escape(ip)}:{port}</plugin_output>"
            )
            if cve:
                lines.append(f"        <cve>{cve}</cve>")
            if cvss is not None:
                lines.append(f"        <cvss3_base_score>{cvss}</cvss3_base_score>")
                lines.append(f"        <cvss_base_score>{cvss}</cvss_base_score>")
            lines.append("      </ReportItem>")

        # Intentional duplicate ReportItem (same pluginID/host/port) for grouping
        if duplicate_every > 0 and (i + 1) % duplicate_every == 0 and plugins:
            pid, pname, family, sev, desc, cve, cvss = plugins[0]
            port, svc, _, _ = PORT_CATALOG[i % len(PORT_CATALOG)]
            if sev == 0:
                port, svc = 0, "general"
            lines.append(
                f"      <!-- intentional duplicate plugin {pid} on {ip}:{port} -->"
            )
            lines.append(
                f'      <ReportItem port="{port}" svc_name="{svc}" protocol="tcp" '
                f'severity="{sev}" pluginID="{pid}" pluginName="{_escape(pname)}" '
                f'pluginFamily="{_escape(family)}">'
            )
            lines.append(f"        <description>{_escape(desc)} (duplicate)</description>")
            lines.append(f"        <synopsis>{_escape(pname)}</synopsis>")
            lines.append(
                f"        <plugin_output>Duplicate observation on {_escape(ip)}</plugin_output>"
            )
            lines.append("      </ReportItem>")

        lines.append("    </ReportHost>")

    lines.append("  </Report>")
    lines.append("</NessusClientData_v2>")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate scaled dummy Nmap/Nessus XML under sample_data/perf/"
    )
    parser.add_argument("--hosts", type=int, default=50, help="Number of hosts (default 50)")
    parser.add_argument(
        "--ports-per-host",
        type=int,
        default=4,
        help="Open ports per host in Nmap XML (default 4)",
    )
    parser.add_argument(
        "--nessus-items-per-host",
        type=int,
        default=6,
        help="ReportItems per host in Nessus XML (default 6)",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=PROJECT_ROOT / "sample_data" / "perf",
        help="Output directory (default: sample_data/perf)",
    )
    parser.add_argument(
        "--duplicate-every",
        type=int,
        default=10,
        help="Emit an intentional duplicate every N hosts (0=disable, default 10)",
    )
    args = parser.parse_args()

    if args.hosts < 1:
        print("--hosts must be >= 1", file=sys.stderr)
        return 1
    if args.ports_per_host < 1:
        print("--ports-per-host must be >= 1", file=sys.stderr)
        return 1
    if args.nessus_items_per_host < 1:
        print("--nessus-items-per-host must be >= 1", file=sys.stderr)
        return 1

    outdir = args.outdir
    if not outdir.is_absolute():
        outdir = PROJECT_ROOT / outdir
    outdir.mkdir(parents=True, exist_ok=True)

    nmap_path = outdir / "perf_nmap.xml"
    nessus_path = outdir / "perf_nessus.nessus"

    nmap_xml = generate_nmap_xml(
        args.hosts, args.ports_per_host, duplicate_every=args.duplicate_every
    )
    nessus_xml = generate_nessus_xml(
        args.hosts, args.nessus_items_per_host, duplicate_every=args.duplicate_every
    )
    nmap_path.write_text(nmap_xml, encoding="utf-8")
    nessus_path.write_text(nessus_xml, encoding="utf-8")

    # Approximate counts (duplicates add a few extras)
    dup_hosts = (
        args.hosts // args.duplicate_every if args.duplicate_every > 0 else 0
    )
    approx_nmap_hosts = args.hosts + dup_hosts
    approx_nessus_items = args.hosts * args.nessus_items_per_host + dup_hosts
    # Each nmap host: ports_per_host port-obs + ~2 scripts/port (+ occasional hostscript)
    approx_nmap_obs = (
        args.hosts * args.ports_per_host * 3  # port + 2 scripts
        + (args.hosts // 7)  # hostscripts
        + dup_hosts * 2  # dup port + script
    )

    print(f"Wrote {nmap_path}")
    print(f"Wrote {nessus_path}")
    print(
        f"Hosts requested: {args.hosts} | "
        f"approx Nmap host blocks: {approx_nmap_hosts} | "
        f"approx Nmap observations: {approx_nmap_obs} | "
        f"approx Nessus ReportItems: {approx_nessus_items}"
    )
    print(
        f"ports-per-host={args.ports_per_host} "
        f"nessus-items-per-host={args.nessus_items_per_host} "
        f"duplicate-every={args.duplicate_every}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
