"""AuthTwin findings importer (authorization-test correlation output).

Ingest-only: Deduplex never runs AuthTwin or replays its requests. Accepts the
artifacts AuthTwin writes under ``<out>/`` after ``correlate`` / ``report``:

  - findings.json         {"version", "stats", "findings": [Finding.to_dict()...]}
  - reports/report.json   {"tool": "AuthTwin", "findings": {...findings.json...},
                           "remediations": {"remediations": [...]}}  (adds OWASP/CWE)
  - reports/findings.csv  flat export (CSV_HEADER in authtwin/report/exports.py)

Mapping choices (kept stable across all three formats so re-imports group):
  - rule_id             = "BOLA/<res_type>" — derived only from fields present in
                          every format (OWASP/CWE exist only with remediations).
  - original_finding_id = AuthTwin finding_id (sha256(res_type|object_id|actor)[:12]),
                          deterministic across AuthTwin runs → retest matching.
  - asset               = host/port/scheme of the first evidence URL (masked URL
                          keeps netloc), else repro_chain host, else
                          hostname "<res_type>:<object_id>".
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from importers.nmap_xml import ParsedObservation, ParseResult
from importers.nuclei_jsonl import _host_port_from_url

TOOL = "authtwin"
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CSV_REQUIRED = {"finding_id", "severity", "res_type", "object_id", "actor_identity"}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def _extract_findings(doc: Any) -> tuple[list[dict], dict[str, dict]] | None:
    """Return (findings, remediations_by_id) if doc is an AuthTwin JSON artifact."""
    remediations: dict[str, dict] = {}
    if isinstance(doc, list):
        findings = doc
    elif isinstance(doc, dict):
        findings = doc.get("findings")
        # report.json nests the correlation report under "findings".
        if isinstance(findings, dict):
            findings = findings.get("findings")
        rem = doc.get("remediations")
        if isinstance(rem, dict):
            rem = rem.get("remediations")
        if isinstance(rem, list):
            remediations = {
                str(r["finding_id"]): r
                for r in rem
                if isinstance(r, dict) and r.get("finding_id")
            }
        if findings is None and str(doc.get("tool", "")).lower() == "authtwin":
            findings = []
    else:
        return None
    if not isinstance(findings, list):
        return None
    if findings and not all(isinstance(f, dict) and "finding_id" in f for f in findings):
        return None
    if not findings and not (isinstance(doc, dict) and (
        str(doc.get("tool", "")).lower() == "authtwin" or "stats" in doc
    )):
        return None
    return findings, remediations


def _csv_header(text: str) -> set[str]:
    first = text.splitlines()[0] if text else ""
    return {c.strip() for c in first.split(",")}


def looks_like_authtwin(path: Path | str) -> bool:
    """Content sniff: AuthTwin findings JSON (any of the shapes) or findings CSV."""
    path = Path(path)
    try:
        text = _read_text(path)
    except OSError:
        return False
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            return _extract_findings(json.loads(stripped)) is not None
        except json.JSONDecodeError:
            return False
    return _CSV_REQUIRED <= _csv_header(stripped)


def _refs(items: Any) -> list[str]:
    if isinstance(items, str):
        return [s for s in items.split(";") if s]
    out = []
    for r in items or []:
        if isinstance(r, dict) and r.get("identifier"):
            out.append(str(r["identifier"]))
        elif isinstance(r, str) and r:
            out.append(r)
    return out


def _severity(value: Any) -> str | None:
    sev = str(value or "").strip().lower()
    return sev if sev in _SEVERITIES else None


def _asset_from_finding(f: dict) -> tuple[str, int | None, str | None]:
    urls: list[str] = [
        str(e.get("url")) for e in f.get("evidence") or [] if isinstance(e, dict) and e.get("url")
    ]
    if f.get("representative_url"):
        urls.append(str(f["representative_url"]))
    for url in urls:
        host, _ip, port, scheme = _host_port_from_url(url)
        if host:
            return host.lower(), port, scheme
    for step in f.get("repro_chain") or []:
        if isinstance(step, dict) and step.get("host"):
            scheme = str(step.get("scheme") or "https")
            port = step.get("port")
            if port is None:
                port = 443 if scheme == "https" else 80 if scheme == "http" else None
            return str(step["host"]).lower(), port, scheme
    return f"{f.get('res_type') or 'resource'}:{f.get('object_id') or 'unknown'}", None, None


def _description(f: dict, owasp: list[str], cwe: list[str], rem: dict | None) -> str:
    access = f.get("access_types") or []
    if isinstance(access, str):
        access = [a for a in access.split("|") if a]
    lines = [
        f"AuthTwin classification: {f.get('classification') or 'n/a'}",
        f"Actor → owner: {f.get('actor_identity')} → {f.get('owner_identity')}",
        f"Object: {f.get('res_type')} '{f.get('object_id')}'",
        f"Access: {', '.join(access) or 'n/a'}",
    ]
    mutations = sorted({
        str(e["mutation"]) for e in f.get("evidence") or []
        if isinstance(e, dict) and e.get("mutation")
    })
    if mutations:
        lines.append(f"Mutations: {', '.join(mutations)}")
    if owasp or cwe:
        lines.append(f"Mappings: {' | '.join(owasp + cwe)}")
    if f.get("rationale"):
        lines.append(f"Rationale: {f['rationale']}")
    if rem and isinstance(rem.get("root_cause"), dict) and rem["root_cause"].get("summary"):
        lines.append(f"Root cause: {rem['root_cause']['summary']}")
    return "\n".join(lines)


def _plugin_output(f: dict) -> str | None:
    lines = []
    for e in f.get("evidence") or []:
        if not isinstance(e, dict):
            continue
        lines.append(
            f"[{e.get('scenario_id')}] {e.get('method')} {e.get('url')} "
            f"as {e.get('actor_identity')}: {e.get('observed_status')} "
            f"(baseline {e.get('baseline_status')}, confidence {e.get('confidence')})"
        )
    for step in f.get("attack_path") or []:
        if isinstance(step, dict):
            lines.append(f"path/{step.get('stage')}: {step.get('description')}")
    if not lines and f.get("evidence_count"):
        lines.append(f"evidence_count: {f['evidence_count']}")
    return "\n".join(lines) or None


def _to_observation(f: dict, rem: dict | None) -> ParsedObservation:
    res_type = str(f.get("res_type") or "resource")
    owasp = _refs(f.get("owasp")) or _refs((rem or {}).get("owasp"))
    cwe = _refs(f.get("cwe")) or _refs((rem or {}).get("cwe"))
    host, port, scheme = _asset_from_finding(f)
    # Evidence URLs are already query-masked by AuthTwin; repro_chain (which names
    # vault identities) is intentionally left out of the excerpt.
    excerpt = {k: v for k, v in f.items() if k != "repro_chain"}
    return ParsedObservation(
        tool=TOOL,
        rule_id=f"BOLA/{res_type}",
        title=str(f.get("title") or f"Authorization anomaly on {res_type}"),
        severity=_severity(f.get("severity")),
        description=_description(f, owasp, cwe, rem),
        plugin_output=_plugin_output(f),
        cve=None,
        cvss=None,
        original_finding_id=str(f["finding_id"]),
        scan_time=None,
        hostname=host,
        ip_address=None,
        port=port,
        protocol=scheme,
        service="http" if scheme in ("http", "https") else None,
        raw_excerpt=json.dumps(excerpt, sort_keys=True, default=str)[:500],
    )


def parse_authtwin_findings(path: Path | str) -> ParseResult:
    path = Path(path)
    result = ParseResult()
    try:
        text = _read_text(path)
    except OSError as exc:
        result.warnings.append(f"Cannot read AuthTwin file: {exc}")
        return result

    stripped = text.lstrip()
    rows: list[dict]
    remediations: dict[str, dict] = {}
    if stripped.startswith(("{", "[")):
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"AuthTwin JSON is invalid: {exc}") from exc
        extracted = _extract_findings(doc)
        if extracted is None:
            raise ValueError("JSON is not an AuthTwin findings.json / report.json")
        rows, remediations = extracted
        if isinstance(doc, dict):
            for w in doc.get("warnings") or []:
                result.warnings.append(f"authtwin: {w}")
    else:
        if not _CSV_REQUIRED <= _csv_header(stripped):
            raise ValueError("CSV is not an AuthTwin findings.csv export")
        rows = list(csv.DictReader(io.StringIO(stripped)))

    for idx, f in enumerate(rows, start=1):
        if not f.get("finding_id"):
            result.skipped_unparseable += 1
            result.warnings.append(f"Finding #{idx}: missing finding_id")
            continue
        result.observations.append(_to_observation(f, remediations.get(str(f["finding_id"]))))
    return result
