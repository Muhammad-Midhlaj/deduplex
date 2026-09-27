# Exports (CSV / XLSX / DOCX)

Deduplex exposes three analyst-facing exports. All of them are **confirmed-only**:
a finding group appears in an export only after an analyst has made a decision
that puts it in the `CONFIRMED` state (`queue_status == "confirmed"`). Triage
recommendations and import-time guesses are never included.

- CSV / XLSX exports are **trackers** (one row per confirmed finding group).
- The DOCX export is a **report** (one section per confirmed finding group).

All three are served over the API and also available from the hub UI:

```text
GET /api/exports/{engagement_id}/tracker.csv
GET /api/exports/{engagement_id}/tracker.xlsx
GET /api/exports/{engagement_id}/report.docx
```

Rows are ordered by `priority_score` (desc), then `finding_group_id` (asc).

## CSV — `tracker.csv`

One row per confirmed finding group. Header row exactly:

| # | Column | Source |
|---|--------|--------|
| 1 | `finding_group_id` | `FindingGroup.id` |
| 2 | `title` | `FindingGroup.title` |
| 3 | `severity` | `FindingGroup.severity` |
| 4 | `tool` | `FindingGroup.tool` |
| 5 | `rule_id` | `FindingGroup.rule_id` |
| 6 | `hostname` | `FindingGroup.asset.hostname` (empty if no asset) |
| 7 | `ip_address` | `FindingGroup.asset.ip_address` (empty if no asset) |
| 8 | `port` | `FindingGroup.asset.port` (empty if no asset) |
| 9 | `protocol` | `FindingGroup.asset.protocol` (empty if no asset) |
| 10 | `decision` | Latest `AnalystDecision.decision` value; falls back to the current `queue_status` value if a group has no decision record |
| 11 | `decision_reason` | Latest `AnalystDecision.reason` (empty if none) |
| 12 | `analyst` | Latest `AnalystDecision.analyst` (empty if none) |
| 13 | `decided_at` | Latest `AnalystDecision.created_at` as ISO-8601 (empty if none) |

"Latest decision" means the most recent `AnalystDecision` by `created_at` for
that group; ties resolve by list order.

## XLSX — `tracker.xlsx`

Single worksheet titled **`Confirmed Findings`**, same shape as the CSV but
with display-friendly header names:

| # | Column |
|---|--------|
| 1 | `Finding Group ID` |
| 2 | `Title` |
| 3 | `Severity` |
| 4 | `Tool` |
| 5 | `Rule ID` |
| 6 | `Hostname` |
| 7 | `IP` |
| 8 | `Port` |
| 9 | `Protocol` |
| 10 | `Decision` |
| 11 | `Reason` |
| 12 | `Analyst` |
| 13 | `Decided At` |

Cell values follow the same source rules as the CSV. Empty asset/decision
fields are written as blank cells (`None` in openpyxl).

## DOCX — `report.docx`

A narrative Word report. Structure:

- Title (level 0): `VAPT Findings Report`
- Paragraphs: `Engagement: <name or id>`, optional `Client: <client>`,
  `Generated: <YYYY-MM-DD HH:MM UTC>`, and a note that the report is
  confirmed-only.
- Heading level 1: `Confirmed Findings`
  - If no confirmed groups: a single paragraph `No confirmed findings for this engagement.`
  - Otherwise, one **level-2 heading per group** numbered in the export order
    (`1. <title or rule_id>`, `2. …`, …) followed by:
    - `Severity: <severity or "n/a">`
    - `Tool / Rule: <tool> / <rule_id>`
    - `Asset: <hostname> / <ip> / <port>/<protocol>` — built from whichever
      fields are present; `n/a` if the group has no asset
    - If a decision exists: `Analyst decision: <decision>`, then
      `Reason: <reason>` and `Analyst: <analyst>` when present.

The DOCX does not have a 1:1 column mapping to the CSV/XLSX — it is a
prose report, not a table.

## Confirmed-only behavior

All three exporters share one filter:

```python
db.query(FindingGroup)
    .filter(
        FindingGroup.engagement_id == engagement_id,
        FindingGroup.queue_status == DecisionValue.CONFIRMED,
    )
    .order_by(FindingGroup.priority_score.desc(), FindingGroup.id)
```

So:

- **Suppressed / triaged / unconfirmed** groups never appear.
- Reverting a group out of `CONFIRMED` (e.g. back to triaged) removes it from
  the next export.
- Re-exporting after a new decision always uses the **latest** decision; the
  earlier decision's `reason` / `analyst` / `created_at` are not included.

## Where the columns come from

- Finding group fields: `app/models.py` → `FindingGroup`.
- Asset fields: `app/models.py` → `Asset` (joined via `FindingGroup.asset`).
- Decision fields: `app/models.py` → `AnalystDecision` (latest by
  `created_at`).
- Exporter code: `services/export_report.py` (`export_tracker_csv`,
  `export_tracker_xlsx`, `export_report_docx`).

If a column or the confirmed-only rule changes, update this page and the
exporters together.
