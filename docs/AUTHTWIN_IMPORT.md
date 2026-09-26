# Importing AuthTwin findings

AuthTwin engine (separate repo): **https://github.com/Muhammad-Midhlaj/authtwin**. Deduplex only **imports** AuthTwin findings files; it never runs AuthTwin or replays requests.

Deduplex treats AuthTwin as a **file-import source only** â€” same rails as
nmap / nessus / nuclei. Deduplex never runs AuthTwin, never replays its
requests, and sends no packets. AuthTwin's authorized-use safety gate stays
entirely inside AuthTwin.

## 1. Export from AuthTwin (in the authorized engagement)

```bash
authtwin correlate --out .authtwin   # writes .authtwin/findings.json
authtwin remediate --out .authtwin   # optional: adds OWASP/CWE mappings
authtwin report    --out .authtwin   # writes .authtwin/reports/report.json + findings.csv
```

Accepted files, in order of preference:

| File | Notes |
|------|-------|
| `<out>/findings.json` | Primary. Full evidence + attack path. |
| `<out>/reports/report.json` | Same findings plus OWASP/CWE and root cause from `remediations`. |
| `<out>/reports/findings.csv` | Fallback. One URL per finding, no per-scenario evidence. |

Detection is by content (a `findings` array of objects with `finding_id`, or
the CSV header), so renamed files such as `authtwin_findings.json` work too.
You can also force it with `tool=authtwin`.

## 2. Import into an engagement

- **UI:** engagement â†’ *Import* â†’ Tool: *AuthTwin findings* (or Auto-detect) â†’ upload.
- **CLI:** `python scripts/import_cli.py --engagement-id 1 --tool authtwin .authtwin/findings.json`
- **API:** `curl -F engagement_id=1 -F tool=authtwin -F file=@.authtwin/findings.json http://127.0.0.1:8000/api/imports`

Try it with `sample_data/sample_authtwin_findings.json` (lab hosts, fake identities).

## Field mapping

| AuthTwin | Observation / Asset |
|----------|---------------------|
| â€” | `tool = "authtwin"` |
| `res_type` | `rule_id = "BOLA/<res_type>"` (identical for JSON/report/CSV so re-imports group) |
| `finding_id` | `original_finding_id` (deterministic across runs â†’ retest matching) |
| `title` | `title` |
| `severity` high/medium/low | `severity` high/medium/low (same scale as nessus/nuclei) |
| `evidence[0].url` â†’ `repro_chain[].host` â†’ `representative_url` (CSV) | Asset host / port / scheme (`host\|\|https\|443`) |
| none of the above | Asset hostname `<res_type>:<object_id>` |
| classification, actorâ†’owner, object, access, mutations, OWASP/CWE, rationale, root cause | `description` |
| evidence scenarios + attack path | `plugin_output` |

Grouping key is `authtwin|BOLA/<res_type>|<asset>`: several actor/object findings
against the same resource type on one host land in one FindingGroup, while each
keeps its own observation and `original_finding_id`. `repro_chain` is not copied
into observation text; the untouched upload is kept under `data/evidence/` as for
every other import.
