# Deduplex

**Deduplex** helps VAPT analysts cut repetitive work: consolidate **Nmap** and **Nessus** results, group **exact** duplicates, keep evidence links, run an analyst decision queue, export confirmed findings, and compare **retest** batches.

Desktop product (Windows): **`Deduplex.exe`** / installer **`Deduplex-Setup.exe`** (Inno Setup). Publisher: **Muhammad Midhlaj**. Current packaging version: **`0.1.0-spike`**.

Public repository: **https://github.com/Muhammad-Midhlaj/deduplex**. Internal folders may still be named `vapt-effort-reduction`.

License: [Apache License 2.0](LICENSE).

## Honest status (lab / localhost spike)

This is an early **desktop + localhost lab** spike, not a hardened multi-user SaaS.

- Auth defaults **off** (`AUTH_ENABLED=false`) for local lab only.
- Desktop launcher **binds `127.0.0.1` only** — do not open `0.0.0.0` without auth.
- Data for frozen builds lives under `%LOCALAPPDATA%\Deduplex\` (SQLite + evidence).
- **Laya** triage / fine-tune and heavy ML (`finetune/`, torch weights) are **private or optional** and are **not** part of the default public desktop tree or Setup bundle unless Core explicitly opens them. Desktop builds intentionally exclude `laya` / `torch` / `transformers`.

See also: [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md)

## What it does (Core)

| Capability | Notes |
|------------|--------|
| Import | Nmap XML and Nessus exports |
| Local scans (Wave 1) | **Explicit Start** only: Nmap -sV -T4 -oX (Nuclei Wave 1b). PATH/allowlist binary, one job at a time, timeout/cancel. Never auto-start. |
| Exact dedupe | Groups on `tool\|rule_id\|asset.canonical_key` (no fuzzy merge in this release) |
| Analyst queue | Decisions with reason/history; exports are **confirmed-only** |
| Retest | Compare baseline vs retest import batches (fixed / still open / new) |
| Desktop | One-folder PyInstaller + Inno `Deduplex-Setup.exe` |

Deferred / not claimed here: fuzzy root-cause merging, **autonomous/unattended** scanning, generative report prose, full client portal, production Postgres + encryption at rest. Wave 1 local scans require an analyst to click **Start** on allowlisted binaries.

## Requirements (source)

- Python 3.11+ (developed on 3.13)
- SQLite by default (SQLAlchemy); Postgres URL optional later

```bash
git clone https://github.com/Muhammad-Midhlaj/deduplex.git
cd deduplex
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env        # optional — never commit .env
```

## Run the API + analyst UI (localhost)

```bash
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- Analyst UI: http://127.0.0.1:8000/
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/api/health

**Do not** bind `0.0.0.0` or set `ALLOW_INSECURE_OPEN_MODE=true` for casual lab use. See [SECURITY.md](SECURITY.md).

### Quick lab walkthrough

1. Create an engagement on Home.
2. Import `sample_data/sample_nmap.xml` (optional Nessus; optional retest `sample_data/sample_nmap_retest.xml`), **or** open **Scans** and Start an Nmap job against a lab target you own (e.g. `127.0.0.1`).
3. Work the Queue (confirm / false_positive / …).
4. Export CSV / XLSX / DOCX (confirmed only).
5. Retest compare on the hub.

Sample hosts are synthetic lab names (`web.lab.local`, `192.168.1.x`) — not customer assets.

## Desktop (Windows spike)

Build and install notes live in `packaging/README.md` once the public tree includes packaging.

- Output exe: `dist\Deduplex\Deduplex.exe`
- Installer: `dist\installer\Deduplex-Setup.exe` (`AppVersion` **0.1.0-spike**)
- Auth-off / localhost-only; no `.env` in the bundle
- Release gate checklist (maintainers): see `RELEASE_CHECKLIST_Deduplex-Setup.md` in the OSS readiness pack / repo docs

Source launcher (deps installed):

```bash
python scripts/desktop_app.py
```

## Exact duplicate key

```text
tool|rule_id|asset.canonical_key
asset.canonical_key = hostname|ip|protocol|port   (lowercased)
```

Re-importing the same findings attaches observations to the existing group. Nessus streaming parse uses defusedxml `iterparse` (XXE defenses on).

## Tests

```bash
pytest -q
```

## Module layout (public Core expectation)

```text
app/           FastAPI app, models, schemas, API, web UI
importers/     Nmap XML + Nessus parsers
services/      import, scan_jobs (Wave 1), grouping, triage (rules; Laya optional), export, retest
templates/     Lightweight HTML analyst UI
tests/         pytest suite
sample_data/   Synthetic Nmap + Nessus samples
scripts/       CLI helpers + desktop launcher
packaging/     PyInstaller + Inno Setup (Deduplex)
```

`finetune/` and heavy ML artifacts are expected to remain **out of the default public export** (private / optional). Rules triage remains the default fallback when Laya is disabled.

## Good first issues

Suggested starter work for contributors (label these when the repo goes public):

1. **Importer edge cases** — add Nessus/Nmap fixture variants + pytest coverage for odd/malformed exports.
2. **Synthetic `sample_data/`** — expand lab-only samples (no real engagement dumps).
3. **Analyst UI polish** — empty states and accessibility improvements in `templates/`.
4. **Export column docs** — document confirmed-only CSV/XLSX/DOCX columns for analysts.
5. **Desktop path tests** — Windows `%LOCALAPPDATA%\Deduplex\` path behavior without needing a GPU.

Please skip `finetune/`, secrets, and real evidence dumps — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Safety

- File imports treat scanner XML/exports as **data only** (parsers never execute payloads).
- Wave 1 **ScanJobs** may run allowlisted local nmap/nuclei only after an analyst clicks **Start** (never auto-start). Deduplex does not auto-suppress findings from model output.
- Exports include **confirmed** findings only after analyst decisions.
- Never commit secrets, customer evidence, or real engagement dumps — see CONTRIBUTING and the publish scrub notes.

## License

Copyright 2026 Muhammad Midhlaj. Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).

