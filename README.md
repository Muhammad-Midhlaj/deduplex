# Deduplex / VAPT Effort Reduction (MVP)

Personal open-source VAPT effort-reduction assistant: consolidate Nmap/Nessus/Nuclei (and AuthTwin authorization findings), exact duplicate grouping, evidence retention, analyst queue & decisions, template exports, retest compare, and localhost Wave 1 scan jobs with a live terminal log.

Laya triage is **feature-flagged** and defaults **off**. When enabled it uses the real `laya` SDK (`typed-decisions`) or an optional remote URL, with rules fallback. Analysts retain validation â€” nothing is auto-confirmed or auto-suppressed.

See `docs/SCANNER_EXECUTION.md` and `docs/AUTHTWIN_IMPORT.md` for scanner and AuthTwin import details.

## Requirements

- Python 3.11+ (developed on 3.13)
- Local SQLite by default (SQLAlchemy). A Postgres URL works when you set `DATABASE_URL`.

## Setup

```bash
cd deduplex
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional
```

## Run the API + analyst UI

```bash
cd deduplex
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- API docs: http://127.0.0.1:8000/docs  
- Analyst UI: http://127.0.0.1:8000/  
- Health: http://127.0.0.1:8000/api/health  

SQLite DB is created at `data/vapt.db`. Raw uploads are stored under `data/evidence/<engagement_id>/`.


## Desktop app (spike) â€” Deduplex

Windows **one-folder** PyInstaller build â€” double-click `Deduplex.exe` for a native Deduplex window (pywebview), no manual venv.
Auth-off / localhost only; data under `%LOCALAPPDATA%\Deduplex\`. Laya/torch excluded.
Legacy `%LOCALAPPDATA%\VAPTEffortReduction\` is one-time migrated on first frozen launch when Deduplex is empty (wipe never auto-deletes the legacy folder).

See [`packaging/README.md`](packaging/README.md) for build steps on Midhlaj, Inno (`Deduplex-Setup.exe`), and smoke notes.

Source launcher (any OS with deps installed):

```bash
python scripts/desktop_app.py
```

## Lab UI (localhost)

Local analyst UI (Jinja) â€” **AUTH off**, bind **127.0.0.1 only**:

```bash
cd deduplex   # or your clone path
source .venv/bin/activate             # Windows: .venv\Scripts\Activate.ps1
$env:AUTH_ENABLED="false"             # PowerShell; export AUTH_ENABLED=false on bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/**

Walkthrough:

1. **Home** â€” create an engagement (name + optional client).
2. **Hub** (`/ui/engagements/{id}`) â€” tabs for Queue | Import | Retest | exports.
3. **Import** â€” upload `sample_data/sample_nmap.xml` (baseline). Optionally import Nessus. For a follow-up scan, check **Retest import = Yes** and upload `sample_data/sample_nmap_retest.xml`.
4. **Queue** â€” filter by status; open a finding; use quick-action buttons (confirmed / false_positive / â€¦) with an optional reason.
5. **Exports** â€” CSV / XLSX / DOCX from hub, queue, or home (confirmed findings only).
6. **Retest** â€” pick baseline + retest batches, run compare; review fixed / still open / new.

Flash messages use query params (`?msg=â€¦&msg_type=ok`). CSRF tokens are required on all UI POSTs. Do **not** bind `0.0.0.0` or set `ALLOW_INSECURE_OPEN_MODE=true` for this lab.

## Sample import flow

### Via CLI

```bash
source .venv/bin/activate

# Create engagement + import Nmap
python scripts/import_cli.py \
  --create-engagement "Lab Demo" \
  --client "Internal Lab" \
  --tool nmap \
  sample_data/sample_nmap.xml

# Import Nessus into the same engagement (use id printed above, e.g. 1)
python scripts/import_cli.py --engagement-id 1 --tool nessus sample_data/sample_nessus.nessus

# Retest import
python scripts/import_cli.py --engagement-id 1 --tool nmap --retest sample_data/sample_nmap_retest.xml

# AuthTwin findings (ingest only â€” see docs/AUTHTWIN_IMPORT.md)
python scripts/import_cli.py --engagement-id 1 --tool authtwin sample_data/sample_authtwin_findings.json
```

### Via UI

See **Lab UI (localhost)** above for the full walkthrough (hub â†’ import â†’ decide â†’ export â†’ retest).

### Via API (curl)

```bash
# Create engagement
curl -s -X POST http://127.0.0.1:8000/api/engagements \
  -H 'Content-Type: application/json' \
  -d '{"name":"Lab Demo","client":"Internal Lab"}'

# Import (replace ENGAGEMENT_ID)
curl -s -X POST http://127.0.0.1:8000/api/imports \
  -F engagement_id=1 \
  -F tool=nmap \
  -F file=@sample_data/sample_nmap.xml

# List pending queue
curl -s 'http://127.0.0.1:8000/api/queue?engagement_id=1&status=pending'

# Record decision
curl -s -X POST http://127.0.0.1:8000/api/finding-groups/1/decisions \
  -H 'Content-Type: application/json' \
  -d '{"decision":"confirmed","reason":"Validated on host","analyst":"alice"}'

# Exports (confirmed only)
curl -OJ http://127.0.0.1:8000/api/exports/1/tracker.csv
curl -OJ http://127.0.0.1:8000/api/exports/1/tracker.xlsx
curl -OJ http://127.0.0.1:8000/api/exports/1/report.docx

# Retest compare
curl -s -X POST http://127.0.0.1:8000/api/retest/compare \
  -H 'Content-Type: application/json' \
  -d '{"engagement_id":1,"retest_import_batch_id":3,"baseline_import_batch_id":1}'
```


## Auth / engagement ACLs (first cut)

Auth is **off by default** (`AUTH_ENABLED=false`) for local lab only. **Do not** bind `0.0.0.0` without `AUTH_ENABLED=true`. Public `/evidence` requires explicit `ALLOW_INSECURE_OPEN_MODE=true` (off by default). With auth on, a default/`dev-only-change-me` `SESSION_SECRET` refuses to start.

When enabled:

1. Set `AUTH_ENABLED=true`, `BOOTSTRAP_API_KEY=<long secret>`, and a strong `SESSION_SECRET`.
2. Restart the app â€” bootstrap creates an **admin** principal with that key.
3. Call APIs with header `X-API-Key: <key>` (or `Authorization: Bearer <key>`).
4. Browser UI: `POST /api/auth/login` with `{"api_key":"..."}` sets an HttpOnly `vapt_session` cookie.
5. Admin can `POST /api/auth/principals` and `POST /api/auth/acl` to grant engagement access.
6. Non-admins only see/mutate engagements they are granted; creators auto-receive ACL on new engagements.
7. `/api/health` stays open. With auth on, the public `/evidence` static mount is disabled.
8. HTML UI POSTs require a double-submit `csrf_token` (cookie + hidden field).
9. `/api/auth/login` is rate-limited (20/min per client IP). Set `SESSION_COOKIE_SECURE=true` behind HTTPS.
10. Nmap/Nessus XML parsing uses **defusedxml**.

```bash
# Example (PowerShell)
$env:AUTH_ENABLED="true"
$env:BOOTSTRAP_API_KEY="dev-admin-key-change-me-16"
$env:SESSION_SECRET="dev-session-secret-change-me"
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
curl -s http://127.0.0.1:8000/api/engagements -H "X-API-Key: dev-admin-key-change-me-16"
```

SQLite remains the default database. Postgres is still deferred.

## Perf load fixtures (Core volume)

Synthetic Nmap/Nessus XML for **Core** import, exact grouping, and analyst-queue load â€” **not** Laya labels or fine-tune data.

```bash
source .venv/bin/activate

# Generate scaled fixtures under sample_data/perf/ (gitignored XML)
python scripts/generate_perf_fixtures.py --hosts 50

# Seed: create engagement, import nmap then nessus, print wall times + totals
# Prefer a separate DB so walkthrough data is untouched:
python scripts/seed_perf_load.py \
  --database-url sqlite:///./data/vapt_perf.db \
  --evidence-dir ./data/evidence_perf \
  --hosts 50

# Reuse existing fixtures / engagement
python scripts/seed_perf_load.py --skip-generate --engagement-id 1 \
  --database-url sqlite:///./data/vapt_perf.db
```

Defaults: 50 hosts, 4 ports/host, 6 Nessus items/host. Intentional duplicates every 10 hosts exercise duplicate grouping. See `sample_data/perf/README.md`.

## Exact duplicate grouping

Observations are grouped on an **exact** key:

```text
tool|rule_id|asset.canonical_key
```

Asset canonical key:

```text
hostname|ip|protocol|port   (lowercased; empty segments allowed)
```

Re-importing the same scanner findings attaches new observations to the existing group (observation count grows; group count stays stable). No fuzzy merging in this release.

### Reimport hash (DefectDojo-inspired pattern)

Stable identities for reimport / retest (reimplemented locally â€” we did **not** vendor DefectDojo):

| Identity | Formula |
|----------|---------|
| `duplicate_key` / `group_key` | `tool` + rule_id + asset.canonical_key (pipe-joined) |
| `finding_hash` | SHA-256 hex of that same material (`services.grouping.build_finding_hash`) |
| Nessus `original_finding_id` | `nessus:{pluginID}:{host}:{protocol}:{port}` |

### Nessus streaming parse

Large `.nessus` files are parsed with **defusedxml** `iterparse` (ReportHost cleared after each host â€” NessusReportv2-style walk). We did **not** add `pytenable` (MIT; heavy SDK) â€” only ReportItem iteration was needed. XXE defenses stay on (`forbid_entities=True`).

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `sqlite:///<project>/data/vapt.db` | SQLAlchemy URL (Postgres-compatible later) |
| `EVIDENCE_DIR` | `<project>/data/evidence` | Raw scanner file storage |
| `LAYA_ENABLED` | `false` | When true, try remote then local Laya SDK; else rules only |
| `LAYA_SERVICE_URL` | `http://127.0.0.1:8090` | Optional remote triage endpoint (tried first) |
| `LAYA_REPO` | `convaiinnovations/laya` | Hugging Face repo for local SDK |
| `LAYA_SUBFOLDER` | `typed-decisions` | Checkpoint subfolder (1024 token budget) |
| `LAYA_DEVICE` | `auto` | `cpu`, `cuda`, or `auto` |
| `LAYA_PRELOAD` | `false` | Load agent on first enabled triage call |
| `LAYA_MODEL_VERSION` | `laya-typed-decisions` | Recorded with Laya recommendations |
| `LAYA_USE_STUB` | `false` | Last-resort deterministic stub (off by default) |
| `LAYA_LOCAL_CHECKPOINT` | empty | Local fine-tuned Agent dir; overrides Hub repo/subfolder when set |
| `RULES_MODEL_VERSION` | `rules-v1` | Recorded with rules recommendations |
| `USE_TF` | unset | Set `USE_TF=0` if transformers hangs on import |
| `AUTH_ENABLED` | `false` | Require API key / session; engagement ACLs |
| `BOOTSTRAP_API_KEY` | empty | Admin key seeded when auth enabled |
| `SESSION_SECRET` | `dev-only-change-me` | HMAC secret for session cookies |
| `ALLOW_INSECURE_OPEN_MODE` | `false` | Opt-in public `/evidence` when auth off |
| `EXPOSE_API_DOCS` | `false` | Show `/docs` when auth is on |
| `SESSION_COOKIE_SECURE` | `false` | Set Secure on session cookie (HTTPS) |
| `MAX_UPLOAD_BYTES` | `33554432` | Max scanner upload size |
| `API_KEY_PEPPER` | empty | HMAC pepper for API keys (else SESSION_SECRET) |

## Enabling Laya (local SDK)

Laya is used for **one narrow task**: recommending which observations need earlier review. It does **not** generate report prose or validate vulnerabilities. Rules prioritization always remains the fallback. High/Critical findings never drop below the rules urgency floor.

```bash
source .venv/bin/activate
pip install -r requirements.txt   # includes laya (pulls torch/transformers)
# Optional: if model load hangs
export USE_TF=0

# Enable in .env (or export)
export LAYA_ENABLED=true
export LAYA_REPO=convaiinnovations/laya
export LAYA_SUBFOLDER=typed-decisions
export LAYA_DEVICE=auto
# LAYA_SERVICE_URL is optional; if the remote answers, it is preferred

# First-run smoke (downloads ~800MB+ weights once)
python scripts/laya_smoke.py
```

Default CI/local tests mock the SDK and do **not** download weights.


## Laya fine-tuning (bounded experiment)

See [`finetune/README.md`](finetune/README.md) for export, synthetic smoke, GPU training (single GPU or Kaggle 2Ã—T4 DDP), evaluation, and enabling a local checkpoint via `LAYA_LOCAL_CHECKPOINT`.

Quick smoke (synthetic data + rules eval + optional CPU dry-run):

```bash
source .venv/bin/activate
python scripts/run_finetune_experiment.py --synthetic --device cpu
```

Do **not** treat synthetic or dry-run results as pilot-ready accuracy. Metrics are only those computed by `finetune.evaluate`; insufficient labels â†’ keep Laya eval-only with rules fallback.

## Tests

```bash
source .venv/bin/activate
pytest -q
```

Smoke coverage: Nmap/Nessus parsers (streaming Nessus + XXE rejection), exact duplicate grouping / reimport hash, decisions + confirmed-only export, retest matching, rules triage + mocked Laya SDK path.

## Module layout

```text
app/           FastAPI app, models, schemas, API, web UI routes
importers/     Nmap XML + Nessus parsers (data only â€” no tool execution)
services/      import orchestration, asset mapping, grouping, triage, export, retest
templates/     Lightweight HTML analyst UI
tests/         pytest suite
sample_data/   Synthetic Nmap + Nessus files
data/evidence/ Retained raw uploads
scripts/       CLI import helper + fine-tune experiment
finetune/      Bounded Laya fine-tune pipeline (export/preprocess/train/eval)
```

## What is intentionally stubbed / optional

- **Laya weights**: the SDK integration is wired; enabling `LAYA_ENABLED=true` loads `typed-decisions` from Hugging Face on first use (~800MB+). Tests mock the SDK so CI never downloads. `LAYA_USE_STUB=true` keeps a deterministic stub as a last resort. Rules fallback always available. Laya never auto-suppresses; High/Critical keep at least rules urgency.
- **Background import jobs**: imports run inline in the request/CLI (fine for MVP file sizes).
- **Auth / engagement ACLs / encryption at rest**: not in this MVP (deferred).
- **Fuzzy / root-cause merging**: deferred; exact keys only.

## Safety notes

- Imported scanner content is treated as **data only**. The app does not execute scanner tools or act on triage predictions.
- Exports include **confirmed** findings only (after analyst decision).

## Open-source projects

Deduplex stands on these open-source projects. Thank you to their maintainers and communities.

### Runtime (Python)

| Project | Role in Deduplex |
| --- | --- |
| [FastAPI](https://github.com/fastapi/fastapi) | HTTP API and app framework |
| [Uvicorn](https://github.com/encode/uvicorn) | ASGI server |
| [SQLAlchemy](https://github.com/sqlalchemy/sqlalchemy) | ORM / database layer (SQLite by default) |
| [Pydantic](https://github.com/pydantic/pydantic) / [pydantic-settings](https://github.com/pydantic/pydantic-settings) | Request/settings models |
| [python-multipart](https://github.com/Kludex/python-multipart) | Multipart upload parsing |
| [Jinja](https://github.com/pallets/jinja) | Analyst HTML templates |
| [httpx](https://github.com/encode/httpx) | HTTP client |
| [lxml](https://github.com/lxml/lxml) | XML parsing for scanner imports |
| [defusedxml](https://github.com/tiran/defusedxml) | Safer XML handling (XXE hardening) |
| [openpyxl](https://foss.heptapod.net/openpyxl/openpyxl) | Excel (XLSX) exports |
| [python-docx](https://github.com/python-openxml/python-docx) | Word (DOCX) exports |
| [pytest](https://github.com/pytest-dev/pytest) / [pytest-asyncio](https://github.com/pytest-dev/pytest-asyncio) | Test suite |
| [Laya](https://pypi.org/project/laya/) | Optional typed-decisions triage SDK (feature-flagged; pulls ML stack when enabled) |

When `LAYA_ENABLED=true`, Laya may pull additional OSS such as [PyTorch](https://github.com/pytorch/pytorch), [🤗 Transformers](https://github.com/huggingface/transformers), and [huggingface_hub](https://github.com/huggingface/huggingface_hub).

### Desktop packaging (Windows)

| Project | Role in Deduplex |
| --- | --- |
| [PyInstaller](https://github.com/pyinstaller/pyinstaller) | One-folder `Deduplex.exe` builds |
| [pywebview](https://github.com/r0x0r/pywebview) | Native desktop window (WebView2) |
| [Inno Setup](https://jrsoftware.org/isinfo.php) | `Deduplex-Setup.exe` installer |

### Scanner formats and external tools

Deduplex **imports** results from these ecosystems (and can launch allowlisted CLIs for Wave 1 jobs). They are not bundled inside the app:

| Project | Role |
| --- | --- |
| [Nmap](https://nmap.org/) ([source](https://github.com/nmap/nmap)) | XML import + Wave 1 scan jobs |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | JSONL import + Wave 1b jobs |
| [SQLite](https://www.sqlite.org/) | Default embedded database |

Nessus `.nessus` files are supported as an **import format** only; Nessus itself is a commercial Tenable product, not open source.

AuthTwin findings import is ingest-only (`tool=authtwin`); AuthTwin remains a separate tool and is not shipped in this repository.

Exact versions live in [`requirements.txt`](requirements.txt), [`requirements-desktop.txt`](requirements-desktop.txt), and [`requirements-desktop-build.txt`](requirements-desktop-build.txt).

## License

Copyright 2026 Muhammad Midhlaj. Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).