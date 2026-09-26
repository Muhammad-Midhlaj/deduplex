# Deduplex — multi-scanner execution roadmap

Locked with Midhlaj / prokect X (26 Sep 2026). Product name Deduplex; repo folder may still be `vapt-effort-reduction`.

## Wave 1 status — **implemented (Nmap MVP + Nuclei 1b)**

| Item | Decision | Status |
|------|----------|--------|
| Nmap | **MVP run** — ScanJob + binary allowlist + explicit Start + `-oX` → `import_service` → dedupe → queue | **Done** |
| Nuclei | **Wave 1b** — same job rails; `-jsonl` → `importers/nuclei_jsonl.py` | **Done** (UI shows form when binary on PATH) |
| Nessus / OpenVAS | **File import only** | Unchanged |
| Burp / ZAP / cloud | **Coming** cards only | UI cards disabled |

### Defaults (locked)

- **Binary:** resolve via `PATH` (`shutil.which`); on first successful resolve, path is written to app-data `scanner_binaries.json` (allowlist). User may override path on draft create.
- **Nmap default `st_sv_t4`:** `-sT -sV -T4` plus `-oX <job_dir>/scan.xml` (Windows-friendly connect; no admin).
- **Nmap optional `ss_sv_t4`:** `-sS -sV -T4` (SYN; needs elevation). Legacy `sv_t4` aliases to connect.
- **Auto-fallback:** if a non-`-sT` run yields only `ports state=unknown`, one reconnect retry with `-sT`.
- **Jobs dir:** `%LOCALAPPDATA%\Deduplex\jobs\<id>\` when frozen / app-data; lab uses `VAPT_APP_DATA_DIR/jobs` or `<project>/data/jobs` (same root as evidence via `get_app_data_dir()`).
- **Lifecycle:** `draft` → explicit **Start** → `queued`/`running` → `succeeded`/`failed`/`cancelled`. **Never auto-start.**
- **Concurrency:** globally **one** queued/running job at a time.
- **Timeout:** default 3600s; cancel uses process-tree kill (`taskkill /T` on Windows, process group on Unix).
- **Import hook:** on exit 0, artifact fed to `services.import_service.import_scanner_file` (`tool=nmap` or `nuclei`).

### UI

- Engagement tab **Scans** → `/ui/engagements/{id}/scans`
- Create draft (targets + profile) → **Start** / **Cancel**
- Coming cards: Burp, ZAP, Cloud

### API

- `POST /api/scan-jobs` — create draft
- `POST /api/scan-jobs/{id}/start` | `/cancel`
- `GET /api/scan-jobs/engagement/{id}` | `GET /api/scan-jobs/{id}`
- `GET /api/scan-jobs/binaries` — PATH presence for nmap/nuclei

## Safety rails (non-negotiable)

- Localhost bind only (`127.0.0.1`); desktop security env unchanged
- **Never auto-start** a scan — user must Start a draft job
- Binary allowlist + light target validation (no shell metacharacters); `shell=False`; timeouts; cancel kill-tree
- No secrets in Setup; no surprise cloud API calls
- Laya triage / finetune **untouched** by this work

## Feed existing pipeline

Runner writes artifacts under jobs dir, then calls the same import path as file upload → `ImportBatch` / `Observation` / grouping. Execution is an artifact producer, not a parallel findings store.

## Later (not Wave 1)

Live Burp/ZAP API, OpenVAS GMP, Qualys/InsightVM / other cloud, distributed agents — only after job rails are stable and Midhlaj opts in per connector.

## Related

- Packaging v1 (Deduplex Setup) is separate and already QA-green.
- No GitHub create/push until Midhlaj pastes a live repo URL.
- Code: `app/models.py` (`ScanJob`), `services/scan_jobs.py`, `app/api/scan_jobs.py`, `templates/scans.html`, `importers/nuclei_jsonl.py`.
