# Deduplex â€” multi-scanner execution roadmap

Wave 1 scanner execution for **Deduplex** (locked 26 Sep 2026).

## Wave 1 status â€” **implemented (Nmap MVP + Nuclei 1b)**

| Item | Decision | Status |
|------|----------|--------|
| Nmap | **MVP run** â€” ScanJob + binary allowlist + explicit Start + `-oX` â†’ `import_service` â†’ dedupe â†’ queue | **Done** |
| Nuclei | **Wave 1b** â€” same job rails; `-jsonl` â†’ `importers/nuclei_jsonl.py` | **Done** (UI shows form when binary on PATH) |
| Nessus / OpenVAS | **File import only** | Unchanged |
| Burp / ZAP / cloud | **Coming** cards only | UI cards disabled |

### Defaults (locked)

- **Binary:** resolve via `PATH` (`shutil.which`); on first successful resolve, path is written to app-data `scanner_binaries.json` (allowlist). User may override path on draft create.
- **Nmap default `st_sv_t4`:** `-sT -sV -T4` plus `-oX <job_dir>/scan.xml` (Windows-friendly connect; no admin).
- **Nmap optional `ss_sv_t4`:** `-sS -sV -T4` (SYN; needs elevation). Legacy `sv_t4` aliases to connect.
- **Auto-fallback:** if a non-`-sT` run yields only `ports state=unknown`, one reconnect retry with `-sT`.
- **Jobs dir:** `%LOCALAPPDATA%\Deduplex\jobs\<id>\` when frozen / app-data; lab uses `VAPT_APP_DATA_DIR/jobs` or `<project>/data/jobs` (same root as evidence via `get_app_data_dir()`).
- **Stdout log:** new runs write merged stdout/stderr to `jobs/<id>/stdout.log` (header `# argv: â€¦` flushed before Popen). Older jobs may still have `scan.log` â€” readers fall back. `job.log_path` points at the active file.
- **Lifecycle:** `draft` â†’ explicit **Start** â†’ `queued`/`running` â†’ `succeeded`/`failed`/`cancelled`. **Never auto-start.**
- **Concurrency:** globally **one** queued/running job at a time.
- **Timeout:** default 3600s; cancel uses process-tree kill (`taskkill /T` on Windows, process group on Unix).
- **Import hook:** on exit 0, artifact fed to `services.import_service.import_scanner_file` (`tool=nmap` or `nuclei`).

### UI

- Engagement tab **Scans** â†’ `/ui/engagements/{id}/scans`
- Create draft (targets + profile) â†’ **Start** / **Cancel**
- **Terminal panel:** dark mono log view under the jobs table. Click **Log** (or auto-select running / latest job). While queued/running, the page polls `GET /api/scan-jobs/{id}/log?offset=` about every 1s and appends chunks; stops on terminal status. Refresh reloads full scrollback from offset 0. Command line shown above the panel (display-only `shlex.join`).
- Coming cards: Burp, ZAP, Cloud

### API

- `POST /api/scan-jobs` â€” create draft
- `POST /api/scan-jobs/{id}/start` | `/cancel`
- `GET /api/scan-jobs/engagement/{id}` | `GET /api/scan-jobs/{id}`
- `GET /api/scan-jobs/{id}/log?offset=0` â€” byte-offset tail of `stdout.log` (JSON: `job_id`, `status`, `command_line`, `offset`, `next_offset`, `chunk`, `eof`, `log_path`; chunk capped ~256KiB; same engagement ACL as other scan-job routes)
- `GET /api/scan-jobs/binaries` â€” PATH presence for nmap/nuclei

## Safety rails (non-negotiable)

- Localhost bind only (`127.0.0.1`); desktop security env unchanged
- **Never auto-start** a scan â€” user must Start a draft job
- Binary allowlist + light target validation (no shell metacharacters); `shell=False`; timeouts; cancel kill-tree
- No secrets in Setup; no surprise cloud API calls
- Laya triage / finetune **untouched** by this work

## Feed existing pipeline

Runner writes artifacts under jobs dir, then calls the same import path as file upload â†’ `ImportBatch` / `Observation` / grouping. Execution is an artifact producer, not a parallel findings store.

## Later (not Wave 1)

Live Burp/ZAP API, OpenVAS GMP, Qualys/InsightVM / other cloud, distributed agents â€” only after job rails are stable and Midhlaj opts in per connector.

## Related

- Packaging v1 (Deduplex Setup) is separate and already QA-green.
- No GitHub create/push until Midhlaj pastes a live repo URL.
- Code: `app/models.py` (`ScanJob`), `services/scan_jobs.py`, `app/api/scan_jobs.py`, `templates/scans.html`, `importers/nuclei_jsonl.py`.
