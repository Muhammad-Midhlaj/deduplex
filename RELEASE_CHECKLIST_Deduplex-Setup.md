# Release checklist — Deduplex-Setup.exe

Gate this list **before** tagging a public Setup build (`0.1.0-spike` or later). All items are blockers unless marked optional.

Product: **Deduplex** · Installer: **`Deduplex-Setup.exe`** · Exe: **`Deduplex.exe`** · Publisher: **Muhammad Midhlaj** · Version source: `packaging/inno/vapt.iss` (`MyAppVersion`).

## 1. Build smoke

- [ ] Clean desktop venv from `requirements-desktop.txt` + `requirements-desktop-build.txt` (not full `requirements.txt` that pulls laya/torch).
- [ ] `pyinstaller packaging\vapt.spec --noconfirm` succeeds.
- [ ] Output exists: `dist\Deduplex\Deduplex.exe`.
- [ ] Inno: `ISCC.exe packaging\inno\vapt.iss` succeeds.
- [ ] Output exists: `dist\installer\Deduplex-Setup.exe` (exact name — not legacy `VAPTEffortReduction-Setup.exe`).
- [ ] `AppVersion` / Setup metadata match the intended tag (e.g. `0.1.0-spike`).

## 2. No torch / Laya in dist

- [ ] Search `dist\Deduplex\` — **no** `torch`, `laya`, `transformers` packages or weight blobs.
- [ ] Health / runtime: `laya_enabled: false`.
- [ ] Public tree for this release excludes `finetune/` and does not ship `LAYA_LOCAL_CHECKPOINT` paths or Hub caches.

## 3. Localhost bind

- [ ] Process listens on **`127.0.0.1` only** (not `0.0.0.0` / all interfaces).
- [ ] Env attempts to set open bind are ignored/refused by `scripts/desktop_app.py`.
- [ ] `GET /api/health` → `auth_enabled: false`, `laya_enabled: false` for lab profile.
- [ ] `ALLOW_INSECURE_OPEN_MODE` effectively false (`/evidence` not publicly mounted).

## 4. LocalAppData paths

- [ ] First launch creates DB/evidence under **`%LOCALAPPDATA%\Deduplex\`** (not under `dist\` or install dir).
- [ ] SQLite: `%LOCALAPPDATA%\Deduplex\vapt.db`
- [ ] Evidence: `%LOCALAPPDATA%\Deduplex\evidence\`
- [ ] Legacy migration (if applicable): empty Deduplex may one-time migrate from `VAPTEffortReduction`; wipe never auto-deletes legacy folder.

## 5. Installer naming & UX

- [ ] Installer filename: **`Deduplex-Setup.exe`**
- [ ] Window / OpenAPI / Start Menu branding: **Deduplex** (not internal “VAPT Effort Reduction” as primary product name).
- [ ] Default uninstall **preserves** LocalAppData; optional wipe is opt-in and Deduplex-only.

## 6. No secrets / `.env` in bundle

- [ ] No `.env` file inside `dist\Deduplex\` or the Setup payload.
- [ ] No committed `BOOTSTRAP_API_KEY` / `SESSION_SECRET` / `API_KEY_PEPPER` values in shipped config.
- [ ] Launcher strips those secrets from the process environment at start.
- [ ] No accidental inclusion of walkthrough exports, analyst JSONL, or real engagement DBs.

## 7. Scrub sample / shipped PII

- [ ] Bundled samples (if any) are **synthetic** only (`sample_data/` lab hosts such as `*.lab.local` / RFC1918 lab ranges).
- [ ] No customer hostnames, engagement names, or evidence dumps in the install tree.
- [ ] Publish scrub inventory reviewed: see `PUBLISH_SCRUB.md`.

## 8. QA smoke sign-off

- [ ] Fresh install via `Deduplex-Setup.exe` on a clean lab machine (or clean LocalAppData).
- [ ] Native Deduplex window loads UI (or documented fallback).
- [ ] Create engagement → import synthetic Nmap → decide one finding → export confirmed → optional retest compare.
- [ ] Quit cleanly; data remains under LocalAppData\Deduplex.
- [ ] Sign-off: **name** ____________ **date** ____________ (IST)

## 9. Tag / publish (after gates)

- [ ] CHANGELOG section for the tag is accurate (no invented features).
- [ ] GitHub release assets (if any) use Deduplex naming; no fake stars/download badges in README.
- [ ] SECURITY.md contact path still valid.

**Do not tag public Setup if any blocker above is open.**

