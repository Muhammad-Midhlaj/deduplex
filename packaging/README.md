# Desktop packaging spike (Windows) — Deduplex

Double-clickable **one-folder** PyInstaller build of **Deduplex** (VAPT Effort Reduction UI),
plus an **Inno Setup** installer for lab machines. Auth-off lab only.

Git folder name may remain `vapt-effort-reduction`; product / exe / LocalAppData use **Deduplex**.

## Security (enforced in `scripts/desktop_app.py`)

| Control | Enforcement |
|---------|-------------|
| Bind host | **Hardcoded `127.0.0.1`**. Env `HOST` / `UVICORN_HOST` / `0.0.0.0` / `*` is ignored/refused. |
| `/evidence` mount | `ALLOW_INSECURE_OPEN_MODE` **forced `false`** every launch — never publicly mounted. |
| Auth / Laya | `AUTH_ENABLED=false`, `LAYA_ENABLED=false` — lab v1 OK **only because** bind is localhost. |
| Secrets | **No `.env` shipped** in the bundle. `SESSION_SECRET` / `BOOTSTRAP_API_KEY` stripped from env at launch. |
| Writable data | Frozen build uses **`%LOCALAPPDATA%\Deduplex\`** only (DB + evidence). Not next to the exe. |

Do **not** change the bind to `0.0.0.0` without enabling auth and dropping this lab profile.

## Desktop window (product shell)

Release `Deduplex.exe` is **windowed** (`console=False` in `packaging/vapt.spec`):

1. Starts uvicorn on **127.0.0.1** in a background thread
2. Waits until `/api/health` responds
3. Opens a **pywebview** (WebView2) window titled **Deduplex** on the local UI
4. Closing the window shuts down the server cleanly
5. If WebView2/pywebview fails: **tkinter** control window (Open UI / About / Quit) + browser fallback

Native File/Help menu (when pywebview menu API is available) plus in-app **File / Help** menu:
Open in browser · About · Quit window · workspace links.

**Debug console build:** temporarily set `console=True` in `packaging/vapt.spec`, rebuild, and run from a terminal to see uvicorn logs.

## QA clean-machine smoke checklist

- [ ] No `torch` / `laya` / `transformers` under `dist\Deduplex\`
- [ ] Data created under `%LOCALAPPDATA%\Deduplex\` (not under `dist\`)
- [ ] `GET /api/health` → `auth_enabled: false`, `laya_enabled: false`
- [ ] Listening on `127.0.0.1` only (not all interfaces)
- [ ] Health / OpenAPI title shows **Deduplex**
- [ ] Native window titled Deduplex (not console-only; UI loads in-window)
- [ ] No `torch` / console flash for release `console=False` build

## Data paths

| Item | Location |
|------|----------|
| SQLite DB | `%LOCALAPPDATA%\Deduplex\vapt.db` |
| Evidence uploads | `%LOCALAPPDATA%\Deduplex\evidence\` |
| Bundled templates / samples | next to the exe (`_internal\` on PyInstaller 6+) |

### Migration from VAPTEffortReduction

On first **frozen** desktop launch, if `%LOCALAPPDATA%\Deduplex\` is missing or empty and
`%LOCALAPPDATA%\VAPTEffortReduction\` exists with content, Deduplex performs a **one-time**
rename (preferred) or copy into `Deduplex` and logs the action (`app.paths.maybe_migrate_legacy_app_data`).

- Wipe / Inno `DelTree` never auto-delete the legacy folder.
- If copy was used, you may manually remove `VAPTEffortReduction` after confirming data under Deduplex.
- Manual alternative: rename/move the folder to `Deduplex` yourself before first launch.

## Uninstall / leftover data

**Default uninstall preserves app data.** Removing `dist\Deduplex\` **or** running the Inno uninstaller **does not** delete `%LOCALAPPDATA%\Deduplex\` (DB + evidence). There is **no** unconditional `[UninstallDelete]` of that folder.

Optional full wipe (opt-in only; **Deduplex folder only**):

1. **Start Menu -> "Remove Deduplex app data (optional)"** — runs `{app}\Wipe-DeduplexData.bat` (`packaging/inno/Wipe-DeduplexData.bat`). Prints the target, asks Y/N, then `rmdir /s /q` that LocalAppData\Deduplex folder only. Fails safely if the folder is missing. Never touches `VAPTEffortReduction`.
2. **Uninstaller MsgBox** — after files are removed, asks whether to also delete `LocalAppData\Deduplex` (DB + evidence). **Default is No** (`MB_YESNO` + `MB_DEFBUTTON2`). Only **Yes** calls `DelTree` on Deduplex.

Documented in `InfoAfterFile` → `packaging/inno/AFTER_INSTALL.txt` and installed `{app}\UNINSTALL_NOTE.txt`.

## Port

Default **8000**. If busy (e.g. lab `uvicorn` already running), the launcher tries **8765** and opens that URL. If both are taken, it exits with a clear error.

## Build on Midhlaj (Windows)

Prefer a **desktop venv without laya/torch** (faster, smaller):

```powershell
cd <repo-root>

python -m venv .venv-desktop
.\.venv-desktop\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements-desktop.txt -r requirements-desktop-build.txt

# From repo root:
pyinstaller packaging\vapt.spec --noconfirm
```

Using the existing `.venv` also works if PyInstaller is installed there, but avoid forcing a full `laya`/torch install just to build the desktop spike.

Output (exact path):

```text
<repo-root>\dist\Deduplex\Deduplex.exe
```

### Run the spike

```powershell
.\dist\Deduplex\Deduplex.exe
```

Or double-click the exe. A console window stays open (spike debug aid). Browser opens to `http://127.0.0.1:8000/` (or `:8765`).

Health check:

```powershell
curl http://127.0.0.1:8000/api/health
# expect: "auth_enabled": false, "laya_enabled": false
```

### Source launcher (no PyInstaller)

```powershell
.\.venv-desktop\Scripts\Activate.ps1
python scripts\desktop_app.py
```

## Inno Setup installer

Requires **Inno Setup 6** (`winget install JRSoftware.InnoSetup`) and a built one-folder tree under `dist\Deduplex\`.

```powershell
cd <repo-root>

# Prefer PATH, else common install locations (per-user or Program Files):
$candidates = @(
  "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
& $iscc packaging\inno\vapt.iss
```

Output (exact path):

```text
<repo-root>\dist\installer\Deduplex-Setup.exe
```

Script: `packaging/inno/vapt.iss` (spec file name `packaging/vapt.spec` kept)

- `AppName` / `DefaultGroupName` / install dir: **Deduplex**
- `PrivilegesRequired=lowest`
- `OutputBaseFilename=Deduplex-Setup`
- `OutputDir=../../dist/installer`
- Default uninstall does **not** delete `%LOCALAPPDATA%\Deduplex\` (no unconditional `[UninstallDelete]`)
- **Silent uninstall** (`/SILENT`, `/VERYSILENT`, QuietUninstallString): **always keeps** `%LOCALAPPDATA%\Deduplex\` (no MsgBox, no DelTree; `UninstallSilent` guard in `[Code]`)
- Optional wipe: `{app}\Wipe-DeduplexData.bat` + Start Menu "Remove Deduplex app data (optional)"; uninstall MsgBox Yes/No (default **No**) then `DelTree` only on Yes — **Deduplex only**
- Documented via `InfoAfterFile` + `UNINSTALL_NOTE.txt` + this README

## What is NOT done yet

- WiX MSI (Inno Setup is the installer path for this spike)
- Code signing
- `console=False` windowed mode (switch in `vapt.spec` for Phase 2)
- Bundling Laya weights (explicitly out of scope for desktop)

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Antivirus quarantine | PyInstaller bootloader false positive — allowlist the dist folder |
| Missing DLL / crash on start | Install [VC++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist) (x64) |
| Templates not found | Rebuild so `templates` is in the COLLECT datas; check `_internal\templates` |
| Port in use | Stop lab uvicorn or let the app fall back to 8765 |
| Huge build / torch in dist | Rebuild from `requirements-desktop*.txt` (excludes laya/torch) |
| `iscc` / ISCC.exe not found | Install Inno Setup 6: `winget install JRSoftware.InnoSetup` |
| Old data not under Deduplex | First launch migrates from `VAPTEffortReduction` when Deduplex empty; or rename the folder manually |
