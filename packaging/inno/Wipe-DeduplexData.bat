@echo off
setlocal EnableExtensions
rem Optional full wipe of Deduplex app data (DB + evidence).
rem Installed beside the app; also available from the Start Menu.
rem Does NOT uninstall the program — only removes LocalAppData\Deduplex.
rem NEVER deletes the legacy %%LOCALAPPDATA%%\VAPTEffortReduction\ folder.

set "TARGET=%LOCALAPPDATA%\Deduplex"

echo.
echo ============================================================
echo  Deduplex — optional app-data wipe
echo ============================================================
echo.
echo This will permanently delete ONLY this folder:
echo.
echo   %TARGET%
echo.
echo Contents typically include:
echo   - SQLite database (vapt.db)
echo   - Evidence uploads
echo.
echo The installed program under Program Files is NOT removed.
echo Default uninstall already leaves this folder alone on purpose.
echo.
echo NOTE: Legacy %%LOCALAPPDATA%%\VAPTEffortReduction\ is NEVER
echo deleted by this script. Remove it manually if you no longer need it.
echo.

if not exist "%TARGET%\" (
  echo Folder not found — nothing to delete. Exiting safely.
  echo.
  pause
  exit /b 0
)

set /p "CONFIRM=Type Y and press Enter to confirm wipe (anything else cancels): "
if /I not "%CONFIRM%"=="Y" (
  echo.
  echo Cancelled — no files were deleted.
  echo.
  pause
  exit /b 0
)

echo.
echo Deleting %TARGET% ...
rmdir /s /q "%TARGET%" 2>nul

if exist "%TARGET%\" (
  echo.
  echo ERROR: Could not fully remove the folder.
  echo Close Deduplex if it is running, then try again.
  echo.
  pause
  exit /b 1
)

echo.
echo Done. Application data under LocalAppData\Deduplex was removed.
echo.
pause
exit /b 0
