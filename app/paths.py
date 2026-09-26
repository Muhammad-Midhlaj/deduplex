"""Resolve project / templates / writable data roots for lab and frozen desktop builds.

Lab/dev (not frozen): project root is the repo checkout (parent of ``app/``).
Desktop (PyInstaller frozen): bundled assets live under ``sys._MEIPASS`` (or the
exe directory); writable DB/evidence live under the OS app-data directory.

Override with env:
  VAPT_PROJECT_ROOT   — root that contains ``templates/`` (and sample_data)
  VAPT_TEMPLATES_DIR  — explicit Jinja templates directory
  VAPT_APP_DATA_DIR   — writable data root (desktop default: LOCALAPPDATA/…)
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

# Product display / LocalAppData folder name (Deduplex rebrand).
APP_DATA_FOLDER_NAME = "Deduplex"
# Pre-rebrand folder — never auto-deleted by wipe/Inno; optional one-time migrate.
LEGACY_APP_DATA_FOLDER_NAME = "VAPTEffortReduction"

logger = logging.getLogger("vapt.paths")


def is_frozen() -> bool:
    """True when running inside a PyInstaller (or similar) frozen bundle."""
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def is_frozen_or_bundled() -> bool:
    """Broader frozen check (``sys.frozen`` even if ``_MEIPASS`` is missing)."""
    return bool(getattr(sys, "frozen", False))


def get_project_root() -> Path:
    """Root that holds bundled/source assets (templates, sample_data)."""
    override = (os.environ.get("VAPT_PROJECT_ROOT") or "").strip()
    if override:
        return Path(override).expanduser().resolve()

    if is_frozen():
        return Path(sys._MEIPASS).resolve()  # type: ignore[attr-defined]

    if is_frozen_or_bundled():
        return Path(sys.executable).resolve().parent

    # app/paths.py → app/ → project root
    return Path(__file__).resolve().parent.parent


def get_templates_dir() -> Path:
    """Jinja2 templates directory."""
    override = (os.environ.get("VAPT_TEMPLATES_DIR") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return get_project_root() / "templates"


def get_sample_data_dir() -> Path:
    return get_project_root() / "sample_data"


def _legacy_app_data_dir_candidate() -> Path | None:
    """Return the pre-rebrand LocalAppData path if the OS app-data root is known."""
    local = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    if local:
        return Path(local).expanduser().resolve() / LEGACY_APP_DATA_FOLDER_NAME
    home = Path.home()
    return (home / ".local" / "share" / LEGACY_APP_DATA_FOLDER_NAME).resolve()


def _dir_is_empty_or_missing(path: Path) -> bool:
    if not path.exists():
        return True
    if not path.is_dir():
        return False
    try:
        next(path.iterdir())
    except StopIteration:
        return True
    except OSError:
        return False
    return False


def maybe_migrate_legacy_app_data(new_dir: Path) -> Path:
    """One-time migrate from ``VAPTEffortReduction`` → ``Deduplex`` when needed.

    Rules (hard constraints):
      - Only runs when *new* dir is missing or empty AND legacy dir exists with content.
      - Prefers ``Path.rename`` (move); falls back to ``shutil.copytree`` then leaves
        the legacy folder in place (never auto-deletes it).
      - Wipe scripts / Inno DelTree must target Deduplex only — not the legacy folder.

    Returns the resolved ``new_dir`` (created if needed by the caller afterward).
    """
    new_dir = new_dir.expanduser()
    try:
        new_resolved = new_dir.resolve()
    except OSError:
        new_resolved = new_dir

    legacy = _legacy_app_data_dir_candidate()
    if legacy is None:
        return new_resolved

    try:
        legacy_resolved = legacy.resolve()
    except OSError:
        legacy_resolved = legacy

    if legacy_resolved == new_resolved:
        return new_resolved

    if not legacy_resolved.is_dir():
        return new_resolved

    if not _dir_is_empty_or_missing(new_resolved):
        # New data already present — leave legacy alone (user may keep both).
        return new_resolved

    if _dir_is_empty_or_missing(legacy_resolved):
        return new_resolved

    # Ensure parent of new_dir exists for rename/copy destination.
    try:
        new_resolved.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("Cannot create parent for Deduplex app data (%s): %s", new_resolved.parent, exc)
        return new_resolved

    # If an empty Deduplex dir exists, remove it so rename can succeed.
    if new_resolved.is_dir() and _dir_is_empty_or_missing(new_resolved):
        try:
            new_resolved.rmdir()
        except OSError:
            pass

    try:
        legacy_resolved.rename(new_resolved)
        logger.info(
            "Migrated app data: renamed %s → %s",
            legacy_resolved,
            new_resolved,
        )
        print(
            f"Migrated app data: renamed\n  {legacy_resolved}\n→ {new_resolved}",
            flush=True,
        )
        return new_resolved.resolve()
    except OSError as rename_exc:
        logger.info("Rename migrate failed (%s); trying copytree", rename_exc)

    try:
        if new_resolved.exists():
            # Non-empty or leftover — do not overwrite.
            if not _dir_is_empty_or_missing(new_resolved):
                return new_resolved.resolve()
            try:
                new_resolved.rmdir()
            except OSError:
                return new_resolved.resolve() if new_resolved.exists() else new_resolved

        shutil.copytree(str(legacy_resolved), str(new_resolved))
        logger.info(
            "Migrated app data: copied %s → %s (legacy folder left in place; "
            "delete manually if desired — wipe tools never auto-remove it)",
            legacy_resolved,
            new_resolved,
        )
        print(
            f"Migrated app data: copied\n  {legacy_resolved}\n→ {new_resolved}\n"
            f"(Legacy folder left in place; wipe tools only remove Deduplex.)",
            flush=True,
        )
        return new_resolved.resolve()
    except OSError as copy_exc:
        logger.warning("App-data migration failed: %s", copy_exc)
        print(f"WARNING: could not migrate legacy app data: {copy_exc}", flush=True)
        return new_resolved


def get_app_data_dir() -> Path:
    """Writable per-user data (DB, evidence). Lab default: ``<project>/data``."""
    override = (os.environ.get("VAPT_APP_DATA_DIR") or "").strip()
    if override:
        return Path(override).expanduser().resolve()

    if is_frozen_or_bundled():
        local = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
        if local:
            return Path(local).expanduser().resolve() / APP_DATA_FOLDER_NAME
        # Non-Windows fallback
        home = Path.home()
        return (home / ".local" / "share" / APP_DATA_FOLDER_NAME).resolve()

    return get_project_root() / "data"


def get_default_database_url() -> str:
    db_path = get_app_data_dir() / "vapt.db"
    # SQLite URLs on Windows need forward slashes; pathlib as_posix handles that.
    return f"sqlite:///{db_path.as_posix()}"


def get_default_evidence_dir() -> Path:
    return get_app_data_dir() / "evidence"
