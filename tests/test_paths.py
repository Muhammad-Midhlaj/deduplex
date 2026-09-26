"""Unit tests for app.paths — frozen vs source resolution (no PyInstaller required)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app import paths


@pytest.fixture(autouse=True)
def _clear_path_env(monkeypatch: pytest.MonkeyPatch):
    for key in (
        "VAPT_PROJECT_ROOT",
        "VAPT_TEMPLATES_DIR",
        "VAPT_APP_DATA_DIR",
        "LOCALAPPDATA",
        "XDG_DATA_HOME",
    ):
        monkeypatch.delenv(key, raising=False)
    yield


def test_project_root_source_tree():
    root = paths.get_project_root()
    assert (root / "app" / "paths.py").is_file()
    assert (root / "templates").is_dir()


def test_templates_dir_default():
    td = paths.get_templates_dir()
    assert td == paths.get_project_root() / "templates"
    assert (td / "base.html").is_file() or td.is_dir()


def test_project_root_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("VAPT_PROJECT_ROOT", str(tmp_path))
    assert paths.get_project_root() == tmp_path.resolve()
    assert paths.get_templates_dir() == tmp_path.resolve() / "templates"


def test_templates_dir_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    custom = tmp_path / "jinja"
    custom.mkdir()
    monkeypatch.setenv("VAPT_TEMPLATES_DIR", str(custom))
    assert paths.get_templates_dir() == custom.resolve()


def test_app_data_dir_lab_default():
    # Not frozen → project/data
    assert paths.get_app_data_dir() == paths.get_project_root() / "data"


def test_app_data_dir_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("VAPT_APP_DATA_DIR", str(tmp_path / "adata"))
    assert paths.get_app_data_dir() == (tmp_path / "adata").resolve()


def test_default_database_url_uses_app_data(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("VAPT_APP_DATA_DIR", str(tmp_path))
    url = paths.get_default_database_url()
    assert url.startswith("sqlite:///")
    assert "vapt.db" in url
    assert tmp_path.as_posix() in url or str(tmp_path) in url.replace("/", "\\")


def test_frozen_project_root_uses_meipass(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    meipass = tmp_path / "_internal"
    meipass.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    assert paths.is_frozen() is True
    assert paths.get_project_root() == meipass.resolve()
    assert paths.get_templates_dir() == meipass.resolve() / "templates"


def test_frozen_app_data_uses_localappdata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    local = tmp_path / "LocalAppData"
    local.mkdir()
    meipass = tmp_path / "_internal"
    meipass.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    expected = (local / paths.APP_DATA_FOLDER_NAME).resolve()
    assert paths.get_app_data_dir() == expected
    assert paths.get_default_evidence_dir() == expected / "evidence"


def test_is_frozen_false_in_tests():
    # Restore: other tests may have set frozen on sys — ensure clean check without attrs
    # After fixtures cleared env; frozen may still be patched from prior test in same module
    # Explicitly unset for this assertion when possible
    frozen_attr = getattr(sys, "frozen", False)
    if not frozen_attr:
        assert paths.is_frozen() is False


def test_app_data_folder_name_is_deduplex():
    assert paths.APP_DATA_FOLDER_NAME == "Deduplex"
    assert paths.LEGACY_APP_DATA_FOLDER_NAME == "VAPTEffortReduction"


def test_migrate_rename_when_new_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    local = tmp_path / "Local"
    local.mkdir()
    legacy = local / paths.LEGACY_APP_DATA_FOLDER_NAME
    legacy.mkdir()
    (legacy / "vapt.db").write_text("db", encoding="utf-8")
    (legacy / "evidence").mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))

    new_dir = local / paths.APP_DATA_FOLDER_NAME
    result = paths.maybe_migrate_legacy_app_data(new_dir)
    assert result == new_dir.resolve()
    assert (new_dir / "vapt.db").is_file()
    assert not legacy.exists()  # rename moved it


def test_migrate_copy_when_rename_blocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """If rename fails, copytree leaves legacy in place (never auto-deleted)."""
    local = tmp_path / "Local"
    local.mkdir()
    legacy = local / paths.LEGACY_APP_DATA_FOLDER_NAME
    legacy.mkdir()
    (legacy / "vapt.db").write_text("db", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local))

    new_dir = local / paths.APP_DATA_FOLDER_NAME

    real_rename = Path.rename

    def boom(self, target):  # noqa: ANN001
        if self.resolve() == legacy.resolve():
            raise OSError("cross-device simulated")
        return real_rename(self, target)

    monkeypatch.setattr(Path, "rename", boom)
    result = paths.maybe_migrate_legacy_app_data(new_dir)
    assert result == new_dir.resolve()
    assert (new_dir / "vapt.db").is_file()
    assert legacy.is_dir()  # legacy preserved after copy
    assert (legacy / "vapt.db").is_file()


def test_migrate_skips_when_new_has_data(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    local = tmp_path / "Local"
    local.mkdir()
    legacy = local / paths.LEGACY_APP_DATA_FOLDER_NAME
    legacy.mkdir()
    (legacy / "old.db").write_text("old", encoding="utf-8")
    new_dir = local / paths.APP_DATA_FOLDER_NAME
    new_dir.mkdir()
    (new_dir / "vapt.db").write_text("new", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local))

    result = paths.maybe_migrate_legacy_app_data(new_dir)
    assert result == new_dir.resolve()
    assert (new_dir / "vapt.db").read_text(encoding="utf-8") == "new"
    assert (legacy / "old.db").is_file()
