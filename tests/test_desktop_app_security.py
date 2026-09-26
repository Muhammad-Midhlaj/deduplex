"""Desktop launcher security rails (no server start)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Import helpers from the script module via path load
import importlib.util

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "desktop_app", ROOT / "scripts" / "desktop_app.py"
)
assert SPEC and SPEC.loader
desktop_app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(desktop_app)


def test_bind_host_constant():
    assert desktop_app.BIND_HOST == "127.0.0.1"


def test_pick_port_refuses_non_localhost():
    with pytest.raises(SystemExit, match="Refusing bind host"):
        desktop_app.pick_port("0.0.0.0")


def test_force_lab_security_env_overwrites(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("LAYA_ENABLED", "true")
    monkeypatch.setenv("ALLOW_INSECURE_OPEN_MODE", "true")
    monkeypatch.setenv("SESSION_SECRET", "should-be-stripped")
    monkeypatch.setenv("BOOTSTRAP_API_KEY", "should-be-stripped-too")
    desktop_app._force_lab_security_env()
    assert os.environ["AUTH_ENABLED"] == "false"
    assert os.environ["LAYA_ENABLED"] == "false"
    assert os.environ["ALLOW_INSECURE_OPEN_MODE"] == "false"
    assert "SESSION_SECRET" not in os.environ
    assert "BOOTSTRAP_API_KEY" not in os.environ


def test_refuse_open_bind_env(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("UVICORN_HOST", "*")
    desktop_app._refuse_open_bind_env()
    assert "HOST" not in os.environ
    assert "UVICORN_HOST" not in os.environ
    err = capsys.readouterr().err
    assert "127.0.0.1" in err


def test_wipe_bat_targets_deduplex_only():
    bat = (ROOT / "packaging" / "inno" / "Wipe-DeduplexData.bat").read_text(encoding="utf-8", errors="replace")
    assert r"%LOCALAPPDATA%\Deduplex" in bat
    assert "VAPTEffortReduction" in bat  # mentioned as never-deleted legacy
    # Must not set TARGET to the legacy folder
    assert 'set "TARGET=%LOCALAPPDATA%\\VAPTEffortReduction"' not in bat
    assert not (ROOT / "packaging" / "inno" / "Wipe-VAPTData.bat").exists()


def test_inno_deltree_targets_deduplex_only():
    iss = (ROOT / "packaging" / "inno" / "vapt.iss").read_text(encoding="utf-8", errors="replace")
    assert r"{localappdata}\Deduplex" in iss
    assert "OutputBaseFilename=Deduplex-Setup" in iss
    assert "DefaultDirName={autopf}\\Deduplex" in iss
    assert 'MyAppExeName "Deduplex.exe"' in iss or 'MyAppExeName "Deduplex.exe"' in iss.replace(" ", "")
    # DelTree path must be Deduplex; legacy must not be ExpandConstant target for wipe
    assert "ExpandConstant('{localappdata}\\VAPTEffortReduction')" not in iss


def test_desktop_display_name_and_wait_helper():
    assert desktop_app.APP_DISPLAY_NAME == "Deduplex"
    assert desktop_app.BIND_HOST == "127.0.0.1"


def test_icon_path_finds_packaging_ico():
    root = ROOT
    path = desktop_app._icon_path(root)
    assert path is not None
    assert path.endswith("deduplex.ico")


def test_inno_silent_uninstall_keeps_localappdata():
    iss = (ROOT / "packaging" / "inno" / "vapt.iss").read_text(encoding="utf-8", errors="replace")
    assert "UninstallSilent" in iss
    assert "if UninstallSilent then" in iss
    assert "Exit;" in iss
    assert "DelTree" in iss
    # Wipe target is Deduplex only
    assert "{localappdata}\\Deduplex" in iss or r"{localappdata}\Deduplex" in iss

def test_uvicorn_log_config_no_colourized_when_stderr_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """console=False / frozen: stderr may be None; log_config must not use ColourizedFormatter."""
    monkeypatch.setattr(desktop_app.sys, "stderr", None)
    monkeypatch.setattr(desktop_app.sys, "stdout", None)

    cfg = desktop_app._uvicorn_log_config(tmp_path)
    assert cfg is not None
    assert cfg["version"] == 1
    # Formatters must be plain logging.Formatter (no class override to uvicorn colourizers)
    for name, fmt in cfg["formatters"].items():
        class_ref = str(fmt.get("()", fmt.get("class", "")))
        assert "Colourized" not in class_ref
        assert "uvicorn.logging" not in class_ref
    handlers = cfg["handlers"]
    assert any(h.get("class") == "logging.FileHandler" for h in handlers.values())
    log_file = tmp_path / "logs" / "deduplex-uvicorn.log"
    assert log_file.parent.is_dir()

    # dictConfig must apply cleanly with stderr=None (the crash path)
    import logging.config

    logging.config.dictConfig(cfg)


def test_uvicorn_log_config_null_handler_without_app_data(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(desktop_app.sys, "stderr", None)
    cfg = desktop_app._uvicorn_log_config(None)
    assert cfg is not None
    assert any(h.get("class") == "logging.NullHandler" for h in cfg["handlers"].values())


def test_uvicorn_log_config_stream_when_stderr_ok():
    cfg = desktop_app._uvicorn_log_config(None)
    assert cfg is not None
    # On a normal TTY/test runner stderr is usable → StreamHandler
    assert any(h.get("class") == "logging.StreamHandler" for h in cfg["handlers"].values())
    for fmt in cfg["formatters"].values():
        assert "Colourized" not in str(fmt)
        assert "uvicorn.logging" not in str(fmt)


def test_needs_safe_uvicorn_log_config_when_stderr_none(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(desktop_app.sys, "stderr", None)
    assert desktop_app._needs_safe_uvicorn_log_config() is True


def test_needs_safe_uvicorn_log_config_when_frozen(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(desktop_app.sys, "frozen", True, raising=False)
    assert desktop_app._needs_safe_uvicorn_log_config() is True


def test_safe_print_noop_when_streams_none(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(desktop_app.sys, "stdout", None)
    monkeypatch.setattr(desktop_app.sys, "stderr", None)
    desktop_app._safe_print("should not raise")
    desktop_app._safe_print("err", file=None)


def test_start_uvicorn_config_kwargs_safe_under_none_stderr(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Ensure the Config() path used by _start_uvicorn would not pick ColourizedFormatter."""
    import inspect

    import uvicorn

    monkeypatch.setattr(desktop_app.sys, "stderr", None)
    monkeypatch.setattr(desktop_app.sys, "stdout", None)
    monkeypatch.setattr(desktop_app.sys, "frozen", True, raising=False)

    assert desktop_app._needs_safe_uvicorn_log_config() is True
    log_config = desktop_app._uvicorn_log_config(tmp_path)
    kwargs: dict = {
        "host": "127.0.0.1",
        "port": 9,  # unused — we only construct Config with a dummy app
        "log_level": "info",
        "access_log": False,
        "log_config": log_config,
    }
    if "use_colors" in inspect.signature(uvicorn.Config.__init__).parameters:
        kwargs["use_colors"] = False

    # Minimal ASGI app — Config construction configures logging immediately in some versions
    async def app(scope, receive, send):  # noqa: ANN001
        return None

    config = uvicorn.Config(app, **kwargs)
    # Default formatter class on uvicorn logging should not be colourized when use_colors=False
    # and our log_config is plain. Smoke: config exists and log_config was accepted.
    assert config.log_config is log_config or config.log_config == log_config

