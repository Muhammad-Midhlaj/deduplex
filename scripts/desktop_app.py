#!/usr/bin/env python3
"""Desktop launcher for Deduplex — native window (pywebview) + localhost lab server.

Security (lab v1 — enforced in code, not optional):
  - Bind host is ALWAYS 127.0.0.1. Env vars that would open 0.0.0.0 / * are ignored.
  - ALLOW_INSECURE_OPEN_MODE is forced false — /evidence is never publicly mounted.
  - AUTH_ENABLED=false and LAYA_ENABLED=false are lab defaults OK *only* because of
    the localhost bind. Do not change the bind without turning auth on.
  - No secrets .env is shipped or loaded from the bundle. Writable DB/evidence live
    under %LOCALAPPDATA%\\Deduplex\\ when frozen (not next to the exe).
  - Optional one-time migrate from legacy %LOCALAPPDATA%\\VAPTEffortReduction\\ when
    Deduplex is missing/empty. Wipe tools never auto-delete the legacy folder.

UI shell:
  - Prefer pywebview (WebView2 on Windows) wrapping http://127.0.0.1:<port>/
  - Fallback: tkinter control window (Start / Open UI / Quit)
  - Release build uses console=False (see packaging/vapt.spec)
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any


# Hardcoded — never take bind host from the environment.
BIND_HOST = "127.0.0.1"
DEFAULT_PORTS = (8000, 8765)
_BLOCKED_BIND_HOSTS = frozenset({"0.0.0.0", "*", "::", "[::]"})
APP_DISPLAY_NAME = "Deduplex"
APP_VERSION = "0.1.0-spike"


def _ensure_project_on_path() -> Path:
    """When running from source, put the repo root on sys.path."""
    here = Path(__file__).resolve()
    root = here.parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root


def _refuse_open_bind_env() -> None:
    """Ignore/refuse any env that would widen the bind beyond localhost."""
    for key in ("HOST", "UVICORN_HOST", "VAPT_BIND_HOST", "BIND_HOST"):
        raw = (os.environ.get(key) or "").strip()
        if not raw:
            continue
        lowered = raw.lower()
        if lowered in _BLOCKED_BIND_HOSTS or lowered.startswith("0.0.0.0"):
            _safe_print(
                f"Ignoring {key}={raw!r} — desktop spike binds 127.0.0.1 only.",
                file=sys.stderr,
            )
            os.environ.pop(key, None)


def _force_lab_security_env() -> None:
    """Force lab-safe flags. Uses assignment (not setdefault) so user env cannot reopen."""
    os.environ["AUTH_ENABLED"] = "false"
    os.environ["LAYA_ENABLED"] = "false"
    os.environ["ALLOW_INSECURE_OPEN_MODE"] = "false"
    for secret_key in ("SESSION_SECRET", "BOOTSTRAP_API_KEY", "API_KEY_PEPPER"):
        os.environ.pop(secret_key, None)


def _configure_desktop_env(project_root: Path) -> Path:
    """Set env *before* importing app.settings. Returns app-data directory."""
    _refuse_open_bind_env()
    _force_lab_security_env()

    frozen = bool(getattr(sys, "frozen", False))
    from app.paths import APP_DATA_FOLDER_NAME, maybe_migrate_legacy_app_data

    if frozen:
        meipass = getattr(sys, "_MEIPASS", None)
        asset_root = Path(meipass) if meipass else Path(sys.executable).resolve().parent
        os.environ["VAPT_PROJECT_ROOT"] = str(asset_root)
        os.environ["VAPT_TEMPLATES_DIR"] = str(asset_root / "templates")

        local = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
        if not local:
            raise SystemExit(
                "LOCALAPPDATA (or XDG_DATA_HOME) is required for the desktop build. "
                "Data must live under the OS app-data directory, not next to the exe."
            )
        app_data = Path(local) / APP_DATA_FOLDER_NAME
        app_data = maybe_migrate_legacy_app_data(app_data)
    else:
        os.environ.setdefault("VAPT_PROJECT_ROOT", str(project_root))
        os.environ.setdefault("VAPT_TEMPLATES_DIR", str(project_root / "templates"))
        app_data = Path(os.environ.get("VAPT_APP_DATA_DIR") or (project_root / "data"))

    app_data = app_data.expanduser().resolve()
    evidence = app_data / "evidence"
    app_data.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)

    os.environ["VAPT_APP_DATA_DIR"] = str(app_data)
    os.environ["DATABASE_URL"] = f"sqlite:///{(app_data / 'vapt.db').as_posix()}"
    os.environ["EVIDENCE_DIR"] = str(evidence)

    return app_data


def _port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def pick_port(host: str = BIND_HOST, candidates: tuple[int, ...] = DEFAULT_PORTS) -> int:
    if host != BIND_HOST:
        raise SystemExit(f"Refusing bind host {host!r}; desktop spike allows {BIND_HOST} only.")
    for port in candidates:
        if _port_free(host, port):
            return port
    tried = ", ".join(str(p) for p in candidates)
    raise SystemExit(
        f"No free port among [{tried}] on {host}. "
        "Stop the other Deduplex / uvicorn process, or free one of those ports."
    )


def _icon_path(project_root: Path) -> str | None:
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "packaging" / "deduplex.ico")
        candidates.append(Path(meipass) / "deduplex.ico")
    candidates.append(project_root / "packaging" / "deduplex.ico")
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / "deduplex.ico")
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def _wait_for_health(url: str, timeout: float = 30.0) -> bool:
    import urllib.request

    health = url.rstrip("/") + "/api/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(health, timeout=1.5) as resp:  # noqa: S310 — localhost only
                if resp.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    return False


class _ServerHandle:
    def __init__(self, server: Any, thread: threading.Thread, url: str) -> None:
        self.server = server
        self.thread = thread
        self.url = url
        self._stopped = False

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self.server.should_exit = True
        # Give the server thread a moment to unwind
        self.thread.join(timeout=5.0)


def _stream_usable(stream: Any) -> bool:
    """True if *stream* can be used as a logging target (not None; has write + isatty)."""
    if stream is None:
        return False
    return callable(getattr(stream, "write", None)) and hasattr(stream, "isatty")


def _safe_print(*args: Any, **kwargs: Any) -> None:
    """Like print(), but no-ops when the target stream is None (console=False / frozen)."""
    stream = kwargs.get("file", sys.stdout)
    if stream is None or not callable(getattr(stream, "write", None)):
        return
    try:
        print(*args, **kwargs)
    except Exception:  # noqa: BLE001 — never crash UI for a log line
        pass


def _needs_safe_uvicorn_log_config() -> bool:
    """Frozen builds and any process without a usable stderr must avoid ColourizedFormatter."""
    if bool(getattr(sys, "frozen", False)):
        return True
    return not _stream_usable(sys.stderr)


def _uvicorn_log_config(app_data: Path | None = None) -> dict | None:
    """Plain logging dictConfig safe when sys.stdout/stderr are None (console=False).

    Uvicorn's default ColourizedFormatter / DefaultFormatter call stream.isatty().
    Under PyInstaller windowed builds that raises AttributeError → ValueError while
    configuring formatter 'default'. This config never uses those formatters.

    Returns None only when a safe default is not required (caller should still prefer
    this helper whenever _needs_safe_uvicorn_log_config() is True).
    """
    formatter = {
        "format": "%(levelname)s:     %(message)s",
        "datefmt": "%Y-%m-%d %H:%M:%S",
    }
    handlers: dict[str, dict[str, Any]] = {}
    handler_names: list[str] = []

    if _stream_usable(sys.stderr):
        handlers["default"] = {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "stream": "ext://sys.stderr",
        }
        handler_names.append("default")
    elif app_data is not None:
        log_dir = Path(app_data) / "logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            handlers["default"] = {
                "class": "logging.FileHandler",
                "formatter": "default",
                "filename": str(log_dir / "deduplex-uvicorn.log"),
                "encoding": "utf-8",
            }
            handler_names.append("default")
        except OSError:
            pass

    if not handler_names:
        handlers["null"] = {"class": "logging.NullHandler"}
        handler_names = ["null"]

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            # Plain logging.Formatter only — uvicorn.Config requires an "access" key
            # even when access_log=False; never use ColourizedFormatter / DefaultFormatter.
            "default": formatter,
            "access": {
                "format": '%(levelname)s:     %(message)s',
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": handlers,
        "loggers": {
            "uvicorn": {"handlers": handler_names, "level": "INFO", "propagate": False},
            "uvicorn.error": {"handlers": handler_names, "level": "INFO", "propagate": False},
            "uvicorn.access": {"handlers": handler_names, "level": "INFO", "propagate": False},
        },
    }


def _start_uvicorn(host: str, port: int, app_data: Path | None = None) -> _ServerHandle:
    import inspect

    import uvicorn
    from app.main import app  # noqa: WPS433 — intentional late import

    config_kwargs: dict[str, Any] = {
        "host": host,
        "port": port,
        "log_level": "info",
        "access_log": False,
    }
    # Always disable colors when supported — ColourizedFormatter calls isatty().
    if "use_colors" in inspect.signature(uvicorn.Config.__init__).parameters:
        config_kwargs["use_colors"] = False
    if _needs_safe_uvicorn_log_config():
        config_kwargs["log_config"] = _uvicorn_log_config(app_data)

    config = uvicorn.Config(app, **config_kwargs)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="deduplex-uvicorn", daemon=True)
    thread.start()
    url = f"http://{host}:{port}/"
    if not _wait_for_health(url):
        server.should_exit = True
        raise SystemExit("Deduplex server failed to become healthy on " + url)
    return _ServerHandle(server, thread, url)


def _show_about() -> None:
    msg = (
        f"{APP_DISPLAY_NAME} {APP_VERSION}\n\n"
        "VAPT Effort Reduction — localhost-only lab build.\n"
        "Binds 127.0.0.1 only. Data under LocalAppData\\Deduplex\\."
    )
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        try:
            messagebox.showinfo(f"About {APP_DISPLAY_NAME}", msg)
        finally:
            root.destroy()
    except Exception:  # noqa: BLE001
        _safe_print(msg)


def _run_pywebview(handle: _ServerHandle, icon: str | None) -> bool:
    """Open native window. Returns False if pywebview/WebView2 unavailable."""
    try:
        import webview
    except ImportError as exc:
        _safe_print(f"pywebview not available ({exc}); using fallback UI.", file=sys.stderr)
        return False

    def open_in_browser() -> None:
        webbrowser.open(handle.url)

    def quit_app() -> None:
        for win in list(webview.windows):
            try:
                win.destroy()
            except Exception:  # noqa: BLE001
                pass

    def about() -> None:
        _show_about()

    menu = None
    try:
        from webview.menu import Menu, MenuAction

        menu = [
            Menu(
                "File",
                [
                    MenuAction("Open in browser", open_in_browser),
                    MenuAction("Quit", quit_app),
                ],
            ),
            Menu(
                "Help",
                [
                    MenuAction(f"About {APP_DISPLAY_NAME}", about),
                ],
            ),
        ]
    except Exception:  # noqa: BLE001 — older pywebview without menu API
        menu = None

    window_kwargs: dict[str, Any] = {
        "title": APP_DISPLAY_NAME,
        "url": handle.url,
        "width": 1280,
        "height": 840,
        "min_size": (900, 600),
    }
    if icon:
        window_kwargs["icon"] = icon

    try:
        webview.create_window(**window_kwargs)
        start_kwargs: dict[str, Any] = {}
        if menu is not None:
            start_kwargs["menu"] = menu
        # private_mode / storage isolation not required for localhost lab
        webview.start(**start_kwargs)
    except Exception as exc:  # noqa: BLE001
        _safe_print(f"pywebview failed ({exc}); using fallback UI.", file=sys.stderr)
        return False
    return True


def _run_tkinter_fallback(handle: _ServerHandle) -> None:
    """Small control window when WebView2/pywebview is unavailable."""
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.title(APP_DISPLAY_NAME)
    root.geometry("420x220")
    root.minsize(360, 180)

    status = tk.StringVar(value=f"Server running at {handle.url}")
    tk.Label(root, text=APP_DISPLAY_NAME, font=("Segoe UI", 16, "bold")).pack(pady=(16, 4))
    tk.Label(root, text="VAPT Effort Reduction — localhost lab", fg="#555").pack()
    tk.Label(root, textvariable=status, wraplength=380).pack(pady=12)

    btn_row = tk.Frame(root)
    btn_row.pack(pady=8)

    def open_ui() -> None:
        webbrowser.open(handle.url)

    def do_quit() -> None:
        handle.stop()
        root.destroy()

    def about() -> None:
        messagebox.showinfo(
            f"About {APP_DISPLAY_NAME}",
            f"{APP_DISPLAY_NAME} {APP_VERSION}\n\n"
            "Localhost-only lab. Bind 127.0.0.1.\n"
            "WebView2 was unavailable — opened control window instead.",
        )

    tk.Button(btn_row, text="Open UI", width=12, command=open_ui).pack(side=tk.LEFT, padx=4)
    tk.Button(btn_row, text="About", width=12, command=about).pack(side=tk.LEFT, padx=4)
    tk.Button(btn_row, text="Quit", width=12, command=do_quit).pack(side=tk.LEFT, padx=4)

    root.protocol("WM_DELETE_WINDOW", do_quit)
    # Auto-open browser once so the user lands in the workspace quickly
    root.after(400, open_ui)
    root.mainloop()


def main() -> None:
    project_root = _ensure_project_on_path()
    app_data = _configure_desktop_env(project_root)

    host = BIND_HOST
    port = pick_port(host)
    icon = _icon_path(project_root)

    _safe_print(f"{APP_DISPLAY_NAME} — starting…")
    _safe_print(f"  Data:     {app_data}")
    _safe_print(f"  AUTH:     {os.environ.get('AUTH_ENABLED')} (lab OK — localhost only)")
    _safe_print(f"  LAYA:     {os.environ.get('LAYA_ENABLED')}")
    _safe_print(f"  OPEN_EV:  {os.environ.get('ALLOW_INSECURE_OPEN_MODE')} (forced off)")
    _safe_print(f"  Bind:     {host} ONLY")

    handle = _start_uvicorn(host, port, app_data=app_data)
    _safe_print(f"  UI:       {handle.url}")
    _safe_print(f"  Health:   {handle.url.rstrip('/')}/api/health")

    try:
        ok = _run_pywebview(handle, icon)
        if not ok:
            _run_tkinter_fallback(handle)
    finally:
        handle.stop()
        _safe_print("Shutting down…")


if __name__ == "__main__":
    main()
