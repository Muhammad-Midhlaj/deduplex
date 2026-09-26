# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-folder spec for Deduplex desktop product.

Build (from repo root on Windows):
  .venv-desktop\\Scripts\\Activate.ps1
  pyinstaller packaging\\vapt.spec --noconfirm

Output (release, windowed):
  dist\\Deduplex\\Deduplex.exe

Debug console build: set console=True below temporarily, or see packaging/README.md.
"""

import sys
from pathlib import Path

block_cipher = None

SPECDIR = Path(SPECPATH)  # noqa: F821 — PyInstaller injects SPECPATH
ROOT = SPECDIR.parent if SPECDIR.name == "packaging" else SPECDIR

datas = [
    (str(ROOT / "templates"), "templates"),
    (str(ROOT / "sample_data"), "sample_data"),
    (str(ROOT / "packaging" / "deduplex.ico"), "packaging"),
    (str(ROOT / "packaging" / "deduplex.png"), "packaging"),
]

hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "sqlalchemy.dialects.sqlite",
    "pydantic_settings",
    "multipart",
    "openpyxl",
    "docx",
    "lxml",
    "defusedxml",
    "httpx",
    "jinja2",
    "webview",
    "webview.platforms.winforms",
    "webview.platforms.edgechromium",
    "clr",
    "pythonnet",
    "app",
    "app.main",
    "app.config",
    "app.paths",
    "app.database",
    "app.models",
    "app.web",
    "app.web.routes",
    "app.api",
    "importers",
    "importers.nmap_xml",
    "importers.nessus",
    "services",
    "services.import_service",
    "services.grouping",
    "services.prioritization",
    "services.export_report",
    "services.retest",
    "services.asset_mapping",
    "services.laya_triage",
]

excludes = [
    "torch",
    "torchvision",
    "torchaudio",
    "transformers",
    "huggingface_hub",
    "laya",
    "tensorflow",
    "tensorboard",
    "pytest",
    "pytest_asyncio",
]

a = Analysis(  # noqa: F821
    [str(ROOT / "scripts" / "desktop_app.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Deduplex",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # release: native window only; set True for debug console (see README)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "packaging" / "deduplex.ico"),
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Deduplex",
)
