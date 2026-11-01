# -*- mode: python ; coding: utf-8 -*-
# Genera auditor.exe (un solo archivo, sin consola) a partir de auditor.py.
# El icono se incrusta en el ejecutable; escudo.ico y auditor_core.exe deben
# seguir junto al .exe para que la aplicacion los encuentre en tiempo de ejecucion.
#
# Copyright (c) 2026 Juan Ramon Martin <zeronet75@gmail.com>
# Licencia MIT (ver el archivo LICENSE).

a = Analysis(
    ['auditor.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='auditor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='escudo.ico',
    version='version_info.txt',
)
