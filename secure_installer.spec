# -*- mode: python ; coding: utf-8 -*-

import sys
import os
import tkinter


def get_tcl_tk_dirs():
    tcl_dir = os.path.join(os.path.dirname(tkinter.__file__), 'tcl')
    tk_dir = os.path.join(os.path.dirname(tkinter.__file__), 'tk')
    tcl_root = os.environ.get('TCL_LIBRARY') or os.path.join(sys.base_prefix, 'tcl')
    tk_root = os.environ.get('TK_LIBRARY') or os.path.join(sys.base_prefix, 'tk')
    datas = []
    for d in [tcl_dir, tk_dir, tcl_root, tk_root]:
        if os.path.exists(d):
            datas.append((d, d))
    return datas

datas = get_tcl_tk_dirs()

a = Analysis(
    ['secure_installer.py'],
    pathex=[],
    binaries=[],
    datas=datas,
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
    name='secure_installer',
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
    icon=['icon.ico'],
)
