# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('cli/wordlists', 'cli/wordlists'),
        ('output/templates', 'output/templates'),
        ('cli/config.yaml', 'cli'),
    ],
    hiddenimports=[
        'dns',
        'dns.resolver',
        'dns.name',
        'dns.rdatatype',
        'dns.rdataclass',
        'dns.rdata',
        'lxml',
        'lxml.etree',
        'bs4',
        'jinja2',
        'yaml',
        'rich',
        'typer',
        'httpx',
        'anyio',
        'anyio._backends._asyncio',
        'certifi',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Pynzor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
