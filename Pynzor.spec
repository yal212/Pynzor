# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

a = Analysis(
    ['src/pynzor/cli/main.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        # Destinations mirror the package layout so __file__-relative loaders
        # (load_config, the Jinja templates dir) resolve inside _MEIPASS.
        ('src/pynzor/cli/wordlists', 'pynzor/cli/wordlists'),
        ('src/pynzor/output/templates', 'pynzor/output/templates'),
        ('src/pynzor/cli/config.yaml', 'pynzor/cli'),
        ('src/pynzor/tui/styles.tcss', 'pynzor/tui'),
        # Textual ships .tcss and widget data the default analysis misses;
        # without these the dashboard starts and then fails to style itself.
        *collect_data_files('textual'),
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
        'pynzor.tui',
        'pynzor.tui.app',
        # Textual resolves widgets dynamically, so they are not discoverable
        # by static analysis.
        *collect_submodules('textual'),
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
