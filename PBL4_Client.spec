# PBL4_Client.spec
from PyInstaller.utils.hooks import collect_dynamic_libs, collect_all

block_cipher = None

sqlite_bins = collect_dynamic_libs('sqlite3')
win10toast_datas, win10toast_bins, win10toast_hidden = collect_all('win10toast')

a = Analysis(
    ['app.py'],
    pathex=['.'],

    binaries=[
        *sqlite_bins,
        *win10toast_bins,
    ],

    datas=[
        *win10toast_datas,

        # ---- C EXTENSIONS ----
        ('build/lib.win-amd64-cpython-313/yarascanner*.pyd', '.'),
        ('build/lib.win-amd64-cpython-313/libcrypto-3-x64.dll', '.'),
        ('build/lib.win-amd64-cpython-313/libssl-3-x64.dll', '.'),

        # ---- CLIENT AS FILESYSTEM ----
        ('Client', 'Client'),

        # ---- ASSETS ----
        ('crypto_config.py', '.'),
        ('full_hash.db', '.'),
        ('App.config', '.'),
    ],

    hiddenimports=[
        'yarascanner',
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Cipher.AES',
        'sqlite3',
        '_sqlite3',
        *win10toast_hidden,
        'uuid',
    ],

    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PBL4_Client',
    console=True,
    upx=True,
    uac_admin=True,
)
