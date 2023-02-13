# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['gui.py'],
             pathex=[],
             binaries=[],
             datas=[( 'C:/User/sasha/OneDrive - Heriot-Watt University/Code/Python/CNS CW-2/Application Development/Server_App/src/server_public.pem', '.'),
			( 'C:/User/sasha/OneDrive - Heriot-Watt University/Code/Python/CNS CW-2/Application Development/Server_App/src/Client_Private_Key.pem', '.'),
			( 'C:/User/sasha/OneDrive - Heriot-Watt University/Code/Python/CNS CW-2/Application Development/Server_App/src/Client_Certificate.cer', '.'),
			( 'C:/User/sasha/OneDrive - Heriot-Watt University/Code/Python/CNS CW-2/Application Development/Server_App/src/CA_Certificate.cer', '.')
		],
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,  
          [],
          name='gui',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None )
