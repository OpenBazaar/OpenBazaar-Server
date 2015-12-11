# -*- mode: python -*-

block_cipher = None


a = Analysis(['openbazaard.py'],
             pathex=['./OpenBazaar-Server'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None,
             excludes=None,
             win_no_prefer_redirects=None,
             win_private_assemblies=None,
             cipher=block_cipher)
a.datas += [('ob.cfg', 'ob.cfg', 'DATA')]
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='openbazaard',
          debug=True,
          strip=None,
          upx=True,
          console=True)
