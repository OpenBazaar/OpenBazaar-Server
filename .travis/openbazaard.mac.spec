# -*- mode: python -*-

block_cipher = None


a = Analysis(['./OpenBazaar-Server/openbazaard.py'],
             pathex=['./OpenBazaar-Server'],
             binaries=None,
             datas=None,
             hiddenimports=['zmq', 'cryptography', 'cffi', 'packaging'],
             hookspath=None,
             runtime_hooks=None,
             excludes=None,
             win_no_prefer_redirects=None,
             win_private_assemblies=None,
             cipher=block_cipher)
a.datas += [('ob.cfg', 'ob.cfg', 'DATA'),('bitcointools/english.txt','env/lib/python2.7/site-packages/bitcointools/english.txt','DATA')]
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='openbazaard-osx',
          debug=True,
          strip=None,
          upx=True,
          console=True)
