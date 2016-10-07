# -*- mode: python -*-

block_cipher = None


a = Analysis(['../openbazaard.py'],
             pathex=['../'],
             binaries=None,
             datas=None,
             hiddenimports=['pystun', 'zmq', 'cryptography', 'cffi', 'packaging'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
a.datas += [('../ob.cfg', 'ob.cfg', 'DATA'),('./bitcointools/english.txt','/home/travis/virtualenv/python2.7.10/lib/python2.7/site-packages/bitcointools/english.txt','DATA')]
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='openbazaard-linux64',
          debug=False,
          strip=False,
          upx=True,
          console=True )
