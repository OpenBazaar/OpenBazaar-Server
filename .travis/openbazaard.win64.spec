# -*- mode: python -*-

block_cipher = None


a = Analysis(['..\\openbazaard.py'],
             pathex=['..\\'],
             binaries=None,
             datas=None,
             hiddenimports=['cryptography', 'bitcoin','zmq.backend.cython' ,'zmq.backend.cffi'],
             hookspath=None,
             runtime_hooks=None,
             excludes=None,
             win_no_prefer_redirects=None,
             win_private_assemblies=None,
             cipher=block_cipher)
a.binaries += [('ssleay32.dll', 'windows\\64\\ssleay32.dll', 'BINARY'),
('libeay32.dll', 'windows\\64\\libeay32.dll', 'BINARY')]
a.datas += [
('ob.cfg', 'ob.cfg', 'DATA'),
('bitcointools\\english.txt', 'windows\\english.txt', 'DATA'),
#('msvcr120.dll', 'c:\\Python27\\msvcr120.dll', 'DATA'),
('msvcr90.dll', 'c:\\Python27\\msvcr90.dll', 'DATA'),
('msvcp90.dll', 'c:\\Python27\\msvcp90.dll', 'DATA')
]
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
a.zipfiles,
a.datas,
          name='openbazaard-windows64',
          icon='windows\\icon.ico',
          debug=False,
          strip=False,
          upx=True,
          console=True )
