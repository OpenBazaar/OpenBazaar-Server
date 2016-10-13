#!/bin/sh

sudo dpkg --add-architecture i386
sudo apt-get update -qq
sudo apt-get install -qq wine1.6

sudo mkdir -p dist/windows32
cd dist/windows32
#wget -O python.msi "http://www.python.org/ftp/python/2.7.12/python-2.7.12.msi"
#wget -O pywin32.exe "http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20220/pywin32-220.win32-py2.7.exe?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fpywin32%2Ffiles%2Fpywin32%2FBuild%2520220%2F&ts=1473864354&use_mirror=superb-sea2"

THIS_SCRIPT_PATH=`readlink -f $0`
THIS_SCRIPT_DIR=`dirname ${THIS_SCRIPT_PATH}`

WINE_TARBALL=${THIS_SCRIPT_DIR}/wine.tar.gz

export WINEPREFIX=`mktemp -d --suffix=_wine`
export WINEARCH="win32 wine wineboot"

echo "Created wine environment at $WINEPREFIX"

if [ "$1" = "--update" ]; then
    echo "Update option given. Starting from existing wine.tar.gz"
    tar --directory=${WINEPREFIX} -xzf ${WINE_TARBALL}
fi

WINEPREFIX=${WINEPREFIX}

# Install Python
wget -N http://python.org/ftp/python/2.7.11/python-2.7.11.msi
wine msiexec /i python-2.7.11.msi /qn 

# Install MSVC
wget -N https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi
wine msiexec /i VCForPython27.msi /qn
wine cmd /c "c:\\Program Files (x86)\\Common Files\\Microsoft\\Visual C++ for Python\\9.0\\vcvarsall.bat" x86

#wget -N https://download.microsoft.com/download/1/1/1/1116b75a-9ec3-481a-a3c8-1777b5381140/vcredist_x86.exe
#wine vcredist_x86.exe /qn

#wine cmd /c "copy c:\\Windows\\System32\\msvcr120.dll c:\\python27"
wine cmd /c "copy c:\\Windows\\System32\\msvcp90.dll c:\\python27"
wine cmd /c "copy c:\\Windows\\System32\\msvcm90.dll c:\\python27"

# Install pip

wget -N https://bootstrap.pypa.io/get-pip.py 
wine c:/Python27/python.exe get-pip.py

wget -N http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20218/pywin32-218.win32-py2.7.exe?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fpywin32%2Ffiles%2Fpywin32%2FBuild%2520218%2F&ts=1475598942&use_mirror=heanet -O pywin32.exe
wine pywin32.exe /s

# Fix TLS Certs issue
wine c:/Python27/python -m pip install pyopenssl ndg-httpsclient pyasn1 

# Set up Virtualenv
wine c:/Python27/python -m pip install virtualenv      
wine c:/Python27/Scripts/virtualenv env
wine c:/Python27/Scripts/activate.bat

wine c:/Python27/python -m pip install vcversioner
wine c:/Python27/python -m pip install https://openbazaar.org/downloads/miniupnpc-1.9-cp27-none-win32.whl
wine c:/Python27/python -m pip install https://openbazaar.org/downloads/PyNaCl-0.3.0-cp27-none-win32.whl
wine c:/Python27/python -m pip install https://openbazaar.org/downloads/Twisted-16.4.1-cp27-cp27m-win32.whl
#wine c:/Python27/python -m pip install https://openbazaar.org/downloads/Twisted-16.4.1-cp27m-win_amd64.whl
#wine c:/Python27/python -m pip install pefile
wine c:/Python27/python -m pip install -r ../../requirements.txt

wine c:/Python27/python -m pip install pyinstaller==3.1
wine c:/Python27/python -m pip install setuptools==19.2
wine c:/Python27/python -m pip install pystun
wine c:/Python27/python -m pip install https://pypi.python.org/packages/7a/ec/47559abcfd6328c802036e8cf00a73885b5a71b4228e7f2dfb51f3ab2d69/pyzmq-15.3.0+fix-cp27-cp27m-win32.whl#md5=fdaa98a1dd2d201cb86229ad59baac17

wget -N https://github.com/pyinstaller/pyinstaller/releases/download/v3.1/PyInstaller-3.1.zip
unzip -o PyInstaller-3.1.zip
cd ../..
wine C:/Python27/python.exe dist/windows32/PyInstaller-3.1/pyinstaller.py -F -n openbazaard-windows32.exe -i images/icon.ico .travis/openbazaard.win.spec --noconfirm --log-level=DEBUG


