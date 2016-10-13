#!/bin/sh


sudo mkdir -p dist/windows64
cd dist/windows64


THIS_SCRIPT_PATH=`readlink -f $0`
THIS_SCRIPT_DIR=`dirname ${THIS_SCRIPT_PATH}`

WINE_TARBALL=${THIS_SCRIPT_DIR}/wine.tar.gz

export WINEPREFIX=`mktemp -d --suffix=_wine`
export WINEARCH="wine wineboot"

echo "Created wine environment at $WINEPREFIX"

if [ "$1" = "--update" ]; then
    echo "Update option given. Starting from existing wine.tar.gz"
    tar --directory=${WINEPREFIX} -xzf ${WINE_TARBALL}
fi

WINEPREFIX=${WINEPREFIX}

# Install Python
wget -N https://www.python.org/ftp/python/2.7.11/python-2.7.11.amd64.msi
wine msiexec /i python-2.7.11.amd64.msi /qn

# Install MSVC
wget -N https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi
wine msiexec /i VCForPython27.msi /qn
wine cmd /c "c:\\Program Files (x86)\\Common Files\\Microsoft\\Visual C++ for Python\\9.0\\vcvarsall.bat" amd64

wine cmd /c "copy c:\\Windows\\System32\\msvcr90.dll ."
wine cmd /c "copy c:\\Windows\\System32\\msvcr120.dll c:\\python27"
wine cmd /c "copy c:\\Windows\\System32\\msvcp90.dll c:\\python27"
wine cmd /c "copy c:\\Windows\\System32\\msvcm90.dll c:\\python27"

# Install pip
wget -N https://bootstrap.pypa.io/get-pip.py 
wine c:/Python27/python.exe get-pip.py

wget -N http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20218/pywin32-218.win-amd64-py2.7.exe?r=&ts=1475526189&use_mirror=pilotfiber -O pywin32.exe
wine pywin32.exe /s

# Fix TLS Certs issue
wine c:/Python27/python -m pip install pyopenssl ndg-httpsclient pyasn1 

# Set up Virtualenv
#wine c:/Python27/python -m pip install virtualenv      
#wine c:/Python27/Scripts/virtualenv env
#wine c:/Python27/Scripts/activate.bat

wine c:/Python27/python -m pip install vcversioner
wine c:/Python27/python -m pip install https://openbazaar.org/downloads/miniupnpc-1.9-cp27-none-win_amd64.whl
wine c:/Python27/python -m pip install https://openbazaar.org/downloads/PyNaCl-0.3.0-cp27-none-win_amd64.whl
wine c:/Python27/python -m pip install https://openbazaar.org/downloads/Twisted-16.4.1-cp27m-win_amd64.whl
wine c:/Python27/python -m pip install -r ../../requirements.txt

wine c:/Python27/python -m pip install pyinstaller==3.1
wine c:/Python27/python -m pip install setuptools==19.2
wine c:/Python27/python -m pip install pystun
wine c:/Python27/python -m pip install https://pypi.python.org/packages/a1/0c/f2029939f3ed0ebdfcd68451ffb5433d9b6268632cf9874a3edbff101008/pyzmq-15.3.0+fix-cp27-cp27m-win_amd64.whl#md5=708b0bb576b8827c4f31a5377a653be5

wine cmd /c "copy c:\\Windows\\System32\\msvcm90.dll c:\\python27"
wine cmd /c "copy c:\\Windows\\System32\\msvcm90.dll c:\\python27"

wget -N https://github.com/pyinstaller/pyinstaller/releases/download/v3.1/PyInstaller-3.1.zip
unzip -o PyInstaller-3.1.zip
cd ../..
wine C:/Python27/python.exe dist/windows64/PyInstaller-3.1/pyinstaller.py -F -n openbazaard-windows64.exe -i images/icon.ico .travis/openbazaard.win64.spec --noconfirm

