#!/bin/bash

virtualenv env
. env/bin/activate
pip install --upgrade pip
pip install --ignore-installed -r requirements.txt
pip install --ignore-installed pyinstaller==3.1
pip install setuptools==19.1
env/bin/pyinstaller -F -n openbazaard-osx -i osx/tent.icns --osx-bundle-identifier=com.openbazaar.openbazaard .travis/openbazaard.mac.spec
echo 'Completed building OpenBazaar-Server binary...'

