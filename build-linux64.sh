#!/bin/bash

virtualenv virt64
source virt64/bin/activate
pip install -r requirements.txt
pip install -q pyinstaller==3.1
pip install -q setuptools==19.2
pip install -q cryptography
pyinstaller -D -F .travis/openbazaard.linux64.spec
