#!/bin/bash

OS="${1}"

mkdir dist


# case "$TRAVIS_OS_NAME" in
#   "linux")

   
    cd OpenBazaar/

    echo "Building Linux Binaries...."
    sudo apt-get -qq update
    sudo apt-get install -qq -y wget
    
    echo "32-bit..."
    
    wget -q https://www.python.org/ftp/python/2.7.10/Python-2.7.10.tgz 
    tar xzf Python-2.7.10.tgz
    sudo apt-get -qq -y install gcc-multilib g++-multilib
    CFLAGS=-m32 LDFLAGS=-m32 ./configure --prefix=/opt/Python2.7-32bits
    make
    make install

    echo "Installing APT packages"
    sudo apt-get -y -qq install npm python-pip python-virtualenv python-dev libffi-dev

    echo "Set up virtualenv"
    virtualenv virt 
    . virt/bin/activate
    
    echo "Install Python dependencies"
    virt/bin/pip install -q -r requirements.txt
    virt/bin/pip install -q pyinstaller==3.1
    virt/bin/pip install -q cryptography
    virt/bin/pip install -q setuptools==19.2
    virt/bin/pyinstaller -D -F .travis/openbazaard.linux32.spec

    
#     ;;
#
#   "osx")
#
#     ;;
# esac
