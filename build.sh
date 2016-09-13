#!/bin/sh

OS="${1}"

mkdir dist

case "$TRAVIS_OS_NAME" in
  "linux")

    echo "Building Linux Binaries...."

    echo "32-bit..."

    wget https://www.python.org/ftp/python/2.7.11/Python-2.7.11.tgz
    tar xzvf Python-2.7.11.tgz
    sudo apt-get install gcc-multilib g++-multilib
    CFLAGS=-m32 LDFLAGS=-m32 ./configure --prefix=/opt/Python2.7-32bits
    make
    sudo make install

    mkdir dist/linux32
    cd dist/linux32

    echo "Installing APT packages"
    sudo apt-get install npm python-pip python-virtualenv python-dev libffi-dev

    echo "Set up virtualenv"
    virtualenv env
    . env/bin/activate

    echo "Install Python dependencies"
    pip install -r ../../requirements.txt
    pip install pyinstaller==3.1
    pip install cryptography
    pip install setuptools==19.2
    cd ../..
    pyinstaller -D -F ./.travis/openbazaard.linux32.spec

    # echo "64-bit"
    #
    # mkdir dist/linux64
    # cd dist/linux64
    #
    # echo "Set up virtualenv"
    # virtualenv env
    # . env/bin/activate
    #
    # echo "Install Python dependencies"
    # pyinstaller -D -F ../../.travis/openbazaard.linux64.spec

    ;;

  "osx")

    ;;
esac
