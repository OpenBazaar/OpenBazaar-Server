#!/bin/sh

OS="${1}"

mkdir dist

case "$TRAVIS_OS_NAME" in
  "linux")

    echo "Building Linux Binaries...."

    echo "32-bit..."

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
    pyinstaller -D -F ../../.travis/openbazaard.linux32.spec

    echo "64-bit"

    mkdir dist/linux64
    cd dist/linux64

    echo "Installing APT packages"
    sudo apt-get install npm python-pip python-virtualenv python-dev libffi-dev

    echo "Set up virtualenv"
    virtualenv env
    . env/bin/activate

    echo "Install Python dependencies"
    pip install -r ../../requirements.txt
    pip install pyinstaller==3.1
    pip install cryptography
    pyinstaller -D -F ../../.travis/openbazaard.linux64.spec

    ;;

  "osx")

    ;;
esac
