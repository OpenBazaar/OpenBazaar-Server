#!/bin/sh

OS="${1}"

mkdir dist

case "$TRAVIS_OS_NAME" in
  "linux")

    echo "Building Linux Binaries...."

    mkdir dist/linux32
    cd dist/linux32

    echo "Installing APT packages"
    sudo apt-get install npm python-pip python-virtualenv python-dev libffi-dev

    echo "Set up virtualenv"
    virtualenv env
    . env/bin/activate

    echo "Install Python dependencies"
    pip install -r requirements.txt
    pip install pyinstaller==3.1
    pip install cryptography
    pyinstaller -D -F -n openbazaard-linux32

    ;;

  "osx")

    ;;
esac
