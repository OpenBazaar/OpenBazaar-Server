#!/bin/bash

sudo bash build-linux64.sh
sudo docker run -i -v "${PWD}:/OpenBazaar" toopher/ubuntu-i386:14.04 /bin/bash -c "linux32 --32bit i386 /OpenBazaar/build-linux32.sh"
sudo bash build-win.sh
sudo bash build-win64.sh
sudo chmod 777 dist/openbazaard-linux32
sudo chmod a+x dist/openbazaard-linux32
sudo chmod 777 dist/openbazaard-linux64
sudo chmod a+x dist/openbazaard-linux64
sudo chmod 777 dist/openbazaard-windows64.exe
sudo chmod 777 dist/openbazaard-windows32.exe
