#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run with sudo" 1>&2
   exit 1
fi

echo "Adding PWNTools to \$PATH in .bashrc"
echo "export PATH=$PWD/bin:\$PATH" >> $(getent passwd $SUDO_USER | cut -d: -f6)/.bashrc


echo "Adding PWNLib to \$PYTHONPATH in .bashrc"
echo "export PYTHONPATH=$PWD/lib:\$PYTHONPATH" >> $(getent passwd $SUDO_USER | cut -d: -f6)/.bashrc

echo "Installing packages"
if [ -f /etc/debian_version ]; then
    DEPS="python-crypto python-paramiko python-sqlalchemy libdistorm64-dev python-gmpy"
    yes | sudo apt-get install ${DEPS}
elif [ -f /etc/arch-release ]; then
    DEPS="python2-crypto python2-paramiko python2-sqlalchemy"
    yes | sudo pacman -S ${DEPS}
fi
echo "All DONE"
