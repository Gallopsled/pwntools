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
DEPS="python-crypto python-paramiko python-sqlalchemy libdistorm64-dev"
yes | sudo apt-get install ${DEPS}

echo "All DONE"
