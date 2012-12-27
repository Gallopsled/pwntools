#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run with sudo" 1>&2
   exit 1
fi

echo "Adding PWNTools to \$PATH in .profile"
echo "PATH=$PWD/bin:\$PATH" >> ~/.profile

echo "Adding PWNLib to \$PYTHONPATH in .profile"
echo "PYTHONPATH=$PWD/lib:\$PYTHONPATH" >> ~/.profile

echo "Installing packages"
DEPS="python-crypto python-paramiko"
yes | sudo apt-get install ${DEPS}

echo "All DONE"