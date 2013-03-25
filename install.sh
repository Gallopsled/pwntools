#!/bin/bash

if [ $UID -ne 0 ] || [ -z "$SUDO_USER" ] ; then
    echo "This script must be run with sudo" 1>&2
    exit
fi

# at this point we're running through sudo
# commands that should run as the user must be prefixed with $DO
DO="sudo -u \"$SUDO_USER\""

echo "Adding PWNTools to \$PATH in .bashrc"
echo "export PATH=$PWD/bin:\$PATH" >> $(getent passwd $SUDO_USER | cut -d: -f6)/.bashrc


echo "Adding PWNLib to \$PYTHONPATH in .bashrc"
echo "export PYTHONPATH=$PWD/lib:\$PYTHONPATH" >> $(getent passwd $SUDO_USER | cut -d: -f6)/.bashrc

echo "Installing packages"
if [ -f /etc/debian_version ]; then
    DEPS="python-crypto python-paramiko python-sqlalchemy libdistorm64-dev python-gmpy python-imaging python-sympy"
    yes | sudo apt-get install ${DEPS}
elif [ -f /etc/arch-release ]; then
    DEPS="python2-crypto python2-paramiko python2-sqlalchemy python2-imaging 
python2-sympy"
    yes | sudo pacman -S ${DEPS}
fi
echo "All DONE"
