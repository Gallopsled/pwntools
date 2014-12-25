#!/usr/bin/env bash

setup_linux()
{
    sudo apt-get update
    sudo apt-get install software-properties-common pwgen
    sudo apt-add-repository --yes ppa:pwntools/binutils
    sudo apt-get update
    sudo apt-get install binutils-arm-linux-gnu binutils-mips-linux-gnu binutils-powerpc-linux-gnu
    wget -nc http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_amd64.deb
    (echo "a30bcb58fd82d32b135eec978eaa22230c44e722 *capstone-2.1.2_amd64.deb" | sha1sum -c) || exit
    sudo dpkg -i *.deb
}

setup_osx()
{
    brew update
    brew install binutils
    brew install capstone
}

case $(uname) in
Darwin) setup_osx   ;;
Linux)  setup_linux ;;
esac

pip install -r requirements.txt
pip install -r docs/requirements.txt
pip install .


#
# Install a demo user for SSH purposes
#
U=demouser
H=/home/$U

sudo useradd -m $U
ssh-keygen -t rsa -f /tmp/$U -N ''

eval $(ssh-agent -s)
ssh-add    /tmp/$U

sudo -u $U mkdir $H/.ssh
sudo -u $U cp    /tmp/$U.pub $H/.ssh/authorized_keys
sudo chmod -R 700 $H

(echo -n "$U:"; pwgen 100 1) | sudo chpasswd
