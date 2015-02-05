#!/usr/bin/env bash

setup_linux()
{
    sudo apt-get install software-properties-common pwgen
    sudo apt-add-repository --yes ppa:pwntools/binutils
    sudo apt-get update
    sudo apt-get install binutils-arm-linux-gnu binutils-mips-linux-gnu binutils-powerpc-linux-gnu
    wget -nc https://github.com/Gallopsled/pwntools-dependencies/raw/master/capstone-2.1.2_amd64.deb
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

# We want to avoid isntalling Capstone 3.0.1 as it
# incurs a big penalty to Travis CI build speeds by
# building libcapstone.so on-the-fly.
#
# To avoid this, we should pre-install capstone==2.1
pip install capstone==2.1

pip install -r requirements.txt
pip install -r docs/requirements.txt
pip install -e .
