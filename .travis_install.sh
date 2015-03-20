#!/usr/bin/env bash
local_deb_extract()
{
    wget $1
    ar vx *.deb
    tar xvf data.tar.gz
    rm -f *.tar.gz *deb*
}

setup_travis()
{
    local_deb_extract https://launchpad.net/~pwntools/+archive/ubuntu/binutils/+files/binutils-arm-linux-gnu_2.22-6ubuntu1.1cross0.11pwntools12~precise_amd64.deb
    local_deb_extract https://launchpad.net/~pwntools/+archive/ubuntu/binutils/+files/binutils-mips-linux-gnu_2.22-6ubuntu1.1cross0.11pwntools12~precise_amd64.deb
    local_deb_extract https://launchpad.net/~pwntools/+archive/ubuntu/binutils/+files/binutils-powerpc-linux-gnu_2.22-6ubuntu1.1cross0.11pwntools12~precise_amd64.deb
    local_deb_extract http://launchpadlibrarian.net/96008040/binutils-multiarch_2.22-6ubuntu1_amd64.deb
    export PATH=$PWD/usr/bin:$PATH
    export LD_LIBRARY_PATH=$PWD/usr/lib

    pushd usr/lib
    ln -s libbfd-2.22-multiarch.so libbfd-2.22.so
    ln -s libopcodes-2.22-multiarch.so libopcodes-2.22.so
    popd

    which arm-linux-gnu-as
    which mips-linux-gnu-as
    which powerpc-linux-gnu-as
}

setup_linux()
{
    sudo apt-get install software-properties-common pwgen
    sudo apt-add-repository --yes ppa:pwntools/binutils
    sudo apt-get update
    sudo apt-get install binutils-arm-linux-gnu binutils-mips-linux-gnu binutils-powerpc-linux-gnu
}

setup_osx()
{
    brew update
    brew install binutils
    brew install capstone
}

if [[ "$TRAVIS" ]]; then
    setup_travis
elif [[ "$(uname)" == "Darwin" ]]; then
    setup_osx
elif [[ "$(uname)" == "Linux" ]]; then
    setup_linux
fi

pip install --upgrade -e .
pip install -r docs/requirements.txt
