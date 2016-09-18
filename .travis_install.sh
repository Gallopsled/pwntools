#!/usr/bin/env bash -e
set -e
local_deb_extract()
{
    wget $1
    ar vx *.deb
    tar xvf data.tar.*
    rm -f *.tar.* *deb*
}

get_binutils()
{
    BINUTILS_PREFIX='https://launchpad.net/~pwntools/+archive/ubuntu/binutils/+files/binutils-'
    BINUTILS_SUFFIX='-linux-gnu_2.22-6ubuntu1.1cross0.11pwntools12~precise_amd64.deb'
    local_deb_extract "${BINUTILS_PREFIX}${1}${BINUTILS_SUFFIX}"
}

get_qemu()
{
    echo "Installing qemu"
    QEMU_INDEX='http://packages.ubuntu.com/en/yakkety/amd64/qemu-user-static/download'
    QEMU_URL=$(curl "$QEMU_INDEX" | grep kernel.org | grep -Eo 'http.*\.deb')
    local_deb_extract "$QEMU_URL"
}

setup_travis()
{
    export PATH=$PWD/usr/bin:$PATH
    export LD_LIBRARY_PATH=$PWD/usr/lib

    # Install libbfd-multiarch and libopcodes-multiarch if not found in the cache
    if [ ! -f usr/lib/libbfd-2.22-multiarch.so ];
    then
        # Install the multiarch binutils
        local_deb_extract http://mirrors.mit.edu/ubuntu/pool/universe/b/binutils/binutils-multiarch_2.22-6ubuntu1_amd64.deb
        pushd usr/lib
        ln -sf libbfd-2.22-multiarch.so libbfd-2.22.so
        ln -sf libopcodes-2.22-multiarch.so libopcodes-2.22.so
        popd
    fi

    # Install/upgrade qemu
    if ! (which qemu-arm-static && qemu-arm-static -version | grep 2.6.1); then
        get_qemu
    fi

    # Install our custom binutils
    which arm-linux-gnu-as     || get_binutils arm
    which mips-linux-gnu-as    || get_binutils mips
    which powerpc-linux-gnu-as || get_binutils powerpc

    # Test that the installs worked
    which arm-linux-gnu-as
    which mips-linux-gnu-as
    which powerpc-linux-gnu-as
    which qemu-arm-static

    # Get rid of files we don't want cached
    rm -rf usr/share
}

setup_linux()
{
    sudo apt-get install -y software-properties-common openssh-server libncurses5-dev libncursesw5-dev
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

if [[ "$USER" == "travis" ]]; then
    setup_travis
elif [[ "$USER" == "shippable" ]]; then
    sudo apt-get update
    sudo apt-get install openssh-server gcc-multilib
    sudo /usr/sbin/sshd -f /etc/ssh/sshd_config &
    setup_travis
elif [[ "$(uname)" == "Darwin" ]]; then
    setup_osx
elif [[ "$(uname)" == "Linux" ]]; then
    setup_linux
fi

dpkg -l
