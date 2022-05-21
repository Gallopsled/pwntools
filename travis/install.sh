#!/usr/bin/env bash -e
set -ex

local_deb_extract()
{
    wget $1
    ar vx *.deb
    tar xvf data.tar.*
    rm -f *.tar.* *deb*
}

install_deb()
{
    version=${2:-bionic}
    package=$1
    echo "Installing $package"
    INDEX="http://packages.ubuntu.com/en/$version/amd64/$package/download"
    URL=$(curl -L "$INDEX" | grep -Eo "https?://.*$package.*\.deb" | head -1)
    local_deb_extract "$URL"
}

setup_travis()
{
    export PATH=$PWD/usr/bin:$PATH
    export LD_LIBRARY_PATH=$PWD/usr/lib:$LD_LIBRARY_PATH
    export LD_LIBRARY_PATH=$PWD/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

    # Install a more modern binutils, which is required for some of the tests
    [[ -f usr/bin/objcopy ]] || install_deb binutils

    # Install/upgrade qemu
    [[ -f usr/bin/qemu-arm-static ]] || install_deb qemu-user-static xenial

    # Install cross-binutils
    [[ -f usr/bin/x86_64-linux-gnu-ar ]]    || install_deb binutils-multiarch
    [[ -f usr/bin/aarch64-linux-gnu-as ]]   || install_deb binutils-aarch64-linux-gnu
    [[ -f usr/bin/arm-linux-gnueabihf-as ]] || install_deb binutils-arm-linux-gnueabihf
    [[ -f usr/bin/mips-linux-gnu-as ]]      || install_deb binutils-mips-linux-gnu
    [[ -f usr/bin/powerpc-linux-gnu-as ]]   || install_deb binutils-powerpc-linux-gnu

    # Test that the installs worked
    as                      --version
    x86_64-linux-gnu-ar     --version
    aarch64-linux-gnu-as    --version
    arm-linux-gnueabihf-as  --version
    mips-linux-gnu-as       --version
    powerpc-linux-gnu-as    --version
    qemu-arm-static         --version

    mips-linux-gnu-ld       --version

    # Force-install capstone because it's broken somehow
    [[ -f usr/lib/libcapstone.so.3 ]] || install_deb libcapstone3

    # Install a newer copy of GDB
    if [[ ! -f usr/bin/gdb ]]; then
        git clone --depth=1 https://github.com/zachriggle/pwntools-gdb-travis-ci.git
        tar xf pwntools-gdb-travis-ci/gdb.tar.xz
        which gdb
        usr/bin/gdb --version
    fi

    # Get rid of files we don't want cached
    rm -rf usr/share
}

setup_ipv6()
{
    echo 0 | sudo tee /proc/sys/net/ipv6/conf/all/disable_ipv6
}

setup_gdbserver()
{
    # https://docs.improbable.io/reference/14.3/shared/debug-cloud-workers#common-issues
    # wget http://archive.ubuntu.com/ubuntu/pool/main/g/gdb/gdbserver_8.3-0ubuntu1_amd64.deb
    if [[ "$(gdbserver --version|grep -Eo '[0-9]+\.[0-9]' |head -1 |cut -d. -f1)" -gt 8 ]]; then
        return
    fi
    wget https://launchpad.net/ubuntu/+source/gdb/8.3-0ubuntu1/+build/16807407/+files/gdbserver_8.3-0ubuntu1_amd64.deb
    sudo apt-get install ./gdbserver_8.3-0ubuntu1_amd64.deb
}

# Contents borrowed from Pwndbg setup.sh
setup_rpyc()
{
    # Find the Python version used by GDB.
    PYVER=$(gdb -batch -q --nx -ex 'pi import platform; print(".".join(platform.python_version_tuple()[:2]))')
    PYTHON+=$(gdb -batch -q --nx -ex 'pi import sys; print(sys.executable)')
    PYTHON+="${PYVER}"

    # Install rpyc
    ${PYTHON} -m pip install --user --upgrade rpyc
}

setup_linux()
{
    sudo apt-get install -y software-properties-common openssh-server libncurses5-dev libncursesw5-dev openjdk-8-jre-headless
    RELEASE="$(lsb_release -sr)"
    if [[ "$RELEASE" < "16.04" ]]; then
        sudo apt-add-repository --yes ppa:pwntools/binutils
        sudo apt-get update
        sudo apt-get install -y binutils-arm-linux-gnu binutils-mips-linux-gnu binutils-powerpc-linux-gnu
    else
        sudo apt-get install -y binutils-arm-linux-gnueabihf binutils-mips-linux-gnu binutils-powerpc-linux-gnu
    fi
}

setup_osx()
{
    brew update
    brew install binutils
    brew install capstone
}

if [[ "$USER" == "travis" ]]; then
#   setup_travis
    setup_ipv6
    setup_gdbserver
    setup_rpyc
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

set +ex
