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
    sudo apt-get install -y software-properties-common openssh-server libncurses5-dev libncursesw5-dev openjdk-8-jre-headless
    sudo apt-add-repository --yes ppa:pwntools/binutils
    sudo apt-get update
    sudo apt-get install binutils-arm-linux-gnu binutils-mips-linux-gnu binutils-powerpc-linux-gnu
}

setup_android_emulator()
{
    # If we are running on Travis CI, and there were no changes to Android
    # or ADB code, then we do not need the emulator
    if [ -n "$TRAVIS" ]; then
        if [ -z "$TRAVIS_COMMIT_RANGE" ]; then
            echo "TRAVIS_COMMIT_RANGE is empty, forcing Android Emulator installation"
        elif ! git show "$TRAVIS_COMMIT_RANGE" ; then
            echo "TRAVIS_COMMIT_RANGE is invalid, forcing Android Emulator installation"
        elif (git log --stat "$TRAVIS_COMMIT_RANGE" | grep -iE "android|adb"); then
            echo "Found Android-related commits, forcing Android Emulator installation"
        else
            # In order to avoid running the doctests that require the Android
            # emulator, while still leaving the code intact, we remove the
            # RST file that Sphinx searches.
            rm -f 'docs/source/adb.rst'
            rm -f 'docs/source/protocols/adb.rst'

            # However, the file needs to be present or else things break.
            touch 'docs/source/adb.rst'
            touch 'docs/source/protocols/adb.rst'

            echo "Skipping Android emulator install, Android tests disabled."
            return
        fi
    fi


    if ! which java; then
        echo "OpenJDK-8-JRE is required for Android stuff"
        exit 1
    fi

    if (uname | grep -i Darwin &>/dev/null); then
        brew install android-sdk android-ndk
    else
        if [ ! -f android-sdk/android ]; then
            # Install the SDK, which gives us the 'android' and 'emulator' commands
            wget https://dl.google.com/android/android-sdk_r24.4.1-linux.tgz
            tar xf android-sdk_r24.4.1-linux.tgz
            rm  -f android-sdk_r24.4.1-linux.tgz

            # Travis caching causes this to exist already
            rm -rf android-sdk

            mv android-sdk-linux android-sdk
            file android-sdk/tools/android
        fi

        export PATH="$PWD/android-sdk/tools:$PATH"
        export PATH="$PWD/android-sdk/platform-tools:$PATH"
        which android

        # Install the NDK, which is required for adb.compile()
        NDK_VERSION=android-ndk-r12b
        if [ ! -f android-ndk/ndk-build ]; then
            wget   https://dl.google.com/android/repository/$NDK_VERSION-linux-x86_64.zip
            unzip -q android-ndk-*.zip
            rm -f    android-ndk-*.zip

            # Travis caching causes this to exist already
            rm -rf android-ndk

            mv     $NDK_VERSION android-ndk
        fi

        export NDK=$PWD/android-ndk
        export PATH=$NDK:$PATH
    fi

    # Grab prerequisites
    echo y | android update sdk --no-ui --all --filter platform-tools,extra-android-support
    echo y | android update sdk --no-ui --all --filter android-21

    # Valid ABIs:
    # - armeabi-v7a
    # - arm64-v8a
    # - x86
    # - x86_64
    ABI='armeabi-v7a'

    # Grab the emulator image
    echo y | android update sdk --no-ui --all --filter sys-img-$ABI-android-21

    # Create our emulator Android Virtual Device (AVD)
    echo no | android --silent create avd --name android-$ABI   --target android-21 --force --snapshot --abi $ABI

    # In the future, it would be nice to be able to use snapshots.
    # However, I haven't gotten them to work nicely.
    emulator -avd android-$ABI -no-window -no-boot-anim -no-skin -no-audio -no-window -no-snapshot &
    adb wait-for-device
    adb shell id
    adb shell getprop
}

setup_osx()
{
    brew update
    brew install binutils
    brew install capstone
}

if [[ "$USER" == "travis" ]]; then
    setup_travis
    setup_android_emulator
elif [[ "$USER" == "shippable" ]]; then
    sudo apt-get update
    sudo apt-get install openssh-server gcc-multilib
    sudo /usr/sbin/sshd -f /etc/ssh/sshd_config &
    setup_travis
elif [[ "$(uname)" == "Darwin" ]]; then
    setup_osx
elif [[ "$(uname)" == "Linux" ]]; then
    setup_linux
    setup_android_emulator
fi


dpkg -l
