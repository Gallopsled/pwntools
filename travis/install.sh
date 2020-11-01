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
    wget http://archive.ubuntu.com/ubuntu/pool/main/g/gdb/gdbserver_8.3-0ubuntu1_amd64.deb
    sudo apt-get install ./gdbserver_8.3-0ubuntu1_amd64.deb
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

setup_android_emulator()
{
    # If we are running on Travis CI, and there were no changes to Android
    # or ADB code, then we do not need the emulator
    if [ -n "$TRAVIS" ]; then
        if [ -z "$TRAVIS_COMMIT_RANGE" ]; then
            echo "TRAVIS_COMMIT_RANGE is empty, forcing Android Emulator installation"
        elif ! (git show "$TRAVIS_COMMIT_RANGE" >/dev/null) ; then
            echo "TRAVIS_COMMIT_RANGE is invalid, forcing Android Emulator installation"
        elif [[ "$TRAVIS_BRANCH" =~ "staging" ]]; then
            echo "TRAVIS_BRANCH ($TRAVIS_BRANCH) indicates a branch we care about"
            echo "Forcing Android Emulator installation"
        elif [[ -n "$TRAVIS_TAG" ]]; then
            echo "TRAVIS_TAG ($TRAVIS_TAG) indicates a new relase"
            echo "Forcing Android Emulator installation"
        elif (git log --stat "$TRAVIS_COMMIT_RANGE" | grep -iE "android|adb" | grep -v "commit "); then
            echo "Found Android-related commits, forcing Android Emulator installation"
        else
            # In order to avoid running the doctests that require the Android
            # emulator, while still leaving the code intact, we remove the
            # RST file that Sphinx searches.
            rm -f 'docs/source/adb.rst'
            rm -f 'docs/source/protocols/adb.rst'

            # However, the file needs to be present or else things break.
            touch 'docs/source/adb.rst'
            touch 'docs/source/protocols/adb.rst' || true

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
        if [ ! -f android-sdk/tools/bin/sdkmanager ]; then
            # Install the SDK, which gives us the 'android' and 'emulator' commands
            wget -nv -O sdk-tools-linux.zip https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip
            unzip -q sdk-tools-linux.zip
            rm    -f sdk-tools-linux.zip

            # Travis caching causes this to exist already
            rm -rf android-sdk

            mkdir android-sdk
            mv tools android-sdk/
            file android-sdk/tools/bin/sdk-manager
        fi

        export PATH="$PWD/android-sdk/tools:$PATH"
        export PATH="$PWD/android-sdk/tools/bin:$PATH"
        export PATH="$PWD/android-sdk/platform-tools:$PATH"
        export ANDROID_SDK_ROOT="$PWD/android-sdk"
        export ANDROID_HOME="$PWD/android-sdk"
        which sdkmanager
    fi

    # Grab prerequisites
    # Valid ABIs:
    # - armeabi-v7a
    # - arm64-v8a
    # - x86
    # - x86_64
    ANDROID_ABI='armeabi-v7a'
    ANDROIDV=android-24
    yes | sdkmanager --install platform-tools 'extras;android;m2repository' emulator ndk-bundle \
          "platforms;$ANDROIDV" "system-images;$ANDROIDV;default;$ANDROID_ABI" >/dev/null
    yes | sdkmanager --licenses

    # enable NDK for adb.compile()
    for d in "$PWD/android-sdk/ndk-bundle/"*/; do
        export PATH="$PATH:$d"
    done

    # Create our emulator Android Virtual Device (AVD)
    # --snapshot flag is deprecated, see bitrise-steplib/steps-create-android-emulator#18
    echo no | avdmanager --silent create avd --name android-$ANDROID_ABI --force --package "system-images;$ANDROIDV;default;$ANDROID_ABI"

    # In the future, it would be nice to be able to use snapshots.
    # However, I haven't gotten them to work nicely.
    android-sdk/emulator/emulator -avd android-$ANDROID_ABI -no-window -no-boot-anim -read-only -no-audio -no-window -no-snapshot &
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
#   setup_travis
    setup_ipv6
    setup_gdbserver
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

set +ex
