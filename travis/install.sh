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
    setup_ipv6
    setup_gdbserver
    setup_android_emulator
elif [[ "$(uname)" == "Darwin" ]]; then
    setup_osx
elif [[ "$(uname)" == "Linux" ]]; then
    setup_linux
    setup_android_emulator
fi

set +ex
