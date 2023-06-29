#!/bin/sh

set -ex

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
    wget -nv -O sdk-tools-linux.zip https://dl.google.com/android/repository/commandlinetools-linux-6858069_latest.zip
    unzip -q sdk-tools-linux.zip
    rm    -f sdk-tools-linux.zip

    # Travis caching causes this to exist already
    rm -rf android-sdk

    mkdir android-sdk
    mv cmdline-tools android-sdk/
    file android-sdk/cmdline-tools/bin/sdkmanager
fi

export PATH="$PWD/android-sdk/cmdline-tools:$PATH"
export PATH="$PWD/android-sdk/cmdline-tools/bin:$PATH"
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
yes | sdkmanager --sdk_root="$ANDROID_HOME" --install platform-tools 'extras;android;m2repository' emulator ndk-bundle \
  "platforms;$ANDROIDV" "system-images;$ANDROIDV;default;$ANDROID_ABI"
yes | sdkmanager --sdk_root="$ANDROID_HOME" --licenses

# enable NDK for adb.compile()
for d in "$PWD/android-sdk/ndk-bundle/"*/; do
export PATH="$PATH:$d"
done

# Create our emulator Android Virtual Device (AVD)
# --snapshot flag is deprecated, see bitrise-steplib/steps-create-android-emulator#18
echo no | avdmanager --silent create avd --name android-$ANDROID_ABI --force --package "system-images;$ANDROIDV;default;$ANDROID_ABI"

# The emulator is crazy and does not even respect its own paths
sed -i "s@=android-sdk@=$PWD/android-sdk@" ~/.android/avd/android-$ANDROID_ABI.avd/config.ini

# In the future, it would be nice to be able to use snapshots.
# However, I haven't gotten them to work nicely.
android-sdk/emulator/emulator -avd android-$ANDROID_ABI -no-window -no-boot-anim -read-only -no-audio -no-window -no-snapshot &
adb wait-for-device
adb shell id
adb shell getprop
