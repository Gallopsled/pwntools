#!/bin/sh

set -ex

# Grab prerequisites
# Valid ABIs:
# - armeabi-v7a
# - arm64-v8a
# - x86
# - x86_64
ANDROID_ABI='x86_64'
ANDROIDV=android-34
export ANDROID_AVD_HOME="$HOME/.android/avd"
mkdir -p "$ANDROID_AVD_HOME"

# Create our emulator Android Virtual Device (AVD)
# --snapshot flag is deprecated, see bitrise-steplib/steps-create-android-emulator#18
export PATH=$PATH:"$ANDROID_HOME"/cmdline-tools/latest/bin:"$ANDROID_HOME"/platform-tools:"$ANDROID_HOME"/emulator
yes | sdkmanager --sdk_root="$ANDROID_HOME" --install "system-images;$ANDROIDV;default;$ANDROID_ABI" "emulator" "platform-tools" # "platforms;$ANDROIDV"
yes | sdkmanager --sdk_root="$ANDROID_HOME" --licenses

echo no | avdmanager --verbose create avd --name android-$ANDROID_ABI --force --abi "default/$ANDROID_ABI" --package "system-images;$ANDROIDV;default;$ANDROID_ABI"
emulator -avd android-$ANDROID_ABI -no-window -no-boot-anim -read-only -no-audio -no-window -no-snapshot -gpu off -accel off -no-metrics &
adb wait-for-device
adb shell id
adb shell getprop
