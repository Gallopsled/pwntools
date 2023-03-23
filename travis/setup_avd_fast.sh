#!/bin/sh

set -ex

# Grab prerequisites
# Valid ABIs:
# - armeabi-v7a
# - arm64-v8a
# - x86
# - x86_64
ANDROID_ABI='armeabi-v7a'
ANDROIDV=android-24

# Create our emulator Android Virtual Device (AVD)
# --snapshot flag is deprecated, see bitrise-steplib/steps-create-android-emulator#18
export PATH=$PATH:"$ANDROID_HOME"/cmdline-tools/latest/bin:"$ANDROID_HOME"/platform-tools
yes | sdkmanager --sdk_root="$ANDROID_HOME" --install "system-images;$ANDROIDV;default;$ANDROID_ABI"
yes | sdkmanager --sdk_root="$ANDROID_HOME" --licenses
echo no | avdmanager --silent create avd --name android-$ANDROID_ABI --force --package "system-images;$ANDROIDV;default;$ANDROID_ABI"

"$ANDROID_HOME"/emulator/emulator -avd android-$ANDROID_ABI -no-window -no-boot-anim -read-only -no-audio -no-window -no-snapshot &
adb wait-for-device
adb shell id
adb shell getprop
