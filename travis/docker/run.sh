#!/usr/bin/env bash
sudo service ssh start

case "$ANDROID" in
    [Yy]* )
        emulator64-arm -avd android-armeabi-v7a -no-window -no-boot-anim -no-skin -no-audio -no-window -no-snapshot &
        adb wait-for-device
        adb shell getprop ro.build.fingerprint
        ;;
    [Nn]* )
        echo "===========================================" >&2
        echo "  WARNING: Disabling all Android tests !!! " >&2
        echo "===========================================" >&2

        echo > 'docs/source/adb.rst'
        echo > 'docs/source/protocols/adb.rst'
        ;;
esac

PWNLIB_NOTERM=1 coverage run -m sphinx -b doctest docs/source docs/build/doctest $TARGET
