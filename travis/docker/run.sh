#!/usr/bin/env bash

# We have to explicitly start the ssh service
sudo service ssh start

# Enable the IPv6 interface
echo 0 | sudo tee /proc/sys/net/ipv6/conf/all/disable_ipv6

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

PWNLIB_NOTERM=1 coverage3 run -m sphinx -b doctest docs/source docs/build/doctest $TARGET
