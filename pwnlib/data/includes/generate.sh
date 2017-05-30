#!/bin/sh
ARCHES="aarch64 arm i386 mips mips64 powerpc powerpc64 s390 amd64"
OSES="android cgc linux freebsd"

rm -rf $OSES

for os in $OSES; do
    mkdir -p $os
    pushd $os

    if [[ "$os" == "linux" ]]; then
        for arch in $ARCHES; do
            constgrep -c $arch -c $os > $arch.h
        done
    else
        constgrep -c $os > $os.h
        for arch in $ARCHES; do
            ln -sf $os.h $arch.h
        done
    fi

    ln -sf arm.h thumb.h
    popd
done
