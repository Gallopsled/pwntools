#!/bin/bash

# This script was used to generate the binaries in this folder
# Its mostly untested and probably assumes stuff about the system it runs on
#
# USE WITH CAUTION

if [ -z "$1" ]; then
  echo "Usage: $0 target"
  exit 0
fi

TARGET="$1"

export CFLAGS="-m32 -Os -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -fdata-sections -Wl,--gc-sections -Wno-error=unused-but-set-variable -Wno-error=format-security"
export MAKEFLAGS='-j 4'
cd ~/src; rm -rf binutils-"$TARGET"-build; mkdir binutils-"$TARGET"-build; cd binutils-"$TARGET"-build/
time { ../binutils-2.22/configure --disable-libquadmath  --disable-libquadmath-support --disable-nls --enable-no_exceptions --enable-no_rtti  --disable-ppl-version-check --disable-cloog-version-check  --disable-foo --without-fp --disable-intl --disable-gprof --disable-ld --target="$TARGET"-linux; make; make; } || exit 1
for f in gas/as-new binutils/objdump binutils/objcopy; do
  strip -s --strip-all --remove-section=.comment --remove-section=.note $f
  upx -qqq --best --ultra-brute $f
  du -hs $f
done
