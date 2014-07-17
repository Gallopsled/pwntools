#!/bin/bash
set -e
pushd linux
ARCHS="$(ls *.h | sed 's/.h$//' | grep -v -e common -e syscall_map)"
popd

python="../../../pwnlib/constants"
headers="../"

rm -rf "$python/linux" "$headers/linux"
mkdir -p "$headers/linux" "$python/linux" "$headers/linux"

for arch in $ARCHS; do
  echo $arch
  swig -Ilinux -Ilinux/diet -includeall -E linux/$arch.h | egrep "^%constant" | ./load_constants.py $python/linux/$arch.py $headers/linux/$arch.h
done

swig -Ifreebsd -includeall -E freebsd/common.h | egrep "^%constant" | ./load_constants.py $python/freebsd.py $headers/freebsd.h
