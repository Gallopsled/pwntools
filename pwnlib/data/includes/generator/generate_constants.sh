#!/bin/bash
set -e

grep -hEo '__NR_\w*' linux/diet/*/syscalls.h | sed 's/__NR\(.*\)/#define SYS\1 __NR\1/' |LC_ALL=C sort -dfu - linux/syscall_map.h >linux/syscall_map.h.new
mv linux/syscall_map.h.new linux/syscall_map.h

pushd linux
ARCHS="$(ls *.h | sed 's/.h$//' | grep -v -e common -e syscall_map)"
popd

python="../../../constants"
headers="../"

rm -rf "$headers/linux" "$headers/freebsd.h"
mkdir -p "$headers/linux"
find "$python" -type f \( -name '*.py' -o -name '*.pyc' \) -not -name "__init__.py"  -not -name 'constant.py' -delete
find "$python" -type d -empty -delete

for arch in $ARCHS; do
  echo $arch
  swig -python -E -cpperraswarn -Ilinux -Ilinux -Ilinux/diet -Ilinux/diet/$arch -includeall linux/$arch.h | egrep "^%constant" | ./load_constants.py $python/linux/$arch.py $headers/linux/$arch.h
done

swig -python -E -Ifreebsd -includeall freebsd/common.h | egrep "^%constant" | ./load_constants.py $python/freebsd.py $headers/freebsd.h
