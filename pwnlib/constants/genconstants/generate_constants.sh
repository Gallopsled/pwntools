#!/bin/sh
set -e
ARCHS="arm i386" # x86_64 ia64 mips mipsel parisc ppc ppc64 s390 s390x sparc sparc64 
base="../"
mkdir -p $base
for os in linux; do
    mkdir -p "$base/$os"
    for arch in $ARCHS; do
        swig -python -I$os/diet -I$os/sys -I$os/vm -includeall -E $os/$arch.h | egrep "^%constant [^_]" | ./load_constants.py $base $os $arch
    done
done
