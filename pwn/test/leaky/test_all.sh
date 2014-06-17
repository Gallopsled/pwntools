#!/bin/bash

make

for file in l_*; do
    class=$(readelf -h ${file} | grep Class: | awk '{print $2}')
    load_address=$(printf "%d\n" $(readelf -l ${file} | grep LOAD | head -n 1 | awk '{print $3}'))
    if test ${load_address} -gt 0; then
        pie='PIE'
    else
        pie='not PIE'
    fi

    if readelf -l ${file} | grep .gnu.hash >/dev/null; then
        hashing="gnu"
    else
        hashing="sysv"
    fi
    echo -e "\n\n\n${file} uses ${hashing} hashing, is ${pie} and is a ${class} elf."

    LD_LIBRARY_PATH=. ./${file} 9999 &
    child=$!
    sleep .5

    ./resolve.py ${file} 9999

    kill ${child}
    sleep .5
done
