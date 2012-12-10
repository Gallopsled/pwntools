#!/usr/bin/env python
import pwn
from pwn import log

def garbage(size):
    vocab1 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    vocab2 = 'abcdefghijklmnopqrstuvwxyz'
    vocab3 = '0123456789'

    current = 0
    result = ''
    while current < size:
        for v1 in vocab1:
            for v2 in vocab2:
                for v3 in vocab3:
                    if current<size:
                        result += v1
                        current += 1
                    if current<size:
                        result += v2
                        current += 1
                    if current<size:
                        result += v3
                        current += 1

    log.info("Generated cyclic pattern, size: %d" % current)
    return result



if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Usage: %s <size>\n       [(-o|--offset)]" % sys.argv[0])
    parser.add_argument('-o','--offset', action='store_true', dest='offset', required=False)
    parser.add_argument('size', action='store', type=int)

    results = parser.parse_args()

    size = results.size
    calc_offset = results.offset
    if calc_offset:
        print "should calculate offset"
    else:
        print garbage(size)
