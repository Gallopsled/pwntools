#!/usr/bin/env python
import pwn
from pwn import log, p32
from pwn import de_bruijn, de_bruijn_find


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Cyclic pattern creator/finder.")
    parser.add_argument('-o','--offset', action='store_true', dest='offset', required=False, help="Toggle to return the offset of the specified pattern (in 0xYYYYYYYY hex form).")
    parser.add_argument('size', action='store', help="The desired size of the created pattern.")

    results = parser.parse_args()

    size = results.size
    calc_offset = results.offset
    if calc_offset:
        try:
            number = p32(int(size, 16))
            print "Pattern '%s'(%s) was found at offset:  %d" % (number, size, de_bruijn_find(number))
        except:
            print "Couldn't read input value.  Must be an integer, preferably on the form 0xyyyyyyyy)"
    else:
        print de_bruijn(int(size))
