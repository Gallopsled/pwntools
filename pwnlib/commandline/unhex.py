#!/usr/bin/env python2
import argparse
import sys
from string import whitespace

parser = argparse.ArgumentParser(description='''
Decodes hex-encoded data provided on the command line or via stdin.
''')
parser.add_argument('hex', nargs='*',
    help='Hex bytes to decode')

def main():
    args = parser.parse_args()
    try:
        if not args.hex:
            s = sys.stdin.read().translate(None, whitespace)
            sys.stdout.write(s.decode('hex'))
        else:
            sys.stdout.write(''.join(sys.argv[1:]).decode('hex'))
    except TypeError, e:
        sys.stderr.write(str(e) + '\n')

if __name__ == '__main__': main()
