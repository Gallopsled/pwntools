#!/usr/bin/env python2
import argparse
import sys

parser = argparse.ArgumentParser(description='''
Hex-encodes data provided on the command line or via stdin.
''')
parser.add_argument('data', nargs='*',
    help='Data to convert into hex')

def main():
    args = parser.parse_args()
    if not args.data:
        print sys.stdin.read().encode('hex')
    else:
        print ' '.join(args.data).encode('hex')

if __name__ == '__main__': main()
