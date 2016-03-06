#!/usr/bin/env python2

import argparse
import os
import re

import pwnlib.log
from pwnlib import asm
from pwnlib import constants
from pwnlib.context import context
from pwnlib.util import safeeval

pwnlib.log.install_default_handler()

p = argparse.ArgumentParser(
    description = "Looking up constants from header files.\n\nExample: constgrep -c freebsd -m  ^PROT_ '3 + 4'",
    formatter_class = argparse.RawDescriptionHelpFormatter,
)

group = p.add_mutually_exclusive_group()
group.add_argument(
    '-e', '--exact',
    metavar = '<constant name>',
    # nargs = 1,
    default = None,
    help = 'Do an exact match for a constant instead of searching for a regex',
)
group.add_argument(
    'regex',
    nargs = '?',
    default = '',
    help = 'The regex matching constant you want to find',
)

p.add_argument(
    'constant',
    nargs = '?',
    default = None,
    help = 'The constant to find',
)

p.add_argument(
    '-i', '--case-insensitive',
    action = 'store_true',
    help = 'Search case insensitive',
)

p.add_argument(
    '-m', '--mask-mode',
    action = 'store_true',
    help = 'Instead of searching for a specific constant value, search for values not containing strictly less bits that the given value.',
)

p.add_argument(
    '-c', '--context',
    metavar = '<opt>',
    choices = context.oses + list(context.architectures),
    default = ['i386','linux'],
    action = 'append',
    help = 'The os/architecture to find constants for (default: linux/i386), choose from: %s' % \
    ', '.join(sorted(context.oses + context.architectures.keys()))
)

def main():
    args = p.parse_args()

    # Find the architecture and os from the list of contexts
    for arch in args.context[::-1]:
        if arch in context.architectures: break
    for os in args.context[::-1]:
        if os in context.oses: break

    if args.exact:
        # This is the simple case
        print asm.cpp(args.exact, os = os, arch = arch).strip()
    else:
        # New we search in the right module.
        # But first: We find the right module
        if os == 'freebsd':
            mod = constants.freebsd
        else:
            mod = getattr(getattr(constants, os), arch)

        # Compile the given regex, for optimized lookup
        if args.case_insensitive:
            matcher = re.compile(args.regex, re.IGNORECASE)
        else:
            matcher = re.compile(args.regex)

        # Evaluate the given constant
        if args.constant:
            constant = safeeval.expr(args.constant)
        else:
            constant = None

        # The found matching constants and the length of the longest string
        out    = []
        maxlen = 0

        for k in dir(mod):
            # No python stuff
            if k.endswith('__') and k.startswith('__'):
                continue

            # Run the regex
            if not matcher.search(k):
                continue

            # Check the constant
            if constant != None:
                val = getattr(mod, k)
                if args.mask_mode:
                    if constant & val != val:
                        continue
                else:
                    if constant != val:
                        continue

            # Append it
            out.append((getattr(mod, k), k))
            maxlen = max(len(k), maxlen)

        # Output all matching constants
        for _, k in sorted(out):
            print '#define %s %s' % (k.ljust(maxlen), asm.cpp(k, os = os, arch = arch).strip())

        # If we are in match_mode, then try to find a combination of
        # constants that yield the exact given value
        # We do not want to find combinations using the value 0.
        if not (constant == None or constant == 0) and args.mask_mode:
            mask = constant
            good = []
            out = [(v, k) for v, k in out if v != 0]

            while mask and out:
                cur = out.pop()
                mask &= ~cur[0]
                good.append(cur)

                out = [(v, k) for v, k in out if mask & v == v]

            if reduce(lambda x, cur: x | cur[0], good, 0) == constant:
                print
                print '(%s) == %s' % (' | '.join(k for v, k in good), args.constant)

if __name__ == '__main__': main()
