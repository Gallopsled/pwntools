#!/usr/bin/env python2
import argparse
import os
import sys
import types

from pwn import *

from . import common

r = text.red
g = text.green
b = text.blue

banner = '\n'.join(['  ' + r('____') + '  ' + g('_') + '          ' + r('_') + ' ' + g('_') + '                 ' + b('__') + ' ' + r('_'),
                    ' ' + r('/ ___|') + g('| |__') + '   ' + b('___') + r('| |') + ' ' + g('|') + ' ' + b('___') + ' ' + r('_ __') + ' ' + g('__ _') + ' ' + b('/ _|') + ' ' + r('|_'),
                    ' ' + r('\___ \\') + g('| \'_ \\') + ' ' + b('/ _ \\') + ' ' + r('|') + ' ' + g('|') + b('/ __|') + ' ' + r('\'__/') + ' ' + g('_` |') + ' ' + b('|_') + r('| __|'),
                    '  ' + r('___) |') + ' ' + g('| | |') + '  ' + b('__/') + ' ' + r('|') + ' ' + g('|') + ' ' + b('(__') + r('| |') + ' ' + g('| (_| |') + '  ' + b('_|') + ' ' + r('|_'),
                    ' ' + r('|____/') + g('|_| |_|') + b('\\___|') + r('_|') + g('_|') + b('\\___|') + r('_|') + '  ' + g('\\__,_|') + b('_|') + '  ' + r('\\__|'),
                    '\n'
                    ])


#  ____  _          _ _                 __ _
# / ___|| |__   ___| | | ___ _ __ __ _ / _| |_
# \___ \| '_ \ / _ \ | |/ __| '__/ _` | |_| __|
#  ___) | | | |  __/ | | (__| | | (_| |  _| |_
# |____/|_| |_|\___|_|_|\___|_|  \__,_|_|  \__|

def _string(s):
    out = []
    for c in s:
        co = ord(c)
        if co >= 0x20 and co <= 0x7e and c not in '/$\'"`':
            out.append(c)
        else:
            out.append('\\x%02x' % co)
    return '"' + ''.join(out) + '"\n'

p = argparse.ArgumentParser(
    description = 'Microwave shellcode -- Easy, fast and delicious',
    formatter_class = argparse.RawDescriptionHelpFormatter,
)


p.add_argument(
    '-?', '--show',
    action = 'store_true',
    help = 'Show shellcode documentation',
)

p.add_argument(
    '-o', '--out',
    metavar = 'file',
    type = argparse.FileType('w'),
    default = sys.stdout,
    help = 'Output file (default: stdout)',
)

p.add_argument(
    '-f', '--format',
    metavar = 'format',
    choices = ['r', 'raw',
               's', 'str', 'string',
               'c',
               'h', 'hex',
               'a', 'asm', 'assembly',
               'p',
               'i', 'hexii',
               'default'],
    default = 'default',
    help = 'Output format (default: hex), choose from {r}aw, {s}tring, {c}-style array, {h}ex string, hex{i}i, {a}ssembly code, {p}reprocssed code',
)

p.add_argument(
    'shellcode',
    nargs = '?',
    choices = shellcraft.templates,
    metavar = 'shellcode',
    help = 'The shellcode you want',
)

p.epilog = 'Available shellcodes are:\n' + '\n'.join(shellcraft.templates)

p.add_argument(
    'args',
    nargs = '*',
    metavar = 'arg',
    default = (),
    help = 'Argument to the chosen shellcode',
)

p.add_argument(
    '-d',
    '--debug',
    help='Debug the shellcode with GDB',
    action='store_true'
)

def main():
    # Banner must be added here so that it doesn't appear in the autodoc
    # generation for command line tools
    p.description = banner + p.description
    args = p.parse_args()

    if not args.shellcode:
        print '\n'.join(shellcraft.templates)
        exit()

    if args.format == 'default':
        if sys.stdout.isatty():
            args.format = 'hex'
        else:
            args.format = 'raw'

    func = shellcraft
    for attr in args.shellcode.split('.'):
        func = getattr(func, attr)

    if args.show:
        # remove doctests
        doc = []
        in_doctest = False
        block_indent = None
        caption = None
        lines = func.__doc__.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.lstrip().startswith('>>>'):
                # this line starts a doctest
                in_doctest = True
                block_indent = None
                if caption:
                    # delete back up to the caption
                    doc = doc[:caption - i]
                    caption = None
            elif line == '':
                # skip blank lines
                pass
            elif in_doctest:
                # indentation marks the end of a doctest
                indent = len(line) - len(line.lstrip())
                if block_indent is None:
                    if not line.lstrip().startswith('...'):
                        block_indent = indent
                elif indent < block_indent:
                    in_doctest = False
                    block_indent = None
                    # re-evalutate this line
                    continue
            elif line.endswith(':'):
                # save index of caption
                caption = i
            else:
                # this is not blank space and we're not in a doctest, so the
                # previous caption (if any) was not for a doctest
                caption = None

            if not in_doctest:
                doc.append(line)
            i += 1
        print '\n'.join(doc).rstrip()
        exit()

    defargs = len(func.func_defaults or ())
    reqargs = func.func_code.co_argcount - defargs
    if len(args.args) < reqargs:
        if defargs > 0:
            log.critical('%s takes at least %d arguments' % (args.shellcode, reqargs))
            sys.exit(1)
        else:
            log.critical('%s takes exactly %d arguments' % (args.shellcode, reqargs))
            sys.exit(1)

    # Captain uglyness saves the day!
    for i, val in enumerate(args.args):
        try:
            args.args[i] = util.safeeval.expr(val)
        except ValueError:
            pass

    # And he strikes again!
    map(common.context_arg, args.shellcode.split('.'))
    code = func(*args.args)

    if args.format in ['a', 'asm', 'assembly']:
        print code
        exit()
    if args.format == 'p':
        print cpp(code)
        exit()

    code = asm(code)

    if args.debug:
        arch = args.shellcode.split('.')[0]
        proc = gdb.debug_shellcode(code, arch=arch)
        proc.interactive()
        sys.exit(0)

    if args.format in ['s', 'str', 'string']:
        code = _string(code)
    elif args.format == 'c':
        code = '{' + ', '.join(map(hex, bytearray(code))) + '}' + '\n'
    elif args.format in ['h', 'hex']:
        code = pwnlib.util.fiddling.enhex(code) + '\n'
    elif args.format in ['i', 'hexii']:
        code = hexii(code) + '\n'

    if not sys.stdin.isatty():
        sys.stdout.write(sys.stdin.read())

    sys.stdout.write(code)

if __name__ == '__main__': main()
