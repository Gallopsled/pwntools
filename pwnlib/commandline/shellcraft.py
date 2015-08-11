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
               'e', 'elf',
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

p.add_argument(
    '-b',
    '--before',
    help='Insert a debug trap before the code',
    action='store_true'
)

p.add_argument(
    '-a',
    '--after',
    help='Insert a debug trap after the code',
    action='store_true'
)

p.add_argument(
    '-v', '--avoid',
    action='append',
    help = 'Encode the shellcode to avoid the listed bytes'
)

p.add_argument(
    '-n', '--newline',
    dest='avoid',
    action='append_const',
    const='\n',
    help = 'Encode the shellcode to avoid newlines'
)

p.add_argument(
    '-z', '--zero',
    dest='avoid',
    action='append_const',
    const='\x00',
    help = 'Encode the shellcode to avoid NULL bytes'
)

p.add_argument(
    '-r',
    '--run',
    help="Run output",
    action='store_true'
)

p.add_argument(
    '--color',
    help="Color output",
    action='store_true',
    default=sys.stdout.isatty()
)

p.add_argument(
    '--no-color',
    help="Disable color output",
    action='store_false',
    dest='color'
)

p.add_argument(
    '--syscalls',
    help="List syscalls",
    action='store_true'
)

p.add_argument(
    '--address',
    help="Load address",
    default=None
)

def get_template(name):
    func = shellcraft
    for attr in name.split('.'):
        func = getattr(func, attr)
    return func

def is_not_a_syscall_template(name):
    template_src = shellcraft._get_source(name)
    return 'man 2' not in read(template_src)

def main():
    # Banner must be added here so that it doesn't appear in the autodoc
    # generation for command line tools
    p.description = banner + p.description
    args = p.parse_args()

    if not args.shellcode:
        templates = shellcraft.templates

        if not args.syscalls:
            templates = filter(is_not_a_syscall_template, templates)

        print '\n'.join(templates)
        exit()

    func = get_template(args.shellcode)

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


    if args.before:
        code = shellcraft.trap() + code
    if args.after:
        code = code + shellcraft.trap()


    if args.format in ['a', 'asm', 'assembly']:
        if args.color:
            from pygments import highlight
            from pygments.formatters import TerminalFormatter
            from pwnlib.lexer import PwntoolsLexer

            code = highlight(code, PwntoolsLexer(), TerminalFormatter())

        print code
        exit()
    if args.format == 'p':
        print cpp(code)
        exit()

    assembly = code

    vma = args.address
    if vma:
        vma = eval(vma)

    if args.format in ['e','elf']:
        args.format = 'default'
        try: os.fchmod(args.out.fileno(), 0700)
        except OSError: pass


        if not args.avoid:
            code = read(make_elf_from_assembly(assembly, vma=vma))
        else:
            code = asm(assembly)
            code = encode(code, args.avoid)
            code = make_elf(code, vma=vma)
            # code = read(make_elf(encode(asm(code), args.avoid)))
    else:
        code = encode(asm(assembly), args.avoid)

    if args.format == 'default':
        if args.out.isatty():
            args.format = 'hex'
        else:
            args.format = 'raw'

    arch = args.shellcode.split('.')[0]

    if args.debug:
        if not args.avoid:
            proc = gdb.debug_assembly(assembly, arch=arch, vma=vma)
        else:
            proc = gdb.debug_shellcode(code, arch=arch, vma=vma)
        proc.interactive()
        sys.exit(0)

    if args.run:
        proc = run_shellcode(code, arch=arch)
        proc.interactive()
        sys.exit(0)

    if args.format in ['s', 'str', 'string']:
        code = _string(code) + '"\n'
    elif args.format == 'c':
        code = '{' + ', '.join(map(hex, bytearray(code))) + '}' + '\n'
    elif args.format in ['h', 'hex']:
        code = pwnlib.util.fiddling.enhex(code) + '\n'
    elif args.format in ['i', 'hexii']:
        code = hexii(code) + '\n'

    if not sys.stdin.isatty():
        args.out.write(sys.stdin.read())

    args.out.write(code)

if __name__ == '__main__': main()
