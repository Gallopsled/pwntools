#!/usr/bin/env python2
import argparse
import os
import subprocess

from pwnlib import constants

# github.com/zachriggle/functions
from functions import functions

ARCHITECTURES = ['i386', 'amd64', 'arm', 'aarch64', 'mips']

SYSCALL_NAMES = [c for c in dir(constants) if c.startswith('__NR_')]

HEADER = '''
<%
import pwnlib.abi
import pwnlib.constants
import pwnlib.shellcraft
%>
'''

DOCSTRING = '''
<%docstring>{name}({arguments_comma_separated}) -> str

Invokes the syscall {name}.

See 'man 2 {name}' for more information.

Arguments:
{arg_docs}
Returns:
    {return_type}
</%docstring>
'''

ARGUMENTS = """
<%page args="{arguments_default_values}"/>
"""

CALL = """
<%
    abi = pwnlib.abi.ABI.syscall()
    stack = abi.stack
    regs = abi.register_arguments[1:]
    allregs = pwnlib.shellcraft.registers.current()

    can_pushstr = {string_arguments!r}
    can_pushstr_array = {array_arguments!r}

    argument_names = {argument_names!r}
    argument_values = [{arguments_comma_separated!s}]

    # Figure out which register arguments can be set immediately
    register_arguments = dict()
    string_arguments = dict()
    dict_arguments = dict()
    array_arguments = dict()

    for name, arg in zip(argument_names, argument_values):
        if arg in allregs:
            index = argument_names.index(name)
            target = regs[index]
            register_arguments[target] = arg
        elif name in can_pushstr and isinstance(arg, str):
            string_arguments[name] = arg
        elif name in can_pushstr_array and isinstance(arg, dict):
            array_arguments[name] = ['%s=%s' % (k,v) for (k,v) in arg.items()]
        elif name in can_pushstr_array and isinstance(arg, (list, tuple)):
            array_arguments[name] = arg
        else:
            index = argument_names.index(name)
            target = regs[index]
            register_arguments[target] = arg

    # Some syscalls have different names on various architectures
    syscalls = {syscalls!r}

    for syscall in syscalls:
        syscall = getattr(pwnlib.constants, syscall, None)
        if syscall:
            break
%>
    /* {name}({syscall_repr}) */
    ${{pwnlib.shellcraft.setregs(register_arguments)}}
%for name, arg in string_arguments.items():
    ${{pwnlib.shellcraft.pushstr(arg, append_null=('\\x00' not in arg))}}
    ${{pwnlib.shellcraft.mov(regs[argument_names.index(name)], abi.stack)}}
%endfor
%for name, arg in array_arguments.items():
    ${{pwnlib.shellcraft.pushstr_array(regs[argument_names.index(name)], arg)}}
%endfor
    ${{pwnlib.shellcraft.syscall(syscall)}}
"""
def can_be_constant(arg):
    if arg.derefcnt == 0:
        return True

def can_be_string(arg):
    if arg.type == 'char' and arg.derefcnt == 1:
        return True

def can_be_array(arg):
    if arg.type == 'char' and arg.derefcnt == 2:
        return True

def fix_bad_arg_names(arg):
    if arg == 'str': return 'str_'
    if arg == 'len': return 'length'
    if arg == 'repr': return 'repr_'
    return arg

def fix_syscall_name(name):
    # Do not use old_mmap
    if name == '__NR_mmap':
        return ['__NR_mmap2', name]
    return [name]

def main(target):
    for name, function in functions.items():
        syscall = '__NR_%s' % name

        if syscall not in SYSCALL_NAMES:
            continue

        syscalls = fix_syscall_name(syscall)

        # Set up the argument string
        argument_names = map(fix_bad_arg_names, [a.name for a in function.args])
        arguments_default_values = ', '.join('%s=0' % a for a in argument_names)
        arguments_comma_separated = ', '.join(argument_names)

        string_arguments = []
        array_arguments = []
        arg_docs = []

        for arg in function.args:

            if can_be_array(arg):
                array_arguments.append(arg.name)

            if can_be_string(arg):
                string_arguments.append(arg.name)

            argname = arg.name
            argtype = str(arg.type) + ('*' * arg.derefcnt)
            arg_docs.append('    {argname}({argtype}): {argname}'.format(**locals()))

        return_type = str(function.type) + ('*' * function.derefcnt)
        arg_docs = '\n'.join(arg_docs)
        syscall_repr = ', '.join(('%s=${repr(%s)}' % (n,n) for n in argument_names))

        lines = [
            HEADER,
            DOCSTRING.format(**locals()),
            ARGUMENTS.format(**locals()),
            CALL.format(**locals())
        ]

        with open(os.path.join(target, name + '.asm'), 'wt+') as f:
            f.write('\n'.join(map(str.strip, lines)))

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('target_directory')
    args = p.parse_args()
    main(args.target_directory)
