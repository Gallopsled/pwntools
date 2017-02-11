#!/usr/bin/env python2
import argparse
import os

from pwnlib import constants
from pwnlib.context import context

# github.com/zachriggle/functions
from functions import functions, Function, Argument

ARCHITECTURES = ['i386', 'amd64', 'arm', 'aarch64', 'mips']

HEADER = '''
<%
import collections
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

    # Load all of the arguments into their destination registers / stack slots.
    register_arguments = dict()
    stack_arguments = collections.OrderedDict()
    string_arguments = dict()
    dict_arguments = dict()
    array_arguments = dict()
    syscall_repr = []

    for name, arg in zip(argument_names, argument_values):
        if arg is not None:
            syscall_repr.append('%s=%r' % (name, arg))

        # If the argument itself (input) is a register...
        if arg in allregs:
            index = argument_names.index(name)
            if index < len(regs):
                target = regs[index]
                register_arguments[target] = arg
            elif arg is not None:
                stack_arguments[index] = arg

        # The argument is not a register.  It is a string value, and we
        # are expecting a string value
        elif name in can_pushstr and isinstance(arg, str):
            string_arguments[name] = arg

        # The argument is not a register.  It is a dictionary, and we are
        # expecting K:V paris.
        elif name in can_pushstr_array and isinstance(arg, dict):
            array_arguments[name] = ['%s=%s' % (k,v) for (k,v) in arg.items()]

        # The arguent is not a register.  It is a list, and we are expecting
        # a list of arguments.
        elif name in can_pushstr_array and isinstance(arg, (list, tuple)):
            array_arguments[name] = arg

        # The argument is not a register, string, dict, or list.
        # It could be a constant string ('O_RDONLY') for an integer argument,
        # an actual integer value, or a constant.
        else:
            index = argument_names.index(name)
            if index < len(regs):
                target = regs[index]
                register_arguments[target] = arg
            elif arg is not None:
                stack_arguments[target] = arg

    # Some syscalls have different names on various architectures.
    # Determine which syscall number to use for the current architecture.
    for syscall in {syscalls!r}:
        if hasattr(pwnlib.constants, syscall):
            break
    else:
        raise Exception("Could not locate any syscalls: %r" % syscalls)
%>
    /* {name}(${{', '.join(syscall_repr)}}) */
%for name, arg in string_arguments.items():
    ${{pwnlib.shellcraft.pushstr(arg, append_null=('\\x00' not in arg))}}
    ${{pwnlib.shellcraft.mov(regs[argument_names.index(name)], abi.stack)}}
%endfor
%for name, arg in array_arguments.items():
    ${{pwnlib.shellcraft.pushstr_array(regs[argument_names.index(name)], arg)}}
%endfor
%for name, arg in stack_arguments.items():
    ${{pwnlib.shellcraft.push(arg)}}
%endfor
    ${{pwnlib.shellcraft.setregs(register_arguments)}}
    ${{pwnlib.shellcraft.syscall(syscall)}}
"""


def can_be_constant(arg):
    if arg.derefcnt == 0:
        return True


def can_be_string(arg):
    if arg.type == 'char' and arg.derefcnt == 1:
        return True
    if arg.type == 'void' and arg.derefcnt == 1:
        return True

def can_be_array(arg):
    if arg.type == 'char' and arg.derefcnt == 2:
        return True
    if arg.type == 'void' and arg.derefcnt == 2:
        return True


def fix_bad_arg_names(func, arg):
    if arg.name == 'str':
        return 'str_'
    if arg.name == 'len':
        return 'length'
    if arg.name == 'repr':
        return 'repr_'

    if func.name == 'open' and arg.name == 'vararg':
        return 'mode'

    return arg.name


def get_arg_default(arg):
    return 0

def fix_rt_syscall_name(name):
    if name.startswith('rt_'):
        return name[3:]
    return name

def fix_syscall_names(name):
    # Do not use old_mmap
    if name == 'SYS_mmap':
        return ['SYS_mmap2', name]
    # Some arches don't have vanilla sigreturn
    if name.endswith('_sigreturn'):
        return ['SYS_sigreturn', 'SYS_rt_sigreturn']
    return [name]


def main(target):
    for arch in ARCHITECTURES:
        with context.local(arch=arch):
            generate_one(target)

def generate_one(target):
    SYSCALL_NAMES = [c for c in dir(constants) if c.startswith('SYS_')]

    for syscall in SYSCALL_NAMES:
        name = syscall[4:]

        # Skip anything with uppercase
        if name.lower() != name:
            print 'Skipping %s' % name
            continue

        # Skip anything that starts with 'unused' or 'sys' after stripping
        if name.startswith('unused'):
            print 'Skipping %s' % name
            continue

        function = functions.get(name, None)

        if name.startswith('rt_'):
            name = name[3:]

        # If we can't find a function, just stub it out with something
        # that has a vararg argument.
        if function is None:
            print 'Stubbing out %s' % name
            args = [Argument('int', 0, 'vararg')]
            function = Function('long', 0, name, args)

        # Some syscalls have different names on different architectures,
        # or are superceded.  We try to do the "best" thing at runtime.
        syscalls = fix_syscall_names(syscall)

        # Set up the argument string for Mako
        argument_names = []
        argument_defaults = []

        #

        for arg in function.args:
            argname = fix_bad_arg_names(function, arg)
            default = get_arg_default(arg)

            # Mako is unable to use *vararg and *kwarg, so we just stub in
            # a whole bunch of additional arguments.
            if argname == 'vararg':
                for j in range(5):
                    argname = 'vararg_%i' % j
                    argument_names.append(argname)
                    argument_defaults.append('%s=%s' % (argname, None))
                break

            argument_names.append(argname)
            argument_defaults.append('%s=%s' % (argname, default))

        arguments_default_values = ', '.join(argument_defaults)
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
            arg_docs.append(
                '    {argname}({argtype}): {argname}'.format(argname=argname,
                                                             argtype=argtype))

        return_type = str(function.type) + ('*' * function.derefcnt)
        arg_docs = '\n'.join(arg_docs)

        template_variables = {
            'name': name,
            'arg_docs': arg_docs,
            'syscalls': syscalls,
            'arguments_default_values': arguments_default_values,
            'arguments_comma_separated': arguments_comma_separated,
            'return_type': return_type,
            'string_arguments': string_arguments,
            'array_arguments': array_arguments,
            'argument_names': argument_names,
        }

        lines = [
            HEADER,
            DOCSTRING.format(**template_variables),
            ARGUMENTS.format(**template_variables),
            CALL.format(**template_variables)
        ]

        with open(os.path.join(target, name + '.asm'), 'wt+') as f:
            f.write('\n'.join(map(str.strip, lines)))

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('target_directory')
    args = p.parse_args()
    main(args.target_directory)
