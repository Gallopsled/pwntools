from __future__ import absolute_import
from __future__ import division

import os
import sys
import tempfile

from pwnlib.context import LocalContext, context
from pwnlib.elf import ELF
from pwnlib.tubes.process import process

__all__ = ['run_assembly', 'run_shellcode', 'run_assembly_exitcode', 'run_shellcode_exitcode']

@LocalContext
def run_assembly(assembly):
    """
    Given an assembly listing, assemble and execute it.

    Returns:

        A :class:`pwnlib.tubes.process.process` tube to interact with the process.

    Example:

        >>> p = run_assembly('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
        >>> p.wait_for_close()
        >>> p.poll()
        3

        >>> p = run_assembly('mov r0, #12; mov r7, #1; svc #0', arch='arm')
        >>> p.wait_for_close()
        >>> p.poll()
        12
    """
    if context.os == 'darwin':
        if sys.platform != 'darwin':
            raise ValueError('Running Mach-O only supported on Darwin machines. Please use:\n'
                             '- https://github.com/MatthewCroughan/NixThePlanet\n'
                             '- https://github.com/sickcodes/Docker-OSX')
        from pwnlib.asm import make_macho_from_assembly
        return process(make_macho_from_assembly(assembly))

    return ELF.from_assembly(assembly).process()

@LocalContext
def run_shellcode(bytes, **kw):
    """Given assembled machine code bytes, execute them.

    Example:

        >>> insn_bytes = asm('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
        >>> p = run_shellcode(insn_bytes)
        >>> p.wait_for_close()
        >>> p.poll()
        3

        >>> insn_bytes = asm('mov r0, #12; mov r7, #1; svc #0', arch='arm')
        >>> p = run_shellcode(insn_bytes, arch='arm')
        >>> p.wait_for_close()
        >>> p.poll()
        12
    """
    if context.os == 'darwin':
        if sys.platform != 'darwin':
            raise ValueError('Running Mach-O only supported on Darwin machines. Please use:\n'
                             '- https://github.com/MatthewCroughan/NixThePlanet\n'
                             '- https://github.com/sickcodes/Docker-OSX')
        from pwnlib.asm import make_macho
        return process(make_macho(bytes))

    return ELF.from_bytes(bytes, **kw).process()

@LocalContext
def run_assembly_exitcode(assembly):
    """
    Given an assembly listing, assemble and execute it, and wait for
    the process to die.

    Returns:

        The exit code of the process.

    Example:

        >>> run_assembly_exitcode('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
        3
    """
    p = run_assembly(assembly)
    p.wait_for_close()
    return p.poll()

@LocalContext
def run_shellcode_exitcode(bytes):
    """
    Given assembled machine code bytes, execute them, and wait for
    the process to die.

    Returns:

        The exit code of the process.

    Example:

        >>> insn_bytes = asm('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
        >>> run_shellcode_exitcode(insn_bytes)
        3
    """
    p = run_shellcode(bytes)
    p.wait_for_close()
    return p.poll()
