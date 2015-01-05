# -*- coding: utf-8 -*-
r"""
Utilities for assembling and disassembling code.

Architecture Selection
------------------------

    Architecture, endianness, and word size are selected by using :mod:`pwnlib.context`.

    Any parameters which can be specified to ``context`` can also be specified as
    keyword arguments to either :func:`asm` or :func:`disasm`.

Assembly
------------------------

    To assemble code, simply invoke :func:`asm` on the code to assemble.

        >>> asm('mov eax, 0')
        '\xb8\x00\x00\x00\x00'

    Additionally, you can use constants as defined in the :mod:`pwnlib.constants`
    module.

        >>> asm('mov eax, SYS_execve')
        '\xb8\x0b\x00\x00\x00'

    Finally, :func:`asm` is used to assemble shellcode provided by ``pwntools``
    in the :mod:`shellcraft` module.

        >>> asm(shellcraft.sh())
        'jhh///sh/bin\x89\xe31\xc9j\x0bX\x99\xcd\x80'

Disassembly
------------------------

    To disassemble code, simply invoke :func:`disasm` on the bytes to disassemble.

    >>> disasm('\xb8\x0b\x00\x00\x00')
    '   0:   b8 0b 00 00 00          mov    eax,0xb'

"""
import tempfile, subprocess, shutil, tempfile, errno, logging, platform
from os import path, environ
from glob import glob
from . import log
from .context import context

log = logging.getLogger(__name__)

__all__ = ['asm', 'cpp', 'disasm', 'which_binutils']

_basedir = path.split(__file__)[0]
_incdir  = path.join(_basedir, 'data', 'includes')

def which_binutils(util, **kwargs):
    """
    Finds a binutils in the PATH somewhere.
    Expects that the utility is prefixed with the architecture name.

    Examples:

        >>> import platform
        >>> which_binutils('as', arch=platform.machine())
        '.../bin/as'
        >>> which_binutils('as', arch='arm') #doctest: +ELLIPSIS
        '.../bin/arm-...-as'
        >>> which_binutils('as', arch='powerpc') #doctest: +ELLIPSIS
        '.../bin/powerpc...-as'
        >>> which_binutils('as', arch='msp430') #doctest: +SKIP
        ...
        Traceback (most recent call last):
        ...
        Exception: Could not find 'as' installed for ContextType(arch = 'msp430')
    """
    with context.local(**kwargs):
        arch = context.arch
        bits = context.bits

        # Fix up pwntools vs Debian triplet naming, and account
        # for 'thumb' being its own pwntools architecture.
        arches = [arch] + {
            'thumb':  ['arm',    'aarch64'],
            'i386':   ['x86_64', 'amd64'],
            'amd64':  ['x86_64', 'i386'],
        }.get(arch, [])

        # If one of the candidate architectures matches the native
        # architecture, use that as a last resort.
        machine = platform.machine()
        try:
            with context.local(arch = machine):
                if context.arch in arches:
                    arches.append(None)
        except AttributeError:
            log.warn_once("Your local binutils won't be used because architecture %r is not supported." % machine)

        for arch in arches:
            # hack for homebrew-installed binutils on mac
            for gutil in ['g'+util, util]:
                # e.g. objdump
                if arch is None: pattern = gutil

                # e.g. aarch64-linux-gnu-objdump
                else:       pattern = '%s*linux*-%s' % (arch,gutil)

                for dir in environ['PATH'].split(':'):
                    res = glob(path.join(dir, pattern))
                    if res:
                        return res[0]

        locals()['context'] = context
        log.warning("""
Could not find %(util)r installed for %(context)s
Try installing binutils for this architecture:
    https://pwntools.readthedocs.org/en/latest/install/binutils.html
""".strip() % locals())
        raise Exception('Could not find %(util)r installed for %(context)s' % locals())

def _assembler():
    gas = which_binutils('as')

    E = {
        'big':    '-EB',
        'little': '-EL'
    }[context.endianness]

    assemblers = {
        'i386'   : [gas, '--32'],
        'amd64'  : [gas, '--64'],

        # Most architectures accept -EL or -EB
        'thumb'  : [gas, '-mthumb', E],
        'arm'    : [gas, E],
        'aarch64': [gas, E],
        'mips'   : [gas, E],
        'mips64' : [gas, E],
        'sparc':   [gas, E],
        'sparc64': [gas, E],

        # Powerpc wants -mbig or -mlittle
        'powerpc':   [gas, '-m%s' % context.endianness],
        'powerpc64': [gas, '-m%s' % context.endianness],

        # ia64 only accepts -mbe or -mle
        'ia64':    [gas, '-m%ce' % context.endianness[0]]
    }

    return assemblers.get(context.arch, [gas])

def _objcopy():
    return [which_binutils('objcopy')]

def _objdump():
    path = [which_binutils('objdump')]

    if context.arch in ('i386', 'amd64'):
        path += ['-Mintel']

    return path

def _include_header():
    os   = context.os
    arch = context.arch

    if os == 'freebsd':
        include = 'freebsd.h'
    elif os == 'linux':
        include = 'linux/%s.h' % arch

    if not include or not path.exists(path.join(_incdir, include)):
        log.warn_once("Could not find system include headers for %s-%s" % (arch,os))
        return '\n'

    return '#include <%s>\n' % include


def _arch_header():
    prefix  = ['.section .shellcode,"ax"']
    headers = {
        'i386'  :  ['.intel_syntax noprefix'],
        'amd64' :  ['.intel_syntax noprefix'],
        'arm'   : ['.syntax unified',
                   '.arch armv7-a',
                   '.arm'],
        'thumb' : ['.syntax unified',
                   '.arch armv7-a',
                   '.thumb'],
        'mips'  : ['.set mips2',
                   '.set noreorder'],
    }

    return '\n'.join(prefix + headers.get(context.arch, [])) + '\n'

def _bfdname():
    arch = context.arch

    bfdnames = {
        'i386'    : 'elf32-i386',
        'amd64'   : 'elf64-x86-64',
        'arm'     : 'elf32-littlearm',
        'thumb'   : 'elf32-littlearm',
        'mips'    : 'elf32-%smips' % context.endianness,
        'alpha'   : 'elf64-alpha',
        'cris'    : 'elf32-cris',
        'ia64'    : 'elf64-ia64-%s' % context.endianness,
        'm68k'    : 'elf32-m68k',
        'powerpc' : 'elf32-powerpc',
        'vax'     : 'elf32-vax',
    }

    if arch in bfdnames:
        return bfdnames[arch]
    else:
        raise Exception("Cannot find bfd name for architecture %r" % arch)


def _bfdarch():
    arch = context.arch
    convert = {
    'i386': 'i386',
    'amd64': 'i386:x86-64',
    'thumb': 'arm',
    'ia64': 'ia64-elf64'
    }

    if arch in convert:
        return convert[arch]

    return arch

def _run(cmd, stdin = None):
    log.debug(subprocess.list2cmdline(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdin  = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE
        )
        stdout, stderr = proc.communicate(stdin)
        exitcode = proc.wait()
    except OSError as e:
        if e.errno == errno.ENOENT:
            log.exception('Could not run %r the program' % cmd[0])
        else:
            raise

    if (exitcode, stderr) != (0, ''):
        msg = 'There was an error running %s:\n' % repr(cmd)
        if exitcode != 0:
            msg += 'It had the exitcode %d.\n' % exitcode
        if stderr != '':
            msg += 'It had this on stdout:\n%s\n' % stderr
        log.error(msg)

    return stdout

def cpp(shellcode, **kwargs):
    r"""cpp(shellcode, ...) -> str

    Runs CPP over the given shellcode.

    The output will always contain exactly one newline at the end.

    Arguments:
        shellcode(str): Shellcode to preprocess

    Kwargs:
        Any arguments/properties that can be set on ``context``

    Examples:

        .. doctest::

            >>> cpp("mov al, SYS_setresuid", arch = "i386", os = "linux")
            'mov al, 164\n'
            >>> cpp("weee SYS_setresuid", arch = "arm", os = "linux")
            'weee (0x900000+164)\n'
            >>> cpp("SYS_setresuid", arch = "thumb", os = "linux")
            '(0+164)\n'
            >>> cpp("SYS_setresuid", os = "freebsd")
            '311\n'
    """

    with context.local(**kwargs):
        arch = context.arch
        os   = context.os
        code = _include_header() + shellcode
        cmd  = [
            'cpp',
            '-C',
            '-nostdinc',
            '-undef',
            '-P',
            '-I' + _incdir,
            '/dev/stdin'
        ]
        return _run(cmd, code).strip('\n').rstrip() + '\n'


def asm(shellcode, vma = 0, **kwargs):
    r"""asm(code, vma = 0, ...) -> str

    Runs :func:`cpp` over a given shellcode and then assembles it into bytes.

    To see which architectures or operating systems are supported,
    look in :mod:`pwnlib.contex`.

    To support all these architecture, we bundle the GNU assembler
    and objcopy with pwntools.

    Args:
      shellcode(str): Assembler code to assemble.
      vma(int):       Virtual memory address of the beginning of assembly

    Kwargs:
        Any arguments/properties that can be set on ``context``

    Examples:

        .. doctest::

            >>> asm("mov eax, SYS_select", arch = 'i386', os = 'freebsd')
            '\xb8]\x00\x00\x00'
            >>> asm("mov eax, SYS_select", arch = 'amd64', os = 'linux')
            '\xb8\x17\x00\x00\x00'
            >>> asm("mov rax, SYS_select", arch = 'amd64', os = 'linux')
            'H\xc7\xc0\x17\x00\x00\x00'
            >>> asm("ldr r0, =SYS_select", arch = 'arm', os = 'linux', bits=32)
            '\x04\x00\x1f\xe5R\x00\x90\x00'
    """
    result = ''

    with context.local(**kwargs):
        assembler = _assembler()
        objcopy   = _objcopy() + ['-j', '.shellcode', '-Obinary']
        code      = '.org %#x\n' % vma
        code      += _arch_header()
        code      += cpp(shellcode)

        log.debug('Assembling\n%s' % code)

        tmpdir    = tempfile.mkdtemp(prefix = 'pwn-asm-')
        step1     = path.join(tmpdir, 'step1')
        step2     = path.join(tmpdir, 'step2')
        step3     = path.join(tmpdir, 'step3')

        try:
            with open(step1, 'w') as fd:
                fd.write(code)

            _run(assembler + ['-o', step2, step1])

            if file(step2,'rb').read(4) == '\x7fELF':
                # Sanity check for seeing if the output has relocations
                relocs = subprocess.check_output(
                    [which_binutils('readelf'), '-r', step2]
                ).strip()
                if len(relocs.split('\n')) > 1:
                    log.error('Shellcode contains relocations:\n%s' % relocs)

            _run(objcopy + [step2, step3])

            with open(step3) as fd:
                result = fd.read()

        except:
            log.exception("An error occurred while assembling:\n%s" % code)
        else:
            shutil.rmtree(tmpdir)
            return result

def disasm(data, vma = 0, **kwargs):
    """disasm(data, ...) -> str

    Disassembles a bytestring into human readable assembler.

    To see which architectures are supported,
    look in :mod:`pwnlib.contex`.

    To support all these architecture, we bundle the GNU objcopy
    and objdump with pwntools.

    Args:
      data(str): Bytestring to disassemble.
      vma(int): Passed through to the --adjust-vma argument of objdump

    Kwargs:
      Any arguments/properties that can be set on ``context``

    Examples:

        .. doctest::

          >>> print disasm('b85d000000'.decode('hex'), arch = 'i386')
             0:   b8 5d 00 00 00          mov    eax,0x5d
          >>> print disasm('b817000000'.decode('hex'), arch = 'amd64')
             0:   b8 17 00 00 00          mov    eax,0x17
          >>> print disasm('48c7c017000000'.decode('hex'), arch = 'amd64')
             0:   48 c7 c0 17 00 00 00    mov    rax,0x17
          >>> print disasm('04001fe552009000'.decode('hex'), arch = 'arm')
             0:   e51f0004        ldr     r0, [pc, #-4]   ; 0x4
             4:   00900052        addseq  r0, r0, r2, asr r0
          >>> print disasm('4ff00500'.decode('hex'), arch = 'thumb', bits=32)
             0:   f04f 0005       mov.w   r0, #5
    """
    result = ''

    with context.local(**kwargs):
        arch   = context.arch
        os     = context.os

        tmpdir = tempfile.mkdtemp(prefix = 'pwn-disasm-')
        step1  = path.join(tmpdir, 'step1')
        step2  = path.join(tmpdir, 'step2')

        bfdarch = _bfdarch()
        bfdname = _bfdname()
        objdump = _objdump() + ['-d', '--adjust-vma', str(vma), '-b', bfdname]
        objcopy = _objcopy() + [
            '-I', 'binary',
            '-O', bfdname,
            '-B', bfdarch,
            '--set-section-flags', '.data=code',
            '--rename-section', '.data=.text',
        ]

        if arch == 'thumb':
            objcopy += ['--prefix-symbol=$t.']
        else:
            objcopy += ['-w', '-N', '*']

        try:

            with open(step1, 'w') as fd:
                fd.write(data)

            res = _run(objcopy + [step1, step2])

            output0 = subprocess.check_output(objdump + [step2])
            output1 = output0.split('<.text>:\n')

            if len(output1) != 2:
                log.error('Could not find .text in objdump output:\n%s' % output0)

            result = output1[1].strip('\n').rstrip().expandtabs()
        except:
            log.exception("An error occurred while disassembling:\n%s" % data)
        else:
            shutil.rmtree(tmpdir)
            return result

