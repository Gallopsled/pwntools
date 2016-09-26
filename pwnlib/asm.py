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

        >>> asm(shellcraft.nop())
        '\x90'

Disassembly
------------------------

    To disassemble code, simply invoke :func:`disasm` on the bytes to disassemble.

    >>> disasm('\xb8\x0b\x00\x00\x00')
    '   0:   b8 0b 00 00 00          mov    eax,0xb'

"""
import errno
import os
import platform
import re
import shutil
import string
import subprocess
import sys
import tempfile
from collections import defaultdict
from glob import glob
from os import environ
from os import path

from . import atexit
from . import shellcraft
from .context import LocalContext
from .context import context
from .log import getLogger

log = getLogger(__name__)

__all__ = ['asm', 'cpp', 'disasm', 'make_elf', 'make_elf_from_assembly']

_basedir = path.split(__file__)[0]
_incdir  = path.join(_basedir, 'data', 'includes')

def dpkg_search_for_binutils(arch, util):
    """Use dpkg to search for any available assemblers which will work.

    Returns:
        A list of candidate package names.
    """

    # Example output:
    # $ dpkg -S 'arm*linux*-as'
    # binutils-arm-linux-gnu: /usr/bin/arm-linux-gnu-as
    # binutils-arm-linux-gnueabihf: /usr/bin/arm-linux-gnueabihf-as
    # binutils-arm-linux-gnueabihf: /usr/x86_64-linux-gnu/arm-linux-gnueabihf/include/dis-asm.h
    # binutils-arm-linux-gnu: /usr/x86_64-linux-gnu/arm-linux-gnu/include/dis-asm.h
    packages = []

    try:
        filename = 'bin/%s*linux*-%s' % (arch, util)
        output = subprocess.check_output(['dpkg','-S',filename])
        for line in output.strip().splitlines():
            package, path = line.split(':', 1)
            packages.append(package)
    except OSError:
        pass
    except subprocess.CalledProcessError:
        pass

    return packages

def print_binutils_instructions(util, context):
    """On failure to find a binutils utility, inform the user of a way
    they can get it easily.
    """
    # This links to our instructions on how to manually install binutils
    # for several architectures.
    instructions = 'https://docs.pwntools.com/en/stable/install/binutils.html'

    # However, if we can directly provide a useful command, go for it.
    binutils_arch = {
        'amd64': 'x86_64',
        'arm':   'armeabi',
        'thumb': 'armeabi',
    }.get(context.arch, context.arch)

    packages = dpkg_search_for_binutils(binutils_arch, util)

    if packages:
        instructions = '$ sudo apt-get install %s' % packages[0]

    log.error("""
Could not find %(util)r installed for %(context)s
Try installing binutils for this architecture:
%(instructions)s
""".strip() % locals())

@LocalContext
def which_binutils(util):
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
    arch = context.arch
    bits = context.bits

    # Fix up pwntools vs Debian triplet naming, and account
    # for 'thumb' being its own pwntools architecture.
    arches = [arch] + {
        'thumb':  ['arm',    'aarch64'],
        'i386':   ['x86_64', 'amd64'],
        'i686':   ['x86_64', 'amd64'],
        'amd64':  ['x86_64', 'i386'],
    }.get(arch, [])

    # If one of the candidate architectures matches the native
    # architecture, use that as a last resort.
    machine = platform.machine()
    machine = 'i386' if machine == 'i686' else machine
    try:
        with context.local(arch = machine):
            if context.arch in arches:
                arches.append(None)
    except AttributeError:
        log.warn_once("Your local binutils won't be used because architecture %r is not supported." % machine)

    utils = [util]

    # hack for homebrew-installed binutils on mac
    if platform.system() == 'Darwin':
        utils = ['g'+util, util]

    for arch in arches:
        for gutil in utils:
            # e.g. objdump
            if arch is None: pattern = gutil

            # e.g. aarch64-linux-gnu-objdump
            else:       pattern = '%s*linux*-%s' % (arch,gutil)

            for dir in environ['PATH'].split(':'):
                res = sorted(glob(path.join(dir, pattern)))
                if res:
                    return res[0]

    # No dice!
    print_binutils_instructions(util, context)

checked_assembler_version = defaultdict(lambda: False)

def _assembler():
    gas = which_binutils('as')

    E = {
        'big':    '-EB',
        'little': '-EL'
    }[context.endianness]

    B = '-%s' % context.bits

    assemblers = {
        'i386'   : [gas, B],
        'amd64'  : [gas, B],

        # Most architectures accept -EL or -EB
        'thumb'  : [gas, '-mthumb', E],
        'arm'    : [gas, E],
        'aarch64': [gas, E],
        'mips'   : [gas, E, B],
        'mips64' : [gas, E, B],
        'sparc':   [gas, E, B],
        'sparc64': [gas, E, B],

        # Powerpc wants -mbig or -mlittle, and -mppc32 or -mppc64
        'powerpc':   [gas, '-m%s' % context.endianness, '-mppc%s' % context.bits],
        'powerpc64': [gas, '-m%s' % context.endianness, '-mppc%s' % context.bits],

        # ia64 only accepts -mbe or -mle
        'ia64':    [gas, '-m%ce' % context.endianness[0]]
    }

    assembler = assemblers.get(context.arch, [gas])

    if not checked_assembler_version[gas]:
        checked_assembler_version[gas] = True
        result = subprocess.check_output([gas, '--version','/dev/null'],
                                         stderr=subprocess.STDOUT)
        version = re.search(r' (\d\.\d+)', result).group(1)
        if version < '2.19':
            log.warn_once('Your binutils version is too old and may not work!\n'  + \
                'Try updating with: https://docs.pwntools.com/en/stable/install/binutils.html\n' + \
                'Reported Version: %r' % result.strip())


    return assembler

def _linker():
    ld  = [which_binutils('ld')]
    bfd = ['--oformat=' + _bfdname()]

    E = {
        'big':    '-EB',
        'little': '-EL'
    }[context.endianness]

    arguments = {
        'i386': ['-m', 'elf_i386'],
    }.get(context.arch, [])

    return ld + bfd + [E] + arguments

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
    include = '%s/%s.h' % (os, arch)

    if not include or not path.exists(path.join(_incdir, include)):
        log.warn_once("Could not find system include headers for %s-%s" % (arch,os))
        return '\n'

    return '#include <%s>\n' % include


def _arch_header():
    prefix  = ['.section .shellcode,"awx"',
                '.global _start',
                '.global __start',
                '_start:',
                '__start:']
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
                   '.set noreorder',
                   ],
    }

    return '\n'.join(prefix + headers.get(context.arch, [])) + '\n'

def _bfdname():
    arch = context.arch
    E    = context.endianness

    bfdnames = {
        'i386'    : 'elf32-i386',
        'aarch64' : 'elf64-%saarch64' % E,
        'amd64'   : 'elf64-x86-64',
        'arm'     : 'elf32-%sarm' % E,
        'thumb'   : 'elf32-%sarm' % E,
        'mips'    : 'elf32-trad%smips' % E,
        'mips64'  : 'elf64-trad%smips' % E,
        'alpha'   : 'elf64-alpha',
        'cris'    : 'elf32-cris',
        'ia64'    : 'elf64-ia64-%s' % E,
        'm68k'    : 'elf32-m68k',
        'powerpc' : 'elf32-powerpc',
        'powerpc64' : 'elf64-powerpc',
        'vax'     : 'elf32-vax',
        'sparc'   : 'elf32-sparc',
        'sparc64' : 'elf64-sparc',
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

@LocalContext
def cpp(shellcode):
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
            'weee (0+164)\n'
            >>> cpp("SYS_setresuid", arch = "thumb", os = "linux")
            '(0+164)\n'
            >>> cpp("SYS_setresuid", os = "freebsd")
            '311\n'
    """
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

@LocalContext
def make_elf_from_assembly(assembly, vma = None, extract=False, shared = False):
    r"""
    Builds an ELF file with the specified assembly as its
    executable code.

    Arguments:

        assembly(str): Assembly
        vma(int): Load address of the binary
        extract(bool): Whether to return the data extracted from the file created,
                       or the path to it.

    Returns:

        The path to the assembled ELF (extract=False), or the data
        of the assembled ELF.

    Example:

        >>> context.clear()
        >>> context.arch = 'amd64'
        >>> sc = 'push rbp; mov rbp, rsp;'
        >>> sc += shellcraft.echo('Hello\n')
        >>> sc += 'mov rsp, rbp; pop rbp; ret'
        >>> solib = make_elf_from_assembly(sc, shared=1)
        >>> subprocess.check_output(['echo', 'World'], env={'LD_PRELOAD': solib})
        'Hello\nWorld\n'
    """
    if shared and vma:
        log.error("Cannot specify a VMA for a shared library.")

    if vma is None:
        if shared:
            vma = 0
        else:
            vma = 0x10000000

    if context.arch == 'thumb':
        to_thumb = shellcraft.arm.to_thumb()

        if not assembly.startswith(to_thumb):
            assembly = to_thumb + assembly

    path = asm(assembly, vma = vma, extract = extract, shared = shared)

    if not extract:
        os.chmod(path, 0755)

    return path

@LocalContext
def make_elf(data, vma = None, strip=True, extract=True, shared=False):
    r"""
    Builds an ELF file with the specified binary data as its
    executable code.

    Arguments:
        data(str): Assembled code
        vma(int):  Load address for the ELF file

    Examples:

        This example creates an i386 ELF that just does
        execve('/bin/sh',...).

        >>> context.clear()
        >>> context.arch = 'i386'
        >>> context.bits = 32
        >>> filename = tempfile.mktemp()
        >>> bin_sh = '6a68682f2f2f73682f62696e89e331c96a0b5899cd80'.decode('hex')
        >>> data = make_elf(bin_sh)
        >>> with open(filename,'wb+') as f:
        ...     f.write(data)
        ...     f.flush()
        >>> os.chmod(filename,0777)
        >>> p = process(filename)
        >>> p.sendline('echo Hello; exit')
        >>> p.recvline()
        'Hello\n'
    """
    retval = None

    if shared and vma:
        log.error("Cannot specify a VMA for a shared library.")

    if context.arch == 'thumb':
        to_thumb = asm(shellcraft.arm.to_thumb(), arch='arm')

        if not data.startswith(to_thumb):
            data = to_thumb + data


    assembler = _assembler()
    linker    = _linker()
    code      = _arch_header()
    code      += '.string "%s"' % ''.join('\\x%02x' % ord(c) for c in data)
    code      += '\n'

    log.debug("Building ELF:\n" + code)

    tmpdir    = tempfile.mkdtemp(prefix = 'pwn-asm-')
    step1     = path.join(tmpdir, 'step1-asm')
    step2     = path.join(tmpdir, 'step2-obj')
    step3     = path.join(tmpdir, 'step3-elf')

    try:
        with open(step1, 'wb+') as f:
            f.write(code)

        _run(assembler + ['-o', step2, step1])

        linker_options = ['-z', 'execstack']
        if vma:
            linker_options += ['--section-start=.shellcode=%#x' % vma,
                               '--entry=%#x' % vma]
        elif shared:
            linker_options += ['-shared', '-init=_start']

        linker_options += ['-o', step3, step2]

        _run(linker + linker_options)

        if strip:
            _run([which_binutils('objcopy'), '-Sg', step3])
            _run([which_binutils('strip'), '--strip-unneeded', step3])

        if not extract:
            os.chmod(step3, 0755)
            retval = step3

        else:
            with open(step3, 'r') as f:
                retval = f.read()
    except Exception:
        log.exception("An error occurred while building an ELF:\n%s" % code)
    else:
        atexit.register(lambda: shutil.rmtree(tmpdir))

    return retval

@LocalContext
def asm(shellcode, vma = 0, extract = True, shared = False):
    r"""asm(code, vma = 0, extract = True, ...) -> str

    Runs :func:`cpp` over a given shellcode and then assembles it into bytes.

    To see which architectures or operating systems are supported,
    look in :mod:`pwnlib.contex`.

    To support all these architecture, we bundle the GNU assembler
    and objcopy with pwntools.

    Arguments:
      shellcode(str): Assembler code to assemble.
      vma(int):       Virtual memory address of the beginning of assembly
      extract(bool):  Extract the raw assembly bytes from the assembled
                      file.  If ``False``, returns the path to an ELF file
                      with the assembly embedded.

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
            >>> asm("mov r0, #SYS_select", arch = 'arm', os = 'linux', bits=32)
            'R\x00\xa0\xe3'
    """
    result = ''

    assembler = _assembler()
    linker    = _linker()
    objcopy   = _objcopy() + ['-j', '.shellcode', '-Obinary']
    code      = ''
    code      += _arch_header()
    code      += cpp(shellcode)

    log.debug('Assembling\n%s' % code)

    tmpdir    = tempfile.mkdtemp(prefix = 'pwn-asm-')
    step1     = path.join(tmpdir, 'step1')
    step2     = path.join(tmpdir, 'step2')
    step3     = path.join(tmpdir, 'step3')
    step4     = path.join(tmpdir, 'step4')

    try:
        with open(step1, 'w') as fd:
            fd.write(code)

        _run(assembler + ['-o', step2, step1])

        if not vma:
            shutil.copy(step2, step3)

        if vma or not extract:
            ldflags = ['-z', 'execstack', '-o', step3, step2]
            if vma:
                ldflags += ['--section-start=.shellcode=%#x' % vma,
                            '--entry=%#x' % vma,
                            '-z', 'max-page-size=4096',
                            '-z', 'common-page-size=4096']
            elif shared:
                ldflags += ['-shared', '-init=_start']
            _run(linker + ldflags)

        elif file(step2,'rb').read(4) == '\x7fELF':
            # Sanity check for seeing if the output has relocations
            relocs = subprocess.check_output(
                [which_binutils('readelf'), '-r', step2]
            ).strip()
            if extract and len(relocs.split('\n')) > 1:
                log.error('Shellcode contains relocations:\n%s' % relocs)
        else:
            shutil.copy(step2, step3)

        if not extract:
            return step3

        _run(objcopy + [step3, step4])

        with open(step4) as fd:
            result = fd.read()

    except Exception:
        lines = '\n'.join('%4i: %s' % (i+1,line) for (i,line) in enumerate(code.splitlines()))
        log.exception("An error occurred while assembling:\n%s" % lines)
    else:
        atexit.register(lambda: shutil.rmtree(tmpdir))

    return result

@LocalContext
def disasm(data, vma = 0, byte = True, offset = True, instructions = True):
    """disasm(data, ...) -> str

    Disassembles a bytestring into human readable assembler.

    To see which architectures are supported,
    look in :mod:`pwnlib.contex`.

    To support all these architecture, we bundle the GNU objcopy
    and objdump with pwntools.

    Arguments:
      data(str): Bytestring to disassemble.
      vma(int): Passed through to the --adjust-vma argument of objdump
      byte(bool): Include the hex-printed bytes in the disassembly
      offset(bool): Include the virtual memory address in the disassembly

    Kwargs:
      Any arguments/properties that can be set on ``context``

    Examples:

        .. doctest::

          >>> print disasm('b85d000000'.decode('hex'), arch = 'i386')
             0:   b8 5d 00 00 00          mov    eax,0x5d
          >>> print disasm('b85d000000'.decode('hex'), arch = 'i386', byte = 0)
             0:   mov    eax,0x5d
          >>> print disasm('b85d000000'.decode('hex'), arch = 'i386', byte = 0, offset = 0)
          mov    eax,0x5d
          >>> print disasm('b817000000'.decode('hex'), arch = 'amd64')
             0:   b8 17 00 00 00          mov    eax,0x17
          >>> print disasm('48c7c017000000'.decode('hex'), arch = 'amd64')
             0:   48 c7 c0 17 00 00 00    mov    rax,0x17
          >>> print disasm('04001fe552009000'.decode('hex'), arch = 'arm')
             0:   e51f0004        ldr     r0, [pc, #-4]   ; 0x4
             4:   00900052        addseq  r0, r0, r2, asr r0
          >>> print disasm('4ff00500'.decode('hex'), arch = 'thumb', bits=32)
             0:   f04f 0005       mov.w   r0, #5
          >>>
    """
    result = ''

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
    except Exception:
        log.exception("An error occurred while disassembling:\n%s" % data)
    else:
        atexit.register(lambda: shutil.rmtree(tmpdir))


    lines = []
    pattern = '^( *[0-9a-f]+: *)((?:[0-9a-f]+ )+ *)(.*)'
    for line in result.splitlines():
        try:
            o, b, i = re.search(pattern, line).groups()
        except:
            lines.append(line)
            continue

        line = ''

        if offset:
            line += o
        if byte:
            line += b
        if instructions:
            line += i
        lines.append(line)

    return '\n'.join(lines)
