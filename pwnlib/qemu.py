"""Run foreign-architecture binaries

So you want to exploit ARM binaries on your Intel PC?

Pwntools has a good level of integration with QEMU user-mode emulation,
in order to run, debug, and pwn foreign architecture binaries.

In general, everything magic happens "behind the scenes", and pwntools
attempts to make your life easier.

When using :class:`.process.process`, pwntools will attempt to blindly
execute the binary, in case your system is configured to use ``binfmt-misc``.

If this fails, pwntools will attempt to manually launch the binary under
qemu user-mode emulation.  Preference is given to statically-linked variants,
i.e. ``qemu-arm-static`` will be selected before ``qemu-arm``.

When debugging binaries with :func:`.gdb.debug`, pwntools automatically adds
the appropriate command-line flags to QEMU to start its GDB stub, and
automatically informs GDB of the correct architecture and sysroot.

You can override the default sysroot by setting the ``QEMU_LD_PREFIX``
environment variable.  This affects where ``qemu`` will look for files when
``open()`` is called, e.g. when the linker is attempting to resolve ``libc.so``.

"""
from __future__ import absolute_import

import os

from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import misc

log = getLogger(__name__)

@LocalContext
def archname():
    """
    Returns the name which QEMU uses for the currently selected
    architecture.

    >>> pwnlib.qemu.archname()
    'i386'
    >>> pwnlib.qemu.archname(arch='powerpc')
    'ppc'
    """
    return {
        ('amd64', 'little'):     'x86_64',
        ('arm', 'big'):          'armeb',
        ('mips', 'little'):      'mipsel',
        ('mips64', 'little'):    'mips64el',
        ('powerpc', 'big'):      'ppc',
        ('powerpc64', 'big'):    'ppc64',
        ('powerpc64', 'little'): 'ppc64le',
        ('thumb', 'little'):     'arm',
        ('thumb', 'big'):        'armeb',
    }.get((context.arch, context.endian), context.arch)

@LocalContext
def user_path():
    """
    Returns the path to the QEMU-user binary for the currently
    selected architecture.

    >>> pwnlib.qemu.user_path()
    'qemu-i386-static'
    >>> pwnlib.qemu.user_path(arch='thumb')
    'qemu-arm-static'
    """
    arch   = archname()
    normal = 'qemu-' + arch
    static = normal + '-static'

    if misc.which(static):
        return static

    if misc.which(normal):
        return normal

    log.warn_once("Neither %r nor %r are available" % (normal, static))

@LocalContext
def ld_prefix(path=None, env=None):
    """Returns the linker prefix for the selected qemu-user binary

    >>> pwnlib.qemu.ld_prefix(arch='arm')
    '/etc/qemu-binfmt/arm'
    """
    if path is None:
        path = get_qemu_user()

    # Did we explicitly specify the path in an environment variable?
    if 'QEMU_LD_PREFIX' in env:
        return env['QEMU_LD_PREFIX']

    if 'QEMU_LD_PREFIX' in os.environ:
        return os.environ['QEMU_LD_PREFIX']

    # Cyclic imports!
    from pwnlib.tubes.process import process

    with context.quiet:
        with process([path, '--help'], env=env) as io:
            line = io.recvline_regex('QEMU_LD_PREFIX *=')

    name, libpath = line.split('=', 1)

    return libpath.strip()

