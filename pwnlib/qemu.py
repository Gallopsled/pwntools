"""Run foreign-architecture binaries

Overview
--------

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

Debugging
~~~~~~~~~

When debugging binaries with :func:`.gdb.debug`, pwntools automatically adds
the appropriate command-line flags to QEMU to start its GDB stub, and
automatically informs GDB of the correct architecture and sysroot.

Sysroot
~~~~~~~
You can override the default sysroot by setting the ``QEMU_LD_PREFIX``
environment variable.  This affects where ``qemu`` will look for files when
``open()`` is called, e.g. when the linker is attempting to resolve ``libc.so``.

Required Setup
--------------

For Ubuntu 16.04 and newer, the setup is relatively straightforward for most
architectures.

First, install the QEMU emulator itself.  If your binary is statically-linked,
thsi is sufficient.

    $ sudo apt-get install qemu-user

If your binary is dynamically linked, you need to install libraries like libc.
Generally, this package is named ``libc6-$ARCH-cross``, e.g. ``libc-mips-cross``.
ARM comes in both soft-float and hard-float variants, e.g. ``armhf``.

    $ sudo apt-get install libc6-arm64-cross

If your binary relies on additional libraries, you can generally find them
easily with ``apt-cache search``.  For example, if it's a C++ binary it
may require ``libstdc++``.

    $ apt-cache search 'libstdc++' | grep arm64

Any other libraries that you require you'll have to find some other way.

Telling QEMU Where Libraries Are
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The libraries are now installed on your system at e.g. ``/usr/aarch64-linux-gnu``.

QEMU does not know where they are, and expects them to be at e.g. ``/etc/qemu-binfmt/aarch64``.
If you try to run your library now, you'll probably see an error about ``libc.so.6`` missing.

Create the ``/etc/qemu-binfmt`` directory if it does not exist, and create a symlink to
the appropriate path.

    $ sudo mkdir /etc/qemu-binfmt
    $ sudo ln -s /usr/aarch64-linux-gnu /etc/qemu-binfmt/aarch64

Now QEMU should be able to run the libraries.
"""
from __future__ import absolute_import
from __future__ import division

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
    system = 'qemu-system-' + arch
    normal = 'qemu-' + arch
    static = normal + '-static'

    if context.os == 'baremetal':
        if misc.which(system):
            return system
    else:
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
    if context.os == 'baremetal':
        return ""

    if path is None:
        path = user_path()

    # Did we explicitly specify the path in an environment variable?
    if env and 'QEMU_LD_PREFIX' in env:
        return env['QEMU_LD_PREFIX']

    if 'QEMU_LD_PREFIX' in os.environ:
        return os.environ['QEMU_LD_PREFIX']

    # Cyclic imports!
    from pwnlib.tubes.process import process

    with context.quiet:
        with process([path, '--help'], env=env) as io:
            line = io.recvline_regex(b'QEMU_LD_PREFIX *=')

    _, libpath = line.split(b'=', 1)

    libpath = libpath.strip()

    if not isinstance(libpath, str):
        libpath = libpath.decode('utf-8')

    return libpath

