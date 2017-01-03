from __future__ import absolute_import

from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import misc

log = getLogger(__name__)

@LocalContext
def get_qemu_arch():
    """
    Returns the name which QEMU uses for the currently selected
    architecture.

    >>> get_qemu_arch()
    'i386'
    >>> get_qemu_arch(arch='powerpc')
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
def get_qemu_user():
    """
    Returns the path to the QEMU-user binary for the currently
    selected architecture.

    >>> get_qemu_user()
    'qemu-i386-static'
    >>> get_qemu_user(arch='thumb')
    'qemu-arm-static'
    """
    arch   = get_qemu_arch()
    normal = 'qemu-' + arch
    static = normal + '-static'

    if misc.which(static):
        return static

    if misc.which(normal):
        return normal

    log.warn_once("Neither %r nor %r are available" % (normal, static))
