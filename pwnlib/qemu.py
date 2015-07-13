from .context import context, LocalContext
from .util import misc

@LocalContext
def get_qemu_arch():
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
    arch   = get_qemu_arch()
    normal = 'qemu-' + arch
    static = normal + '-static'

    if misc.which(static):
        return static

    if misc.which(normal):
        return normal

    log.error("Neither %r nor %r are available" % (normal, static))
