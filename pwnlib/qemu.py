from .context import context, LocalContext

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
