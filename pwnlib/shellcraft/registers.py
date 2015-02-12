import re

from ..context import context
from ..util.misc import register_sizes

mips =  map('r{}'.format, range(32))
mips += map('v{}'.format, range(2))
mips += map('a{}'.format, range(4))
mips += map('t{}'.format, range(8))
mips += map('s{}'.format, range(9))
mips += map('t{}'.format, range(8,10))
mips += map('k{}'.format, range(2))
mips += ['zero', 'at', 'gp', 'sp', 'ra']

arm = map('r{}'.format, range(13))
arm += ["sp", "lr", "pc", "cpsr"]

i386_baseregs = [ "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "ip"]

i386 = map('e{}'.format, i386_baseregs)
i386 += i386_baseregs
i386 += [ "eflags", "cs", "ss", "ds", "es", "fs", "gs", ]

amd64 =  map('r{}'.format, i386_baseregs)
amd64 += map('r{}'.format, range(10,16))
amd64 += map('r{}d'.format, range(10,16))
amd64 += i386

powerpc =  map('r{}'.format, range(32))
powerpc += ["pc", "msr", "cr", "lr", "ctr", "xer", "orig_r3", "trap" ]
powerpc =  map('%{}'.format, powerpc)

sparc =  map('g{}'.format, range(8))
sparc += map('o{}'.format, range(5))
sparc += map('l{}'.format, range(8))
sparc += map('i{}'.format, range(5))
sparc += ["pc", "sp", "fp", "psr" ]
sparc =  map('%{}'.format, sparc)



# x86/amd64 registers in decreasing size
i386_ordered = [
    ['rax', 'eax', 'ax', 'al'],
    ['rbx', 'ebx', 'bx', 'bl'],
    ['rcx', 'ecx', 'cx', 'cl'],
    ['rdx', 'edx', 'dx', 'dl'],
    ['rdi', 'edi', 'di'],
    ['rsi', 'esi', 'si'],
    ['rbp', 'ebp', 'bp'],
    ['rsp', 'esp', 'sp'],
    ['r8', 'r8d', 'r8w', 'r8b'],
    ['r9', 'r9d', 'r9w', 'r9b'],
    ['r10', 'r10d', 'r10w', 'r10b'],
    ['r11', 'r11d', 'r11w', 'r11b'],
    ['r12', 'r12d', 'r12w', 'r12b'],
    ['r13', 'r13d', 'r13w', 'r13b'],
    ['r14', 'r14d', 'r14w', 'r14b'],
    ['r15', 'r15d', 'r15w', 'r15b']
]

all_regs, sizes, bigger, smaller = register_sizes(i386_ordered, [64, 32, 16, 8, 8])
native64 = {k:v[0] for k,v in bigger.items()}
native32 = {k:v[1] for k,v in bigger.items() if not k.startswith('r')}

class Register(object):
    #: Register name
    name = None

    #: List of larger registers, in order from largest to smallest
    bigger = None

    #: List of smaller regsters, in order from smallest to largest
    smaller = None

    #: Size of the register, in bits
    size = None

    #: Does this register have a 'high' register for mask 0xff00
    ff00 = None

    #: Flags for 64-bit mode.64-bit
    #: The first bit is set, if the register can be used with a REX-mode
    #: The second bit is set, if the register can be used without a REX-prefix
    rex_mode = 0

    #: Is this a 64-bit only register?
    is64bit = False

    #: Name of the native 64-bit register
    native64 = None

    #: Name of the native 32-bit register
    native32 = None

    #: Name of the register which should be used to clear
    #: this register, e.g. xor REG, REG.
    #: Useful for AMD64 for xor eax, eax is shorter than
    #: xor rax, rax and has the same effect.
    xor = None

    def __init__(self, name, size):
        self.name = name
        self.size = size

        for row in i386_ordered:
            if name in row:
                self.bigger  = row[0:row.index(name)]
                self.smaller = row[row.index(name)+1:]
                self.sizes   = {64>>i:r for i,r in enumerate(row)}
                self.native64 = row[0]
                self.native32 = row[1]
                self.xor = self.sizes[min(self.size, 32)]

        if self.size >= 32 and name.endswith('x'):
            self.ff00 = name[1] + 'h'

        if name[-1] != 'h':
            self.rex_mode |= 1

        if name[0] != 'r':
            self.rex_mode |= 2

        if name.startswith('r') or name[1:3].isdigit():
            self.is64bit = True

    def fits(self, value):
        return self.size >= bits_required(value)

    def __str__(self):
        return self.name

    def __repr__(self):
        return "Register(%r)" % self.namepyth

intel = {}

for row in i386_ordered:
    for i, reg in enumerate(row):
        intel[reg] = Register(reg, 64 >> i)

def get_register(name):
    return intel.get(name, None)

def is_register(obj):
    if isinstance(obj, Register):
        return True
    return get_register(obj)


def bits_required(value):
    bits  = 0

    if value < 0:
        value = -(value)

    while value:
        value >>= 8
        bits += 8
    return bits


# def is_register(sz):
#     try:
#         sz = sz.lower()
#         return sz.lower() in {
#         'i386': i386,
#         'amd64': amd64,
#         'powerpc': powerpc,
#         'sparc': sparc,
#         'arm': arm,
#         'aarch64': arm,
#         'thumb': arm,
#         'mips': mips,
#         'mips64': mips
#         }[context.arch]
#     except:
#         return False

def register_size(reg):
    return sizes[reg]

def fits_in_register(reg, value):
    return register_size(reg) >= bits_required(value)
