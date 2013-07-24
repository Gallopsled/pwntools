from pwn.internal.shellcode_helper import *
import pwn
import string

@shellcode_reqs(arch=['i386', 'amd64', 'arm', 'thumb'])
def mov(dest, src, stack_allowed = True, arch = None):
    """Does a mov into the dest while newlines and null characters.

    The src can be be an immediate or another register.

    If the stack is not allowed to be used, set stack_allowed to False.
    """

    comment = '// Set %s = %s\n' % (dest, src)

    src = arg_fixup(src)
    allowed = pwn.get_only()

    if src == dest:
        return "// setting %s to %s, but this is a no-op" % (dest, src)

    if arch == 'i386':
        return comment + _mov_i386(dest, src, stack_allowed)
    elif arch == 'amd64':
        return comment + _mov_amd64(dest, src, stack_allowed)
    elif arch == 'arm':
        return comment + _mov_arm(dest, src)
    elif arch == 'thumb':
        return comment + _mov_thumb(dest, src)

    no_support('mov', 'any', arch)

def _fix_regs(regs, in_sizes):
    sizes = {}
    bigger = {}
    smaller = {}

    for l in regs:
        for r, s in zip(l, in_sizes):
            sizes[r] = s

        for n, r in enumerate(l):
            bigger[r] = [r_ for r_ in l if sizes[r_] > sizes[r] or r == r_]
            smaller[r] = [r_ for r_ in l if sizes[r_] < sizes[r]]

    return pwn.concat(regs), sizes, bigger, smaller


def _mov_i386(dest, src, stack_allowed):
    regs = [['eax', 'ax', 'al', 'ah'],
            ['ebx', 'bx', 'bl', 'bh'],
            ['ecx', 'cx', 'cl', 'ch'],
            ['edx', 'dx', 'dl', 'dh'],
            ['edi', 'di'],
            ['esi', 'si'],
            ['ebp', 'bp'],
            ['esp', 'sp'],
            ]

    all_regs, sizes, bigger, smaller = _fix_regs(regs, [32, 16, 8, 8])

    if dest not in all_regs:
        bug('%s is not a register' % str(dest))

    if isinstance(src, int):
        if src >= 2**sizes[dest] or src < -(2**(sizes[dest]-1)):
            pwn.log.warning('Number 0x%x does not fit into %s' % (src, dest))

        srcp = packs_little_endian[sizes[dest]](src)

        if src == 0:
            return 'xor %s, %s' % (dest, dest)

        if '\x00' not in srcp and '\n' not in srcp:
            return 'mov %s, 0x%x' % (dest, src)

        if stack_allowed and sizes[dest] == 32 and -128 <= src <= 127 and src != 0xa:
            return 'push 0x%x\npop %s' % (src, dest)

        if stack_allowed and sizes[dest] == 16 and -128 <= src <= 127 and src != 0xa:
            return 'push 0x%x\npop %s\ninc esp\ninc esp' % (src, dest)

        a,b = pwn.xor_pair(srcp, avoid = '\x00\n')
        u = unpacks_little_endian[sizes[dest]]
        a = u(a)
        b = u(b)
        return 'mov %s, 0x%x\nxor %s, 0x%x' % (dest, a, dest, b)

    elif src in all_regs:
        if src == dest or src in bigger[dest] or src in smaller[dest]:
            return ''
        elif sizes[dest] == sizes[src]:
            return 'mov %s, %s' % (dest, src)
        elif sizes[dest] > sizes[src]:
            return 'movzx %s, %s' % (dest, src)
        else:
            for r in bigger[dest]:
                if sizes[r] == sizes[src]:
                    return 'mov %s, %s' % (r, src)
            bug('Register %s could not be moved into %s' % (src, dest))

    bug('%s is neither a register nor an immediate' % src)

def _mov_amd64(dest, src, stack_allowed):
    regs = [['rax', 'eax', 'ax', 'al'],
            ['rbx', 'ebx', 'bx', 'bl'],
            ['rcx', 'ecx', 'cx', 'cl'],
            ['rdx', 'edx', 'dx', 'dl'],
            ['rdi', 'edi', 'di', 'dil'],
            ['rsi', 'esi', 'si', 'sil'],
            ['rbp', 'ebp', 'bp', 'bpl'],
            ['rsp', 'esp', 'sp', 'spl'],
            ['r8', 'r8d', 'r8w', 'r8b'],
            ['r9', 'r9d', 'r9w', 'r9b'],
            ['r10', 'r10d', 'r10w', 'r10b'],
            ['r11', 'r11d', 'r11w', 'r11b'],
            ['r12', 'r12d', 'r12w', 'r12b'],
            ['r13', 'r13d', 'r13w', 'r13b'],
            ['r14', 'r14d', 'r14w', 'r14b'],
            ['r15', 'r15d', 'r15w', 'r15b']
            ]

    all_regs, sizes, bigger, smaller = _fix_regs(regs, [64, 32, 16, 8, 8])

    if dest not in all_regs:
        bug('%s is not a register' % str(dest))

    if isinstance(src, int):
        if src >= 2**sizes[dest] or src < -(2**(sizes[dest]-1)):
            pwn.log.warning('Number 0x%x does not fit into %s' % (src, dest))

        srcp = packs_little_endian[sizes[dest]](src)

        if src == 0:
            if sizes[dest] == 64:
                return 'xor %s, %s' % (smaller[dest][0], smaller[dest][0])
            else:
                return 'xor %s, %s' % (dest, dest)

        if '\x00' not in srcp and '\n' not in srcp:
            return 'mov %s, 0x%x' % (dest, src)

        if stack_allowed and sizes[dest] == 64 and -128 <= src <= 127 and src != 0xa:
            return 'push 0x%x\npop %s' % (src, dest)

        # TODO: is it a good idea to transform mov('eax', 17) to mov('rax', 17)
        # automatically?
        if stack_allowed and sizes[dest] == 32 and -128 <= src <= 127 and src != 0xa:
            return 'push 0x%x\npop %s' % (src, bigger[dest][0])

        a,b = pwn.xor_pair(srcp, avoid = '\x00\n')
        u = unpacks_little_endian[sizes[dest]]
        a = u(a)
        b = u(b)
        return 'mov %s, 0x%x\nxor %s, 0x%x' % (dest, a, dest, b)

    elif src in all_regs:
        if src == dest or src in bigger[dest] or src in smaller[dest]:
            return ''
        elif sizes[dest] == sizes[src]:
            return 'mov %s, %s' % (dest, src)
        elif sizes[dest] == 64 and sizes[src] == 32:
            return 'mov %s, %s' % (smaller[dest][0], src)
        elif sizes[dest] > sizes[src]:
            return 'movzx %s, %s' % (dest, src)
        else:
            for r in bigger[dest]:
                if sizes[r] == sizes[src]:
                    return 'mov %s, %s' % (r, src)
            bug('Register %s could not be moved into %s' % (src, dest))

    bug('%s is neither a register nor an immediate' % src)

def _mov_arm(dst, src):
    import string

    if not isinstance(src, int):
        return "mov %s, %s" % (dst, src)

    if len(asm("ldr %s, =%d" % (dst, src))) == 4:
        return "ldr %s, =%d" % (dst, src)

    srcu =  src & 0xffffffff
    srcn = ~src & 0xffffffff

    for n, op in zip([srcu, srcn], ['mov', 'mvn']):
        shift1 = 0
        while (0x03 << shift1) & n == 0:
            shift1 += 2

        shift2 = shift1 + 8

        while (0x03 << shift2) & n == 0:
            shift2 += 2

        if n == (n & (0xff << shift1)) + (n & (0xff << shift2)):
            return '\n'.join([
                "// mov %s, #%d" % (dst, src),
                "%s %s, #%d" % (op,    dst, (n & (0xff << shift1))),
                "%s %s, #%d" % ("eor", dst, (n & (0xff << shift2)))
            ])

    id = pwn.randoms(32, only = string.ascii_lowercase)

    return '\n'.join([
        "ldr %s, %s" % (dst, id),
        "b %s_after" % id,
        "%s: .word %d" % (id, src),
        "%s_after:" % id])

def _mov_thumb(dst, src):
    if not isinstance(src, int):
        return "mov %s, %s" % (dst, src)

    srcu = src & 0xffffffff
    srcs = srcu - 2 * (srcu & 0x80000000)

    if srcu == 0:
        return 'eor %s, %s' % (dst, dst)

    if srcu < 256:
        return 'mov %s, #%d' % (dst, src)

    if -256 < srcs < 0:
        return 'eor %s, %s\nsub %s, #%d' % (dst, dst, dst, -srcs)

    shift1 = 0
    while (1 << shift1) & src == 0:
        shift1 += 1

    if (0xff << shift1) & src == src:
        if shift1 < 4:
            return 'mov %s, #%d\nlsl %s, #4\nlsr %s, #%d' % (dst, src >> shift1, dst, dst, 4-shift1)
        return 'mov %s, #%d\nlsl %s, #%d' % (dst, src >> shift1, dst, shift1)

    shift2 = 8
    while (1 << shift2) & src == 0:
        shift2 += 1

    if ((0xff << shift2) | 0xff) & src == src:
        return 'mov %s, #%d\nlsl %s, #%d\nadd %s, #%d' % (dst, src >> shift2, dst, shift2, dst, src & 0xff)

    shift3 = shift1 + 8
    while (1 << shift3) & src == 0:
        shift3 += 1

    if ((0xff << shift1) | (0xff << shift3)) & src == src:
        return 'mov %s, #%d\nlsl %s, #%d\nadd %s, #%d\nlsl %s, #%d' % (dst, src >> shift3, dst, shift3 - shift1, dst, (src >> shift1) & 0xff, dst, shift1)

    id = pwn.randoms(32, only = string.ascii_lowercase)

    if (src & 0xFF000000 == 0x0):
        src = src | 0xFF000000

        extra = ''.join([
        "lsl %s, #8" % dst,
        "lsr %s, #8" % dst,
        ])

    return '\n'.join([
        "ldr %s, %s" % (dst, id),
        "b %s_after" % id,
        "%s: .word %d" % (id, src),
        "%s_after:" % id,
		extra])
