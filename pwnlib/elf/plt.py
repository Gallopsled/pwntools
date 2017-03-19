"""Emulates instructions in the PLT to locate symbols more accurately.
"""
import logging

from pwnlib.args import args
from pwnlib.log import getLogger
from pwnlib.util import fiddling
from pwnlib.util import packing

log = getLogger(__name__)

DEBUG = args.PLT_DEBUG or 0

if not DEBUG:
    log.setLevel(logging.DEBUG + 1)

def emulate_plt_instructions(elf, got, address, data, targets):
    """Emulates instructions in ``data``

    Arguments:
        elf(ELF): ELF that we are emulating
        got(int): Address of the GOT, as expected in e.g. EBX
        address(int): Address of ``data`` for emulation
        data(str): Array of bytes to emulate
        targets(list): List of target addresses

    Returns:
        :class:`dict`: Map of ``{address: target}`` for each address which
            reaches one of the selected targets.
    """
    rv = {}

    # Unicorn doesn't support big-endian for everything yet.
    if elf.endian == 'big' and elf.arch == 'mips':
        data = packing.unpack_many(data, bits=32, endian='little')
        data = packing.flat(data, bits=32, endian='big')

    # Brute force addresses, assume that PLT entry points are at 4-byte aligned
    # Do not emulate more than a handful of instructions.
    for i, pc in enumerate(range(address, address + len(data), 4)):
        if log.isEnabledFor(logging.DEBUG):
            log.debug('%s %#x', fiddling.enhex(data[i*4:(i+1) * 4]), pc)
            log.debug(elf.disasm(pc, 4))
        target = emulate_plt_instructions_inner(elf, got, pc, data[i*4:], targets)

        if target in targets:
            log.debug("%#x -> %#x", pc, target)
            rv[pc] = target

    return rv

def emulate_plt_instructions_inner(elf, got, pc, data, targets):
    # Deferred import to not affect load time
    import unicorn as U

    # Instantiate the emulator with the correct arguments for the current
    # architecutre.
    arch = {
        'aarch64': U.UC_ARCH_ARM64,
        'amd64': U.UC_ARCH_X86,
        'arm': U.UC_ARCH_ARM,
        'i386': U.UC_ARCH_X86,
        'mips': U.UC_ARCH_MIPS,
        # 'powerpc': U.UC_ARCH_PPC, <-- Not actually supported
        'thumb': U.UC_ARCH_ARM,
    }.get(elf.arch, None)

    if arch is None:
        log.warn("Could not emulate PLT instructions for %r" % elf)
        return {}

    emulation_bits = elf.bits

    # x32 uses 64-bit instructions, just restricts itself to a 32-bit
    # address space.
    if elf.arch == 'amd64' and elf.bits == 32:
        emulation_bits = 64

    mode = {
        32: U.UC_MODE_32,
        64: U.UC_MODE_64
    }.get(emulation_bits)

    if elf.arch in ('arm', 'aarch64'):
        mode = U.UC_MODE_ARM

    uc = U.Uc(arch, mode)

    # Map the page of memory, and fill it with the contents
    start = pc & (~0xfff)
    stop  = (pc + len(data) + 0xfff) & (~0xfff)

    if not (0 <= start <= stop <= (1 << elf.bits)):
        return None

    uc.mem_map(start, stop-start)
    uc.mem_write(pc, data)
    assert uc.mem_read(pc, len(data)) == data

    # MIPS is unique in that it relies entirely on _DYNAMIC, at the beginning
    # of the GOT.  Each PLT stub loads an address stored here.
    # Because of this, we have to support loading memory from this location.
    #
    # https://www.cr0.org/paper/mips.elf.external.resolution.txt
    magic_addr = 0xdbdbdbdb

    if elf.arch == 'mips':
        # Map the GOT so that MIPS can access it
        p_magic = packing.p32(magic_addr)
        start = got & (~0xfff)
        try:
            uc.mem_map(start, start+0x1000)
        except Exception:
            # Ignore double-mapping
            pass

        uc.mem_write(got, p_magic)

        # Separately, Unicorn is apparently unable to hook unmapped memory
        # accesses on MIPS.  So we also have to map the page that contains
        # the magic address.
        start = magic_addr & (~0xfff)
        try:
            uc.mem_map(start, start+0x1000)
        except Exception:
            # Ignore double-mapping
            pass
        trap = packing.p32(0x34000000, endian=elf.endian)
        uc.mem_write(magic_addr, trap)

    # Hook invalid addresses and any accesses out of the specified address range
    stopped_addr = []

    def hook_mem(uc, access, address, size, value, user_data):
        # Special case to allow MIPS to dereference the _DYNAMIC pointer
        # in the GOT.
        if elf.arch == 'mips' and address == got:
            return True

        user_data.append(address)
        uc.emu_stop()
        return False

    uc.hook_add(U.UC_HOOK_MEM_READ, hook_mem, stopped_addr)
    uc.hook_add(U.UC_HOOK_MEM_UNMAPPED, hook_mem, stopped_addr)

    # callback for tracing instructions
    # def hook_code(uc, address, size, user_data):
    #     print(">>> Tracing instruction at 0x%x, instruction size = 0x%x, data=%r" %(address, size, uc.mem_read(address, size)))
    # uc.hook_add(U.UC_HOOK_CODE, hook_code)

    # For Intel, set the value of EBX
    if elf.arch == 'i386':
        uc.reg_write(U.x86_const.UC_X86_REG_EBX, got)

    # Special case for MIPS, which is the most silly architecture
    # https://sourceware.org/ml/binutils/2004-11/msg00116.html
    if elf.arch == 'mips' and elf.bits == 32:
        OFFSET_GP_GOT = 0x7ff0
        uc.reg_write(U.mips_const.UC_MIPS_REG_GP, got + 0x7ff0)

    try:
        uc.emu_start(pc, until=-1, count=5)
    except U.UcError as error:
        UC_ERR = (k for k,v in \
                    U.unicorn_const.__dict__.items()
                    if error.errno == v and k.startswith('UC_ERR_')).next()
        log.debug("%#x: %s (%s)", pc, error, UC_ERR)

    if elf.arch == 'mips':
        pc = uc.reg_read(U.mips_const.UC_MIPS_REG_PC)
        if pc+1 == magic_addr:
            t8 = uc.reg_read(U.mips_const.UC_MIPS_REG_T8)
            stopped_addr.append(elf._mips_got.get(t8, 0))

    retval = 0
    if stopped_addr:
        retval = stopped_addr.pop()

    return retval
