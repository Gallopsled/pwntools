"""Emulates instructions in the PLT to locate symbols more accurately.
"""
from pwnlib.context import context
from pwnlib.log import getLogger

log = getLogger(__name__)


def emulate_plt_instructions(elf, ebx, address, data, targets):
    """Emulates instructions in ``data``

    Arguments:
        address(int): Address of ``data`` for emulation
        data(str): Array of bytes to emulate
        targets(list): List of target addresses

    Returns:
        :class:`dict`: Map of ``{address: target}`` for each address which
            reaches one of the selected targets.
    """
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
    }.get(context.arch, None)

    if arch is None:
        log.warn("Could not emulate PLT instructions for %r" % elf.path)
        return {}

    mode = {
        32: U.UC_MODE_32,
        64: U.UC_MODE_64
    }.get(context.bits)

    if context.arch in ('arm', 'aarch64'):
        mode = U.UC_MODE_ARM

    if context.endian == 'little':
        mode |= U.UC_MODE_LITTLE_ENDIAN
    else:
        mode |= U.UC_MODE_BIG_ENDIAN

    uc = U.Uc(arch, mode)

    # Map the page of memory, and fill it with the contents
    start = address & (~0xfff)
    stop  = (address + len(data) + 0xfff) & (~0xfff)
    uc.mem_map(start, stop-start)
    uc.mem_write(address, data)
    assert uc.mem_read(address, len(data)) == data

    # Hook invalid addresses and any accesses out of the specified address range
    stopped_addr = []

    def hook_mem(uc, access, address, size, value, user_data):
        user_data.append(address)
        uc.emu_stop()
        return False

    uc.hook_add(U.UC_HOOK_MEM_READ, hook_mem, stopped_addr)
    uc.hook_add(U.UC_HOOK_MEM_UNMAPPED, hook_mem, stopped_addr)

    # Brute force addresses, assume that PLT entry points are 8-byte-aligned
    # Do not emulate more than a handful of instructions.
    rv = {}
    for pc in range(address, address + len(data), 8):

        # For Intel, set the value of EBX
        if context.arch == 'i386' and ebx:
            uc.reg_write(U.x86_const.UC_X86_REG_EBX, ebx)

        # Special case on ARM, do not emulate all-zero NOPs
        if elf.read(pc, 4) == '\x00\x00\x00\x00':
            continue

        try:
            uc.emu_start(pc, until=-1, count=4)
        except U.UcError:
            continue

        if not stopped_addr:
            continue

        address = stopped_addr.pop()

        log.debug("%#x -> %#x", pc, address)

        if address in targets:
            rv[pc] = address

    return rv
