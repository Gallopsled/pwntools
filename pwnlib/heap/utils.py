import re
from pwnlib.util import packing


def u32(bytes_):
    return packing.u32(bytes_)


def u64(bytes_):
    return packing.u64(bytes_)


def p32(number):
    return packing.p32(number)


def p64(number):
    return packing.p64(number)


def read_memory(pid, address, size):
    with open('/proc/%s/mem' % pid, 'rb') as mem:
        mem.seek(address)
        return mem.read(size)


def write_memory(pid, address, buffer):
    with open('/proc/%s/mem' % pid, 'wb') as mem:
        mem.seek(address)
        return mem.write(buffer)


def align_address(address, align):
    """Align the address to the given size."""
    return address + ((align - (address % align)) % align)


def get_libc_version_from_name(name):
    libc_version = tuple(int(_) for _ in re.search(r"libc6?[-_](\d+)\.(\d+)\.so", name).groups())
    return libc_version


def get_main_arena_addr(libc, pointer_size):
    malloc_hook_addr = libc.symbols["__malloc_hook"]
    return align_address(malloc_hook_addr + pointer_size, 0x20)  # only for x86, for arm is other technique
