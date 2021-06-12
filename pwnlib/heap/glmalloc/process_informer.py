import os.path
import pwnlib.util.proc
from pwnlib.heap.glmalloc.utils import (
    get_libc_version_from_name, get_main_arena_addr
)
from pwnlib.util.packing import u32, u64


class ProcessInformer:
    """Helper class with information about process memory such as pointer_size,
    and which allows perform operations over memory.

    Attributes:
        libc_version (tuple(int, int)): The glibc version in
            format (major, minor)
        pid (int): pid of the process
        pointer_size (int): size in bytes of a pointer in the process
        main_arena_address (int): address of the main arena malloc state

    """

    def __init__(self, pid, libc):
        libc_name = os.path.basename(libc.path)
        self.libc_version = get_libc_version_from_name(libc_name)
        self.pid = pid

        if "64" in libc.get_machine_arch():
            self.pointer_size = 8
            self.unpack_pointer = u64
        else:
            self.pointer_size = 4
            self.unpack_pointer = u32

        self.unpack_int = u32

        self.main_arena_address = get_main_arena_addr(libc, self.pointer_size)

    def read_memory(self, address, size):
        with open('/proc/%s/mem' % self.pid, 'rb') as mem:
            mem.seek(address)
            return mem.read(size)

    def maps(self):
        return pwnlib.util.proc.MemoryMaps.from_process(self.pid)

    def is_libc_version_higher_than(self, version):
        return self.libc_version > version

    def is_libc_version_lower_than(self, version):
        return self.libc_version < version


class CoreFileInformer:
    """Helper class with information about corefile such as pointer_size,
    and which allows perform operations over memory.

    Attributes:
        libc_version (tuple(int, int)): The glibc version in
            format (major, minor)
        pid (int): pid of the process
        pointer_size (int): size in bytes of a pointer in the process
        main_arena_address (int): address of the main arena malloc state

    """

    def __init__(self, corefile, libc):
        libc_name = os.path.basename(libc.path)
        self.libc_version = get_libc_version_from_name(libc_name)
        self.corefile = corefile

        if "64" in self.corefile.get_machine_arch():
            self.pointer_size = 8
            self.unpack_pointer = u64
        else:
            self.pointer_size = 4
            self.unpack_pointer = u32

        self.unpack_int = u32

        self.main_arena_address = get_main_arena_addr(libc, self.pointer_size)

    def read_memory(self, address, size):
        return self.corefile.read(address, size)

    def maps(self):
        return pwnlib.util.proc.MemoryMaps.from_str(str(self.corefile.mappings))

    def map_with_address(self, addr):
        for mapping in self.corefile.mappings:
            if mapping.start <= addr < mapping.stop:
                return mapping

        raise IndexError("address {:#x} out of range".format(addr))

    def is_libc_version_higher_than(self, version):
        return self.libc_version > version

    def is_libc_version_lower_than(self, version):
        return self.libc_version < version
