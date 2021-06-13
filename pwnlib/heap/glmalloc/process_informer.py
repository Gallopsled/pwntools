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
        process : The process to explore
        libc_version (tuple(int, int)): The glibc version in
            format (major, minor)
        pointer_size (int): size in bytes of a pointer in the process
        main_arena_address (int): address of the main arena malloc state

    """

    def __init__(self, process, libc_version=None):
        self.process = process
        libc = process._libc()

        if "64" in libc.get_machine_arch():
            self.pointer_size = 8
            self.unpack_pointer = u64
        else:
            self.pointer_size = 4
            self.unpack_pointer = u32

        self.unpack_int = u32

        libc_name = os.path.basename(libc.path)
        self.libc_version = libc_version or get_libc_version_from_name(libc_name)
        self.main_arena_address = get_main_arena_addr(libc, self.pointer_size)

    def read_memory(self, address, size):
        return self.process.leak(address, size)

    def map_with_address(self, addr):
        for mapping in self.process.mappings:
            if mapping.start <= addr < mapping.stop:
                return mapping

        raise IndexError("address {:#x} out of range".format(addr))

    def is_libc_version_higher_than(self, version):
        return self.libc_version > version

    def is_libc_version_lower_than(self, version):
        return self.libc_version < version


class CoreFileInformer:
    """Helper class with information about corefile such as pointer_size,
    and which allows perform operations over memory.

    Attributes:
        corefile : The corefile to explore
        libc_version (tuple(int, int)): The glibc version in
            format (major, minor)
        pointer_size (int): size in bytes of a pointer in the process
        main_arena_address (int): address of the main arena malloc state

    """

    def __init__(self, corefile, libc, libc_version=None):
        self.corefile = corefile

        if "64" in self.corefile.get_machine_arch():
            self.pointer_size = 8
            self.unpack_pointer = u64
        else:
            self.pointer_size = 4
            self.unpack_pointer = u32

        self.unpack_int = u32

        # read the libc version from corefile since libc can be provided by an user
        # from a different path that does not include the version
        libc_map = corefile.libc
        libc_name = os.path.basename(libc_map.path)
        self.libc_version = libc_version or get_libc_version_from_name(libc_name)

        # libc required to read symbols and locate the main arena address
        self.main_arena_address = get_main_arena_addr(libc, self.pointer_size)

    def read_memory(self, address, size):
        return self.corefile.read(address, size)

    def map_with_address(self, addr):
        for mapping in self.corefile.mappings:
            if mapping.start <= addr < mapping.stop:
                return mapping

        raise IndexError("address {:#x} out of range".format(addr))

    def is_libc_version_higher_than(self, version):
        return self.libc_version > version

    def is_libc_version_lower_than(self, version):
        return self.libc_version < version
