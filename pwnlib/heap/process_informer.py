from .utils import *
from .memory_maps import MemoryMaps
import os.path


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
        return MemoryMaps.from_process(self.pid)

    def is_libc_version_higher_than(self, version):
        return self.libc_version > version

    def is_libc_version_lower_than(self, version):
        return self.libc_version < version
