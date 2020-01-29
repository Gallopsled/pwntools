from .utils import *
from .basic_formatter import *


class MallocChunkParser:
    """Class with the logic to parsing the malloc_chunk struct from binary
        data.

        Attributes:
            pid (int): Target process pid
            pointer_size (int): Size of pointers in target process
            unpack_pointer (func(bytes)): Function to get an int from the
                pointer bytes

        Args:
            process_informer (ProcessInformer): Helper to perform operations over
                memory
    """

    def __init__(self, process_informer):
        self.process_informer = process_informer
        self.pid = process_informer.pid
        self.pointer_size = process_informer.pointer_size
        self.unpack_pointer = process_informer.unpack_pointer

        self._raw_chunk_size = self.pointer_size * 6

    def parse_from_address(self, address):
        raw_chunk = self.process_informer.read_memory(
            address,
            self._raw_chunk_size
        )
        return self.parse_from_raw(address, raw_chunk)

    def parse_from_raw(self, address, raw_chunk):

        offset = 0
        previous_size = self.unpack_pointer(
            raw_chunk[offset: offset + self.pointer_size]
        )

        offset += self.pointer_size
        size_with_flags = self.unpack_pointer(
            raw_chunk[offset: offset + self.pointer_size]
        )

        offset += self.pointer_size
        fd = self.unpack_pointer(
            raw_chunk[offset: offset + self.pointer_size]
        )

        offset += self.pointer_size
        bk = self.unpack_pointer(
            raw_chunk[offset: offset + self.pointer_size]
        )

        offset += self.pointer_size
        fd_nextsize = self.unpack_pointer(
            raw_chunk[offset: offset + self.pointer_size]
        )

        offset += self.pointer_size
        bk_nextsize = self.unpack_pointer(
            raw_chunk[offset: offset + self.pointer_size]
        )

        size, prev_in_use, mmapped, main_arena = self._parse_size_and_flags(
            size_with_flags
        )

        return MallocChunk(
            address,
            previous_size,
            size,
            prev_in_use,
            mmapped,
            main_arena,
            fd,
            bk,
            fd_nextsize,
            bk_nextsize,
            self.pointer_size
         )

    def _parse_size_and_flags(self, size_with_flags):
        size = size_with_flags & ~0x7
        prev_in_use = bool(size_with_flags & 0x1)
        mmapped = bool(size_with_flags & 0x2)
        main_arena = bool(size_with_flags & 0x4)

        return size, prev_in_use, mmapped, main_arena


class MallocChunk:
    """Class to represent the information contained in the malloc_chunk struct
    of the glibc.

    ```c
    struct malloc_chunk {
      INTERNAL_SIZE_T      mchunk_prev_size;
      INTERNAL_SIZE_T      mchunk_size;
      struct malloc_chunk* fd;
      struct malloc_chunk* bk;
      struct malloc_chunk* fd_nextsize;
      struct malloc_chunk* bk_nextsize;
    };
    ```

    Attributes:
        address (int): The start address of the chunk
        previous_size (int): Size of the previous chunk (if previous is free)
        size (int): Size of the chunk
        prev_in_use (bool): True if previous chunk is being used (not free)
        mmapped (bool): True if chunk is allocated through mmap
        non_main_arena (bool): True if chunk resides in the main arena
        fd (int): Pointer to the next chunk of the bins (if chunk is free)
        bk (int): Pointer to the previous chunk of the bins (if chunk is free)
        fd_nextsize (int): Pointer to the next chunk with a larger size
            (only used in large bins)
        bk_nextsize (int): Pointer to the next chunk with an smaller size
            (only used in large bins)
        data_address (int): Address where starts the chunk user data
            (the address returned by malloc)
        size_with_flags (int): The raw size value of the chunk, which includes
            the NON_MAIN_ARENA, MMAPPED and PREV_IN_USE flags in the
            lowest-value bits

    """

    def __init__(self, address, previous_size, size, prev_in_use, mmapped,
                 non_main_arena, fd, bk, fd_nextsize, bk_nextsize, pointer_size):
        self.address = address
        self.previous_size = previous_size
        self.size = size
        self.prev_in_use = prev_in_use
        self.mmapped = mmapped
        self.non_main_arena = non_main_arena
        self.fd = fd
        self.bk = bk
        self.fd_nextsize = fd_nextsize
        self.bk_nextsize = bk_nextsize
        self.data_address = self.address + pointer_size * 2
        self.size_with_flags = size | int(non_main_arena)*4 | int(mmapped)*2 | int(prev_in_use)

        if pointer_size == 8:
            self._pack_pointer = p64
        else:
            self._pack_pointer = p32

    def __str__(self):
        string = ""
        string += "previous_size = {:#x}\n".format(self.previous_size)
        string += "size = {:#x}\n".format(self.size_with_flags)
        string += "fd = {:#x}\n".format(self.fd)
        string += "bk = {:#x}\n".format(self.bk)
        string += "fd_nextsize = {:#x}\n".format(self.fd_nextsize)
        string += "bk_nextsize = {:#x}\n".format(self.bk_nextsize)

        return string

    def format_first_bytes_as_hexdump_str(self):
        msg = []
        raw_bytes = self._fd_bytes()
        raw_bytes += self._bk_bytes()

        for byte in raw_bytes:
            msg.append("{:02x} ".format(byte))

        msg.append("  ")

        for byte in raw_bytes:
            msg.append(
                chr(byte) if 0x20 <= byte < 0x7F else "."
            )

        return "".join(msg)

    def _fd_bytes(self):
        return bytearray(self._pack_pointer(self.fd))

    def _bk_bytes(self):
        return bytearray(self._pack_pointer(self.bk))

    def format_flags_as_str(self):
        flags = []
        if self.non_main_arena:
            flags.append("NON_MAIN_ARENA")
        if self.mmapped:
            flags.append("MMAPPED")
        if self.prev_in_use:
            flags.append("PREV_IN_USE")

        return "|".join(flags)
