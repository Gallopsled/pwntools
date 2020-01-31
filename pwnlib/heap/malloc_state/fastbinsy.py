from pwnlib.heap.utils import *
from pwnlib.heap.bins.fast_bin import FastBinEntry


class FastBinsYParser:
    """Class with the logic to parse the `fastbinsY` attribute of the
    `malloc_state` struct.

    Args:
         pointer_size (int): The pointer size in bytes of the process.
    """

    def __init__(self, pointer_size):
        self._pointer_size = pointer_size
        if pointer_size == 8:
            self._u = u64
        else:
            self._u = u32

    def parse_from_collection(self, base_address, collection_array):
        """Returns a FastBinsY object by parsing a `fastbinsY` binary array.

        Args:
            collection_array (bytes): Binary `fastbinsY` array of `malloc_state` struct.

        Returns:
            FastBinsY
        """

        base_size = self._pointer_size * 4
        entries = []
        for i, fd in enumerate(collection_array):
            address = base_address + i * self._pointer_size
            chunks_size = base_size + i * self._pointer_size * 2
            entries.append(FastBinEntry(address, fd, chunks_size))

        return FastBinsY(entries)


class FastBinsY:
    """Class to represent the `fastbinsY` attribute of malloc_state struct.

    Attributes:
        entries (list of :class:`FastBinEntry`): pointers to the first chunks
            of the each fast bin.
    """

    def __init__(self, entries):
        self.entries = entries

    def __getitem__(self, index):
        return self.entries[index]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    def __str__(self):
        string = ""

        i = 1
        for fast_bin_entry in self.entries:
            string += "{} Fastbin [{:#x}] => {:#x}\n".format(
                i,
                fast_bin_entry.chunks_size,
                fast_bin_entry.fd
            )
            i += 1

        return string
