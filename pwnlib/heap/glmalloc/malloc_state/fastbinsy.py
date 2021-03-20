from pwnlib.util.packing import u64, u32
from pwnlib.heap.glmalloc.bins import FastBinEntry


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
    """

    def __init__(self, entries):
        #: :class:`list` of :class:`FastBinEntry`: Pointers to the first chunks
        #: of the each fast bin.
        self.entries = entries

    def __getitem__(self, index):
        return self.entries[index]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)
