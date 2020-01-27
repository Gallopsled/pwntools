
from pwnlib.heap.utils import *
from .bins import Bins
from pwnlib.heap.bins import *
from .bins_indexes import *


class BinsParser:
    """Class with the logic to parse the `bins` attribute of the
    `malloc_state` struct.

    Args:
         pointer_size (int): The pointer size in bytes of the process.
    """

    def __init__(self, pointer_size):
        self._pointer_size = pointer_size
        if pointer_size == 8:
            self._largebin_index_to_min_size = largebin64_index_to_min_size
        else:
            self._largebin_index_to_min_size = largebin32_index_to_min_size

    def parse_from_collection(self, base_address, collection_array):
        """Returns a FastBinsY object by parsing a `bins` binary array.

        Args:
            collection_array (bytes): Binary `bins` array of `malloc_state` struct.

        Returns:
            Bins
        """

        num_entries = len(collection_array)
        entries = []

        for i in range(0, num_entries, 2):
            fd = collection_array[i]
            bk = collection_array[i + 1]
            address = base_address + i * self._pointer_size

            index = int(i / 2)
            entry = self._to_bin_entry(index, address, fd, bk)
            entries.append(entry)

        return Bins(entries)

    def _to_bin_entry(self, index, address, fd, bk):
        if index < SMALL_BINS_START_INDEX:
            return UnsortedBinEntry(address, fd, bk)
        elif index < LARGE_BINS_START_INDEX:
            chunks_size = self._bin_index_to_size(index)
            return SmallBinEntry(address, fd, bk, chunks_size)
        else:
            min_chunks_size = self._bin_index_to_size(index)
            return LargeBinEntry(address, fd, bk, min_chunks_size)

    def _bin_index_to_size(self, index):
        if index < SMALL_BINS_START_INDEX:
            return 0
        elif index < LARGE_BINS_START_INDEX:
            return (self._pointer_size * 4) + (index - 1) * (self._pointer_size * 2)
        elif index < 126:
            return self._largebin_index_to_min_size[index+1]
        else:
            return 0x100000


largebin32_index_to_min_size = {
    64: 0x200,
    65: 0x240,
    66: 0x280,
    67: 0x2c0,
    68: 0x300,
    69: 0x340,
    70: 0x380,
    71: 0x3c0,
    72: 0x400,
    73: 0x440,
    74: 0x480,
    75: 0x4c0,
    76: 0x500,
    77: 0x540,
    78: 0x580,
    79: 0x5c0,
    80: 0x600,
    81: 0x640,
    82: 0x680,
    83: 0x6c0,
    84: 0x700,
    85: 0x740,
    86: 0x780,
    87: 0x7c0,
    88: 0x800,
    89: 0x840,
    90: 0x880,
    91: 0x8c0,
    92: 0x900,
    93: 0x940,
    94: 0x980,
    95: 0x9c0,
    96: 0xa00,
    97: 0xc00,
    98: 0xe00,
    99: 0x1000,
    100: 0x1200,
    101: 0x1400,
    102: 0x1600,
    103: 0x1800,
    104: 0x1a00,
    105: 0x1c00,
    106: 0x1e00,
    107: 0x2000,
    108: 0x2200,
    109: 0x2400,
    110: 0x2600,
    111: 0x2800,
    112: 0x2a00,
    113: 0x3000,
    114: 0x4000,
    115: 0x5000,
    116: 0x6000,
    117: 0x7000,
    118: 0x8000,
    119: 0x9000,
    120: 0xa000,
    121: 0x10000,
    122: 0x18000,
    123: 0x20000,
    124: 0x28000,
    125: 0x40000,
    126: 0x80000
}


largebin64_index_to_min_size = {
    64: 0x400,
    65: 0x440,
    66: 0x480,
    67: 0x4c0,
    68: 0x500,
    69: 0x540,
    70: 0x580,
    71: 0x5c0,
    72: 0x600,
    73: 0x640,
    74: 0x680,
    75: 0x6c0,
    76: 0x700,
    77: 0x740,
    78: 0x780,
    79: 0x7c0,
    80: 0x800,
    81: 0x840,
    82: 0x880,
    83: 0x8c0,
    84: 0x900,
    85: 0x940,
    86: 0x980,
    87: 0x9c0,
    88: 0xa00,
    89: 0xa40,
    90: 0xa80,
    91: 0xac0,
    92: 0xb00,
    93: 0xb40,
    94: 0xb80,
    95: 0xbc0,
    96: 0xc00,
    97: 0xc40,
    98: 0xe00,
    99: 0x1000,
    100: 0x1200,
    101: 0x1400,
    102: 0x1600,
    103: 0x1800,
    104: 0x1a00,
    105: 0x1c00,
    106: 0x1e00,
    107: 0x2000,
    108: 0x2200,
    109: 0x2400,
    110: 0x2600,
    111: 0x2800,
    112: 0x2a00,
    113: 0x3000,
    114: 0x4000,
    115: 0x5000,
    116: 0x6000,
    117: 0x7000,
    118: 0x8000,
    119: 0x9000,
    120: 0xa000,
    121: 0x10000,
    122: 0x18000,
    123: 0x20000,
    124: 0x28000,
    125: 0x40000,
    126: 0x80000,
}


