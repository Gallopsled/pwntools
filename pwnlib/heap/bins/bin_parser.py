from pwnlib.heap.bins.small_bin import SmallBins, SmallBin, SmallBinEntry
from pwnlib.heap.bins.large_bin import LargeBins, LargeBin, LargeBinEntry
from pwnlib.heap.bins.unsorted_bin import \
    UnsortedBins, \
    UnsortedBin, \
    UnsortedBinEntry


class BinParser:
    """Class with the logic to parse the structs of a bin (unsorted, small
    and large) from raw memory and create its respective implementation:
    UnsortedBin, SmallBin or LargeBin.

    Args:
        malloc_chunk_parser (MallocChunkParser): a parser of the chunks in the
            heap.

    """

    def __init__(self, malloc_chunk_parser):
        self._pointer_size = malloc_chunk_parser.pointer_size
        self._malloc_chunk_parser = malloc_chunk_parser

    def parse_unsorted_bin_from_malloc_state(self, malloc_state):
        """Returns the unsorted bin of the arena based on the malloc state
        information.

        Args:
            malloc_state (MallocState)

        Returns:
            UnsortedBin
        """
        return UnsortedBins(
            self._parse_from_bin_entry(malloc_state.unsorted_bin)
        )

    def parse_small_bins_from_malloc_state(self, malloc_state):
        """Returns the small bins of the arena based on the malloc state
        information.

        Args:
            malloc_state (MallocState)

        Returns:
            list of SmallBin
        """
        small_bins = []
        for small_entry in malloc_state.small_bins:
            small_bins.append(
                self._parse_from_bin_entry(small_entry)
            )
        return SmallBins(small_bins)

    def parse_large_bins_from_malloc_state(self, malloc_state):
        """Returns the small bins of the arena based on the malloc state
        information.

        Args:
            malloc_state (MallocState)

        Returns:
            list of LargeBin
        """
        large_bins = []
        for large_entry in malloc_state.large_bins:
            large_bins.append(
                self._parse_from_bin_entry(large_entry)
            )
        return LargeBins(large_bins)

    def _parse_from_bin_entry(self, bin_entry):
        chunks = []
        base_bin_address = bin_entry.address - (self._pointer_size*2)
        addresses = [base_bin_address]
        current_address = bin_entry.fd
        while current_address not in addresses:
            addresses.append(current_address)
            try:
                chunk = self._malloc_chunk_parser.parse_from_address(
                    current_address
                )
                chunks.append(chunk)
                current_address = chunk.fd
            except OSError:
                # to avoid hanging in case some pointer is corrupted
                break

        return BinFactory.create(bin_entry, chunks)


class BinFactory:
    """Helper class to create different bin classes based on the type of entry
    provided.
    """

    @staticmethod
    def create(bin_entry, chunks):

        if isinstance(bin_entry, LargeBinEntry):
            return LargeBin(bin_entry, chunks)
        elif isinstance(bin_entry, SmallBinEntry):
            return SmallBin(bin_entry, chunks)
        elif isinstance(bin_entry, UnsortedBinEntry):
            return UnsortedBin(bin_entry, chunks)

        raise TypeError()
