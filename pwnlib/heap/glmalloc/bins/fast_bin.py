from pwnlib.heap.glmalloc.bins import Bins, Bin, BinEntry


class FastBinParser:
    """Class with the logic to parse the chunks of a fast bin from raw memory
    and create FastBin objects.

    Args:
        malloc_chunk_parser (MallocChunkParser): a parser of the chunks in the
            heap.
    """

    def __init__(self, malloc_chunk_parser):
        self._malloc_chunk_parser = malloc_chunk_parser

    def parse_all_from_malloc_state(self, malloc_state):
        """Returns the fast bins of the arena based on the malloc state
        information.

        Args:
            malloc_state (MallocState)

        Returns:
            list of FastBin
        """
        fast_bins = []
        for bin_entry in malloc_state.fastbinsY:
            fast_bin = self._parse_from_fast_bin_entry(bin_entry)
            fast_bins.append(fast_bin)
        return FastBins(fast_bins)

    def _parse_from_fast_bin_entry(self, fast_bin_entry):
        chunks = []
        addresses = []
        current_address = fast_bin_entry.fd
        while current_address != 0x0 and current_address not in addresses:
            addresses.append(current_address)
            try:
                chunk = self._malloc_chunk_parser.parse_from_address(
                    current_address
                )
                chunks.append(chunk)
                current_address = chunk.fd
            except (OSError, IOError):
                # to avoid hanging in case some pointer is corrupted
                break

        return FastBin(fast_bin_entry, chunks)


class FastBins(Bins):
    """Sequence of fast bins.
    """

    def _name(self):
        return "Fast Bins"

    @property
    def bins(self):
        """:obj:`list` of :class:`FastBin`: The bins of the sequence."""
        return super(FastBins, self).bins


class FastBin(Bin):
    """Class to represent a fast bin of the glibc.
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(FastBin, self).__init__(bin_entry, malloc_chunks)

    def _name(self):
        return "Fast Bin"

    @property
    def bin_entry(self):
        """:class:`FastBinEntry`: The entry of malloc_state for the fast bin."""
        return super(FastBin, self).bin_entry


class FastBinEntry(BinEntry):
    """Class to contain the information of a entry in `fastbinsY` attribute
     of `malloc_state` struct.
    """

    def __init__(self, address, fd, chunks_size):
        super(FastBinEntry, self).__init__(
            address, fd, chunks_size=chunks_size)
