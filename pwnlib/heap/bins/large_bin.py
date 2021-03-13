from pwnlib.heap.bins.bin import Bins, Bin, BinEntry


class LargeBins(Bins):
    """Sequence of large bins.
    """

    def _name(self):
        return "Large Bins"

    @property
    def bins(self):
        """:obj:`list` of :class:`LargeBin`: The bins of the sequence."""
        return super(LargeBins, self).bins


class LargeBin(Bin):
    """Class to represent an large bin of the glibc.
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(LargeBin, self).__init__(bin_entry, malloc_chunks)

    @property
    def min_chunks_size(self):
        return self.chunks_size

    def _name(self):
        return "Large Bin"

    @property
    def bin_entry(self):
        """:class:`LargeBinEntry`: The entry of malloc_state for the large bin."""
        return super(LargeBin, self).bin_entry


class LargeBinEntry(BinEntry):
    """Class to contain the information of a large bin entry in `bins` of
    malloc state.
    """

    def __init__(self, address, fd, bk, chunks_size):
        super(LargeBinEntry, self).__init__(
            address=address, fd=fd, bk=bk, chunks_size=chunks_size)

    @property
    def min_chunks_size(self):
        return self.chunks_size

    def __str__(self):
        return "Large Bin [>={:#x}]: fd={:#x}, bk={:#x}".format(
            self.chunks_size, self.fd, self.bk
        )
