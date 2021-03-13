from pwnlib.heap.bins.bin import Bins, Bin, BinEntry


class SmallBins(Bins):
    """Sequence of small bins.
    """

    def _name(self):
        return "Small Bins"

    @property
    def bins(self):
        """:obj:`list` of :class:`SmallBin`: The bins of the sequence."""
        return super(SmallBins, self).bins


class SmallBin(Bin):
    """Class to represent an small bin of the glibc.
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(SmallBin, self).__init__(bin_entry, malloc_chunks)

    def _name(self):
        return "Small Bin"

    @property
    def bin_entry(self):
        """:class:`SmallBinEntry`: The entry of malloc_state for the small bin."""
        return super(SmallBin, self).bin_entry


class SmallBinEntry(BinEntry):
    """Class to contain the information of a small bin entry in `bins` of
    malloc state.
    """

    def __init__(self, address, fd, bk, chunks_size):
        super(SmallBinEntry, self).__init__(
            address, fd, bk=bk, chunks_size=chunks_size)

    def __str__(self):
        return "Small Bin [{:#x}]: fd={:#x}, bk={:#x}".format(
            self.chunks_size, self.fd, self.bk
        )
