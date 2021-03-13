from pwnlib.heap.bins.bin import Bins, Bin, BinEntry


class UnsortedBins(Bins):
    """Sequence of unsorted bins. There is only 1 bin in this sequence, however
    it is encapsulated in this class for compatibility with the other bin
    types.
    """

    def __init__(self, bin):
        super(UnsortedBins, self).__init__([bin])

    def _name(self):
        return "Unsorted Bins"

    @property
    def bins(self):
        """:obj:`list` of :class:`UnsortedBin`: The bins of the sequence."""
        return super(UnsortedBins, self).bins


class UnsortedBin(Bin):
    """Class to represent an unsorted bin of the glibc
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(UnsortedBin, self).__init__(bin_entry, malloc_chunks)

    def _name(self):
        return "Unsorted Bin"

    @property
    def bin_entry(self):
        """:class:`UnsortedBinEntry`: The entry of malloc_state for the unsorted
            bin."""
        return super(UnsortedBin, self).bin_entry


class UnsortedBinEntry(BinEntry):
    """Class to contain the information of a unsorted bin entry in `bins` of
    malloc state.
    """

    def __init__(self, address, fd, bk):
        super(UnsortedBinEntry, self).__init__(address, fd, bk=bk)

    def __str__(self):
        return "Unsorted Bin : fd={:#x}, bk={:#x}".format(
            self.fd, self.bk
        )
