from .bin import *


class UnsortedBins(Bins):
    """Sequence of unsorted bins. There is only 1 bin in this sequence, however
    it is encapsulated in this class for compatibility with the other bin
    types.

    Attributes:
        bins (:obj:`list` of :class:`UnsortedBin`): The bins of the sequence.
    """

    def __init__(self, bin):
        super(UnsortedBins, self).__init__([bin])

    def _name(self):
        return "Unsorted Bins"


class UnsortedBin(Bin):
    """Class to represent an unsorted bin of the glibc
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(UnsortedBin, self).__init__(bin_entry, malloc_chunks)

    def __repr__(self):

        msg = "Unsorted bins [count = {}] => {:#x}".format(
            len(self),
            self.fd
        )

        for chunk in self.malloc_chunks:
            msg += chunk.to_bin_str()

        return msg

    def _name(self):
        return "Unsorted Bin"


class UnsortedBinEntry(BinEntry):
    """Class to contain the information of a unsorted bin entry in `bins` of
    malloc state.

    Attributes:
        chunks_size (int): 0 since any size is allowed.
    """

    def __init__(self, address, fd, bk):
        super(UnsortedBinEntry, self).__init__(address, fd, bk=bk)

    def __str__(self):
        return "Unsorted Bin : fd={:#x}, bk={:#x}".format(
            self.fd, self.bk
        )