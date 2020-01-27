from .bin import *


class UnsortedBin(Bin):
    """Class to represent an unsorted bin of the glibc
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(UnsortedBin, self).__init__(bin_entry, malloc_chunks)

    def __str__(self):

        msg = "Unsorted bins [count = {}] => {:#x}".format(
            len(self),
            self.fd
        )

        for chunk in self.malloc_chunks:
            msg += chunk.to_bin_str()

        return msg


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
