from .bin import *


class LargeBin(Bin):
    """Class to represent an large bin of the glibc
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(LargeBin, self).__init__(bin_entry, malloc_chunks)

    @property
    def min_chunks_size(self):
        return self.chunks_size

    def __str__(self):

        msg = "Largebin [min_size = {:#x}, count = {}] => {:#x}".format(
            self.min_chunks_size,
            len(self),
            self.fd
        )

        for chunk in self.malloc_chunks:
            msg += chunk.to_bin_str()

        return msg


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
