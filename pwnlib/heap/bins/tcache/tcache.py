from pwnlib.heap.bins.bin import Bins, Bin, BinEntry


class Tcaches(Bins):
    """Sequence of tcache bins.

    Attributes:
        bins (:obj:`list` of :class:`Tcache`): The bins of the sequence.

    """
    pass


class Tcache(Bin):
    """Class to represent a tcache of the glibc

    Attributes:
        bin_entry (TcacheEntry): The entry of tcache_perthread_struct for the
            bin.
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(Tcache, self).__init__(bin_entry, malloc_chunks)


class TcacheEntry(BinEntry):
    """Class to contain the information of each entry in
    tcache_perthread_struct struct.

    Attributes:
        bk (int): 0 since it is not used.
    """

    def __init__(self, address, fd, chunks_size):
        super(TcacheEntry, self).__init__(address, fd, chunks_size=chunks_size)

