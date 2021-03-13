from pwnlib.heap.glmalloc.bins import Bins, Bin, BinEntry


class Tcaches(Bins):
    """Sequence of tcache bins.
    """

    @property
    def bins(self):
        """:obj:`list` of :class:`Tcache`: The bins of the sequence."""
        return super(Tcaches, self).bins


class Tcache(Bin):
    """Class to represent a tcache of the glibc
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(Tcache, self).__init__(bin_entry, malloc_chunks)

    @property
    def bin_entry(self):
        """:class:`TcacheEntry`: The entry of tcache_perthread_struct for the
            bin."""
        return super(Tcache, self).bin_entry


class TcacheEntry(BinEntry):
    """Class to contain the information of each entry in
    tcache_perthread_struct struct.
    """

    def __init__(self, address, fd, chunks_size):
        super(TcacheEntry, self).__init__(address, fd, chunks_size=chunks_size)

