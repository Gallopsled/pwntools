from pwnlib.heap.bins.bin import *


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
