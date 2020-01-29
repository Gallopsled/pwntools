from pwnlib.heap.bins.bin import *


class Tcaches(Bins):
    pass


class Tcache(Bin):
    """Class to represent a tcache of the glibc

    Attributes:
        bin_entry (TcacheEntry): The entry of tcache_perthread_struct for the
            bin.
        chunks (list of MallocChunk): The chunks which are inserted in
            the tcache.
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(Tcache, self).__init__(bin_entry, malloc_chunks)
