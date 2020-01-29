from pwnlib.heap.bins.bin import BinEntry


class TcacheEntry(BinEntry):
    """Class to contain the information of each entry in
    tcache_perthread_struct struct.
    """

    def __init__(self, address, fd, chunks_size):
        super(TcacheEntry, self).__init__(address, fd, chunks_size=chunks_size)

