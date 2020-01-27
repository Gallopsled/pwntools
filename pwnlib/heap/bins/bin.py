
class Bin(object):
    """Base class to be inherit by the bins. This class provides the basic info
    of the bin entry as well as the chunks of the bin.

    Attributes:
        bin_entry (BinEntry): The entry of malloc_state.bins for the bin.
        fd (int): Shortcut to the fd pointer of the entry of the current bin.
        bk (int): Shortcut to the bk pointer of the entry of the current bin.
        chunks_size (int): Size which should have the chunks in the bin.
        malloc_chunks (list of MallocChunk): The chunks which are inserted in
            the bin.
        chunks (list of MallocChunk): Alias for malloc_chunks.
    """

    def __init__(self, bin_entry, malloc_chunks):
        self._bin_entry = bin_entry
        self._malloc_chunks = malloc_chunks

    @property
    def bin_entry(self):
        return self._bin_entry

    @property
    def fd(self):
        return self.bin_entry.fd

    @property
    def bk(self):
        return self.bin_entry.bk

    @property
    def chunks_size(self):
        return self.bin_entry.chunks_size

    @property
    def malloc_chunks(self):
        return self._malloc_chunks

    @property
    def chunks(self):
        return self.malloc_chunks

    def __len__(self):
        return len(self.malloc_chunks)

    def __iter__(self):
        return iter(self.malloc_chunks)


class BinEntry(object):
    """Class to contain the common information of each bin entry.

    Attributes:
        address (int): The address of the bin entry.
        fd (int): The address of first chunk of the bin.
        bk (int): The address of last chunk of the bin. 0 if not used.
        chunks_size (int): Size which should have the chunks in the bin. 0 if
            not used.
    """

    def __init__(self, address, fd, bk=0, chunks_size=0):
        self.address = address
        self.fd = fd
        self.bk = bk
        self.chunks_size = chunks_size
