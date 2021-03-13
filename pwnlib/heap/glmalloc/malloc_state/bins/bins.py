from pwnlib.heap.glmalloc.malloc_state.bins import \
    LARGE_BINS_START_INDEX, SMALL_BINS_START_INDEX, UNSORTED_BIN_INDEX


class Bins:
    """Class to represent the `bins` attribute of malloc_state struct.
    """

    def __init__(self, entries):
        #: :class:`list` of :class:`BinEntry`: Entries with pointers to the first
        #: and last chunks of the each double linked bin.
        self.entries = entries

    @property
    def unsorted_bin_entry(self):
        """:class:`BinEntry`: Returns the entry of the unsorted bin.
        """
        return self.entries[UNSORTED_BIN_INDEX]

    @property
    def small_bins_entries(self):
        """:obj:`list` of  :class:`BinEntry`: Returns the entries of
        the small bins.
        """
        return self.entries[SMALL_BINS_START_INDEX:LARGE_BINS_START_INDEX]

    @property
    def large_bins_entries(self):
        """:obj:`list` of :class:`BinEntry`: Returns the entries of
        the large bins.
        """
        return self.entries[LARGE_BINS_START_INDEX:]

    def __getitem__(self, index):
        return self.entries[index]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)
