from pwnlib.heap.malloc_state.bins.bins_indexes import \
    LARGE_BINS_START_INDEX, SMALL_BINS_START_INDEX, UNSORTED_BIN_INDEX


class Bins:
    """Class to represent the `bins` attribute of malloc_state struct.

    Attributes:
        entries (list of :class:`BinEntry`): entries with pointers to the first
            and last chunks of the each double linked bin.
    """

    def __init__(self, entries):
        self.entries = entries

    @property
    def unsorted_bin_entry(self):
        """Returns the entry of the unsorted bin.

        Returns:
            BinEntry
        """
        return self.entries[UNSORTED_BIN_INDEX]

    @property
    def small_bins_entries(self):
        """Returns the entries of the small bins.

        Returns:
            :obj:`list` of  :class:`BinEntry`
        """
        return self.entries[SMALL_BINS_START_INDEX:LARGE_BINS_START_INDEX]

    @property
    def large_bins_entries(self):
        """Returns the entries of the large bins.

        Returns:
            :obj:`list` of  :class:`BinEntry`
        """
        return self.entries[LARGE_BINS_START_INDEX:]

    def __getitem__(self, index):
        return self.entries[index]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    def __str__(self):
        string = ""
        i = 1
        for bin_entry in self.entries:
            string += "{} {}\n".format(i, bin_entry)
            i += 1

        return string
