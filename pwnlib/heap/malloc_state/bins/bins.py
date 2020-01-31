from .bins_indexes import *


class Bins:
    """Class to represent the `bins` attribute of malloc_state struct.

    Attributes:
        entries (list of :class:`BinEntry`): entries with pointers to the first
            and last chunks of the each double linked bin.
        unsorted_bin_entry (:class:`BinEntry`): entry of the unsorted bin.
        small_bins_entries (list of :class:`BinEntry`): entries of the small
            bins.
        large_bins_entries (list of :class:`BinEntry`): entries of the large
            bins.
    """

    def __init__(self, entries):
        self.entries = entries

    @property
    def unsorted_bin_entry(self):
        return self.entries[UNSORTED_BIN_INDEX]

    @property
    def small_bins_entries(self):
        return self.entries[SMALL_BINS_START_INDEX:LARGE_BINS_START_INDEX]

    @property
    def large_bins_entries(self):
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
