from .bins_indexes import *


class Bins:
    """Class to represent the `bins` attribute of malloc_state struct.

    Attributes:
        entries (list of BinEntry): pointers to the first chunks of the each
            double linked bin.
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

    @property
    def base_address(self):
        return self.address(0)

    def address(self, index):
        return self.entries[index].address

    def fd(self, index):
        return self.entries[index].fd

    def bk(self, index):
        return self.entries[index].bk

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
