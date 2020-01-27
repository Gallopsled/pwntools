from .small_bin import *
from .large_bin import *
from .unsorted_bin import *


class BinFactory:
    """Helper class to create different bin classes based on the type of entry
    provided.
    """

    @staticmethod
    def create(bin_entry, chunks):

        if isinstance(bin_entry, LargeBinEntry):
            return LargeBin(bin_entry, chunks)
        elif isinstance(bin_entry, SmallBinEntry):
            return SmallBin(bin_entry, chunks)
        elif isinstance(bin_entry, UnsortedBinEntry):
            return UnsortedBin(bin_entry, chunks)

        raise TypeError()
