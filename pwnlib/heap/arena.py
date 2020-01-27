from .bins import NoTcacheError


class ArenaParser:
    """Class to parse the arena items and retrieve Arena objects

    Args:
        malloc_state_parser (MallocStateParser)
        heap_parser (HeapParser)
        bin_parser (BinParser)
        fast_bin_parser (FastBinParser)
        tcache_parser (TcacheParser)
    """

    def __init__(self, malloc_state_parser, heap_parser, bin_parser,
                 fast_bin_parser, tcache_parser):
        self._malloc_state_parser = malloc_state_parser
        self._heap_parser = heap_parser
        self._bin_parser = bin_parser
        self._fast_bin_parser = fast_bin_parser
        self._tcache_parser = tcache_parser

    def parse_all_from_main_malloc_state_address(self, main_malloc_state_address):
        """Returns all the arenas of the process from the address of the
        main arena malloc state

        Args:
            main_malloc_state_address(int): The address of the main arena
                malloc state

        Returns:
            list of Arena
        """

        malloc_states = self._malloc_state_parser.parse_all_from_main_malloc_state_address(
            main_malloc_state_address
        )
        return [self.parse_from_malloc_state(malloc_state) for malloc_state in malloc_states]

    def parse_from_malloc_state(self, malloc_state):
        """Returns all the arena information based on the malloc state.

        Args:
            malloc_state (MallocState)

        Returns:
            Arena
        """
        heap = self._heap_parser.parse_from_malloc_state(malloc_state)
        unsorted_bin = self._bin_parser.parse_unsorted_bin_from_malloc_state(
            malloc_state
        )
        small_bins = self._bin_parser.parse_small_bins_from_malloc_state(
            malloc_state
        )
        large_bins = self._bin_parser.parse_large_bins_from_malloc_state(
            malloc_state
        )
        fast_bins = self._fast_bin_parser.parse_all_from_malloc_state(
            malloc_state
        )
        tcaches = self._tcache_parser.parse_all_from_malloc_state(malloc_state)

        return Arena(
            malloc_state,
            heap,
            unsorted_bin,
            small_bins,
            large_bins,
            fast_bins,
            tcaches
        )


class Arena(object):
    """Class with the information of the arena

    Attributes:
        malloc_state (MallocState)
        heap (Heap)
        tcaches (list of Tcaches)
        fast_bins (list of FastBin)
        unsorted_bin (UnsortedBin)
        small_bins (list of SmallBin)
        large_bins (list of LargeBin)
    """

    def __init__(self, malloc_state, heap, unsorted_bin,
                 small_bins, large_bins, fast_bins, tcaches):
        self.malloc_state = malloc_state
        self.heap = heap
        self._tcaches = tcaches
        self.fast_bins = fast_bins
        self.unsorted_bin = unsorted_bin
        self.small_bins = small_bins
        self.large_bins = large_bins

    @property
    def tcaches(self):
        if self._tcaches is None:
            raise NoTcacheError()

        return self._tcaches
