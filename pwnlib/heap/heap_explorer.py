from .bins import *
from .arena import ArenaParser
from .malloc_state import MallocStateParser
from .heap import HeapParser
from .malloc_chunk import MallocChunkParser
from .process_informer import ProcessInformer


class HeapExplorer:
    """Main class of the library. which functions to access to all items of the
    glibc heap management, such as arenas, malloc_state, heap and bins.

    Attributes:
        tcaches_enabled(bool): Indicates if tcaches are enabled for the current
            glibc version.

    Examples:
        >>> p = process('bash')
        >>> hp = p.heap_explorer
        >>> hp.tcaches_enabled # doctest: +SKIP
        True
        >>> print(hp.arena().summary()) # doctest: +SKIP
        ========================== Arena ==========================
        - Malloc State (0x7fad3f0a5c40)
            top = 0x564c90e90f20
            last_remainder = 0x0
            next = 0x7fad3f0a5c40
            next_free = 0x0
            system_mem = 0x21000
        - Heap (0x564c90e83000)
            chunks_count = 0x245
            top: addr = 0x564c90e90f20, size = 0x130e0
        - Tcaches
            [23] 0x188 (1)
            [41] 0x2a8 (1)
        - Fast bins
            [-] No chunks found
        - Unsorted bins
            [-] No chunks found
        - Small bins
            [-] No chunks found
        - Large bins
            [-] No chunks found
        ===========================================================

    """

    def __init__(self, pid, libc):
        process_informer = ProcessInformer(pid, libc)
        self._process_informer = process_informer
        self._main_arena_address = process_informer.main_arena_address
        self._pointer_size = process_informer.pointer_size

        self._malloc_state_parser = MallocStateParser(process_informer)

        malloc_chunk_parser = MallocChunkParser(process_informer)

        self._heap_parser = HeapParser(
            malloc_chunk_parser,
            self._malloc_state_parser
        )

        self._bin_parser = BinParser(malloc_chunk_parser)
        self._fast_bin_parser = FastBinParser(malloc_chunk_parser)

        self.tcaches_enabled = self._are_tcaches_enabled()

        if self.tcaches_enabled:
            self._tcache_parser = EnabledTcacheParser(
                malloc_chunk_parser,
                self._heap_parser
            )
        else:
            self._tcache_parser = DisabledTcacheParser()

        self._arena_parser = ArenaParser(
            self._malloc_state_parser,
            self._heap_parser,
            self._bin_parser,
            self._fast_bin_parser,
            self._tcache_parser
        )

    def _are_tcaches_enabled(self):
        if self._process_informer.is_libc_version_lower_than((2, 26)):
            return False

        tcache_chunk_size = self._pointer_size * 64 + 0x50
        return tcache_chunk_size == self.heap().chunks[0].size

    def arenas_count(self):
        """Returns the number of arenas

        Examples:
            >>> p = process('bash')
            >>> hp = p.heap_explorer
            >>> hp.arenas_count() # doctest: +SKIP
            2

        Returns:
            int
        """
        return len(self.all_arenas_malloc_states())

    def malloc_state(self, arena_index=0):
        """Returns the malloc_arena of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        Examples:
        >>> p = process('bash')
        >>> hp = p.heap_explorer
        >>> ms = hp.malloc_state()
        >>> hex(ms.top) # doctest: +SKIP
        '0x55c4669ff6e0'
        >>> hex(ms.address) # doctest: +SKIP
        '0x7f97053fbc40'
        >>> print(ms) # doctest: +SKIP
        ======================== Malloc State (0x7f97053fbc40) ========================
        mutex = 0x0
        flags = 0x1
        have_fastchunks = 0x0
        fastbinsY
          [0] 0x20 => 0x0
          [1] 0x30 => 0x0
          [2] 0x40 => 0x0
          [3] 0x50 => 0x0
          [4] 0x60 => 0x55c4669fdc20
          [5] 0x70 => 0x0
          [6] 0x80 => 0x0
          [7] 0x90 => 0x0
          [8] 0xa0 => 0x0
          [9] 0xb0 => 0x0
        top = 0x55c4669ff6e0
        last_remainder = 0x0
        bins
         Unsorted bins
          [0] fd=0x55c4669fed40 bk=0x55c4669fdca0
         Small bins
          [1] 0x20 fd=0x7f97053fbcb0 bk=0x7f97053fbcb0
          [2] 0x30 fd=0x7f97053fbcc0 bk=0x7f97053fbcc0
                            .......
          [61] 0x3e0 fd=0x7f97053fc070 bk=0x7f97053fc070
          [62] 0x3f0 fd=0x7f97053fc080 bk=0x7f97053fc080
         Large bins
          [63] 0x400 fd=0x7f97053fc090 bk=0x7f97053fc090
          [64] 0x440 fd=0x7f97053fc0a0 bk=0x7f97053fc0a0
                            ......
          [125] 0x80000 fd=0x7f97053fc470 bk=0x7f97053fc470
          [126] 0x100000 fd=0x7f97053fc480 bk=0x7f97053fc480
        binmap = [0x0, 0x0, 0x0, 0x0]
        next = 0x7f96f8000020
        next_free = 0x0
        attached_threads = 0x1
        system_mem = 0x21000
        max_system_mem = 0x21000
        ================================================================================

        Returns:
            :class:`MallocState`
        """
        return self.all_arenas_malloc_states()[arena_index]

    def all_arenas_malloc_states(self):
        """Returns the malloc states of all arenas

        Returns:
            list of :class:`MallocState`
        """
        return self._malloc_state_parser.parse_all_from_main_malloc_state_address(
            self._main_arena_address
        )

    def heap(self, arena_index=0):
        """Returns the heap of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected


        Examples:
            >>> p = process('bash')
            >>> hp = p.heap_explorer
            >>> heap = hp.heap()
            >>> len(heap.chunks) # doctest: +SKIP
            574
            >>> print(heap) # doctest: +SKIP
            ============================ Heap (0x555635100000) ============================
            0x555635100000 0x250 PREV_IN_USE
              00 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00   ................
            0x555635100250 0x410 PREV_IN_USE
              61 61 61 0a 0a 20 76 65 72 73 69 6f 6e 20 3d 20   aaa.. version =
            0x555635100660 0x120 PREV_IN_USE
              0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x555635100780 0x120 PREV_IN_USE
              0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5556351008a0 0x60 PREV_IN_USE
              00 00 00 00 00 00 00 00 10 00 10 35 56 55 00 00   ...........5VU..
            0x555635100900 0x60 PREV_IN_USE
              b0 08 10 35 56 55 00 00 10 00 10 35 56 55 00 00   ...5VU.....5VU..
            0x555635100960 0x60 PREV_IN_USE
              10 09 10 35 56 55 00 00 10 00 10 35 56 55 00 00   ...5VU.....5VU..
            0x5556351009c0 0x60 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x555635100a20 0x60 PREV_IN_USE
              70 09 10 35 56 55 00 00 10 00 10 35 56 55 00 00   p..5VU.....5VU..
            0x555635100a80 0x60 PREV_IN_USE
              30 0a 10 35 56 55 00 00 10 00 10 35 56 55 00 00   0..5VU.....5VU..
            0x555635100ae0 0x60 PREV_IN_USE
              90 0a 10 35 56 55 00 00 10 00 10 35 56 55 00 00   ...5VU.....5VU..
            0x555635100b40 0x60 PREV_IN_USE
              f0 0a 10 35 56 55 00 00 10 00 10 35 56 55 00 00   ...5VU.....5VU..
            0x555635100ba0 0x60 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x555635100c00 0x20 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x555635100c20 0x60 PREV_IN_USE
              a0 0b 10 35 56 55 00 00 00 00 00 00 00 00 00 00   ...5VU..........
            0x555635100c80 0x20 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x555635100ca0 0x1010 PREV_IN_USE
              a0 9c 6e d6 8b 7f 00 00 40 1d 10 35 56 55 00 00   ..n.....@..5VU..
            0x555635101cb0 0x90
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x555635101d40 0x910 PREV_IN_USE
              a0 0c 10 35 56 55 00 00 a0 9c 6e d6 8b 7f 00 00   ...5VU....n.....
            0x555635102650 0x90
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5556351026e0 0x1e920 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            ================================================================================

        Returns:
            :class:`Heap`
        """
        malloc_state = self.malloc_state(arena_index)
        return self._heap_parser.parse_from_malloc_state(malloc_state)

    def all_arenas_heaps(self):
        """Returns the heaps of all arenas

        Returns:
            list of :class:`Heap`
        """
        malloc_states = self.all_arenas_malloc_states()
        heaps = []
        for malloc_state in malloc_states:
            heaps.append(
                self._heap_parser.parse_from_malloc_state(malloc_state)
            )
        return heaps

    def unsorted_bin(self, arena_index=0):
        """Returns the unsorted bin of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        Examples:

            >>> p = process('bash')
            >>> hp = p.heap_explorer
            >>> unsorted_bins = hp.unsorted_bin()
            >>> print(unsorted_bins) # doctest: +SKIP
            ================================ Unsorted Bins ================================
            [0] Unsorted Bin (2) => Chunk(0x555635101d40 0x910 PREV_IN_USE) => Chunk(0x55563
            5100ca0 0x1010 PREV_IN_USE) => 0x7f8bd66e9ca0
            ================================================================================

        Returns:
            :class:`UnsortedBins`
        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_unsorted_bin_from_malloc_state(
            malloc_state
        )

    def all_arenas_unsorted_bins(self):
        """Returns the unsorted bins of all arenas

        Returns:
            list of :class:`UnsortedBins`
        """
        unsorted_bins = []
        for malloc_state in self.all_arenas_malloc_states():
            unsorted_bins.append(
                self._bin_parser.parse_unsorted_bin_from_malloc_state(
                    malloc_state
                )
            )
        return unsorted_bins

    def small_bins(self, arena_index=0):
        """Returns the small bins of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        Examples:
            >>> p = process('bash')
            >>> hp = p.heap_explorer
            >>> small_bins = hp.small_bins()
            >>> print(small_bins) # doctest: +SKIP
            ================================== Small Bins ==================================
                [-] No chunks found
            ================================================================================


        Returns:
            :class:`SmallBins`
        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_small_bins_from_malloc_state(
            malloc_state,
        )

    def all_arenas_small_bins(self):
        """Returns the small bins of all arenas

        Returns:
            list of :class:`SmallBins`
        """
        all_small_bins = []
        for malloc_state in self.all_arenas_malloc_states():
            all_small_bins.append(
                self._bin_parser.parse_small_bins_from_malloc_state(
                    malloc_state
                )
            )
        return all_small_bins

    def large_bins(self, arena_index=0):
        """Returns the large bins of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        Examples:
            >>> p = process('bash')
            >>> hp = p.heap_explorer
            >>> large_bins = hp.large_bins()
            >>> print(large_bins) # doctest: +SKIP
            ================================== Large Bins ==================================
                [-] No chunks found
            ================================================================================


        Returns:
            :class:`LargeBins`
        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_large_bins_from_malloc_state(
            malloc_state,
        )

    def all_arenas_large_bins(self):
        """Returns the large bins of all arenas

        Returns:
            list of :class:`LargeBins`
        """
        all_large_bins = []
        for malloc_state in self.all_arenas_malloc_states():
            all_large_bins.append(
                self._bin_parser.parse_large_bins_from_malloc_state(
                    malloc_state
                )
            )
        return all_large_bins

    def fast_bins(self, arena_index=0):
        """Returns the fast_bins of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        Examples:
            >>> p = process('bash')
            >>> hp = p.heap_explorer
            >>> fast_bins = hp.fast_bins()
            >>> print(fast_bins) # doctest: +SKIP
            ================================== Fast Bins ==================================
            [4] Fast Bin 0x60 (2) => Chunk(0x555635100c20 0x60 PREV_IN_USE) => Chunk(0x55563
            5100ba0 0x60 PREV_IN_USE) => 0x0
            ================================================================================

        Returns:
            :class:`FastBins`
        """
        malloc_state = self.malloc_state(arena_index)
        return self._fast_bin_parser.parse_all_from_malloc_state(malloc_state)

    def all_arenas_fast_bins(self):
        """Returns the small bins of all arenas

        Returns:
            list of :class:`FastBin`
        """
        malloc_states = self.all_arenas_malloc_states()
        all_fast_bins = []
        for malloc_state in malloc_states:
            all_fast_bins.append(
                self._fast_bin_parser.parse_all_from_malloc_state(malloc_state)
            )
        return all_fast_bins

    def tcaches(self, arena_index=0):
        """Returns the tcaches of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        >>> p = process('bash')
        >>> hp = p.heap_explorer
        >>> try: # doctest: +SKIP
        ...     print(hp.tcaches())
        ... except NoTcacheError:
        ...     pass
        ...
        =================================== Tcaches ===================================
        [23] Tcache 0x188 (1) => Chunk(0x56383e3c0250 0x190 PREV_IN_USE) => 0x0
        [41] Tcache 0x2a8 (1) => Chunk(0x56383e3bffa0 0x2b0 PREV_IN_USE) => 0x0
        ================================================================================


        Returns:
            :class:`Tcache`
        """
        if not self.tcaches_enabled:
            raise NoTcacheError()

        malloc_state = self.malloc_state(arena_index)
        return self._tcache_parser.parse_all_from_malloc_state(malloc_state)

    def all_arenas_tcaches(self):
        """Returns the tcaches of all arenas

        Returns:
            list of :class:`Tcache`
        """
        if not self.tcaches_enabled:
            raise NoTcacheError()

        malloc_states = self.all_arenas_malloc_states()
        all_tcaches = []
        for malloc_state in malloc_states:
            all_tcaches.append(
                self._tcache_parser.parse_all_from_malloc_state(malloc_state)
            )
        return all_tcaches

    def arena(self, arena_index=0):
        """Returns the selected arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        Examples:
            >>> p = process('bash')
            >>> hp = p.heap_explorer
            >>> arena = hp.arena()
            >>> print(arena.summary()) # doctest: +SKIP
            ========================== Arena ==========================
            - Malloc State (0x7fad3f0a5c40)
                top = 0x564c90e90f20
                last_remainder = 0x0
                next = 0x7fad3f0a5c40
                next_free = 0x0
                system_mem = 0x21000
            - Heap (0x564c90e83000)
                chunks_count = 0x245
                top: addr = 0x564c90e90f20, size = 0x130e0
            - Tcaches
                [23] 0x188 (1)
                [41] 0x2a8 (1)
            - Fast bins
                [-] No chunks found
            - Unsorted bins
                [-] No chunks found
            - Small bins
                [-] No chunks found
            - Large bins
                [-] No chunks found
            ===========================================================

        Returns:
            :class:`Arena`
        """
        malloc_state = self.malloc_state(arena_index)
        return self._arena_parser.parse_from_malloc_state(malloc_state)

    def all_arenas(self):
        """Returns all arenas

        Returns:
            list of :class:`Arena`
        """
        return self._arena_parser.parse_all_from_main_malloc_state_address(
            self._main_arena_address
        )
