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

        Returns:
            int
        """
        return len(self.all_arenas_malloc_states())

    def malloc_state(self, arena_index=0):
        """Returns the malloc_arena of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

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
