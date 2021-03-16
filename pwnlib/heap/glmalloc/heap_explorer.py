from pwnlib.heap.glmalloc.bins import \
    BinParser, \
    FastBinParser, \
    EnabledTcacheParser, \
    DisabledTcacheParser, \
    NoTcacheError
from pwnlib.heap.glmalloc.arena import ArenaParser
from pwnlib.heap.glmalloc.malloc_state import MallocStateParser
from pwnlib.heap.glmalloc.heap import HeapParser, HeapError
from pwnlib.heap.glmalloc.malloc_chunk import MallocChunkParser
from pwnlib.heap.glmalloc.process_informer import ProcessInformer


class HeapExplorer:
    """Main class of the library. which functions to access to all items of the
    glibc heap management, such as arenas, malloc_state, heap and bins.

    Examples:
        >>> p = process('sh')
        >>> hp = p.heap_explorer()
        >>> hp.tcaches_enabled # doctest: +SKIP
        True
        >>> print(hp.arena().summary()) # doctest: +ELLIPSIS
        =====... Arena =====...
        - Malloc State (...)
            top = ...
            last_remainder = ...
            next = ...
            next_free = ...
            system_mem = ...
        - Heap (...)
            chunks_count = ...
            top: addr = ..., size = ...
        - Tcaches
        ...
        - Fast bins
        ...
        - Unsorted bins
        ...
        - Small bins
        ...
        - Large bins
        ...
        =====...

    """

    def __init__(self, pid, libc, use_tcache=None, safe_link=None):
        self._process_informer = ProcessInformer(pid, libc)

        if use_tcache is None:
            use_tcache = self._are_tcaches_enabled()

        #: :class:`bool`: Indicates if tcaches are enabled for the current
        #: glibc version.
        self.tcaches_enabled = use_tcache

        if safe_link is None:
            safe_link = self._is_safe_link_enabled()

        #: :class:`bool`: Indicates if tcaches and fastbin are protected
        # by safe-link
        self.safe_link = safe_link

    def _is_safe_link_enabled(self):
        # safe-link protection is included in version 2.32
        return self._process_informer.is_libc_version_higher_than((2, 31))

    def _are_tcaches_enabled(self):
        # tcaches were added in version 2.26
        return self._process_informer.is_libc_version_higher_than((2, 25))

    def arenas_count(self):
        """Returns the number of arenas

        Returns:
            int

        Examples:
            >>> p = process('sh')
            >>> hp = p.heap_explorer()
            >>> number_of_arenas = hp.arenas_count()
            >>> number_of_arenas # doctest: +SKIP
            2
        """
        return len(self.all_arenas_malloc_states())

    def malloc_state(self, arena_index=0):
        """Returns the malloc_arena of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        Returns:
            :class:`MallocState`

        Examples:
            >>> p = process('sh')
            >>> hp = p.heap_explorer()
            >>> ms = hp.malloc_state()
            >>> ms_top = ms.top
            >>> hex(ms_top) # doctest: +ELLIPSIS
            '0x...'
            >>> ms_address = ms.address
            >>> hex(ms_address) # doctest: +ELLIPSIS
            '0x...'
            >>> ms_str = str(ms)
            >>> print(ms_str) # doctest: +ELLIPSIS
            ====... Malloc State (0x...) ====...
            mutex = 0x...
            flags = 0x...
            have_fastchunks = 0x...
            fastbinsY
              [0] 0x20 => 0x...
              [1] 0x30 => 0x...
              [2] 0x40 => 0x...
              [3] 0x50 => 0x...
              [4] 0x60 => 0x...
              [5] 0x70 => 0x...
              [6] 0x80 => 0x...
              [7] 0x90 => 0x...
              [8] 0xa0 => 0x...
              [9] 0xb0 => 0x...
            top = 0x...
            last_remainder = 0x...
            bins
             Unsorted bins
              [0] fd=0x... bk=0x...
             Small bins
              [1] 0x20 fd=0x... bk=0x...
              [2] 0x30 fd=0x... bk=0x...
            ...
             Large bins
              [63] 0x400 fd=0x... bk=0x...
              [64] 0x440 fd=0x... bk=0x...
            ...
            binmap = [0x..., 0x..., 0x..., 0x...]
            next = 0x...
            next_free = 0x...
            attached_threads = 0x...
            system_mem = 0x...
            max_system_mem = 0x...
            ==========================...
        """
        return self.all_arenas_malloc_states()[arena_index]

    def all_arenas_malloc_states(self):
        """Returns the malloc states of all arenas

        Returns:
            list of :class:`MallocState`

        Examples:
            >>> p = process('sh')
            >>> hp = p.heap_explorer()
            >>> mmss = hp.all_arenas_malloc_states()
            >>> mmss_str = "\\n".join([str(ms) for ms in mmss])
            >>> print(mmss_str) # doctest: +ELLIPSIS
            ====... Malloc State (0x...) ====...
            mutex = 0x...
            flags = 0x...
            have_fastchunks = 0x...
            fastbinsY
              [0] 0x20 => 0x...
              [1] 0x30 => 0x...
              [2] 0x40 => 0x...
              [3] 0x50 => 0x...
              [4] 0x60 => 0x...
              [5] 0x70 => 0x...
              [6] 0x80 => 0x...
              [7] 0x90 => 0x...
              [8] 0xa0 => 0x...
              [9] 0xb0 => 0x...
            top = 0x...
            last_remainder = 0x...
            bins
             Unsorted bins
              [0] fd=0x... bk=0x...
             Small bins
              [1] 0x20 fd=0x... bk=0x...
              [2] 0x30 fd=0x... bk=0x...
            ...
             Large bins
              [63] 0x400 fd=0x... bk=0x...
              [64] 0x440 fd=0x... bk=0x...
            ...
            binmap = [0x..., 0x..., 0x..., 0x...]
            next = 0x...
            next_free = 0x...
            attached_threads = 0x...
            system_mem = 0x...
            max_system_mem = 0x...
            ...
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

        Examples:
            >>> p = process('sh')
            >>> p.sendline('init='+'A'*0x1000)
            >>> hp = p.heap_explorer()
            >>> heap = hp.heap()
            >>> number_chunks = len(heap.chunks)
            >>> len(number_chunks) # doctest: +SKIP
            574
            >>> top_chunk = heap.top
            >>> top_chunk_address = top_chunk.address
            >>> hex(top_chunk_address) # doctest: +ELLIPSIS
            '0x...'
            >>> print(heap) # doctest: +ELLIPSIS
            =====... Heap (0x...) =====...
            0x... 0x...
            ...
            ========...
        """
        malloc_state = self.malloc_state(arena_index)
        return self._heap_parser.parse_from_malloc_state(malloc_state)

    def all_arenas_heaps(self):
        """Returns the heaps of all arenas

        Returns:
            :obj:`list` of :class:`Heap`

        Example:
            >>> p = process('sh')
            >>> p.sendline('init='+'A'*0x1000)
            >>> hp = p.heap_explorer()
            >>> hhpp = hp.all_arenas_heaps()
            >>> hhpp_str = "\\n".join([str(h) for h in hhpp])
            >>> print(hhpp_str) # doctest: +ELLIPSIS
            =====... Heap (0x...) =====...
            0x... 0x...
            ...
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

        Examples:

            >>> p = process('sh')
            >>> p.sendline('init='+'A'*0x1000)
            >>> hp = p.heap_explorer()
            >>> unsorted_bins = hp.unsorted_bin()
            >>> unsorted_bins_str = str(unsorted_bins)
            >>> print(unsorted_bins_str) # doctest: +SKIP
            =====... Unsorted Bins =====...
            ...
            =====...
            >>> unsorted_bin = unsorted_bins[0]
            >>> unsorted_bin_entry = unsorted_bin.bin_entry
            >>> unsorted_bin_entry.fd == unsorted_bin.fd
            True
            >>> unsorted_bin_entry.bk == unsorted_bin.bk
            True
            >>> unsorted_bin_entry.chunks_size == unsorted_bin.chunks_size
            True

        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_unsorted_bin_from_malloc_state(
            malloc_state
        )

    def all_arenas_unsorted_bins(self):
        """Returns the unsorted bins of all arenas

        Returns:
            list of :class:`UnsortedBins`

        Example:
            >>> p = process('sh')
            >>> p.sendline('init='+'A'*0x1000)
            >>> hp = p.heap_explorer()
            >>> uubb = hp.all_arenas_unsorted_bins()
            >>> uubb_str = "\\n".join([str(ub) for ub in uubb])
            >>> print(uubb_str) # doctest: +ELLIPSIS
            =====... Unsorted Bins =====...
            ...
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

        Examples:
            >>> p = process('sh')
            >>> p.sendline('init bins')
            >>> hp = p.heap_explorer()
            >>> small_bins = hp.small_bins()
            >>> print(small_bins) # doctest: +ELLIPSIS
            =====... Small Bins =====...
            ...
            =====...
        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_small_bins_from_malloc_state(
            malloc_state,
        )

    def all_arenas_small_bins(self):
        """Returns the small bins of all arenas

        Returns:
            list of :class:`SmallBins`

        Example:
            >>> p = process('sh')
            >>> hp = p.heap_explorer()
            >>> bb = hp.all_arenas_small_bins()
            >>> bb_str = "\\n".join([str(b) for b in bb])
            >>> print(bb_str) # doctest: +ELLIPSIS
            =====... Small Bins =====...
            ...
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

        Examples:
            >>> p = process('sh')
            >>> p.sendline('init bins')
            >>> hp = p.heap_explorer()
            >>> large_bins = hp.large_bins()
            >>> print(large_bins) # doctest: +ELLIPSIS
            =====... Large Bins =====...
            ...
            =====...
        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_large_bins_from_malloc_state(
            malloc_state,
        )

    def all_arenas_large_bins(self):
        """Returns the large bins of all arenas

        Returns:
            :obj:`list` of :class:`LargeBins`

        Example:
            >>> p = process('sh')
            >>> hp = p.heap_explorer()
            >>> bb = hp.all_arenas_large_bins()
            >>> bb_str = "\\n".join([str(b) for b in bb])
            >>> print(bb_str) # doctest: +ELLIPSIS
            =====... Large Bins =====...
            ...
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

        Examples:
            >>> p = process('sh')
            >>> p.sendline('init bins')
            >>> hp = p.heap_explorer()
            >>> fast_bins = hp.fast_bins()
            >>> print(fast_bins) # doctest: +ELLIPSIS
            =====... Fast Bins =====...
            ...
            ======...
            >>> number_of_fastbins = len(fast_bins)
            >>> fast_bins_counts = [len(fast_bin) for fast_bin in fast_bins]
        """
        malloc_state = self.malloc_state(arena_index)
        return self._fast_bin_parser.parse_all_from_malloc_state(malloc_state)

    def all_arenas_fast_bins(self):
        """Returns the small bins of all arenas

        Returns:
            :obj:`list` of :class:`FastBins`

        Example:
            >>> p = process('sh')
            >>> p.sendline('init bins')
            >>> hp = p.heap_explorer()
            >>> bb = hp.all_arenas_fast_bins()
            >>> bb_str = "\\n".join([str(b) for b in bb])
            >>> print(bb_str) # doctest: +ELLIPSIS
            =====... Fast Bins =====...
            ...
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

        Returns:
            :class:`Tcaches`

        Example:
            >>> p = process('sh')
            >>> p.sendline('init bins')
            >>> hp = p.heap_explorer()
            >>> try:
            ...     tcaches_str = str(hp.tcaches())
            ... except NoTcacheError:
            ...     tcaches_str = ""
            ...
            >>> print(tcaches_str) # doctest: +SKIP
            =================================== Tcaches ===================================
            [23] Tcache 0x188 (1) => Chunk(0x56383e3c0250 0x190 PREV_IN_USE) => 0x0
            [41] Tcache 0x2a8 (1) => Chunk(0x56383e3bffa0 0x2b0 PREV_IN_USE) => 0x0
            ================================================================================

        """
        if not self.tcaches_enabled:
            raise NoTcacheError()

        malloc_state = self.malloc_state(arena_index)
        return self._tcache_parser.parse_all_from_malloc_state(malloc_state)

    def all_arenas_tcaches(self):
        """Returns the tcaches of all arenas

        Returns:
            :obj:`list` of :class:`Tcaches`

        Example:
            >>> p = process('sh')
            >>> p.sendline('init bins')
            >>> hp = p.heap_explorer()
            >>> try:
            ...     ttcc = hp.all_arenas_tcaches()
            ...     tcaches_str = "\\n".join([str(tc) for tc in ttcc])
            ... except NoTcacheError:
            ...     tcaches_str = ""
            ...
            >>> print(tcaches_str) # doctest: +SKIP
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

        Returns:
            :class:`Arena`

        Examples:
            >>> p = process('sh')
            >>> p.sendline('init bins')
            >>> hp = p.heap_explorer()
            >>> arena = hp.arena()
            >>> arena_summary = arena.summary()
            >>> print(arena_summary) # doctest: +ELLIPSIS
            =====... Arena =====...
            - Malloc State (0x...)
                top = 0x...
                last_remainder = 0x...
                next = 0x...
                next_free = 0x...
                system_mem = 0x...
            - Heap (0x...)
                chunks_count = 0x...
                top: addr = 0x..., size = 0x...
            - Tcaches
            ...
            - Fast bins
            ...
            - Unsorted bins
            ...
            - Small bins
            ...
            - Large bins
            ...
            ======...
            >>> arena_str = str(arena)
            >>> print(arena_str) # doctest: +SKIP
            +++++... Arena +++++...
            +++++++++++...
            =====... Malloc State (0x...) =====...
            mutex = 0x...
            flags = 0x...
            have_fastchunks = 0x...
            fastbinsY
              [0] 0x20 => 0x...
              [1] 0x30 => 0x...
              [2] 0x40 => 0x...
              [3] 0x50 => 0x...
              [4] 0x60 => 0x...
              [5] 0x70 => 0x...
              [6] 0x80 => 0x...
              [7] 0x90 => 0x...
              [8] 0xa0 => 0x...
              [9] 0xb0 => 0x...
            top = 0x...
            last_remainder = 0x...
            bins
             Unsorted bins
              [0] fd=0x... bk=0x...
             Small bins
              [1] 0x20 fd=0x... bk=0x...
              [2] 0x30 fd=0x... bk=0x...
            ...
             Large bins
              [63] 0x400 fd=0x... bk=0x...
              [64] 0x440 fd=0x... bk=0x...
            ...
            binmap = [0x..., 0x..., 0x..., 0x...]
            next = 0x...
            next_free = 0x...
            attached_threads = 0x...
            system_mem = 0x...
            max_system_mem = 0x...
            =====...
            =====... Heap (0x...) =====...
            0x... 0x...
            ...
            =====...
            =====... Tcaches =====...
            ...
            =====...
            =====... Fast Bins ======...
            ...
            =====...
            =====... Unsorted Bins =====...
            ...
            =====...
            =====... Small Bins =====...
            ...
            =====...
            =====... Large Bins =====...
            ...
            =====...
            ++++++...

        """
        malloc_state = self.malloc_state(arena_index)
        return self._arena_parser.parse_from_malloc_state(malloc_state)

    def all_arenas(self):
        """Returns all arenas

        Returns:
            :obj:`list` of :class:`Arena`

        Example:
            >>> p = process('sh')
            >>> p.sendline('init bins')
            >>> hp = p.heap_explorer()
            >>> arenas = hp.all_arenas()
            >>> arenas_str = "\\n".join([str(a) for a in arenas])
            >>> print(arenas_str) # doctest: +SKIP
        """
        return self._arena_parser.parse_all_from_main_malloc_state_address(
            self._main_arena_address
        )

    @property
    def _main_arena_address(self):
        return self._process_informer.main_arena_address

    @property
    def _pointer_size(self):
        return self._process_informer.pointer_size

    @property
    def _malloc_state_parser(self):
        return MallocStateParser(self._process_informer)

    @property
    def _malloc_chunk_parser(self):
        return MallocChunkParser(self._process_informer)

    @property
    def _heap_parser(self):
        return HeapParser(
            self._malloc_chunk_parser,
            self._malloc_state_parser
        )

    @property
    def _bin_parser(self):
        return BinParser(self._malloc_chunk_parser)

    @property
    def _fast_bin_parser(self):
        return FastBinParser(
            self._malloc_chunk_parser,
            safe_link=self.safe_link
        )

    @property
    def _tcache_parser(self):
        if self.tcaches_enabled:
            return EnabledTcacheParser(
                self._malloc_chunk_parser,
                self._heap_parser,
                safe_link=self.safe_link,
            )
        else:
            return DisabledTcacheParser()

    @property
    def _arena_parser(self):
        return ArenaParser(
            self._malloc_state_parser,
            self._heap_parser,
            self._bin_parser,
            self._fast_bin_parser,
            self._tcache_parser
        )