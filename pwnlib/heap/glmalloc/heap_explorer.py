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


class HeapExplorer:
    """Main class of the library. which functions to access to all items of the
    glibc heap management, such as arenas, malloc_state, heap and bins.

    """

    def __init__(self, process_informer, use_tcache=None, safe_link=None):
        self._process_informer = process_informer

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

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> hp.arenas_count()
            2

        Tests:
            >>> c = Corefile(pwnlib.data.heap.x86_64.get("core.23.fast_bins1"))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.23.so'))
            >>> he.arenas_count()
            1

        """
        return len(self.all_arenas_malloc_states())

    def malloc_state(self, arena_index=0):
        """Returns the malloc_arena of the arena

        Args:
            arena_index (int, optional): The index of the desired arena. If none
                is specified, then the index of the main arena will be selected

        Returns:
            :class:`MallocState`

        ::

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> ms = he.malloc_state()
            >>> hex(ms.top)
            '0x55f7cec4df30'
            >>> hex(ms.address)
            '0x7f6c0f17eba0'
            >>> print(ms)
            ======================== Malloc State (0x7f6c0f17eba0) ========================
            mutex = 0x0
            flags = 0x0
            have_fastchunks = 0x0
            fastbinsY
              [0] 0x20 => 0x0
              [1] 0x30 => 0x0
              [2] 0x40 => 0x0
              [3] 0x50 => 0x0
              [4] 0x60 => 0x0
              [5] 0x70 => 0x0
              [6] 0x80 => 0x0
              [7] 0x90 => 0x0
              [8] 0xa0 => 0x0
              [9] 0xb0 => 0x0
            top = 0x55f7cec4df30
            last_remainder = 0x0
            bins
             Unsorted bins
              [0] fd=0x7f6c0f17ec00 bk=0x7f6c0f17ec00
             Small bins
              [1] 0x20 fd=0x7f6c0f17ec10 bk=0x7f6c0f17ec10
              [2] 0x30 fd=0x7f6c0f17ec20 bk=0x7f6c0f17ec20
              [3] 0x40 fd=0x7f6c0f17ec30 bk=0x7f6c0f17ec30
            ...........
              [60] 0x3d0 fd=0x7f6c0f17efc0 bk=0x7f6c0f17efc0
              [61] 0x3e0 fd=0x7f6c0f17efd0 bk=0x7f6c0f17efd0
              [62] 0x3f0 fd=0x7f6c0f17efe0 bk=0x7f6c0f17efe0
             Large bins
              [63] 0x400 fd=0x7f6c0f17eff0 bk=0x7f6c0f17eff0
              [64] 0x440 fd=0x7f6c0f17f000 bk=0x7f6c0f17f000
              [65] 0x480 fd=0x7f6c0f17f010 bk=0x7f6c0f17f010
              [66] 0x4c0 fd=0x7f6c0f17f020 bk=0x7f6c0f17f020
            ...........
              [124] 0x40000 fd=0x7f6c0f17f3c0 bk=0x7f6c0f17f3c0
              [125] 0x80000 fd=0x7f6c0f17f3d0 bk=0x7f6c0f17f3d0
              [126] 0x100000 fd=0x7f6c0f17f3e0 bk=0x7f6c0f17f3e0
            binmap = [0x0, 0x0, 0x0, 0x0]
            next = 0x7f6c0f17eba0
            next_free = 0x0
            attached_threads = 0x1
            system_mem = 0x21000
            max_system_mem = 0x21000
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get("core.32.sample1"))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.malloc_state())  # doctest: +ELLIPSIS
            ===... Malloc State (0x7ff101adaba0) ===...
            mutex = 0x0
            flags = 0x0
            have_fastchunks = 0x0
            fastbinsY
              [0] 0x20 => 0x0
              [1] 0x30 => 0x0
              [2] 0x40 => 0x0
              [3] 0x50 => 0x0
              [4] 0x60 => 0x0
              [5] 0x70 => 0x0
              [6] 0x80 => 0x0
              [7] 0x90 => 0x0
              [8] 0xa0 => 0x0
              [9] 0xb0 => 0x0
            top = 0x55c9539e11a0
            last_remainder = 0x0
            bins
             Unsorted bins
              [0] fd=0x7ff101adac00 bk=0x7ff101adac00
             Small bins
              [1] 0x20 fd=0x7ff101adac10 bk=0x7ff101adac10
              [2] 0x30 fd=0x7ff101adac20 bk=0x7ff101adac20
              [3] 0x40 fd=0x55c9539df610 bk=0x55c9539e0110
              [4] 0x50 fd=0x7ff101adac40 bk=0x7ff101adac40
              [5] 0x60 fd=0x7ff101adac50 bk=0x7ff101adac50
              [6] 0x70 fd=0x7ff101adac60 bk=0x7ff101adac60
              [7] 0x80 fd=0x7ff101adac70 bk=0x7ff101adac70
              [8] 0x90 fd=0x7ff101adac80 bk=0x7ff101adac80
              [9] 0xa0 fd=0x7ff101adac90 bk=0x7ff101adac90
              [10] 0xb0 fd=0x7ff101adaca0 bk=0x7ff101adaca0
              [11] 0xc0 fd=0x7ff101adacb0 bk=0x7ff101adacb0
              [12] 0xd0 fd=0x7ff101adacc0 bk=0x7ff101adacc0
              [13] 0xe0 fd=0x7ff101adacd0 bk=0x7ff101adacd0
              [14] 0xf0 fd=0x7ff101adace0 bk=0x7ff101adace0
              [15] 0x100 fd=0x7ff101adacf0 bk=0x7ff101adacf0
              [16] 0x110 fd=0x7ff101adad00 bk=0x7ff101adad00
              [17] 0x120 fd=0x7ff101adad10 bk=0x7ff101adad10
              [18] 0x130 fd=0x7ff101adad20 bk=0x7ff101adad20
              [19] 0x140 fd=0x7ff101adad30 bk=0x7ff101adad30
              [20] 0x150 fd=0x7ff101adad40 bk=0x7ff101adad40
              [21] 0x160 fd=0x7ff101adad50 bk=0x7ff101adad50
              [22] 0x170 fd=0x7ff101adad60 bk=0x7ff101adad60
              [23] 0x180 fd=0x7ff101adad70 bk=0x7ff101adad70
              [24] 0x190 fd=0x7ff101adad80 bk=0x7ff101adad80
              [25] 0x1a0 fd=0x7ff101adad90 bk=0x7ff101adad90
              [26] 0x1b0 fd=0x7ff101adada0 bk=0x7ff101adada0
              [27] 0x1c0 fd=0x7ff101adadb0 bk=0x7ff101adadb0
              [28] 0x1d0 fd=0x7ff101adadc0 bk=0x7ff101adadc0
              [29] 0x1e0 fd=0x7ff101adadd0 bk=0x7ff101adadd0
              [30] 0x1f0 fd=0x7ff101adade0 bk=0x7ff101adade0
              [31] 0x200 fd=0x7ff101adadf0 bk=0x7ff101adadf0
              [32] 0x210 fd=0x7ff101adae00 bk=0x7ff101adae00
              [33] 0x220 fd=0x7ff101adae10 bk=0x7ff101adae10
              [34] 0x230 fd=0x7ff101adae20 bk=0x7ff101adae20
              [35] 0x240 fd=0x7ff101adae30 bk=0x7ff101adae30
              [36] 0x250 fd=0x7ff101adae40 bk=0x7ff101adae40
              [37] 0x260 fd=0x7ff101adae50 bk=0x7ff101adae50
              [38] 0x270 fd=0x7ff101adae60 bk=0x7ff101adae60
              [39] 0x280 fd=0x7ff101adae70 bk=0x7ff101adae70
              [40] 0x290 fd=0x7ff101adae80 bk=0x7ff101adae80
              [41] 0x2a0 fd=0x7ff101adae90 bk=0x7ff101adae90
              [42] 0x2b0 fd=0x7ff101adaea0 bk=0x7ff101adaea0
              [43] 0x2c0 fd=0x7ff101adaeb0 bk=0x7ff101adaeb0
              [44] 0x2d0 fd=0x7ff101adaec0 bk=0x7ff101adaec0
              [45] 0x2e0 fd=0x7ff101adaed0 bk=0x7ff101adaed0
              [46] 0x2f0 fd=0x7ff101adaee0 bk=0x7ff101adaee0
              [47] 0x300 fd=0x7ff101adaef0 bk=0x7ff101adaef0
              [48] 0x310 fd=0x7ff101adaf00 bk=0x7ff101adaf00
              [49] 0x320 fd=0x7ff101adaf10 bk=0x7ff101adaf10
              [50] 0x330 fd=0x7ff101adaf20 bk=0x7ff101adaf20
              [51] 0x340 fd=0x7ff101adaf30 bk=0x7ff101adaf30
              [52] 0x350 fd=0x7ff101adaf40 bk=0x7ff101adaf40
              [53] 0x360 fd=0x7ff101adaf50 bk=0x7ff101adaf50
              [54] 0x370 fd=0x7ff101adaf60 bk=0x7ff101adaf60
              [55] 0x380 fd=0x7ff101adaf70 bk=0x7ff101adaf70
              [56] 0x390 fd=0x7ff101adaf80 bk=0x7ff101adaf80
              [57] 0x3a0 fd=0x7ff101adaf90 bk=0x7ff101adaf90
              [58] 0x3b0 fd=0x7ff101adafa0 bk=0x7ff101adafa0
              [59] 0x3c0 fd=0x7ff101adafb0 bk=0x7ff101adafb0
              [60] 0x3d0 fd=0x7ff101adafc0 bk=0x7ff101adafc0
              [61] 0x3e0 fd=0x7ff101adafd0 bk=0x7ff101adafd0
              [62] 0x3f0 fd=0x7ff101adafe0 bk=0x7ff101adafe0
             Large bins
              [63] 0x400 fd=0x7ff101adaff0 bk=0x7ff101adaff0
              [64] 0x440 fd=0x7ff101adb000 bk=0x7ff101adb000
              [65] 0x480 fd=0x7ff101adb010 bk=0x7ff101adb010
              [66] 0x4c0 fd=0x7ff101adb020 bk=0x7ff101adb020
              [67] 0x500 fd=0x7ff101adb030 bk=0x7ff101adb030
              [68] 0x540 fd=0x7ff101adb040 bk=0x7ff101adb040
              [69] 0x580 fd=0x7ff101adb050 bk=0x7ff101adb050
              [70] 0x5c0 fd=0x7ff101adb060 bk=0x7ff101adb060
              [71] 0x600 fd=0x7ff101adb070 bk=0x7ff101adb070
              [72] 0x640 fd=0x7ff101adb080 bk=0x7ff101adb080
              [73] 0x680 fd=0x7ff101adb090 bk=0x7ff101adb090
              [74] 0x6c0 fd=0x7ff101adb0a0 bk=0x7ff101adb0a0
              [75] 0x700 fd=0x7ff101adb0b0 bk=0x7ff101adb0b0
              [76] 0x740 fd=0x7ff101adb0c0 bk=0x7ff101adb0c0
              [77] 0x780 fd=0x7ff101adb0d0 bk=0x7ff101adb0d0
              [78] 0x7c0 fd=0x7ff101adb0e0 bk=0x7ff101adb0e0
              [79] 0x800 fd=0x7ff101adb0f0 bk=0x7ff101adb0f0
              [80] 0x840 fd=0x7ff101adb100 bk=0x7ff101adb100
              [81] 0x880 fd=0x7ff101adb110 bk=0x7ff101adb110
              [82] 0x8c0 fd=0x7ff101adb120 bk=0x7ff101adb120
              [83] 0x900 fd=0x7ff101adb130 bk=0x7ff101adb130
              [84] 0x940 fd=0x7ff101adb140 bk=0x7ff101adb140
              [85] 0x980 fd=0x7ff101adb150 bk=0x7ff101adb150
              [86] 0x9c0 fd=0x7ff101adb160 bk=0x7ff101adb160
              [87] 0xa00 fd=0x7ff101adb170 bk=0x7ff101adb170
              [88] 0xa40 fd=0x7ff101adb180 bk=0x7ff101adb180
              [89] 0xa80 fd=0x7ff101adb190 bk=0x7ff101adb190
              [90] 0xac0 fd=0x7ff101adb1a0 bk=0x7ff101adb1a0
              [91] 0xb00 fd=0x7ff101adb1b0 bk=0x7ff101adb1b0
              [92] 0xb40 fd=0x7ff101adb1c0 bk=0x7ff101adb1c0
              [93] 0xb80 fd=0x7ff101adb1d0 bk=0x7ff101adb1d0
              [94] 0xbc0 fd=0x7ff101adb1e0 bk=0x7ff101adb1e0
              [95] 0xc00 fd=0x7ff101adb1f0 bk=0x7ff101adb1f0
              [96] 0xc40 fd=0x7ff101adb200 bk=0x7ff101adb200
              [97] 0xe00 fd=0x7ff101adb210 bk=0x7ff101adb210
              [98] 0x1000 fd=0x7ff101adb220 bk=0x7ff101adb220
              [99] 0x1200 fd=0x7ff101adb230 bk=0x7ff101adb230
              [100] 0x1400 fd=0x7ff101adb240 bk=0x7ff101adb240
              [101] 0x1600 fd=0x7ff101adb250 bk=0x7ff101adb250
              [102] 0x1800 fd=0x7ff101adb260 bk=0x7ff101adb260
              [103] 0x1a00 fd=0x7ff101adb270 bk=0x7ff101adb270
              [104] 0x1c00 fd=0x7ff101adb280 bk=0x7ff101adb280
              [105] 0x1e00 fd=0x7ff101adb290 bk=0x7ff101adb290
              [106] 0x2000 fd=0x7ff101adb2a0 bk=0x7ff101adb2a0
              [107] 0x2200 fd=0x7ff101adb2b0 bk=0x7ff101adb2b0
              [108] 0x2400 fd=0x7ff101adb2c0 bk=0x7ff101adb2c0
              [109] 0x2600 fd=0x7ff101adb2d0 bk=0x7ff101adb2d0
              [110] 0x2800 fd=0x7ff101adb2e0 bk=0x7ff101adb2e0
              [111] 0x2a00 fd=0x7ff101adb2f0 bk=0x7ff101adb2f0
              [112] 0x3000 fd=0x7ff101adb300 bk=0x7ff101adb300
              [113] 0x4000 fd=0x7ff101adb310 bk=0x7ff101adb310
              [114] 0x5000 fd=0x7ff101adb320 bk=0x7ff101adb320
              [115] 0x6000 fd=0x7ff101adb330 bk=0x7ff101adb330
              [116] 0x7000 fd=0x7ff101adb340 bk=0x7ff101adb340
              [117] 0x8000 fd=0x7ff101adb350 bk=0x7ff101adb350
              [118] 0x9000 fd=0x7ff101adb360 bk=0x7ff101adb360
              [119] 0xa000 fd=0x7ff101adb370 bk=0x7ff101adb370
              [120] 0x10000 fd=0x7ff101adb380 bk=0x7ff101adb380
              [121] 0x18000 fd=0x7ff101adb390 bk=0x7ff101adb390
              [122] 0x20000 fd=0x7ff101adb3a0 bk=0x7ff101adb3a0
              [123] 0x28000 fd=0x7ff101adb3b0 bk=0x7ff101adb3b0
              [124] 0x40000 fd=0x7ff101adb3c0 bk=0x7ff101adb3c0
              [125] 0x80000 fd=0x7ff101adb3d0 bk=0x7ff101adb3d0
              [126] 0x100000 fd=0x7ff101adb3e0 bk=0x7ff101adb3e0
            binmap = [0x10, 0x0, 0x0, 0x0]
            next = 0x7ff101adaba0
            next_free = 0x0
            attached_threads = 0x1
            system_mem = 0x21000
            max_system_mem = 0x21000
            =====...

        """
        return self.all_arenas_malloc_states()[arena_index]

    def all_arenas_malloc_states(self):
        """Returns the malloc states of all arenas

        Returns:
            list of :class:`MallocState`

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.all_arenas_malloc_states()[0])
            ======================== Malloc State (0x7f6c0f17eba0) ========================
            mutex = 0x0
            flags = 0x0
            have_fastchunks = 0x0
            fastbinsY
              [0] 0x20 => 0x0
              [1] 0x30 => 0x0
              [2] 0x40 => 0x0
              [3] 0x50 => 0x0
              [4] 0x60 => 0x0
              [5] 0x70 => 0x0
              [6] 0x80 => 0x0
              [7] 0x90 => 0x0
              [8] 0xa0 => 0x0
              [9] 0xb0 => 0x0
            top = 0x55f7cec4df30
            last_remainder = 0x0
            bins
             Unsorted bins
              [0] fd=0x7f6c0f17ec00 bk=0x7f6c0f17ec00
             Small bins
              [1] 0x20 fd=0x7f6c0f17ec10 bk=0x7f6c0f17ec10
              [2] 0x30 fd=0x7f6c0f17ec20 bk=0x7f6c0f17ec20
              [3] 0x40 fd=0x7f6c0f17ec30 bk=0x7f6c0f17ec30
            ...........
              [60] 0x3d0 fd=0x7f6c0f17efc0 bk=0x7f6c0f17efc0
              [61] 0x3e0 fd=0x7f6c0f17efd0 bk=0x7f6c0f17efd0
              [62] 0x3f0 fd=0x7f6c0f17efe0 bk=0x7f6c0f17efe0
             Large bins
              [63] 0x400 fd=0x7f6c0f17eff0 bk=0x7f6c0f17eff0
              [64] 0x440 fd=0x7f6c0f17f000 bk=0x7f6c0f17f000
              [65] 0x480 fd=0x7f6c0f17f010 bk=0x7f6c0f17f010
              [66] 0x4c0 fd=0x7f6c0f17f020 bk=0x7f6c0f17f020
            ...........
              [124] 0x40000 fd=0x7f6c0f17f3c0 bk=0x7f6c0f17f3c0
              [125] 0x80000 fd=0x7f6c0f17f3d0 bk=0x7f6c0f17f3d0
              [126] 0x100000 fd=0x7f6c0f17f3e0 bk=0x7f6c0f17f3e0
            binmap = [0x0, 0x0, 0x0, 0x0]
            next = 0x7f6c0f17eba0
            next_free = 0x0
            attached_threads = 0x1
            system_mem = 0x21000
            max_system_mem = 0x21000
            ================================================================================

        Tests:
            >>> c = Corefile(pwnlib.data.heap.x86_64.get("core.32.sample1"))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.all_arenas_malloc_states()[0])  # doctest: +ELLIPSIS
            ===... Malloc State (0x7ff101adaba0) ===...
            mutex = 0x0
            flags = 0x0
            have_fastchunks = 0x0
            fastbinsY
              [0] 0x20 => 0x0
              [1] 0x30 => 0x0
              [2] 0x40 => 0x0
              [3] 0x50 => 0x0
              [4] 0x60 => 0x0
              [5] 0x70 => 0x0
              [6] 0x80 => 0x0
              [7] 0x90 => 0x0
              [8] 0xa0 => 0x0
              [9] 0xb0 => 0x0
            top = 0x55c9539e11a0
            last_remainder = 0x0
            bins
             Unsorted bins
              [0] fd=0x7ff101adac00 bk=0x7ff101adac00
             Small bins
              [1] 0x20 fd=0x7ff101adac10 bk=0x7ff101adac10
              [2] 0x30 fd=0x7ff101adac20 bk=0x7ff101adac20
              [3] 0x40 fd=0x55c9539df610 bk=0x55c9539e0110
              [4] 0x50 fd=0x7ff101adac40 bk=0x7ff101adac40
              [5] 0x60 fd=0x7ff101adac50 bk=0x7ff101adac50
              [6] 0x70 fd=0x7ff101adac60 bk=0x7ff101adac60
              [7] 0x80 fd=0x7ff101adac70 bk=0x7ff101adac70
              [8] 0x90 fd=0x7ff101adac80 bk=0x7ff101adac80
              [9] 0xa0 fd=0x7ff101adac90 bk=0x7ff101adac90
              [10] 0xb0 fd=0x7ff101adaca0 bk=0x7ff101adaca0
              [11] 0xc0 fd=0x7ff101adacb0 bk=0x7ff101adacb0
              [12] 0xd0 fd=0x7ff101adacc0 bk=0x7ff101adacc0
              [13] 0xe0 fd=0x7ff101adacd0 bk=0x7ff101adacd0
              [14] 0xf0 fd=0x7ff101adace0 bk=0x7ff101adace0
              [15] 0x100 fd=0x7ff101adacf0 bk=0x7ff101adacf0
              [16] 0x110 fd=0x7ff101adad00 bk=0x7ff101adad00
              [17] 0x120 fd=0x7ff101adad10 bk=0x7ff101adad10
              [18] 0x130 fd=0x7ff101adad20 bk=0x7ff101adad20
              [19] 0x140 fd=0x7ff101adad30 bk=0x7ff101adad30
              [20] 0x150 fd=0x7ff101adad40 bk=0x7ff101adad40
              [21] 0x160 fd=0x7ff101adad50 bk=0x7ff101adad50
              [22] 0x170 fd=0x7ff101adad60 bk=0x7ff101adad60
              [23] 0x180 fd=0x7ff101adad70 bk=0x7ff101adad70
              [24] 0x190 fd=0x7ff101adad80 bk=0x7ff101adad80
              [25] 0x1a0 fd=0x7ff101adad90 bk=0x7ff101adad90
              [26] 0x1b0 fd=0x7ff101adada0 bk=0x7ff101adada0
              [27] 0x1c0 fd=0x7ff101adadb0 bk=0x7ff101adadb0
              [28] 0x1d0 fd=0x7ff101adadc0 bk=0x7ff101adadc0
              [29] 0x1e0 fd=0x7ff101adadd0 bk=0x7ff101adadd0
              [30] 0x1f0 fd=0x7ff101adade0 bk=0x7ff101adade0
              [31] 0x200 fd=0x7ff101adadf0 bk=0x7ff101adadf0
              [32] 0x210 fd=0x7ff101adae00 bk=0x7ff101adae00
              [33] 0x220 fd=0x7ff101adae10 bk=0x7ff101adae10
              [34] 0x230 fd=0x7ff101adae20 bk=0x7ff101adae20
              [35] 0x240 fd=0x7ff101adae30 bk=0x7ff101adae30
              [36] 0x250 fd=0x7ff101adae40 bk=0x7ff101adae40
              [37] 0x260 fd=0x7ff101adae50 bk=0x7ff101adae50
              [38] 0x270 fd=0x7ff101adae60 bk=0x7ff101adae60
              [39] 0x280 fd=0x7ff101adae70 bk=0x7ff101adae70
              [40] 0x290 fd=0x7ff101adae80 bk=0x7ff101adae80
              [41] 0x2a0 fd=0x7ff101adae90 bk=0x7ff101adae90
              [42] 0x2b0 fd=0x7ff101adaea0 bk=0x7ff101adaea0
              [43] 0x2c0 fd=0x7ff101adaeb0 bk=0x7ff101adaeb0
              [44] 0x2d0 fd=0x7ff101adaec0 bk=0x7ff101adaec0
              [45] 0x2e0 fd=0x7ff101adaed0 bk=0x7ff101adaed0
              [46] 0x2f0 fd=0x7ff101adaee0 bk=0x7ff101adaee0
              [47] 0x300 fd=0x7ff101adaef0 bk=0x7ff101adaef0
              [48] 0x310 fd=0x7ff101adaf00 bk=0x7ff101adaf00
              [49] 0x320 fd=0x7ff101adaf10 bk=0x7ff101adaf10
              [50] 0x330 fd=0x7ff101adaf20 bk=0x7ff101adaf20
              [51] 0x340 fd=0x7ff101adaf30 bk=0x7ff101adaf30
              [52] 0x350 fd=0x7ff101adaf40 bk=0x7ff101adaf40
              [53] 0x360 fd=0x7ff101adaf50 bk=0x7ff101adaf50
              [54] 0x370 fd=0x7ff101adaf60 bk=0x7ff101adaf60
              [55] 0x380 fd=0x7ff101adaf70 bk=0x7ff101adaf70
              [56] 0x390 fd=0x7ff101adaf80 bk=0x7ff101adaf80
              [57] 0x3a0 fd=0x7ff101adaf90 bk=0x7ff101adaf90
              [58] 0x3b0 fd=0x7ff101adafa0 bk=0x7ff101adafa0
              [59] 0x3c0 fd=0x7ff101adafb0 bk=0x7ff101adafb0
              [60] 0x3d0 fd=0x7ff101adafc0 bk=0x7ff101adafc0
              [61] 0x3e0 fd=0x7ff101adafd0 bk=0x7ff101adafd0
              [62] 0x3f0 fd=0x7ff101adafe0 bk=0x7ff101adafe0
             Large bins
              [63] 0x400 fd=0x7ff101adaff0 bk=0x7ff101adaff0
              [64] 0x440 fd=0x7ff101adb000 bk=0x7ff101adb000
              [65] 0x480 fd=0x7ff101adb010 bk=0x7ff101adb010
              [66] 0x4c0 fd=0x7ff101adb020 bk=0x7ff101adb020
              [67] 0x500 fd=0x7ff101adb030 bk=0x7ff101adb030
              [68] 0x540 fd=0x7ff101adb040 bk=0x7ff101adb040
              [69] 0x580 fd=0x7ff101adb050 bk=0x7ff101adb050
              [70] 0x5c0 fd=0x7ff101adb060 bk=0x7ff101adb060
              [71] 0x600 fd=0x7ff101adb070 bk=0x7ff101adb070
              [72] 0x640 fd=0x7ff101adb080 bk=0x7ff101adb080
              [73] 0x680 fd=0x7ff101adb090 bk=0x7ff101adb090
              [74] 0x6c0 fd=0x7ff101adb0a0 bk=0x7ff101adb0a0
              [75] 0x700 fd=0x7ff101adb0b0 bk=0x7ff101adb0b0
              [76] 0x740 fd=0x7ff101adb0c0 bk=0x7ff101adb0c0
              [77] 0x780 fd=0x7ff101adb0d0 bk=0x7ff101adb0d0
              [78] 0x7c0 fd=0x7ff101adb0e0 bk=0x7ff101adb0e0
              [79] 0x800 fd=0x7ff101adb0f0 bk=0x7ff101adb0f0
              [80] 0x840 fd=0x7ff101adb100 bk=0x7ff101adb100
              [81] 0x880 fd=0x7ff101adb110 bk=0x7ff101adb110
              [82] 0x8c0 fd=0x7ff101adb120 bk=0x7ff101adb120
              [83] 0x900 fd=0x7ff101adb130 bk=0x7ff101adb130
              [84] 0x940 fd=0x7ff101adb140 bk=0x7ff101adb140
              [85] 0x980 fd=0x7ff101adb150 bk=0x7ff101adb150
              [86] 0x9c0 fd=0x7ff101adb160 bk=0x7ff101adb160
              [87] 0xa00 fd=0x7ff101adb170 bk=0x7ff101adb170
              [88] 0xa40 fd=0x7ff101adb180 bk=0x7ff101adb180
              [89] 0xa80 fd=0x7ff101adb190 bk=0x7ff101adb190
              [90] 0xac0 fd=0x7ff101adb1a0 bk=0x7ff101adb1a0
              [91] 0xb00 fd=0x7ff101adb1b0 bk=0x7ff101adb1b0
              [92] 0xb40 fd=0x7ff101adb1c0 bk=0x7ff101adb1c0
              [93] 0xb80 fd=0x7ff101adb1d0 bk=0x7ff101adb1d0
              [94] 0xbc0 fd=0x7ff101adb1e0 bk=0x7ff101adb1e0
              [95] 0xc00 fd=0x7ff101adb1f0 bk=0x7ff101adb1f0
              [96] 0xc40 fd=0x7ff101adb200 bk=0x7ff101adb200
              [97] 0xe00 fd=0x7ff101adb210 bk=0x7ff101adb210
              [98] 0x1000 fd=0x7ff101adb220 bk=0x7ff101adb220
              [99] 0x1200 fd=0x7ff101adb230 bk=0x7ff101adb230
              [100] 0x1400 fd=0x7ff101adb240 bk=0x7ff101adb240
              [101] 0x1600 fd=0x7ff101adb250 bk=0x7ff101adb250
              [102] 0x1800 fd=0x7ff101adb260 bk=0x7ff101adb260
              [103] 0x1a00 fd=0x7ff101adb270 bk=0x7ff101adb270
              [104] 0x1c00 fd=0x7ff101adb280 bk=0x7ff101adb280
              [105] 0x1e00 fd=0x7ff101adb290 bk=0x7ff101adb290
              [106] 0x2000 fd=0x7ff101adb2a0 bk=0x7ff101adb2a0
              [107] 0x2200 fd=0x7ff101adb2b0 bk=0x7ff101adb2b0
              [108] 0x2400 fd=0x7ff101adb2c0 bk=0x7ff101adb2c0
              [109] 0x2600 fd=0x7ff101adb2d0 bk=0x7ff101adb2d0
              [110] 0x2800 fd=0x7ff101adb2e0 bk=0x7ff101adb2e0
              [111] 0x2a00 fd=0x7ff101adb2f0 bk=0x7ff101adb2f0
              [112] 0x3000 fd=0x7ff101adb300 bk=0x7ff101adb300
              [113] 0x4000 fd=0x7ff101adb310 bk=0x7ff101adb310
              [114] 0x5000 fd=0x7ff101adb320 bk=0x7ff101adb320
              [115] 0x6000 fd=0x7ff101adb330 bk=0x7ff101adb330
              [116] 0x7000 fd=0x7ff101adb340 bk=0x7ff101adb340
              [117] 0x8000 fd=0x7ff101adb350 bk=0x7ff101adb350
              [118] 0x9000 fd=0x7ff101adb360 bk=0x7ff101adb360
              [119] 0xa000 fd=0x7ff101adb370 bk=0x7ff101adb370
              [120] 0x10000 fd=0x7ff101adb380 bk=0x7ff101adb380
              [121] 0x18000 fd=0x7ff101adb390 bk=0x7ff101adb390
              [122] 0x20000 fd=0x7ff101adb3a0 bk=0x7ff101adb3a0
              [123] 0x28000 fd=0x7ff101adb3b0 bk=0x7ff101adb3b0
              [124] 0x40000 fd=0x7ff101adb3c0 bk=0x7ff101adb3c0
              [125] 0x80000 fd=0x7ff101adb3d0 bk=0x7ff101adb3d0
              [126] 0x100000 fd=0x7ff101adb3e0 bk=0x7ff101adb3e0
            binmap = [0x10, 0x0, 0x0, 0x0]
            next = 0x7ff101adaba0
            next_free = 0x0
            attached_threads = 0x1
            system_mem = 0x21000
            max_system_mem = 0x21000
            =====...

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

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> heap = he.heap()
            >>> len(heap.chunks)
            574
            >>> hex(heap.top.address)
            '0x5575a9e19080'
            >>> print(heap)
            ============================ Heap (0x5575a9e08000) ============================
            0x5575a9e08000 0x290 PREV_IN_USE
              05 00 01 00 00 00 00 00 00 00 00 00 00 00 02 00   ................
            0x5575a9e08290 0x20 PREV_IN_USE
              65 73 5f 45 53 2e 55 54 46 2d 38 00 00 00 00 00   es_ES.UTF-8.....
            0x5575a9e082b0 0x80 PREV_IN_USE
              00 00 00 00 00 00 00 00 a0 82 e0 a9 75 55 00 00   ............uU..
            0x5575a9e08330 0x310 PREV_IN_USE
              a0 82 e0 a9 75 55 00 00 40 fa 05 31 1a 7f 00 00   ....uU..@..1....
            .............
            0x5575a9e18110 0x20 PREV_IN_USE
              4f 4c 44 50 57 44 3d 2f 68 6f 6d 65 2f 75 73 65   OLDPWD=/home/use
            0x5575a9e18130 0x130 PREV_IN_USE
              4c 43 5f 43 54 59 50 45 3d 65 6e 5f 55 53 2e 55   LC_CTYPE=en_US.U
            0x5575a9e18380 0x20
              65 73 5f 45 53 2e 55 54 46 2d 38 00 00 00 00 00   es_ES.UTF-8.....
            0x5575a9e19080 0xff80 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            ================================================================================


        Tests:
            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.tcaches1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.heap())  # doctest: +ELLIPSIS
            ===... Heap (0x5597c998c000) ===...
            0x5597c998c000 0x290 PREV_IN_USE
              00 00 00 00 03 00 00 00 03 00 00 00 00 00 00 00   ................
            0x5597c998c290 0x40 PREV_IN_USE
              8c 99 7c 59 05 00 00 00 10 c0 98 c9 97 55 00 00   ..|Y.........U..
            0x5597c998c2d0 0x60 PREV_IN_USE
              8c 99 7c 59 05 00 00 00 10 c0 98 c9 97 55 00 00   ..|Y.........U..
            0x5597c998c330 0x40 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5597c998c370 0x40 PREV_IN_USE
              2c 5b e4 90 92 55 00 00 10 c0 98 c9 97 55 00 00   ,[...U.......U..
            0x5597c998c3b0 0x60 PREV_IN_USE
              6c 5b e4 90 92 55 00 00 10 c0 98 c9 97 55 00 00   l[...U.......U..
            0x5597c998c410 0x40 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5597c998c450 0x40 PREV_IN_USE
              0c 5a e4 90 92 55 00 00 10 c0 98 c9 97 55 00 00   .Z...U.......U..
            0x5597c998c490 0x60 PREV_IN_USE
              4c 5a e4 90 92 55 00 00 10 c0 98 c9 97 55 00 00   LZ...U.......U..
            0x5597c998c4f0 0x40 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5597c998c530 0x1010 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5597c998d540 0x1fac0 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            ====...

        """
        malloc_state = self.malloc_state(arena_index)
        return self._heap_parser.parse_from_malloc_state(malloc_state)

    def all_arenas_heaps(self):
        """Returns the heaps of all arenas

        Returns:
            :obj:`list` of :class:`Heap`

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.all_arenas_heaps()[0])
            ============================ Heap (0x5575a9e08000) ============================
            0x5575a9e08000 0x290 PREV_IN_USE
              05 00 01 00 00 00 00 00 00 00 00 00 00 00 02 00   ................
            0x5575a9e08290 0x20 PREV_IN_USE
              65 73 5f 45 53 2e 55 54 46 2d 38 00 00 00 00 00   es_ES.UTF-8.....
            0x5575a9e082b0 0x80 PREV_IN_USE
              00 00 00 00 00 00 00 00 a0 82 e0 a9 75 55 00 00   ............uU..
            0x5575a9e08330 0x310 PREV_IN_USE
              a0 82 e0 a9 75 55 00 00 40 fa 05 31 1a 7f 00 00   ....uU..@..1....
            .............
            0x5575a9e18110 0x20 PREV_IN_USE
              4f 4c 44 50 57 44 3d 2f 68 6f 6d 65 2f 75 73 65   OLDPWD=/home/use
            0x5575a9e18130 0x130 PREV_IN_USE
              4c 43 5f 43 54 59 50 45 3d 65 6e 5f 55 53 2e 55   LC_CTYPE=en_US.U
            0x5575a9e18380 0x20
              65 73 5f 45 53 2e 55 54 46 2d 38 00 00 00 00 00   es_ES.UTF-8.....
            0x5575a9e19080 0xff80 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            ================================================================================


        Tests:
            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.tcaches1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.all_arenas_heaps()[0])  # doctest: +ELLIPSIS
            ===... Heap (0x5597c998c000) ===...
            0x5597c998c000 0x290 PREV_IN_USE
              00 00 00 00 03 00 00 00 03 00 00 00 00 00 00 00   ................
            0x5597c998c290 0x40 PREV_IN_USE
              8c 99 7c 59 05 00 00 00 10 c0 98 c9 97 55 00 00   ..|Y.........U..
            0x5597c998c2d0 0x60 PREV_IN_USE
              8c 99 7c 59 05 00 00 00 10 c0 98 c9 97 55 00 00   ..|Y.........U..
            0x5597c998c330 0x40 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5597c998c370 0x40 PREV_IN_USE
              2c 5b e4 90 92 55 00 00 10 c0 98 c9 97 55 00 00   ,[...U.......U..
            0x5597c998c3b0 0x60 PREV_IN_USE
              6c 5b e4 90 92 55 00 00 10 c0 98 c9 97 55 00 00   l[...U.......U..
            0x5597c998c410 0x40 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5597c998c450 0x40 PREV_IN_USE
              0c 5a e4 90 92 55 00 00 10 c0 98 c9 97 55 00 00   .Z...U.......U..
            0x5597c998c490 0x60 PREV_IN_USE
              4c 5a e4 90 92 55 00 00 10 c0 98 c9 97 55 00 00   LZ...U.......U..
            0x5597c998c4f0 0x40 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5597c998c530 0x1010 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            0x5597c998d540 0x1fac0 PREV_IN_USE
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
            =====...

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

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.unsorted_bin())
            ================================ Unsorted Bins ================================
            [0] Unsorted Bin (2) => Chunk(0x5597afccc330 0x1010 PREV_IN_USE) => Chunk(0x5597afccb2e0 0x1010 PREV_IN_USE) => 0x7f1c523a4c00
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.unsorted_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.unsorted_bin())  # doctest: +ELLIPSIS
            ===... Unsorted Bins ===...
            [0] Unsorted Bin (2) => Chunk(0x55c9a83ed330 0x1010 PREV_IN_USE) => Chunk(0x55c9a83ec2e0 0x1010 PREV_IN_USE) => 0x7fcbe729bc00
            ======...

        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_unsorted_bin_from_malloc_state(
            malloc_state
        )

    def all_arenas_unsorted_bins(self):
        """Returns the unsorted bins of all arenas

        Returns:
            list of :class:`UnsortedBins`

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.all_arenas_unsorted_bins()[0])
            ================================ Unsorted Bins ================================
            [0] Unsorted Bin (2) => Chunk(0x5597afccc330 0x1010 PREV_IN_USE) => Chunk(0x5597afccb2e0 0x1010 PREV_IN_USE) => 0x7f1c523a4c00
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.unsorted_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.all_arenas_unsorted_bins()[0])  # doctest: +ELLIPSIS
            ===... Unsorted Bins ===...
            [0] Unsorted Bin (2) => Chunk(0x55c9a83ed330 0x1010 PREV_IN_USE) => Chunk(0x55c9a83ec2e0 0x1010 PREV_IN_USE) => 0x7fcbe729bc00
            ======...
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

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.small_bins())
            ================================== Small Bins ==================================
            [6] Small Bin 0x80 (3) => Chunk(0x55f241d7fed0 0x80 PREV_IN_USE) => Chunk(0x55f241d80070 0x80 PREV_IN_USE) => Chunk(0x55f241d80210 0x80 PREV_IN_USE) => 0x7ff159b83c70
            [8] Small Bin 0xa0 (3) => Chunk(0x55f241d80130 0xa0 PREV_IN_USE) => Chunk(0x55f241d7ff90 0xa0 PREV_IN_USE) => Chunk(0x55f241d7fdf0 0xa0 PREV_IN_USE) => 0x7ff159b83c90
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.small_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.small_bins()) # doctest: +ELLIPSIS
            ===... Small Bins ===...
            [6] Small Bin 0x80 (3) => Chunk(0x55bed6e87ed0 0x80 PREV_IN_USE) => Chunk(0x55bed6e88070 0x80 PREV_IN_USE) => Chunk(0x55bed6e88210 0x80 PREV_IN_USE) => 0x7feeee344c70
            [8] Small Bin 0xa0 (3) => Chunk(0x55bed6e88130 0xa0 PREV_IN_USE) => Chunk(0x55bed6e87f90 0xa0 PREV_IN_USE) => Chunk(0x55bed6e87df0 0xa0 PREV_IN_USE) => 0x7feeee344c90
            ======...
        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_small_bins_from_malloc_state(
            malloc_state,
        )

    def all_arenas_small_bins(self):
        """Returns the small bins of all arenas

        Returns:
            list of :class:`SmallBins`

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.all_arenas_small_bins()[0])
            ================================== Small Bins ==================================
            [6] Small Bin 0x80 (3) => Chunk(0x55f241d7fed0 0x80 PREV_IN_USE) => Chunk(0x55f241d80070 0x80 PREV_IN_USE) => Chunk(0x55f241d80210 0x80 PREV_IN_USE) => 0x7ff159b83c70
            [8] Small Bin 0xa0 (3) => Chunk(0x55f241d80130 0xa0 PREV_IN_USE) => Chunk(0x55f241d7ff90 0xa0 PREV_IN_USE) => Chunk(0x55f241d7fdf0 0xa0 PREV_IN_USE) => 0x7ff159b83c90
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.small_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.all_arenas_small_bins()[0]) # doctest: +ELLIPSIS
            ===... Small Bins ===...
            [6] Small Bin 0x80 (3) => Chunk(0x55bed6e87ed0 0x80 PREV_IN_USE) => Chunk(0x55bed6e88070 0x80 PREV_IN_USE) => Chunk(0x55bed6e88210 0x80 PREV_IN_USE) => 0x7feeee344c70
            [8] Small Bin 0xa0 (3) => Chunk(0x55bed6e88130 0xa0 PREV_IN_USE) => Chunk(0x55bed6e87f90 0xa0 PREV_IN_USE) => Chunk(0x55bed6e87df0 0xa0 PREV_IN_USE) => 0x7feeee344c90
            ======...
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

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.large_bins())
            ================================== Large Bins ==================================
            [35] Large Bin 0x1000 (3) => Chunk(0x55efb3ce9290 0x1010 PREV_IN_USE) => Chunk(0x55efb3cee1d0 0x1010 PREV_IN_USE) => Chunk(0x55efb3ceba30 0x1010 PREV_IN_USE) => 0x7f3cddff8220
            [38] Large Bin 0x1600 (4) => Chunk(0x55efb3cea2e0 0x1710 PREV_IN_USE) => Chunk(0x55efb3cf19c0 0x1710 PREV_IN_USE) => Chunk(0x55efb3cef220 0x1710 PREV_IN_USE) => Chunk(0x55efb3ceca80 0x1710 PREV_IN_USE) => 0x7f3cddff8250
            ================================================================================


        Tests:
            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.large_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.large_bins()) # doctest: +ELLIPSIS
            ===... Large Bins ===...
            [35] Large Bin 0x1000 (3) => Chunk(0x558fce0db290 0x1010 PREV_IN_USE) => Chunk(0x558fce0e01d0 0x1010 PREV_IN_USE) => Chunk(0x558fce0dda30 0x1010 PREV_IN_USE) => 0x7f90c8f3e220
            [38] Large Bin 0x1600 (4) => Chunk(0x558fce0dc2e0 0x1710 PREV_IN_USE) => Chunk(0x558fce0e39c0 0x1710 PREV_IN_USE) => Chunk(0x558fce0e1220 0x1710 PREV_IN_USE) => Chunk(0x558fce0dea80 0x1710 PREV_IN_USE) => 0x7f90c8f3e250
            ======...
        """
        malloc_state = self.malloc_state(arena_index)
        return self._bin_parser.parse_large_bins_from_malloc_state(
            malloc_state,
        )

    def all_arenas_large_bins(self):
        """Returns the large bins of all arenas

        Returns:
            :obj:`list` of :class:`LargeBins`

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.all_arenas_large_bins()) # doctest: +ELLIPSIS
            ================================== Large Bins ==================================
            [35] Large Bin 0x1000 (3) => Chunk(0x55efb3ce9290 0x1010 PREV_IN_USE) => Chunk(0x55efb3cee1d0 0x1010 PREV_IN_USE) => Chunk(0x55efb3ceba30 0x1010 PREV_IN_USE) => 0x7f3cddff8220
            [38] Large Bin 0x1600 (4) => Chunk(0x55efb3cea2e0 0x1710 PREV_IN_USE) => Chunk(0x55efb3cf19c0 0x1710 PREV_IN_USE) => Chunk(0x55efb3cef220 0x1710 PREV_IN_USE) => Chunk(0x55efb3ceca80 0x1710 PREV_IN_USE) => 0x7f3cddff8250
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.large_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.all_arenas_large_bins()[0]) # doctest: +ELLIPSIS
            ===... Large Bins ===...
            [35] Large Bin 0x1000 (3) => Chunk(0x558fce0db290 0x1010 PREV_IN_USE) => Chunk(0x558fce0e01d0 0x1010 PREV_IN_USE) => Chunk(0x558fce0dda30 0x1010 PREV_IN_USE) => 0x7f90c8f3e220
            [38] Large Bin 0x1600 (4) => Chunk(0x558fce0dc2e0 0x1710 PREV_IN_USE) => Chunk(0x558fce0e39c0 0x1710 PREV_IN_USE) => Chunk(0x558fce0e1220 0x1710 PREV_IN_USE) => Chunk(0x558fce0dea80 0x1710 PREV_IN_USE) => 0x7f90c8f3e250
            ======...
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

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.fast_bins())
            ================================== Fast Bins ==================================
            [0] Fast Bin 0x20 (2) => Chunk(0x1330140 0x20 PREV_IN_USE) => Chunk(0x1330070 0x20 PREV_IN_USE) => 0x0
            [3] Fast Bin 0x50 (2) => Chunk(0x13300d0 0x50 PREV_IN_USE) => Chunk(0x1330000 0x50 PREV_IN_USE) => 0x0
            ================================================================================

        Tests:
            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.23.fast_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.23.so'))
            >>> print(he.fast_bins()) # doctest: +ELLIPSIS
            ===... Fast Bins ===...
            [0] Fast Bin 0x20 (2) => Chunk(0x1b5c140 0x20 PREV_IN_USE) => Chunk(0x1b5c070 0x20 PREV_IN_USE) => 0x0
            [3] Fast Bin 0x50 (2) => Chunk(0x1b5c0d0 0x50 PREV_IN_USE) => Chunk(0x1b5c000 0x50 PREV_IN_USE) => 0x0
            ======...
        """
        malloc_state = self.malloc_state(arena_index)
        return self._fast_bin_parser.parse_all_from_malloc_state(malloc_state)

    def all_arenas_fast_bins(self):
        """Returns the small bins of all arenas

        Returns:
            :obj:`list` of :class:`FastBins`

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.all_arenas_fast_bins()[0])
            ================================== Fast Bins ==================================
            [0] Fast Bin 0x20 (2) => Chunk(0x1b5c140 0x20 PREV_IN_USE) => Chunk(0x1b5c070 0x20 PREV_IN_USE) => 0x0
            [3] Fast Bin 0x50 (2) => Chunk(0x1b5c0d0 0x50 PREV_IN_USE) => Chunk(0x1b5c000 0x50 PREV_IN_USE) => 0x0
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.23.fast_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.23.so'))
            >>> print(he.all_arenas_fast_bins()[0]) # doctest: +ELLIPSIS
            ===... Fast Bins ===...
            [0] Fast Bin 0x20 (2) => Chunk(0x1b5c140 0x20 PREV_IN_USE) => Chunk(0x1b5c070 0x20 PREV_IN_USE) => 0x0
            [3] Fast Bin 0x50 (2) => Chunk(0x1b5c0d0 0x50 PREV_IN_USE) => Chunk(0x1b5c000 0x50 PREV_IN_USE) => 0x0
            ======...
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

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> he.tcaches_enabled
            True
            >>> print(he.tcaches())
            =================================== Tcaches ===================================
            [23] Tcache 0x188 (1) => Chunk(0x56383e3c0250 0x190 PREV_IN_USE) => 0x0
            [41] Tcache 0x2a8 (1) => Chunk(0x56383e3bffa0 0x2b0 PREV_IN_USE) => 0x0
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.tcaches1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> he.tcaches_enabled
            True
            >>> print(he.tcaches()) # doctest: +ELLIPSIS
            ===... Tcaches ===...
            [10] Tcache 0xb8 (3) => Chunk(0x5597c998c460 0x40 PREV_IN_USE) => Chunk(0x5597c998c380 0x40 PREV_IN_USE) => Chunk(0x5597c998c2a0 0x40 PREV_IN_USE) => 0x0
            [12] Tcache 0xd8 (3) => Chunk(0x5597c998c4a0 0x60 PREV_IN_USE) => Chunk(0x5597c998c3c0 0x60 PREV_IN_USE) => Chunk(0x5597c998c2e0 0x60 PREV_IN_USE) => 0x0
            ======...

            Tcaches were included in libc 2.26 so trying to access them in previous versions raises an error

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.23.fast_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.23.so'))
            >>> try:
            ...    he.tcaches()
            ... except NoTcacheError as e:
            ...    print(e)
            Tcache are not available in the current libc

        """
        if not self.tcaches_enabled:
            raise NoTcacheError()

        malloc_state = self.malloc_state(arena_index)
        return self._tcache_parser.parse_all_from_malloc_state(malloc_state)

    def all_arenas_tcaches(self):
        """Returns the tcaches of all arenas

        Returns:
            :obj:`list` of :class:`Tcaches`


        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> he.tcaches_enabled
            True
            >>> print(he.all_arenas_tcaches()[0]) # doctest: +SKIP
            =================================== Tcaches ===================================
            [10] Tcache 0xb8 (3) => Chunk(0x5597c998c460 0x40 PREV_IN_USE) => Chunk(0x5597c998c380 0x40 PREV_IN_USE) => Chunk(0x5597c998c2a0 0x40 PREV_IN_USE) => 0x0
            [12] Tcache 0xd8 (3) => Chunk(0x5597c998c4a0 0x60 PREV_IN_USE) => Chunk(0x5597c998c3c0 0x60 PREV_IN_USE) => Chunk(0x5597c998c2e0 0x60 PREV_IN_USE) => 0x0
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.tcaches1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> he.tcaches_enabled
            True
            >>> print(he.all_arenas_tcaches()[0]) # doctest: +ELLIPSIS
            ===... Tcaches ===...
            [10] Tcache 0xb8 (3) => Chunk(0x5597c998c460 0x40 PREV_IN_USE) => Chunk(0x5597c998c380 0x40 PREV_IN_USE) => Chunk(0x5597c998c2a0 0x40 PREV_IN_USE) => 0x0
            [12] Tcache 0xd8 (3) => Chunk(0x5597c998c4a0 0x60 PREV_IN_USE) => Chunk(0x5597c998c3c0 0x60 PREV_IN_USE) => Chunk(0x5597c998c2e0 0x60 PREV_IN_USE) => 0x0
            ======...

            Tcaches were included in libc 2.26 so trying to access them in previous versions raises an error

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.23.fast_bins1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.23.so'))
            >>> try:
            ...    he.all_arenas_tcaches()
            ... except NoTcacheError as e:
            ...    print(e)
            Tcache are not available in the current libc
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

        .. code-block:: python

            >>> p = process('sh')
            >>> hp = p.heap_explorer()
            >>> arena = hp.arena()
            >>> print(arena.summary())
            ==================================== Arena ====================================
            - Malloc State (0x7f4ca8fe8ba0)
                top = 0x55587a7bf380
                last_remainder = 0x0
                next = 0x7f4ca8fe8ba0
                next_free = 0x0
                system_mem = 0x21000
            - Heap (0x55587a7bc000)
                chunks_count = 0x8
                top: addr = 0x55587a7bf380, size = 0x1dc80
            - Tcaches
                [-] No chunks found
            - Fast bins
                [-] No chunks found
            - Unsorted bins
                [0] 0x0 (2)
            - Small bins
                [-] No chunks found
            - Large bins
                [-] No chunks found
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.sample1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.arena().summary()) # doctest: +ELLIPSIS
            ===... Arena ===...
            - Malloc State (0x7ff101adaba0)
                top = 0x55c9539e11a0
                last_remainder = 0x0
                next = 0x7ff101adaba0
                next_free = 0x0
                system_mem = 0x21000
            - Heap (0x55c9539df000)
                chunks_count = 0x3f
                top: addr = 0x55c9539e11a0, size = 0x1ee60
            - Tcaches
                [10] 0xb8 (7)
            - Fast bins
                [-] No chunks found
            - Unsorted bins
                [-] No chunks found
            - Small bins
                [3] 0x40 (23)
            - Large bins
                [-] No chunks found
            ======...

        """
        malloc_state = self.malloc_state(arena_index)
        return self._arena_parser.parse_from_malloc_state(malloc_state)

    def all_arenas(self):
        """Returns all arenas

        Returns:
            :obj:`list` of :class:`Arena`

        .. code-block:: python

            >>> p = process('sh')
            >>> he = p.heap_explorer()
            >>> print(he.all_arenas()[0].summary()) # doctest: +SKIP
            ==================================== Arena ====================================
            - Malloc State (0x7f4ca8fe8ba0)
                top = 0x55587a7bf380
                last_remainder = 0x0
                next = 0x7f4ca8fe8ba0
                next_free = 0x0
                system_mem = 0x21000
            - Heap (0x55587a7bc000)
                chunks_count = 0x8
                top: addr = 0x55587a7bf380, size = 0x1dc80
            - Tcaches
                [-] No chunks found
            - Fast bins
                [-] No chunks found
            - Unsorted bins
                [0] 0x0 (2)
            - Small bins
                [-] No chunks found
            - Large bins
                [-] No chunks found
            ================================================================================

        Tests:

            >>> c = Corefile(pwnlib.data.heap.x86_64.get('core.32.sample1'))
            >>> he = c.heap_explorer(libc_path=pwnlib.data.heap.x86_64.get('libc-2.32.so'))
            >>> print(he.all_arenas()[0].summary()) # doctest: +ELLIPSIS
            ===... Arena ===...
            - Malloc State (0x7ff101adaba0)
                top = 0x55c9539e11a0
                last_remainder = 0x0
                next = 0x7ff101adaba0
                next_free = 0x0
                system_mem = 0x21000
            - Heap (0x55c9539df000)
                chunks_count = 0x3f
                top: addr = 0x55c9539e11a0, size = 0x1ee60
            - Tcaches
                [10] 0xb8 (7)
            - Fast bins
                [-] No chunks found
            - Unsorted bins
                [-] No chunks found
            - Small bins
                [3] 0x40 (23)
            - Large bins
                [-] No chunks found
            ======...
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