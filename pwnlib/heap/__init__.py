# -*- coding: utf-8 -*-
"""
During heap exploit development, it is frequently useful to obtain an
image of the heap layout as well as of the bins used by the glibc.


To provide access to the heap items, an :class:`HeapExplorer` has to be used,
which can be obtained from :attr:`pwnlib.tubes.process.heap_explorer`

Examples
----------

Get a summary of the items of the arena:

    >>> p = process('sh')
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

View the malloc state:

    >>> p = process('sh')
    >>> hp = p.heap_explorer
    >>> print(hp.malloc_state()) # doctest: +SKIP
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


List the chunks of the bins:

    >>> p = process('sh')
    >>> hp = p.heap_explorer
    >>> print(hp.tcaches()) # doctest: +SKIP
    =================================== Tcaches ===================================
    [23] Tcache 0x188 (1) => Chunk(0x56383e3c0250 0x190 PREV_IN_USE) => 0x0
    [41] Tcache 0x2a8 (1) => Chunk(0x56383e3bffa0 0x2b0 PREV_IN_USE) => 0x0
    ================================================================================
    >>> print(hp.fast_bins()) # doctest: +SKIP
    ================================== Fast Bins ==================================
    [4] Fast Bin 0x60 (2) => Chunk(0x555635100c20 0x60 PREV_IN_USE) => Chunk(0x55563
    5100ba0 0x60 PREV_IN_USE) => 0x0
    ================================================================================
    >>> print(hp.unsorted_bin()) # doctest: +SKIP
    ================================ Unsorted Bins ================================
    [0] Unsorted Bin (2) => Chunk(0x555635101d40 0x910 PREV_IN_USE) => Chunk(0x55563
    5100ca0 0x1010 PREV_IN_USE) => 0x7f8bd66e9ca0
    ================================================================================
    >>> print(hp.small_bins()) # doctest: +SKIP
    ================================== Small Bins ==================================
        [-] No chunks found
    ================================================================================
    >>> print(hp.large_bins()) # doctest: +SKIP
    ================================== Large Bins ==================================
        [-] No chunks found
    ================================================================================



List the chunks of the arena heap:

    >>> p = process('sh')
    >>> hp = p.heap_explorer
    >>> print(hp.heap()) # doctest: +SKIP
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

Get all the arena information:

    >>> p = process('sh')
    >>> hp = p.heap_explorer
    >>> print(hp.arena()) # doctest: +SKIP
    ++++++++++++++++++++++++++++++++++++ Arena ++++++++++++++++++++++++++++++++++++
    ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
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
                ........
      [61] 0x3e0 fd=0x7f97053fc070 bk=0x7f97053fc070
      [62] 0x3f0 fd=0x7f97053fc080 bk=0x7f97053fc080
     Large bins
      [63] 0x400 fd=0x7f97053fc090 bk=0x7f97053fc090
      [64] 0x440 fd=0x7f97053fc0a0 bk=0x7f97053fc0a0
                ........
      [125] 0x80000 fd=0x7f97053fc470 bk=0x7f97053fc470
      [126] 0x100000 fd=0x7f97053fc480 bk=0x7f97053fc480
    binmap = [0x0, 0x0, 0x0, 0x0]
    next = 0x7f96f8000020
    next_free = 0x0
    attached_threads = 0x1
    system_mem = 0x21000
    max_system_mem = 0x21000
    ================================================================================
    ============================ Heap (0x55c4669fd000) ============================
    0x55c4669fd000 0x250 PREV_IN_USE
      00 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00   ................
    0x55c4669fd250 0x410 PREV_IN_USE
      61 61 61 0a 0a 20 76 65 72 73 69 6f 6e 20 3d 20   aaa.. version =
    0x55c4669fd660 0x120 PREV_IN_USE
      0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
                ..........
    0x55c4669fdca0 0x1010 PREV_IN_USE
      a0 bc 3f 05 97 7f 00 00 40 ed 9f 66 c4 55 00 00   ..?.....@..f.U..
    0x55c4669fecb0 0x90
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0x55c4669fed40 0x910 PREV_IN_USE
      a0 dc 9f 66 c4 55 00 00 a0 bc 3f 05 97 7f 00 00   ...f.U....?.....
    0x55c4669ff650 0x90
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0x55c4669ff6e0 0x1e920 PREV_IN_USE
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    ================================================================================
    =================================== Tcaches ===================================
    [4] Tcache 0x58 (7) => Chunk(0x55c4669fdb50 0x60 PREV_IN_USE) => Chunk(0x55c4669
    fdaf0 0x60 PREV_IN_USE) => Chunk(0x55c4669fda90 0x60 PREV_IN_USE) => Chunk(0x55c
    4669fda30 0x60 PREV_IN_USE) => Chunk(0x55c4669fd970 0x60 PREV_IN_USE) => Chunk(0
    x55c4669fd910 0x60 PREV_IN_USE) => Chunk(0x55c4669fd8b0 0x60 PREV_IN_USE) => 0x0
    ================================================================================
    ================================== Fast Bins ==================================
    [4] Fast Bin 0x60 (2) => Chunk(0x55c4669fdc20 0x60 PREV_IN_USE) => Chunk(0x55c46
    69fdba0 0x60 PREV_IN_USE) => 0x0
    ================================================================================
    ================================ Unsorted Bins ================================
    [0] Unsorted Bin (2) => Chunk(0x55c4669fed40 0x910 PREV_IN_USE) => Chunk(0x55c46
    69fdca0 0x1010 PREV_IN_USE) => 0x7f97053fbca0
    ================================================================================
    ================================== Small Bins ==================================
        [-] No chunks found
    ================================================================================
    ================================== Large Bins ==================================
        [-] No chunks found
    ================================================================================
    ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


Access to items of the non main arena:
    >>> p = process('sh')
    >>> hp = p.heap_explorer
    >>> hp.arenas_count() # doctest: +SKIP
    2
    >>> _ = [print(arena.summary()) for arena in hp.all_arenas()] # doctest: +SKIP
    ==================================== Arena ====================================
    - Malloc State (0x7f97053fbc40)
        top = 0x55c4669ff6e0
        last_remainder = 0x0
        next = 0x7f9700000020
        next_free = 0x0
        system_mem = 0x21000
    - Heap (0x55c4669fd000)
        chunks_count = 0x15
        top: addr = 0x55c4669ff6e0, size = 0x1e920
    - Tcaches
        [4] 0x58 (7)
    - Fast bins
        [4] 0x60 (2)
    - Unsorted bins
        [0] 0x0 (2)
    - Small bins
        [-] No chunks found
    - Large bins
        [-] No chunks found
    ================================================================================
    ==================================== Arena ====================================
    - Malloc State (0x7f9700000020)
        top = 0x7f9700002b30
        last_remainder = 0x0
        next = 0x7f97053fbc40
        next_free = 0x0
        system_mem = 0x21000
    - Heap (0x7f97000008c0)
        chunks_count = 0x4
        top: addr = 0x7f9700002b30, size = 0x1e4d0
    - Tcaches
        [-] No chunks found
    - Fast bins
        [-] No chunks found
    - Unsorted bins
        [-] No chunks found
    - Small bins
        [-] No chunks found
    - Large bins
        [-] No chunks found
    ================================================================================
    >>> _ = [print(ms) for ms in hp.all_arenas_fast_bins()] # doctest: +SKIP
    ================================== Fast Bins ==================================
    [4] Fast Bin 0x60 (2) => Chunk(0x55c4669fdc20 0x60 PREV_IN_USE) => Chunk(0x55c46
    69fdba0 0x60 PREV_IN_USE) => 0x0
    ================================================================================
    ================================== Fast Bins ==================================
        [-] No chunks found
    ================================================================================
    >>> print(hp.fast_bins()) # doctest: +SKIP
    ================================== Fast Bins ==================================
    [4] Fast Bin 0x60 (2) => Chunk(0x55c4669fdc20 0x60 PREV_IN_USE) => Chunk(0x55c4669fdba0 0x60 PREV_IN_USE) => 0x0
    ================================================================================
    >>> print(hp.fast_bins(arena_index=1)) # doctest: +SKIP
    ================================== Fast Bins ==================================
        [-] No chunks found
    ================================================================================

"""

from .heap_explorer import HeapExplorer
