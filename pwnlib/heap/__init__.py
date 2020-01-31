# -*- coding: utf-8 -*-
"""
During heap exploit development, it is frequently useful to obtain an
image of the heap layout as well as of the bins used by the glibc.

"""

# TODO: write heap documentation
#   * Tcaches
#   * Fast bins
#   * Unsorted bin
#   * Small bins
#   * Large bins
#   * Arena
#   * Use examples
#   * Memory Maps

from .heap_explorer import HeapExplorer
