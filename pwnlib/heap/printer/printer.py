from heap_explorer.malloc_state import *
from .formatter import *

import shutil


def get_terminal_width():
    try:
        return shutil.get_terminal_size().columns
    except AttributeError:
        import os
        _, columns = os.popen('stty size', 'r').read().split()
        return columns


class BinPrinter:

    _MAXIMUM_WIDTH = 80

    def __init__(self, pointer_size):
        self.width = self._MAXIMUM_WIDTH
        term_width = get_terminal_width()

        if term_width < self.width:
            self.width = term_width

        self.title_surrounded_symbol = "="
        self._pointer_size = pointer_size

        self._heap_formatter = HeapFormatter(pointer_size)
        self._bin_formatter = BinFormatter(pointer_size)
        self._malloc_state_formatter = MallocStateFormatter()
        self._arena_formatter = ArenaFormatter(pointer_size)

    def print_arena(self, arena):
        self._print_super_title("Arena")
        self.print_malloc_state(arena.malloc_state)
        self.print_heap(arena.heap)
        self.print_all_bins_types(arena)
        self._print_super_close()

    def print_arena_summary(self, arena):
        self._print_title("Arena")
        print(self._arena_formatter.format_arena_summary(arena))
        self._print_close()

    def print_malloc_state(self, malloc_state):
        self._print_title("Malloc State ({:#x})".format(malloc_state.address))
        print(self._malloc_state_formatter.format_malloc_state(malloc_state))
        self._print_close()

    def print_heap(self, heap):
        self._print_title("Heap ({:#x})".format(heap.address))
        print(self._heap_formatter.format_heap(heap))
        self._print_close()

    def print_all_bins_types(self, arena, print_all=False):
        try:
            self.print_tcaches(arena.tcaches, print_all)
        except NoTcacheError:
            pass

        self.print_fast_bins(arena.fast_bins, print_all)
        self.print_unsorted_bin(arena.unsorted_bin, print_all)
        self.print_small_bins(arena.small_bins, print_all)
        self.print_large_bins(arena.large_bins, print_all)

    def print_tcaches(self, tcaches, print_all=False):
        return self._print_bins(tcaches, "Tcaches", print_all)

    def print_fast_bins(self, fast_bins, print_all=False):
        return self._print_bins(
            fast_bins,
            "Fast bins",
            print_all,
        )

    def print_unsorted_bin(self, unsorted_bin, print_all=False):
        return self._print_bins(
            [unsorted_bin],
            "Unsorted bins",
            print_all,
            start_index=UNSORTED_BIN_INDEX
        )

    def print_small_bins(self, small_bins, print_all=False):
        return self._print_bins(
            small_bins,
            "Small bins",
            print_all,
            start_index=SMALL_BINS_START_INDEX
        )

    def print_large_bins(self, large_bins, print_all=False):
        return self._print_bins(
            large_bins,
            "Large bins",
            print_all,
            start_index=LARGE_BINS_START_INDEX
        )

    def _print_bins(self, bins, title, print_all=False, start_index=0):
        self._print_title(title)
        print(self._bin_formatter.format_bins(bins, start_index, print_all))
        self._print_close()

    def _print_title(self, title):
        print(self._format_title(title))

    def _format_title(self, title, separator="="):
        side_len = self._calc_side_len(title)
        side = separator * side_len
        return "{} {} {}".format(side, title, side)

    def _format_super_title(self, title):
        msg = "{}\n".format(self._format_title(title, separator="+"))
        msg += "+" * self.width
        return msg

    def _print_super_title(self, title):
        print(self._format_super_title(title))

    def _calc_side_len(self, title):
        return int((self.width - len(title) - 2) / 2)

    def _print_close(self):
        print("=" * self.width)

    def _print_super_close(self):
        print("+" * self.width)
