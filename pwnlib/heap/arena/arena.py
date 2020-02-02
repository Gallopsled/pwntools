from pwnlib.heap.bins import NoTcacheError
from pwnlib.heap.malloc_state import \
    SMALL_BINS_START_INDEX, \
    LARGE_BINS_START_INDEX
from pwnlib.heap.basic_formatter import BasicFormatter


class Arena(object):
    """Class with the information of the arena.

    Attributes:
        malloc_state (MallocState): The malloc_state struct of the arena
        heap (Heap): The heap of the arena
        tcaches (Tcaches): The tcaches of the arena. If
            tcaches are not available, an exception :class:`NoTcacheError` is
            raised
        fast_bins (FastBins): The fast bins of the arena
        unsorted_bin (UnsortedBins): The unsorted bin of the arena
        small_bins (SmallBins): The small bins of the arena
        large_bins (LargeBins): The large bins of the arena
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
        self._basic_formatter = BasicFormatter()

    @property
    def tcaches(self):
        if self._tcaches is None:
            raise NoTcacheError()

        return self._tcaches


    def __str__(self):
        msg = [
            self._basic_formatter.super_header("Arena"),
            str(self.malloc_state),
            str(self.heap),
        ]

        try:
            msg.append(str(self.tcaches))
        except NoTcacheError:
            pass

        msg.append(str(self.fast_bins))
        msg.append(str(self.unsorted_bin))
        msg.append(str(self.small_bins))
        msg.append(str(self.large_bins))
        msg.append(self._basic_formatter.super_footer())

        return "\n".join(msg)

    def summary(self):
        msg = [
            self._basic_formatter.header("Arena"),
            self._format_summary(),
            self._basic_formatter.footer()
        ]
        return "\n".join(msg)

    def _format_summary(self):
        msg = ""

        malloc_state = self.malloc_state
        msg += "- Malloc State ({:#x})\n".format(malloc_state.address)
        msg += "    top = {:#x}\n".format(malloc_state.top)
        msg += "    last_remainder = {:#x}\n".format(
            malloc_state.last_remainder
        )
        msg += "    next = {:#x}\n".format(malloc_state.next)
        msg += "    next_free = {:#x}\n".format(malloc_state.next_free)
        msg += "    system_mem = {:#x}\n".format(malloc_state.system_mem)

        heap = self.heap
        msg += "- Heap ({:#x})\n".format(heap.address)
        msg += "    chunks_count = {:#x}\n".format(len(heap.chunks))
        msg += "    top: addr = {:#x}, size = {:#x}\n".format(
            heap.top.address, heap.top.size
        )

        try:
            tcaches = self.tcaches
            msg += "- Tcaches\n"
            msg += "{}\n".format(tcaches.summary())
        except NoTcacheError:
            pass

        msg += "- Fast bins\n"
        msg += "{}\n".format(self.fast_bins.summary())

        msg += "- Unsorted bins\n"
        msg += "{}\n".format(self.unsorted_bin.summary())

        msg += "- Small bins\n"
        msg += "{}\n".format(
            self.small_bins.summary(start_index=SMALL_BINS_START_INDEX)
        )

        msg += "- Large bins\n"
        msg += "{}".format(
            self.large_bins.summary(start_index=LARGE_BINS_START_INDEX)
        )

        return msg
