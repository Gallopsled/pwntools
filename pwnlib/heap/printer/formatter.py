from heap_explorer.bins import *
from heap_explorer.malloc_state import *


class MallocChunkFormatter:

    def __init__(self, pointer_size):
        if pointer_size == 8:
            self._p = p64
        else:
            self._p = p32

    def format_chunk_flags_as_str(self, chunk):
        flags = []
        if chunk.non_main_arena:
            flags.append("NON_MAIN_ARENA")
        if chunk.mmapped:
            flags.append("MMAPPED")
        if chunk.prev_in_use:
            flags.append("PREV_IN_USE")

        return "|".join(flags)

    def format_chunk_first_bytes_as_hexdump_str(self, chunk):
        msg = ""
        raw_bytes = bytearray(self._p(chunk.fd))
        raw_bytes += bytearray(self._p(chunk.bk))

        for byte in raw_bytes:
            msg += "{:02x} ".format(byte)

        msg += "  "

        for byte in raw_bytes:
            msg += chr(byte) if 0x20 <= byte < 0x7F else "."

        return msg


class BinFormatter:

    def __init__(self, pointer_size):
        self._malloc_chunk_formatter = MallocChunkFormatter(pointer_size)

    def format_bins_summary(self, bins, start_index=0):
        bins_str = []
        for i, bin_ in enumerate(bins):
            if len(bin_) > 0:
                bins_str.append(
                    "    [{}] {:#x} ({})".format(
                        start_index + i, bin_.chunks_size, len(bin_))
                )

        if bins_str:
            return "\n".join(bins_str)
        else:
            return "    [-] No chunks found"

    def format_bins(self, bins, start_index=0, print_all=True):
        bins_str = []
        for i, bin_ in enumerate(bins):
            if print_all or len(bin_) > 0:
                bins_str.append("[{}] {}".format(
                    i + start_index, self._format_bin_as_str(bin_))
                )

        if bins_str:
            return "\n".join(bins_str)
        else:
            return "    [-] No chunks found"

    def _format_bin_as_str(self, bin_):
        msg = self._format_bin_name_as_str(bin_)

        if not isinstance(bin_, UnsortedBin):
            msg += " {:#x}".format(bin_.chunks_size)

        msg += " ({})".format(len(bin_.malloc_chunks))

        next_address = bin_.fd
        for chunk in bin_.malloc_chunks:
            flags = self._malloc_chunk_formatter.format_chunk_flags_as_str(chunk)
            msg += " => Chunk({:#x} {:#x}".format(next_address, chunk.size)
            if flags:
                msg += " {}".format(flags)
            msg += ")"
            next_address = chunk.fd

        msg += " => {:#x}".format(next_address)
        return msg

    def _format_bin_name_as_str(self, bin_):
        if isinstance(bin_, FastBin):
            return "Fastbin"
        elif isinstance(bin_, UnsortedBin):
            return "Unsorted bins"
        elif isinstance(bin_, SmallBin):
            return "Smallbin"
        elif isinstance(bin_, LargeBin):
            return "Largebin"
        elif isinstance(bin_, Tcache):
            return "Tcache"
        else:
            raise TypeError()


class HeapFormatter:

    def __init__(self, pointer_size):
        self._malloc_chunk_formatter = MallocChunkFormatter(pointer_size)

    def format_heap(self, heap):
        chunks_str = [self._format_heap_chunk_as_str(chunk) for chunk in heap.chunks]
        return "\n".join(chunks_str)

    def _format_heap_chunk_as_str(self, chunk):
        msg = ""
        flags = self._malloc_chunk_formatter.format_chunk_flags_as_str(chunk)

        msg += "{:#x} {:#x} {}".format(chunk.address, chunk.size, flags)
        msg += "\n"
        msg += "  " + self._malloc_chunk_formatter.format_chunk_first_bytes_as_hexdump_str(chunk)

        return msg


class MallocStateFormatter:

    def format_malloc_state(self, malloc_state):
        string = ""
        string += "mutex = {:#x}\n".format(malloc_state.mutex)
        string += "flags = {:#x}\n".format(malloc_state.flags)

        if malloc_state.have_fastchunks is not None:
            string += "have_fastchunks = {:#x}\n".format(malloc_state.have_fastchunks)

        string += self._format_malloc_state_fastbinsY_as_str(malloc_state.fastbinsY)

        string += "top = {:#x}\n".format(malloc_state.top)
        string += "last_remainder = {:#x}\n".format(malloc_state.last_remainder)
        string += self._format_malloc_state_bins_as_str(malloc_state.bins)

        string += "binmap = [{:#x}, {:#x}, {:#x}, {:#x}]\n".format(
            malloc_state.binmap[0],
            malloc_state.binmap[1],
            malloc_state.binmap[2],
            malloc_state.binmap[3]
        )
        string += "next = {:#x}\n".format(malloc_state.next)
        string += "next_free = {:#x}\n".format(malloc_state.next_free)

        if malloc_state.attached_threads is not None:
            string += "attached_threads = {:#x}\n".format(
                malloc_state.attached_threads
            )
        string += "system_mem = {:#x}\n".format(malloc_state.system_mem)
        string += "max_system_mem = {:#x}".format(malloc_state.max_system_mem)

        return string

    def _format_malloc_state_fastbinsY_as_str(self, fastbinsY):
        string = "fastbinsY\n"
        for i, entry in enumerate(fastbinsY):
            string += "  [{}] {:#x} => {:#x}\n".format(
                i, entry.chunks_size, entry.fd)

        return string

    def _format_malloc_state_bins_as_str(self, bins):
        string = "bins\n"
        index = 0

        string += " Unsorted bins\n"
        unsorted_entry = bins.unsorted_bin_entry
        string += "  [{}] fd={:#x} bk={:#x}\n".format(
            index, unsorted_entry.fd, unsorted_entry.bk)

        index += 1
        string += " Small bins\n"
        for small_entry in bins.small_bins_entries:
            string += "  [{}] {:#x} fd={:#x} bk={:#x}\n".format(
                index, small_entry.chunks_size, small_entry.fd, small_entry.bk)
            index += 1

        string += " Large bins\n"
        for small_entry in bins.large_bins_entries:
            string += "  [{}] {:#x} fd={:#x} bk={:#x}\n".format(
                index, small_entry.chunks_size, small_entry.fd, small_entry.bk)
            index += 1

        return string


class ArenaFormatter:

    def __init__(self, pointer_size):
        self._bins_formatter = BinFormatter(pointer_size)

    def format_arena_summary(self, arena):
        msg = ""

        malloc_state = arena.malloc_state
        msg += "- Malloc State ({:#x})\n".format(malloc_state.address)
        msg += "    top = {:#x}\n".format(malloc_state.top)
        msg += "    last_remainder = {:#x}\n".format(malloc_state.last_remainder)
        msg += "    next = {:#x}\n".format(malloc_state.next)
        msg += "    next_free = {:#x}\n".format(malloc_state.next_free)
        msg += "    system_mem = {:#x}\n".format(malloc_state.system_mem)

        heap = arena.heap
        msg += "- Heap ({:#x})\n".format(heap.address)
        msg += "    chunks_count = {:#x}\n".format(len(heap.chunks))
        msg += "    top: addr = {:#x}, size = {:#x}\n".format(heap.top.address, heap.top.size)

        try:
            tcaches = arena.tcaches
            msg += "- Tcaches\n"
            msg += "{}\n".format(
                self._bins_formatter.format_bins_summary(tcaches)
            )
        except NoTcacheError:
            pass

        msg += "- Fast bins\n"
        msg += "{}\n".format(
            self._bins_formatter.format_bins_summary(arena.fast_bins)
        )

        msg += "- Unsorted bins\n"
        if len(arena.unsorted_bin) > 0:
            msg += "    [0] ({})\n".format(len(arena.unsorted_bin))
        else:
            msg += "    [-] No chunks found\n"

        msg += "- Small bins\n"
        msg += "{}\n".format(
            self._bins_formatter.format_bins_summary(
                arena.small_bins,
                start_index=SMALL_BINS_START_INDEX
            )
        )

        msg += "- Large bins\n"
        msg += "{}".format(
            self._bins_formatter.format_bins_summary(
                arena.large_bins,
                start_index=LARGE_BINS_START_INDEX
            )
        )

        return msg


