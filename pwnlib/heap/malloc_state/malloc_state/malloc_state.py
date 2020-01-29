from pwnlib.heap.basic_formatter import BasicFormatter


class MallocState:
    """
    Representation of the glibc struct malloc_state

    ```c
    struct malloc_state
    {
      __libc_lock_define (, mutex);
      int flags;
      int have_fastchunks;
      mfastbinptr fastbinsY[NFASTBINS];
      mchunkptr top;
      mchunkptr last_remainder;
      mchunkptr bins[NBINS * 2 - 2];
      unsigned int binmap[BINMAPSIZE];
      struct malloc_state *next;
      struct malloc_state *next_free;
      INTERNAL_SIZE_T attached_threads;
      INTERNAL_SIZE_T system_mem;
      INTERNAL_SIZE_T max_system_mem;
    };
    ```

    Notes:
        The field have_fastchunks was introduced in glibc version 2.27. In that
        case, in this class that field value will be None.

    Attributes:
        mutex (int):
        flags (int):
        have_fastchunks (int or None):
        fastbinsY (FastBinsY):
        top (int):
        last_remainder (int):
        bins (Bins):
        binmap (list[4] of int):
        next (int):
        next_free (int):
        attached_threads (int):
        system_mem (int):
        max_system_mem (int):
    """

    def __init__(self, address, mutex, flags, have_fastchunks,
                 fastbinsY, top, last_remainder, bins, binmap, next_,
                 next_free, attached_threads, system_mem, max_system_mem):
        self.address = address
        self.mutex = mutex
        self.flags = flags
        self.have_fastchunks = have_fastchunks
        self.fastbinsY = fastbinsY
        self.top = top
        self.last_remainder = last_remainder
        self.bins = bins
        self.binmap = binmap
        self.next = next_
        self.next_free = next_free
        self.attached_threads = attached_threads
        self.system_mem = system_mem
        self.max_system_mem = max_system_mem
        self._basic_formatter = BasicFormatter()

    @property
    def unsorted_bin(self):
        return self.bins.unsorted_bin_entry

    @property
    def small_bins(self):
        return self.bins.small_bins_entries

    @property
    def large_bins(self):
        return self.bins.large_bins_entries

    def __str__(self):
        msg = [
            self._basic_formatter.header(
                "Malloc State ({:#x})".format(self.address)
            ),
            self._format_malloc_state(),
            self._basic_formatter.footer()
        ]
        return "\n".join(msg)

    def _format_malloc_state(self):
        string = [
            "mutex = {:#x}".format(self.mutex),
            "flags = {:#x}".format(self.flags)
        ]

        if self.have_fastchunks is not None:
            string.append(
                "have_fastchunks = {:#x}".format(self.have_fastchunks)
            )

        string.append(self._format_malloc_state_fastbinsY_as_str())

        string.append("top = {:#x}".format(self.top))
        string.append("last_remainder = {:#x}".format(self.last_remainder))
        string.append(self._format_malloc_state_bins_as_str())

        string.append("binmap = [{:#x}, {:#x}, {:#x}, {:#x}]".format(
            self.binmap[0],
            self.binmap[1],
            self.binmap[2],
            self.binmap[3]
        ))
        string.append("next = {:#x}".format(self.next))
        string.append("next_free = {:#x}".format(self.next_free))

        if self.attached_threads is not None:
            string.append("attached_threads = {:#x}".format(
                self.attached_threads
            ))
        string.append("system_mem = {:#x}".format(self.system_mem))
        string.append("max_system_mem = {:#x}".format(self.max_system_mem))

        return "\n".join(string)

    def _format_malloc_state_fastbinsY_as_str(self):
        string = ["fastbinsY"]
        for i, entry in enumerate(self.fastbinsY):
            string.append("  [{}] {:#x} => {:#x}".format(
                i, entry.chunks_size, entry.fd
            ))

        return "\n".join(string)

    def _format_malloc_state_bins_as_str(self):
        string = ["bins"]
        index = 0

        string.append(" Unsorted bins")
        unsorted_entry = self.bins.unsorted_bin_entry
        string.append("  [{}] fd={:#x} bk={:#x}".format(
            index, unsorted_entry.fd, unsorted_entry.bk
        ))

        index += 1
        string.append(" Small bins")
        for small_entry in self.bins.small_bins_entries:
            string.append("  [{}] {:#x} fd={:#x} bk={:#x}".format(
                index, small_entry.chunks_size, small_entry.fd, small_entry.bk
            ))
            index += 1

        string.append(" Large bins")
        for small_entry in self.bins.large_bins_entries:
            string.append("  [{}] {:#x} fd={:#x} bk={:#x}".format(
                index, small_entry.chunks_size, small_entry.fd, small_entry.bk
            ))
            index += 1

        return "\n".join(string)

    def __repr__(self):
        string = "mutex = {:#x}\n".format(self.mutex)
        string += "flags = {:#x}\n".format(self.flags)

        if self.have_fastchunks is not None:
            string += "have_fastchunks = {:#x}\n".format(self.have_fastchunks)

        string += str(self.fastbinsY)

        string += "top = {:#x}\n".format(self.top)
        string += "last_remainder = {:#x}\n".format(self.last_remainder)
        string += str(self.bins)

        string += "binmap = [{:#x}, {:#x}, {:#x}, {:#x}]\n".format(
            self.binmap[0],
            self.binmap[1],
            self.binmap[2],
            self.binmap[3]
        )
        string += "next = {:#x}\n".format(self.next)
        string += "next_free = {:#x}\n".format(self.next_free)
        string += "attached_threads = {:#x}\n".format(self.attached_threads)
        string += "system_mem = {:#x}\n".format(self.system_mem)
        string += "max_system_mem = {:#x}\n".format(self.max_system_mem)

        return string
