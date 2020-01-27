

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
