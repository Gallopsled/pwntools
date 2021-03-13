from pwnlib.heap.glmalloc.basic_formatter import BasicFormatter


class MallocState:
    """Representation of the glibc malloc_state struct.


    Here is the definition of the malloc_state struct in libc 2.27:

    .. highlight:: c
    .. code-block:: c

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

    Notes:
        The field have_fastchunks was introduced in libc version 2.27. In case
        libc version is inferior that field value will be None.

        The field attached_threads was introduced in libc version 2.23. In case
        libc version is inferior that field value will be None.
     """

    def __init__(self, address, mutex, flags, have_fastchunks,
                 fastbinsY, top, last_remainder, bins, binmap, next_,
                 next_free, attached_threads, system_mem, max_system_mem):

        #: :class:`int`: Address of the malloc_state
        self.address = address

        #: :class:`int`: Mutex value of the malloc_state
        self.mutex = mutex

        #: :class:`int`: Flags of the malloc_state
        self.flags = flags

        #: :class:`int` or :class:`None`: Indicates if there are chunks in the
        #: fastbins
        self.have_fastchunks = have_fastchunks

        #: :class:`FastBinsY`: Fast bin entries
        self.fastbinsY = fastbinsY

        #: :class:`int`: Pointer to the top chunk of the heap
        self.top = top

        #: :class:`int`: Pointer to the last remainder chunk
        self.last_remainder = last_remainder

        #: :class:`Bins`: All bins entries of the malloc_state (Unsorted,
        #: Small and Large)
        self.bins = bins

        #: :class:`list[4]` of :class:`int`: Bitmap which indicates the bins
        #: with chunks
        self.binmap = binmap

        #: :class:`int`: Address of the next malloc_state struct
        self.next = next_

        #: :class:`int` or :class:`None`
        self.next_free = next_free

        #: :class:`int`: Number of threads attached to the arena
        self.attached_threads = attached_threads

        #: :class:`int`: Available heap size
        self.system_mem = system_mem

        #: :class:`int`: Maximum heap size
        self.max_system_mem = max_system_mem
        self._basic_formatter = BasicFormatter()

    @property
    def unsorted_bin(self):
        """:class:`BinEntry`: Unsorted bin entry of the malloc_state"""
        return self.bins.unsorted_bin_entry

    @property
    def small_bins(self):
        """:class:`list` of :class:`BinEntry`: Small bins entries of the
        malloc_state"""
        return self.bins.small_bins_entries

    @property
    def large_bins(self):
        """:class:`list` of :class:`BinEntry`: Large bins entries of the
        malloc_state"""
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
