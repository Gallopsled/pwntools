from pwnlib.heap.glmalloc.bins import TcacheEntry


class TcachePerthreadStructParser:
    """Class with the logic to parsing the tcache_perthread_struct struct
    from binary data.


    Args:
        process_informer (ProcessInformer): Helper to perform operations over
            memory

    """
    TCACHE_MAX_BINS = 64

    def __init__(self, process_informer):
        self._process_informer = process_informer
        self._pointer_size = process_informer.pointer_size
        self._unpack_pointer = process_informer.unpack_pointer
        self._tcache_perthread_struct_size = self.TCACHE_MAX_BINS + \
            self._pointer_size * \
            self.TCACHE_MAX_BINS

    def parse_from_address(self, address):
        """Returns a TcachePerthreadStruct object by parsing the
            `tcache_perthread_struct` struct at the given address.

        Args:
            address (int): Address of the `tcache_perthread_struct`.

        Returns:
            TcachePerthreadStruct
        """
        raw_tcache_perthread_struct = self._process_informer.read_memory(
            address,
            self._tcache_perthread_struct_size
        )

        return self._parse_from_raw(address, raw_tcache_perthread_struct)

    def _parse_from_raw(self, address, raw_tcache_perthread_struct):
        counts = []
        for i in range(self.TCACHE_MAX_BINS):
            count = raw_tcache_perthread_struct[i]
            counts.append(count)

        entries = []
        for i in range(self.TCACHE_MAX_BINS):
            index = self.TCACHE_MAX_BINS + i * self._pointer_size
            current_address = address + index
            fd = self._unpack_pointer(
                raw_tcache_perthread_struct[index:index+self._pointer_size]
            )
            tcache_chunks_size = self._pointer_size * 3 + i * self._pointer_size * 2
            entries.append(
                TcacheEntry(current_address, fd, tcache_chunks_size)
            )

        return TcachePerthreadStruct(address, counts, entries)


class TcachePerthreadStruct:
    """Class to contain the information of tcache_perthread_struct struct.

    typedef struct tcache_perthread_struct
    {
      char counts[TCACHE_MAX_BINS];
      tcache_entry *entries[TCACHE_MAX_BINS];
    } tcache_perthread_struct;
    """
    TCACHE_MAX_BINS = 64

    def __init__(self, address, counts, entries):
        #: :class:`int`: Address of the structure
        self.address = address

        #: :class:`list` of :class:`int`: List with indicative counts of chunks of each
        #: tcache
        self.counts = counts

        #: :class:`list` of :class:`TcacheEntry`: One entrie per tcache,
        #: which indicates the address of the first chunk in the bin
        self.entries = entries
