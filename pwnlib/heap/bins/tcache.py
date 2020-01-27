from .bin import *


class NoTcacheError(Exception):
    """Exception raised when tries to access to tcache in glibc when those are
    disabled.
    """

    def __init__(self, message="Tcache are not available in the current glibc"):
        super(NoTcacheError, self).__init__(message)


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

    Attributes:
        counts (list of int): List with indicative counts of chunks of each
            tcache
        entries (list of TcacheEntry): One entrie per tcache,
            which indicates the address of the first chunk in the bin

    """
    TCACHE_MAX_BINS = 64

    def __init__(self, address, counts, entries):
        self.address = address
        self.counts = counts
        self.entries = entries

    def __str__(self):
        string = ""
        for i in range(self.TCACHE_MAX_BINS):
            string += "{} [{}] {:#x}\n".format(
                i,
                self.counts[i],
                self.entries[i]
            )
        return string


class TcacheParser:
    """Abstract class that defines the public methods of a Tcache
    """

    def parse_all_from_malloc_state(self, malloc_state):
        raise NotImplemented()


class DisabledTcacheParser:
    """Class to use when tcaches are disabled
    """

    def parse_all_from_malloc_state(self, malloc_state):
        """Fake method that always returns None
        """
        return None


class EnabledTcacheParser:
    """Class with the logic to parse the chunks of a tcache from raw memory
    and create Tcache objects.

    Args:
        malloc_chunk_parser (MallocChunkParser): a parser of the chunks in the
            heap.
        heap_parser (HeapParser): a parser of the heap metadata and chunks.
    """

    def __init__(self, malloc_chunk_parser, heap_parser):
        self._process_informer = malloc_chunk_parser.process_informer
        self._pointer_size = malloc_chunk_parser.pointer_size
        self._malloc_chunk_parser = malloc_chunk_parser
        self._tcache_perthread_parser = TcachePerthreadStructParser(
            malloc_chunk_parser.process_informer
        )
        self._heap_parser = heap_parser

    def are_tcache_enabled(self):
        return True

    def parse_all_from_malloc_state(self, malloc_state):
        """Returns the tcaches of the arena based on the malloc state
        information.

        Args:
            malloc_state (MallocState)

        Returns:
            list of Tcache
        """
        heap_address, _ = self._heap_parser.calculate_heap_address_and_size_from_malloc_state(malloc_state)
        return self._parse_all_from_heap_address(heap_address)

    def _parse_all_from_heap_address(self, heap_address):
        tcache_perthread_struct_address = heap_address + 0x10
        tcache_perthread = self._tcache_perthread_parser.parse_from_address(
            tcache_perthread_struct_address
        )

        tcaches = []
        for entry in tcache_perthread.entries:
            tcache = self._parse_from_tcache_entry(entry)
            tcaches.append(tcache)
        return tcaches

    def _parse_from_tcache_entry(self, entry):
        pointer = entry.fd
        addresses = [entry.address]
        chunks = []
        while pointer != 0x0 and pointer not in addresses:
            addresses.append(pointer)
            try:
                chunk_base_address = pointer - self._pointer_size*2
                chunk = self._malloc_chunk_parser.parse_from_address(
                    chunk_base_address
                )
                chunks.append(chunk)
                pointer = chunk.fd
            except OSError:
                # to avoid hanging in case some pointer is corrupted
                break

        return Tcache(entry, chunks)


class Tcache(Bin):
    """Class to represent a tcache of the glibc

    Attributes:
        bin_entry (TcacheEntry): The entry of tcache_perthread_struct for the
            bin.
        chunks (list of MallocChunk): The chunks which are inserted in
            the tcache.
    """

    def __init__(self, bin_entry, malloc_chunks):
        super(Tcache, self).__init__(bin_entry, malloc_chunks)

    def __str__(self):
        msg = "Tcache [size = {:#x}, count = {}] => {:#x}".format(
            self.chunks_size,
            len(self),
            self.fd
        )

        for chunk in self.chunks:
            msg += chunk.to_bin_str()

        return msg


class TcacheEntry(BinEntry):
    """Class to contain the information of each entry in
    tcache_perthread_struct struct.
    """

    def __init__(self, address, fd, chunks_size):
        super(TcacheEntry, self).__init__(address, fd, chunks_size=chunks_size)
