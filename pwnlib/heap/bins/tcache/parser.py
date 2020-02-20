from pwnlib.heap.bins.tcache.tcache_per_thread_struct import \
    TcachePerthreadStructParser
from pwnlib.heap.bins.tcache.tcache import Tcaches, Tcache


class TcacheParser:
    """Abstract class that defines the public methods of a Tcache
    """

    def parse_all_from_malloc_state(self, malloc_state):
        raise NotImplementedError()


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
        heap_address, _ = self._heap_parser.calculate_heap_address_and_size_from_malloc_state(
            malloc_state)
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
        return Tcaches(tcaches)

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
            except (OSError, IOError):
                # to avoid hanging in case some pointer is corrupted
                break

        return Tcache(entry, chunks)
