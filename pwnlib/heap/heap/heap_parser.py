from .heap_info import HeapInfoParser
from pwnlib.heap.utils import align_address
from .heap import Heap


class HeapParser:
    """Class to parse the chunks of a heap and return a Heap object

    Args:
        malloc_chunk_parser (MallocChunkParser): parser for the raw malloc
            chunks
        malloc_state_parser (MallocStateParser): parser for the raw malloc_state
            struct
    """

    def __init__(self, malloc_chunk_parser, malloc_state_parser):
        self._process_informer = malloc_chunk_parser.process_informer
        self._pointer_size = malloc_chunk_parser.pointer_size
        self._malloc_alignment = self._pointer_size * 2
        self._raw_heap_info_size = self._pointer_size * 4

        self._malloc_chunk_parser = malloc_chunk_parser
        self._malloc_state_parser = malloc_state_parser
        self._heap_info_parser = HeapInfoParser(self._process_informer)

    def parse_from_malloc_state(self, malloc_state):
        """Returns the heap of the arena of the given malloc state

        Args:
            malloc_state (MallocState)

        Returns:
            Heap
        """

        heap_address, heap_size = self.calculate_heap_address_and_size_from_malloc_state(malloc_state)
        return self._parse_from_address(heap_address, heap_size)

    def calculate_heap_address_and_size_from_malloc_state(self, malloc_state):
        """Returns the heap start address and heap size, based on the
        information of the provided malloc state

        Args:
            malloc_state (MallocState)

        Returns:
            tuple(int, int)
        """
        maps = self._process_informer.maps()
        current_heap_map = maps.map_with_address(malloc_state.top)
        main_heap_map = maps.heap

        is_main_heap = current_heap_map.address == main_heap_map.address
        if is_main_heap:
            heap_start_address = current_heap_map.address
        else:
            heap_start_address = self._calculate_non_main_heap_start_address(
                current_heap_map.address
            )

        heap_size = current_heap_map.size - \
            (heap_start_address - current_heap_map.start_address)
        return heap_start_address, heap_size

    def _calculate_non_main_heap_start_address(self, heap_map_start_address):
        heap_info = self._heap_info_parser.parse_from_address(heap_map_start_address)
        heap_start_address = heap_info.ar_ptr + \
            self._malloc_state_parser.raw_malloc_state_size
        return align_address(heap_start_address, self._malloc_alignment)

    def _parse_from_address(self, address, size):
        raw_heap = self._process_informer.read_memory(address, size)
        return self._parse_from_raw(address, raw_heap)

    def _parse_from_raw(self, heap_address, raw_heap):
        offset = 0
        chunks = []

        first_chunk = self._malloc_chunk_parser.parse_from_raw(
            heap_address,
            raw_heap
        )

        if first_chunk.size == 0:
            offset += self._pointer_size*2

        while offset < len(raw_heap):
            current_address = heap_address + offset
            chunk = self._malloc_chunk_parser.parse_from_raw(
                current_address,
                raw_heap[offset:]
            )
            offset += chunk.size
            chunks.append(chunk)

        return Heap(heap_address, chunks, self._pointer_size)

