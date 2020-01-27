from .utils import align_address
from construct import *


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

        return Heap(heap_address, chunks)


class Heap:
    """Class to represent a heap with some useful metadata. Heap is considered
    a collection of chunks.

    Attributes:
        address (int): The start address of the heap
        chunks (list of MallocChunk):  The list of chunks of the heap
        top (MallocChunk): The Top chunk of the heap
    """

    def __init__(self, address, malloc_chunks):
        self.address = address
        self.chunks = malloc_chunks

    @property
    def top(self):
        return self.chunks[-1]


class HeapInfoParser:
    """Class to parse the `heap_info` structure

    Args:
        process_informer (ProcessInformer): Helper to perform operations over
            memory and obtain info of the process
    """

    def __init__(self, process_informer):
        self._process_informer = process_informer
        self._pointer_size = process_informer.pointer_size
        if self._pointer_size == 8:
            pointer_type = Int64ul
        else:
            pointer_type = Int32ul

        self.heap_info_definition = Struct(
            "ar_ptr"/ pointer_type,
            "prev"/ pointer_type,
            "size" / pointer_type,
            "mprotect_size" / pointer_type
        )

    def parse_from_address(self, address):
        raw_heap_info = self._process_informer.read_memory(
            address,
            self.heap_info_definition.sizeof()
        )
        return self._parse_from_raw(raw_heap_info)

    def _parse_from_raw(self, raw):
        heap_info_collection = self.heap_info_definition.parse(raw)

        return HeapInfo(
            ar_ptr=heap_info_collection.ar_ptr,
            prev=heap_info_collection.prev,
            size=heap_info_collection.size,
            mprotect_size=heap_info_collection.mprotect_size
        )


class HeapInfo:
    """Class with the information of the `heap_info` structure.

    ```c
    typedef struct _heap_info
    {
      mstate ar_ptr; /* Arena for this heap. */
      struct _heap_info *prev; /* Previous heap. */
      size_t size;   /* Current size in bytes. */
      size_t mprotect_size; /* Size in bytes that has been mprotected
                               PROT_READ|PROT_WRITE.  */
      /* Make sure the following data is properly aligned, particularly
         that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
         MALLOC_ALIGNMENT. */
      char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
    } heap_info;
    ```

    Attributes:
        ar_ptr (int): Address of the arena `malloc_state` structure.
        prev (int): Address of the previous heap.
        size (int): Size of the heap.
        mprotect_size (int): Size of the heap which has benn mprotected with
            PROT_READ|PROT_WRITE.
    """

    def __init__(self, ar_ptr, prev, size, mprotect_size):
        self.ar_ptr = ar_ptr
        self.prev = prev
        self.size = size
        self.mprotect_size = mprotect_size
