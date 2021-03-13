from pwnlib.heap.basic_formatter import BasicFormatter


class Heap:
    """Class to represent a heap with some useful metadata. Heap is considered
    a collection of chunks.
    """

    def __init__(self, address, malloc_chunks, pointer_size):

        #: :class:`int`: The start address of the heap
        self.address = address

        #: :class:`list` of :class:`MallocChunk`:  The list of chunks of the heap
        self.chunks = malloc_chunks
        self._pointer_size = pointer_size
        self._basic_formatter = BasicFormatter()

    @property
    def top(self):
        """:class:`MallocChunk`: The Top chunk of the heap"""
        return self.chunks[-1]

    def __str__(self):
        msg = [
            self._basic_formatter.header("Heap ({:#x})".format(self.address)),
            self._format_heap(),
            self._basic_formatter.footer()
        ]
        return "\n".join(msg)

    def _format_heap(self):
        chunks_str = [
            self._format_chunk_as_str(chunk) for chunk in self.chunks
        ]
        return "\n".join(chunks_str)

    def _format_chunk_as_str(self, chunk):
        flags = chunk.format_flags_as_str()
        msg = [
            "{:#x} {:#x} {}".format(chunk.address, chunk.size, flags),
            "  " + chunk.format_first_bytes_as_hexdump_str()
        ]
        return "\n".join(msg)
