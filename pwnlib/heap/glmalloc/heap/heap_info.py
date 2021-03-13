from construct import Int64ul, Int32ul, Struct


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
    """

    def __init__(self, ar_ptr, prev, size, mprotect_size):
        #: :class:`int`: Address of the arena `malloc_state` structure.
        self.ar_ptr = ar_ptr

        #: :class:`int`: Address of the previous heap.
        self.prev = prev

        #: :class:`int`: Size of the heap.
        self.size = size

        #: :class:`int`: Size of the heap which has been mprotected with
        #: PROT_READ|PROT_WRITE.
        self.mprotect_size = mprotect_size
