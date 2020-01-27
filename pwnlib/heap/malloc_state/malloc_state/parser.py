from pwnlib.heap.malloc_state.bins import *
from pwnlib.heap.malloc_state.fastbinsy import *
from construct import *
from .malloc_state import MallocState

NFASTBINS = 10
NBINS = 128
INT_SIZE = 4
BINMAPSIZE = 4

class MallocStateParser:
    """Class with the logic of parsing the malloc_state struct from binary
    data. Handles special cases which depends on the glibc version.

    Args:
        process_informer (ProcessInformer): Helper to perform operations over
            memory
    """

    def __init__(self, process_informer):
        self._process_informer = process_informer
        self._pointer_size = process_informer.pointer_size

        self._bins_parser = BinsParser(self._pointer_size)
        self._fastbinsy_parser = FastBinsYParser(self._pointer_size)

        self._libc_version = self._process_informer.libc_version

        self._malloc_state_struct_definition = MallocStateStructSelector(
            self._process_informer.libc_version,
            process_informer.pointer_size
        ).select_malloc_state_struct_definition()

        self.raw_malloc_state_size = self._calculate_raw_malloc_state_size()



    def parse_all_from_main_malloc_state_address(self, base_address):
        """Parses the whole list of malloc_state structs from the
        process memory, by following the `next` pointer in the struct

        Returns:
            list of MallocState
        """
        malloc_state_address = base_address
        addresses = []
        malloc_states = []
        while malloc_state_address not in addresses:
            addresses.append(malloc_state_address)
            malloc_state = self.parse_from_address(malloc_state_address)
            malloc_states.append(malloc_state)
            malloc_state_address = malloc_state.next

        return malloc_states

    def parse_from_address(self, address):
        """Parses a malloc_state struct from the process memory

        Returns:
            MallocState
        """
        raw_malloc_state = self._process_informer.read_memory(
            address,
            self.raw_malloc_state_size
        )
        return self.parse_from_raw(address, raw_malloc_state)

    def parse_from_raw(self, address, raw_malloc_state):
        """Parses a binary malloc_state struct

        Args:
            address (int): address of the data, useful as metadata for bins arrays
            raw_malloc_state (bytearray): malloc_state in binary form

        Returns:
            MallocState
        """
        malloc_state_collection = self._malloc_state_struct_definition.parse(
            raw_malloc_state
        )

        mutex = malloc_state_collection.mutex
        flags = malloc_state_collection.flags
        try:
            have_fastchunks = malloc_state_collection.have_fastchunks
        except AttributeError:
            have_fastchunks = None

        fastbinsY_address = address + \
            self._malloc_state_struct_definition.fastbinsY_offset
        fastbinsY = self._fastbinsy_parser.parse_from_collection(
            fastbinsY_address,
            malloc_state_collection.fastbinsY
        )

        top = malloc_state_collection.top
        last_remainder = malloc_state_collection.last_remainder

        bins_address = address + \
            self._malloc_state_struct_definition.bins_offset
        bins = self._bins_parser.parse_from_collection(
            bins_address,
            malloc_state_collection.bins
        )

        binmap = list(malloc_state_collection.binmap)
        next_ = malloc_state_collection.next
        next_free = malloc_state_collection.next_free
        try:
            attached_threads = malloc_state_collection.attached_threads
        except AttributeError:
            attached_threads = None

        system_mem = malloc_state_collection.system_mem
        max_system_mem = malloc_state_collection.max_system_mem

        return MallocState(
            address,
            mutex,
            flags,
            have_fastchunks,
            fastbinsY,
            top,
            last_remainder,
            bins,
            binmap,
            next_,
            next_free,
            attached_threads,
            system_mem,
            max_system_mem
        )

    def _calculate_raw_malloc_state_size(self):
        return self._malloc_state_struct_definition.size


class MallocStateStructSelector:

    def __init__(self, libc_version, pointer_size):
        self._pointer_size = pointer_size
        if pointer_size == 8:
            self._pointer_type = Int64ul
        else:
            self._pointer_type = Int32ul

        self._libc_version = libc_version

    def select_malloc_state_struct_definition(self):
        if self._libc_version >= (2, 27):
            return self._define_malloc_state_struct_27()
        elif self._libc_version >= (2, 23):
            return self._define_malloc_state_struct_23()
        else:
            return self._define_malloc_state_struct_19()

    def _define_malloc_state_struct_27(self):
        pointer_type = self._pointer_type
        if self._pointer_size == 8:
            padding_bytes = 0
        else:
            padding_bytes = 4

        fastbinsY_offset = pointer_type.sizeof() + Int32ul.sizeof()*2
        bins_offset = fastbinsY_offset + pointer_type.sizeof()*NFASTBINS \
            + padding_bytes + pointer_type.sizeof()*2

        struct_definition = Struct(
            "mutex" / pointer_type,
            "flags" / Int32ul,
            "have_fastchunks" / Int32ul,
            "fastbinsY" / pointer_type[NFASTBINS],
            Padding(padding_bytes),
            "top" / pointer_type,
            "last_remainder" / pointer_type,
            "bins" / pointer_type[NBINS * 2 - 2],
            "binmap" / Int32ul[BINMAPSIZE],
            "next" / pointer_type,
            "next_free" / pointer_type,
            "attached_threads" / pointer_type,
            "system_mem" / pointer_type,
            "max_system_mem" / pointer_type
        )

        return MallocStateStructDefinition(
            struct_definition,
            fastbinsY_offset,
            bins_offset
        )

    def _define_malloc_state_struct_23(self):
        pointer_type = self._pointer_type

        fastbinsY_offset = Int32ul.sizeof()*2
        bins_offset = fastbinsY_offset + pointer_type.sizeof() * NFASTBINS \
            + pointer_type.sizeof()*2

        struct_definition = Struct(
           "mutex" / Int32ul,
           "flags" / Int32ul,
           "fastbinsY" / pointer_type[NFASTBINS],
           "top" / pointer_type,
           "last_remainder" / pointer_type,
           "bins" / pointer_type[NBINS * 2 - 2],
           "binmap" / Int32ul[BINMAPSIZE],
           "next" / pointer_type,
           "next_free" / pointer_type,
           "attached_threads" / pointer_type,
           "system_mem" / pointer_type,
           "max_system_mem" / pointer_type
        )

        return MallocStateStructDefinition(
            struct_definition,
            fastbinsY_offset,
            bins_offset
        )

    def _define_malloc_state_struct_19(self):
        pointer_type = self._pointer_type

        fastbinsY_offset = Int32ul.sizeof()*2
        bins_offset = fastbinsY_offset + pointer_type.sizeof() * NFASTBINS \
            + pointer_type.sizeof()*2

        struct_definition = Struct(
           "mutex" / Int32ul,
           "flags" / Int32ul,
           "fastbinsY" / pointer_type[NFASTBINS],
           "top" / pointer_type,
           "last_remainder" / pointer_type,
           "bins" / pointer_type[NBINS * 2 - 2],
           "binmap" / Int32ul[BINMAPSIZE],
           "next" / pointer_type,
           "next_free" / pointer_type,
           "system_mem" / pointer_type,
           "max_system_mem" / pointer_type
        )

        return MallocStateStructDefinition(
            struct_definition,
            fastbinsY_offset,
            bins_offset
        )


class MallocStateStructDefinition(object):

    def __init__(self, struct_definition, fastbinsY_offset, bins_offset):
        self.struct_definition = struct_definition
        self.fastbinsY_offset = fastbinsY_offset
        self.bins_offset = bins_offset

    def parse(self, raw):
        return self.struct_definition.parse(raw)

    @property
    def size(self):
        return self.struct_definition.sizeof()
