from copy import deepcopy

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.rop import ROP
from pwnlib.util.packing import *

log = getLogger(__name__)

class Elf32_Rel(object):
    """
    typedef struct elf32_rel {
        Elf32_Addr	r_offset;
        Elf32_Word	r_info;
    } Elf32_Rel;
    """
    size=1 # see _build_structures method for explanation
    def __init__(self, r_offset=0, r_info=0):
        self.r_offset = r_offset
        self.r_info = r_info

    def __bytes__(self):
        return p32(self.r_offset) + p32(self.r_info)

    def __str__(self):
        return str(bytes(self))

    def __flat__(self):
        return bytes(self)


class Elf64_Rel(object):
    """
    typedef struct elf64_rel {
        Elf64_Addr r_offset;
        Elf64_Xword r_info;
    } Elf64_Rel;
    """
    size=24
    def __init__(self, r_offset=0, r_info=0):
        self.r_offset = r_offset
        self.r_info = r_info

    def __bytes__(self):
        return p64(self.r_offset) + p64(self.r_info) + p64(0)

    def __str__(self):
        return str(bytes(self))

    def __flat__(self):
        return bytes(self)


class Elf32_Sym(object):
    """
    typedef struct elf32_sym{
        Elf32_Word	st_name;
        Elf32_Addr	st_value;
        Elf32_Word	st_size;
        unsigned char	st_info;
        unsigned char	st_other;
        Elf32_Half	st_shndx;
    } Elf32_Sym;
    """
    size = 16
    def __init__(self, st_name=0, st_value=0, st_size=0, st_info=0, st_other=0, st_shndx=0):
        self.st_name = st_name
        self.st_value = st_value
        self.st_size = st_size
        self.st_info = st_info
        self.st_other = st_other
        self.st_shndx = st_shndx

    def __bytes__(self):
        return p32(self.st_name) + \
            p32(self.st_value) + \
            p32(self.st_size) + \
            p8(self.st_info) + \
            p8(self.st_other) + \
            p16(self.st_shndx)

    def __str__(self):
        return str(bytes(self))

    def __flat__(self):
        return bytes(self)


class Elf64_Sym(object):
    """
    typedef struct elf64_sym {
        Elf64_Word st_name;
        unsigned char	st_info;
        unsigned char	st_other;
        Elf64_Half st_shndx;
        Elf64_Addr st_value;
        Elf64_Xword st_size;
    } Elf64_Sym;
    """
    size=24
    def __init__(self, st_name=0, st_value=0, st_size=0, st_info=0, st_other=0, st_shndx=0):
        self.st_name = st_name
        self.st_value = st_value
        self.st_size = st_size
        self.st_info = st_info
        self.st_other = st_other
        self.st_shndx = st_shndx

    def __bytes__(self):
        return p32(self.st_name) + \
            p8(self.st_info) + \
            p8(self.st_other) + \
            p16(self.st_shndx) + \
            p64(self.st_value) + \
            p64(self.st_size)

    def __str__(self):
        return str(bytes(self))

    def __flat__(self):
        return bytes(self)


class Queue(list):
    def size(self):
        size = 0
        for v in self:
            # Lists, strings and ints all have size context.size
            # Assuming int size equals address size
            if isinstance(v, MarkedBytes):
                size += len(v)
            else:
                size += context.bytes
        return size


class MarkedBytes(bytes):
    pass


class Ret2dlresolvePayload(object):
    def __init__(self, elf, symbol, args, data_addr=None):
        self.elf = elf
        self.elf_base = elf.address if elf.pie else 0
        self.strtab = elf.dynamic_value_by_tag("DT_STRTAB") + self.elf_base
        self.symtab = elf.dynamic_value_by_tag("DT_SYMTAB") + self.elf_base
        self.jmprel = elf.dynamic_value_by_tag("DT_JMPREL") + self.elf_base
        self.symbol = context._encode(symbol)
        self.args = args
        self.real_args = self._format_args()        
        
        self.data_addr = data_addr if data_addr is not None else self._get_recommended_address()

        # Will be set when built
        self.reloc_index = -1
        self.payload = b""

        # PIE is untested, gcc forces FULL-RELRO when PIE is set
        if self.elf.pie and self.elf_base == 0:
            log.warning("WARNING: ELF is PIE but it has not base address")

        self._build()

    def _padding(self, payload_len, modulo):
        if payload_len % modulo == 0: return b""
        return (modulo - (payload_len%modulo))*b"A"

    def _format_args(self):
        # Encode every string in args
        def aux(args):
            for i, arg in enumerate(args):
                if isinstance(arg, (str,bytes)):
                    args[i] = context._encode(args[i]) + b"\x00"
                elif isinstance(arg, (list, tuple)):
                    aux(arg)

        args = deepcopy(self.args)
        aux(args)
        return args

    def _get_recommended_address(self):
        bss = self.elf.get_section_by_name(".bss").header.sh_addr + self.elf_base
        bss_size = self.elf.get_section_by_name(".bss").header.sh_size
        addr = bss + bss_size
        addr = addr + (0x1000-(addr % 0x1000)) - 0x200 #next page in memory - 0x200
        return addr
        
    def _build_structures(self):
        # The first part of the payload is the usual of ret2dlresolve.
        if context.bits == 32:
            ElfSym = Elf32_Sym
            ElfRel = Elf32_Rel
        elif context.bits == 64:
            ElfSym = Elf64_Sym
            ElfRel = Elf64_Rel
        else:
            log.error("Unsupported bits")

        # where the address of the symbol will be saved
        # (ElfRel.r_offset points here)
        self.payload += b"A"*context.bytes

        # Symbol name. Ej: system
        symbol_name_addr = self.data_addr + len(self.payload)
        self.payload += self.symbol + b"\x00"
        self.payload += self._padding(self.data_addr + len(self.payload) - self.symtab, ElfSym.size)

        # ElfSym
        sym_addr = self.data_addr + len(self.payload)
        sym = ElfSym(st_name=symbol_name_addr - self.strtab)
        self.payload += bytes(sym)
        self.payload += self._padding(self.data_addr + len(self.payload) - self.jmprel, ElfRel.size)

        # ElfRel
        rel_addr = self.data_addr + len(self.payload)
        index = (sym_addr - self.symtab) // ElfSym.size
        if context.bits == 64:
            index = index << 32
        else: # 32
            index = index << 8
        rel_type = 7
        rel = ElfRel(r_offset=self.data_addr, r_info=index+rel_type)
        self.payload += bytes(rel)

        # It seems to be treated as an index in 64b and
        # as an offset in 32b. That's why Elf32_Rel.size = 1
        self.reloc_index = (rel_addr - self.jmprel)//ElfRel.size
        
        log.debug("Symtab: %s", hex(self.symtab))
        log.debug("Strtab: %s", hex(self.strtab))
        log.debug("Jmprel: %s", hex(self.jmprel))
        log.debug("ElfSym addr: %s", hex(sym_addr))
        log.debug("ElfRel addr: %s", hex(rel_addr))
        log.debug("Symbol name addr: %s", hex(symbol_name_addr))
        log.debug("Data addr: %s", hex(self.data_addr))

    def _build_args(self):
        # The second part of the payload will include strings and pointers needed for ROP.
        queue = Queue()

        # We first have to process the arguments: replace lists and strings with
        # pointers to the payload. Add lists contents and marked strings to the queue
        # to be processed later.
        for i, arg in enumerate(self.real_args):
            if isinstance(arg, (list, tuple)):
                self.real_args[i] = self.data_addr + len(self.payload) + queue.size()
                queue.extend(arg)
            elif isinstance(arg, bytes): 
                self.real_args[i] = self.data_addr + len(self.payload) + queue.size()
                queue.append(MarkedBytes(arg))

        # Now we process the generated queue, which contains elements that will be in
        # the payload. We replace lists and strings with pointers, add lists elements
        # to the queue, and mark strings so next time they are processed they are 
        # added and not replaced again.
        while len(queue) > 0:
            top = queue[0]
            if isinstance(top, (list, tuple)):
                top = pack(self.data_addr + len(self.payload) + queue.size())
                queue.extend(queue[0])
            elif isinstance(top, MarkedBytes):
                # Just add them
                pass
            elif isinstance(top, bytes):
                top = pack(self.data_addr + len(self.payload) + queue.size())
                queue.append(MarkedBytes(queue[0]))
            elif isinstance(top, int):
                top = pack(top)
            else:
                print(1)

            self.payload += top
            queue.pop(0)

    def _build(self):
        self._build_structures()
        self._build_args()