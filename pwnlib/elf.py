"""Exposes functionality for manipulating ELF files
"""
from . import log, asm
from .util import misc
import mmap, subprocess, os
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import describe_e_type
from elftools.elf.constants import P_FLAGS

def load(*args, **kwargs):
    """Compatibility wrapper for pwntools v1"""
    return ELF(*args, **kwargs)

class ELF(ELFFile):
    """Encapsulates information about an ELF file.

    :ivar path: Path to the binary on disk
    :ivar symbols:  Dictionary of {name: address} for all symbols in the ELF
    :ivar plt:      Dictionary of {name: address} for all functions in the PLT
    :ivar got:      Dictionary of {name: address} for all function pointers in the GOT
    :ivar libs:     Dictionary of {path: address} for each shared object required to load the ELF

    Example:

    .. code-block:: python

       bash = ELF('/bin/bash')
       hex(bash.symbols['read'])
       # 0x41dac0
       hex(bash.plt['read'])
       # 0x41dac0
       u32(bash.read(bash.got['read'], 4))
       # 0x41dac6
       print disasm(bash.read(bash.plt['read'],16), arch='amd64')
       # 0:   ff 25 1a 18 2d 00       jmp    QWORD PTR [rip+0x2d181a]        # 0x2d1820
       # 6:   68 59 00 00 00          push   0x59
       # b:   e9 50 fa ff ff          jmp    0xfffffffffffffa60
    """
    def __init__(self, path):
        # elftools uses the backing file for all reads and writes
        # in order to permit writing without being able to write to disk,
        # mmap() the file.
        self.file = open(path,'rb')
        self.mmap = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)

        super(ELF,self).__init__(self.mmap)

        self.path     = os.path.abspath(path)

        self._populate_got_plt()
        self._populate_symbols()
        self._populate_libraries()

        if self.elftype == 'DYN':
            self._address = 0
        else:
            self._address = min(filter(bool, (s.header.p_vaddr for s in self.segments)))
        self.load_addr = self._address

        for seg in self.executable_segments:
            if seg.header.p_type == 'PT_GNU_STACK':
                self.execstack = True
                log.info('Stack is executable!')

    @property
    def elfclass(self):
        """ELF class (32 or 64).

        .. note::
            Set during ``ELFFile._identify_file``
        """
        return self._elfclass

    @elfclass.setter
    def elfclass(self, newvalue):
        self._elfclass = newvalue

    @property
    def elftype(self):
        """ELF type (EXEC, DYN, etc)"""
        return describe_e_type(self.header.e_type).split()[0]

    @property
    def segments(self):
        """A list of all segments in the ELF"""
        return list(self.iter_segments())

    @property
    def sections(self):
        """A list of all sections in the ELF"""
        return list(self.iter_sections())

    @property
    def dwarf(self):
        """DWARF info for the elf"""
        return self.get_dwarf_info()

    @property
    def address(self):
        """Address of the lowest segment loaded in the ELF.
        When updated, cascades updates to segment vaddrs, section addrs, symbols, plt, and got.

        >>> bash = ELF('/bin/sh')
        >>> old = bash.symbols['read']
        >>> bash.address += 0x1000
        >>> bash.symbols['read'] == old + 0x1000
        True
        """
        return self._address

    @address.setter
    def address(self, new):
        delta     = new-self._address
        update    = lambda x: x+delta

        for segment in self.segments:
            segment.header.p_vaddr += delta

        for section in self.sections:
            section.header.sh_addr += delta

        self.symbols = {k:update(v) for k,v in self.symbols.items()}
        self.plt     = {k:update(v) for k,v in self.plt.items()}
        self.got     = {k:update(v) for k,v in self.got.items()}

        self._address = update(self.address)

    def section(self, name):
        """Gets data for the named section

        Args:
            name(str): Name of the section

        Returns:
            String containing the bytes for that section
        """
        return self.get_section_by_name(name).data()

    @property
    def executable_segments(self):
        """Returns: list of all segments which are executable."""
        return [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_X]

    @property
    def writable_segments(self):
        """Returns: list of all segments which are writeable"""
        return [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_W]

    @property
    def non_writable_segments(self):
        """Returns: list of all segments which are NOT writeable"""
        return [s for s in self.segments if not s.header.p_flags & P_FLAGS.PF_W]

    def _populate_libraries(self):
        """
        >>> from os.path import exists
        >>> bash = ELF('/bin/bash')
        >>> all(map(exists, bash.libs.keys()))
        True
        >>> any(map(lambda x: 'libc' in x, bash.libs.keys()))
        True
        """
        try:
            data = subprocess.check_output('ulimit -s unlimited; ldd ' + misc.sh_string(self.path), shell = True)
            self.libs = misc.parse_ldd_output(data)
        except subprocess.CalledProcessError:
            self.libs = {}

    def _populate_symbols(self):
        """
        >>> bash = ELF('/bin/bash')
        >>> bash.symbols['_start'] == bash.header.e_entry
        True
        """
        # By default, have 'symbols' include everything in the PLT.
        #
        # This way, elf.symbols['write'] will be a valid address to call
        # for write().
        self.symbols = dict(self.plt)

        for section in self.sections:
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                if not symbol.entry.st_value:
                    continue

                self.symbols[symbol.name] = symbol.entry.st_value

    def _populate_got_plt(self):
        """Loads the GOT and the PLT symbols and addresses.

        The following doctest checks the valitidy of the addresses.
        This assumes that each GOT entry points to its PLT entry,
        usually +6 bytes but could be anywhere within 0-16 bytes.

        >>> from pwnlib.util.packing import unpack
        >>> bash = ELF('/bin/bash')
        >>> def validate_got_plt(sym):
        ...     got      = bash.got[sym]
        ...     plt      = bash.plt[sym]
        ...     got_addr = unpack(bash.read(got, bash.elfclass/8), bash.elfclass)
        ...     return got_addr in range(plt,plt+0x10)
        ...
        >>> all(map(validate_got_plt, bash.got.keys()))
        True
        """
        plt = self.get_section_by_name('.plt')
        got = self.get_section_by_name('.got')

        # Find the relocation section for PLT
        rel_plt = next(s for s in self.sections if s.header.sh_info == self.sections.index(plt))

        # Find the symbols for the relocation section
        sym_rel_plt = self.sections[rel_plt.header.sh_link]

        self.got = {}
        self.plt = {}

        # Populate the GOT
        for rel in rel_plt.iter_relocations():
            sym_idx  = rel.entry.r_info_sym
            symbol   = sym_rel_plt.get_symbol(sym_idx)
            name     = symbol.name

            self.got[name] = rel.entry.r_offset

        # Based on the ordering of the GOT symbols, populate the PLT
        for i,(addr,name) in enumerate(sorted((addr,name) for name, addr in self.got.items())):
            self.plt[name] = plt.header.sh_addr + (i+1)*plt.header.sh_addralign

    def search(self, needle, writable = False):
        """search(needle, writable = False) -> str generator

        Search the ELF's virtual address space for the specified string.

        Args:
            needle(str): String to search for.
            writable(bool): Search only writable sections.

        Returns:
            An iterator for each virtual address that matches.

        Examples:
            >>> bash = ELF('/bin/bash')
            >>> bash.address + 1 == next(bash.search('ELF'))
            True

            >>> sh = ELF('/bin/sh')
            >>> # /bin/sh should only depend on libc
            >>> libc = ELF(sh.libs.keys()[0])
            >>> # this string should be in there because of system(3)
            >>> len(list(libc.search('/bin/sh'))) > 0
            True
        """

        if writable:
            segments = self.writable_segments
        else:
            segments = self.segments

        for seg in segments:
            addr   = seg.header.p_vaddr
            data   = seg.data()
            offset = 0
            while True:
                offset = data.find(needle, offset)
                if offset == -1:
                    break
                yield addr + offset
                offset += 1

    def offset_to_vaddr(self, offset):
        """Translates the specified offset to a virtual address.

        Args:
            offset(int): Offset to translate

        Returns:
            Virtual address which corresponds to the file offset, or None

        Examples:
            >>> bash = ELF('/bin/bash')
            >>> bash.address == bash.offset_to_vaddr(0)
            True
            >>> bash.address += 0x123456
            >>> bash.address == bash.offset_to_vaddr(0)
            True
        """
        for segment in self.segments:
            begin = segment.header.p_offset
            size  = segment.header.p_filesz
            end   = begin + size
            if begin <= offset and offset <= end:
                delta = offset - begin
                return segment.header.p_vaddr + delta + (self.address - self.load_addr)
        return None


    def vaddr_to_offset(self, address):
        """Translates the specified virtual address to a file address

        Args:
            address(int): Virtual address to translate

        Returns:
            Offset within the ELF file which corresponds to the address,
            or None.

        Examples:
            >>> bash = ELF('/bin/bash')
            >>> 0 == bash.vaddr_to_offset(bash.address)
            True
            >>> bash.address += 0x123456
            >>> 0 == bash.vaddr_to_offset(bash.address)
            True
        """
        load_address = address - self.address + self.load_addr

        for segment in self.segments:
            begin = segment.header.p_vaddr
            size  = segment.header.p_memsz
            end   = begin + size
            if begin <= load_address and load_address <= end:
                delta = load_address - begin
                return segment.header.p_offset + delta

        log.warning("Address %#x does not exist in %s" % (address, self.file.name))
        return None

    def read(self, address, count):
        """Read data from the specified virtual address

        Args:
            address(int): Virtual address to read
            count(int): Number of bytes to read

        Returns:
            A string of bytes, or None

        Examples:
          >>> bash = ELF('/bin/bash')
          >>> bash.read(bash.address+1, 3)
          'ELF'
        """
        offset = self.vaddr_to_offset(address)

        if offset is not None:
            old = self.stream.tell()
            self.stream.seek(offset)
            data = self.stream.read(count)
            self.stream.seek(old)
            return data

        return None

    def write(self, address, data):
        """Writes data to the specified virtual address

        Args:
            address(int): Virtual address to write
            data(str): Bytes to write

        Note::
            This routine does not check the bounds on the write to ensure
            that it stays in the same segment.

        Examples:
          >>> bash = ELF('/bin/bash')
          >>> bash.read(bash.address+1, 3)
          'ELF'
          >>> bash.write(bash.address, "HELO")
          >>> bash.read(bash.address, 4)
          'HELO'
        """
        offset = self.vaddr_to_offset(address)

        if offset is not None:
            old = self.stream.tell()
            self.stream.seek(offset)
            self.stream.write(data)
            self.stream.seek(old)

        return None

    def save(self, path):
        """Save the ELF to a file

        >>> bash = ELF('/bin/bash')
        >>> bash.save('/tmp/bash_copy')
        >>> copy = file('/tmp/bash_copy')
        >>> bash = file('/bin/bash')
        >>> bash.read() == copy.read()
        True
        """
        old = self.stream.tell()

        with open(path,'wb+') as fd:
            self.stream.seek(0)
            fd.write(self.get_data())

        self.stream.seek(old)

    def get_data(self):
        """Retrieve the raw data from the ELF file.

        >>> bash = ELF('/bin/bash')
        >>> fd   = open('/bin/bash')
        >>> bash.get_data() == fd.read()
        True
        """
        old = self.stream.tell()
        self.stream.seek(0)
        data = self.stream.read(self.stream.size())
        self.stream.seek(old)
        return data

    def disasm(self, address, n_bytes):
        """Returns a string of disassembled instructions at
        the specified virtual memory address"""
        return asm.disasm(self.read(address, n_bytes), vma=address)

    def asm(self, address, assembly):
        """Assembles the specified instructions and inserts them
        into the ELF at the specified address.

        The resulting binary can be saved with ELF.save()
        """
        self.write(address, asm.asm(assembly))

    def bss(self, offset):
        """Returns an index into the .bss segment"""
        orig_bss = self.get_section_by_name('.bss').header.sh_addr
        curr_bss = orig_bss - self.load_addr + self.address
        return curr_bss + offset
