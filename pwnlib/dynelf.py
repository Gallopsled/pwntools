"""
Resolve symbols in loaded, dynamically-linked ELF binaries.
Given a function which can leak data at an arbitrary address,
any symbol in any loaded library can be resolved.

Example
^^^^^^^^

::

    # Assume a process or remote connection
    p = process('./pwnme')

    # Declare a function that takes a single address, and
    # leaks at least one byte at that address.
    def leak(address):
        data = p.read(address, 4)
        log.debug("%#x => %s" % (address, (data or '').encode('hex')))
        return data

    # For the sake of this example, let's say that we
    # have any of these pointers.  One is a pointer into
    # the target binary, the other two are pointers into libc
    main   = 0xfeedf4ce
    libc   = 0xdeadb000
    system = 0xdeadbeef

    # With our leaker, and a pointer into our target binary,
    # we can resolve the address of anything.
    #
    # We do not actually need to have a copy of the target
    # binary for this to work.
    d = DynELF(leak, main)
    assert d.lookup(None,     'libc') == libc
    assert d.lookup('system', 'libc') == system

    # However, if we *do* have a copy of the target binary,
    # we can speed up some of the steps.
    d = DynELF(leak, main, elf=ELF('./pwnme'))
    assert d.lookup(None,     'libc') == libc
    assert d.lookup('system', 'libc') == system

    # Alternately, we can resolve symbols inside another library,
    # given a pointer into it.
    d = DynELF(leak, libc + 0x1234)
    assert d.lookup('system')      == system

DynELF
"""
from . import elf
from .elf     import ELF, constants
from .memleak import MemLeak
from .context import context

from elftools.elf.enums import ENUM_D_TAG

import logging, ctypes

log    = logging.getLogger(__name__)
sizeof = ctypes.sizeof

def sysv_hash(symbol):
    """sysv_hash(str) -> int

    Function used to generate SYSV-style hashes for strings.
    """
    h = 0
    g = 0
    for c in symbol:
        h = (h << 4) + ord(c)
        g = h & 0xf0000000
        h ^= (g >> 24)
        h &= ~g
    return h & 0xffffffff

def gnu_hash(s):
    """gnu_hash(str) -> int

    Function used to generated GNU-style hashes for strings.
    """
    h = 5381
    for c in s:
        h = h * 33 + ord(c)
    return h & 0xffffffff

class DynELF(object):
    '''
    DynELF knows how to resolve symbols in remote processes via an infoleak or
    memleak vulnerability encapsulated by :class:`pwnlib.memleak.MemLeak`.

    Implementation Details:

        Resolving Functions:

            In all ELFs which export symbols for importing by other libraries,
            (e.g. ``libc.so``) there are a series of tables which give exported
            symbol names, exported symbol addresses, and the ``hash`` of those
            exported symbols.  By applying a hash function to the name of the
            desired symbol (e.g., ``'printf'``), it can be located in the hash
            table.  Its location in the hash table provides an index into the
            string name table (strtab_), and the symbol address (symtab_).

            Assuming we have the base address of ``libc.so``, the way to resolve
            the address of ``printf`` is to locate the ``symtab``, ``strtab``,
            and hash table. The string ``"printf"`` is hashed according to the
            style of the hash table (SYSV_ or GNU_), and the hash table is
            walked until a matching entry is located. We can verify an exact
            match by checking the string table, and then get the offset into
            ``libc.so`` from the ``symtab``.

        Resolving Library Addresses:

            If we have a pointer into a dynamically-linked executable, we can
            leverage an internal linker structure called the `link map`_. This
            is a linked list structure which contains information about each
            loaded library, including its full path and base address.

            A pointer to the ``link map`` can be found in two ways.  Both are
            referenced from entries in the DYNAMIC_ array.

            - In non-RELRO binaries, a pointer is placed in the `.got.plt`_ area
              in the binary. This is marked by finding the DT_PLTGOT_ area in the
              binary.
            - In all binaries, a pointer can be found in the area described by
              the DT_DEBUG_ area.  This exists even in stripped binaries.

            For maximum flexibility, both mechanisms are used exhaustively.

    .. _symtab:    https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
    .. _strtab:    https://refspecs.linuxbase.org/elf/gabi4+/ch4.strtab.html
    .. _.got.plt:  https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/specialsections.html
    .. _DYNAMIC:   http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#dynamic_section
    .. _SYSV:      https://refspecs.linuxbase.org/elf/gabi4+/ch5.dynamic.html#hash
    .. _GNU:       https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
    .. _DT_DEBUG:  https://reverseengineering.stackexchange.com/questions/6525/elf-link-map-when-linked-as-relro
    .. _link map:  https://google.com
    '''

    def __init__(self, leak, pointer=None, elf=None):
        '''
        Instantiates an object which can resolve symbols in a running binary
        given a :class:`pwnlib.memleak.MemLeak` leaker and a pointer inside
        the binary.

        Arguments:
            leak(MemLeak): Instance of pwnlib.memleak.MemLeak for leaking memory
            pointer(int):  A pointer into a loaded ELF file
            elf(str,ELF):  Path to the ELF file on disk, or a loaded :class:`pwnlib.elf.ELF`.
        '''
        self._elfclass = None
        self._link_map = None
        self._waitfor  = None
        self._bases    = {}
        self._dynamic  = None

        if not (pointer or (elf and elf.address)):
            log.error("Must specify either a pointer into a module and/or an ELF file with a valid base address")

        pointer = pointer or elf.address

        if not isinstance(leak, MemLeak):
            leak = MemLeak(leak)

        self.leak    = leak
        self.libbase = self._find_base(pointer or elf.address)

        if elf:
            self._find_linkmap_assisted(elf)

    @classmethod
    def for_one_lib_only(cls, leak, ptr):
        return cls(leak, ptr)

    @classmethod
    def from_lib_ptr(cls, leak, ptr):
        return cls(leak, ptr)

    @staticmethod
    def find_base(leak, ptr):
        """Given a :class:`pwnlib.memleak.MemLeak` object and a pointer into a
        library, find its base address.
        """
        return DynELF(leak, ptr).libbase

    @property
    def elfclass(self):
        """32 or 64"""
        if not self._elfclass:
            elfclass = self.leak.field(self.libbase, elf.Elf_eident.EI_CLASS)
            self._elfclass =  {constants.ELFCLASS32: 32,
                              constants.ELFCLASS64: 64}[elfclass]
        return self._elfclass

    @property
    def link_map(self):
        """Pointer to the runtime link_map object"""
        if not self._link_map:
            self._link_map = self._find_linkmap()
        return self._link_map

    @property
    def dynamic(self):
        """
        Returns:
            Pointer to the ``.DYNAMIC`` area.
        """
        if not self._dynamic:
            self._dynamic = self._find_dynamic_phdr()
        return self._dynamic

    def _find_linkmap_assisted(self, path):
        """Uses an ELF file to assist in finding the link_map.
        """
        if isinstance(path, ELF):
            path = path.path

        # Load a fresh copy of the ELF
        with context.local(log_level='error'):
            elf = ELF(path)
        elf.address = self.libbase

        self.waitfor("Loading from %r" % elf.path)

        # Create a fake leaker which just leaks out of the 'loaded' ELF
        @MemLeak
        def fake_leak(address):
            data = elf.read(address, 4)
            return data

        # Save off our real leaker, use the fake leaker
        real_leak = self.leak
        self.leak = fake_leak

        # Get useful pointers for resolving the linkmap faster
        pltgot = self._find_dt(constants.DT_PLTGOT)
        debug  = self._find_dt(constants.DT_DEBUG)

        # Restore the real leaker
        self.leak = real_leak

        # Find the linkmap using the helper pointers
        self._find_linkmap(pltgot, debug)
        self.success('Done')

    def _find_base(self, ptr):
        page_size = 0x1000
        page_mask = ~(page_size - 1)

        ptr &= page_mask
        w = None

        while True:
            if self.leak.b(ptr) == 0x7f and self.leak.n(ptr+1,3) == 'ELF':
                break
            ptr -= page_size

            # Defer creating the spinner in the event that 'ptr'
            # is already the base address
            w = w or self.waitfor("Finding base address")
            self.status('%#x' % ptr)

        # If we created a spinner, print the success message
        if w:
            self.success('%#x' % ptr)

        return ptr


    def _find_dynamic_phdr(self):
        """
        Returns the address of the first Program Header with the type
        PT_DYNAMIC.
        """
        leak  = self.leak
        base  = self.libbase

        #First find PT_DYNAMIC
        Ehdr  = {32: elf.Elf32_Ehdr, 64: elf.Elf64_Ehdr}[self.elfclass]
        Phdr  = {32: elf.Elf32_Phdr, 64: elf.Elf64_Phdr}[self.elfclass]

        self.status("PT_DYNAMIC")

        phead = base + leak.field(base, Ehdr.e_phoff)
        self.status("PT_DYNAMIC header = %#x" % phead)

        phnum = leak.field(base, Ehdr.e_phnum)
        self.status("PT_DYNAMIC count = %#x" % phnum)

        for i in range(phnum):
            if leak.field(phead, Phdr.p_type) == constants.PT_DYNAMIC:
                break
            phead += sizeof(Phdr)
        else:
            self.failure("Could not find Program Header of type PT_DYNAMIC")
            return None

        dynamic = leak.field(phead, Phdr.p_vaddr)
        self.status("PT_DYNAMIC @ %#x" % dynamic)

        #Sometimes this is an offset instead of an address
        if 0 < dynamic < 0x400000:
            dynamic += base

        return dynamic

    def _find_dt(self, tags):
        """
        Find an entry in the DYNAMIC array.

        Arguments:
            tags(int, tuple): Single tag, or list of tags to search for

        Returns:
            Pointer to the data described by the specified entry.
        """
        if not isinstance(tags, (list, tuple)):
            tags = [tags]

        leak    = self.leak
        base    = self.libbase
        dynamic = self.dynamic
        name    = lambda tag: next(k for k,v in ENUM_D_TAG.items() if v == tag)

        Dyn = {32: elf.Elf32_Dyn,    64: elf.Elf64_Dyn}     [self.elfclass]

        # Found the _DYNAMIC program header, now find PLTGOT entry in it
        # An entry with a DT_NULL tag marks the end of the DYNAMIC array.
        while True:
            d_tag = leak.field(dynamic, Dyn.d_tag)

            if d_tag == constants.DT_NULL:
                return None
            elif d_tag in tags:
                break

            #Skip to next
            dynamic += sizeof(Dyn)
        else:
            self.failure("Could not find any of: " % map(name, tags))
            return None

        self.status("Found %s at %#x" % (name(d_tag), dynamic))
        ptr = leak.field(dynamic, Dyn.d_ptr)

        # Sometimes this is an offset rather than an actual pointer.
        if 0 < ptr < 0x400000:
            ptr += self.libbase

        return ptr


    def _find_linkmap(self, pltgot=None, debug=None):
        """
        The linkmap is a chained structure created by the loader at runtime
        which contains information on the names and load addresses osf all
        libraries.

        For non-RELRO binaries, a pointer to this is stored in the .got.plt
        area.

        For RELRO binaries, a pointer is additionally stored in the DT_DEBUG
        area.
        """
        w = self.waitfor("Finding linkmap")

        Got     = {32: elf.Elf_i386_GOT, 64: elf.Elf_x86_64_GOT}[self.elfclass]
        r_debug = {32: elf.Elf32_r_debug, 64: elf.Elf64_r_debug}[self.elfclass]

        result = None
        pltgot = pltgot or self._find_dt(constants.DT_PLTGOT)

        if pltgot:
            w.status("GOT.linkmap")
            result = self.leak.field(pltgot, Got.linkmap)
            w.status("GOT.linkmap %#x" % result)

        if not result:
            debug = debug or self._find_dt(constants.DT_DEBUG)
            if debug:
                w.status("r_debug.linkmap")
                result = self.leak.field(debug, r_debug.r_map)
                w.status("r_debug.linkmap %#x" % result)

        if not (pltgot or debug):
            w.failure("Could not find DT_PLTGOT or DT_DEBUG")
            return None

        if 0 < result < 0x400000:
            result += self.libbase

        w.success('%#x' % result)
        return result

    def waitfor(self, msg):
        if not self._waitfor:
            self._waitfor = log.waitfor(msg)
        else:
            self.status(msg)
        return self._waitfor

    def failure(self, msg):
        if not self._waitfor:
            log.failure(msg)
        else:
            self._waitfor.failure(msg)
            self._waitfor = None

    def success(self, msg):
        if not self._waitfor:
            log.success(msg)
        else:
            self._waitfor.success(msg)
            self._waitfor = None

    def status(self, msg):
        if not self._waitfor:
            log.info(msg)
        else:
            self._waitfor.status(msg)

    def lookup (self, symb = None, lib = None):
        """lookup(symb = None, lib = None) -> int

        Find the address of ``symbol``, which is found in ``lib``.

        Arguments:
            symb(str): Named routine to look up
            lib(str): Substring to match for the library name.
              If omitted, the current library is searched.
              If set to ``'libc'``, ``'libc.so'`` is assumed.

        Returns:
            Address of the named symbol, or ``None``.
        """

        if lib == 'libc':
            lib = 'libc.so'

        #
        # Get a pretty name for the symbol to show the user
        #
        if symb and lib:
            pretty = '%r in %r' % (symb, lib)
        else:
            pretty = symb or lib

        if not pretty:
            self.failure("Must specify a library or symbol")

        self.waitfor('Resolving %s' % pretty)

        #
        # If we are loading from a different library, create
        # a DynELF instance for it.
        #
        if lib: dynlib = self._dynamic_load_dynelf(lib)
        else:   dynlib = self

        #
        # If we are resolving a symbol in the library, find it.
        #
        if symb: result = dynlib._lookup(symb)
        else:    result = dynlib.libbase

        #
        # Did we win?
        #
        if result: self.success("%#x" % result)
        else:      self.failure("Could not find %s" % pretty)

        return result

    def bases(self):
        '''Resolve base addresses of all loaded libraries.

        Return a dictionary mapping library path to its base address.
        '''
        if not self._bases:
            leak    = self.leak
            LinkMap = {32: elf.Elf32_Link_Map, 64: elf.Elf64_Link_Map}[self.elfclass]

            cur = self.link_map
            while cur:
                p_name = leak.field(cur, LinkMap.l_name)
                name   = leak.s(p_name)
                addr   = leak.field(cur, LinkMap.l_addr)
                cur    = leak.field(cur, LinkMap.l_next)

                self._bases[name] = addr

        return self._bases

    def _dynamic_load_dynelf(self, libname):
        """_dynamic_load_dynelf(libname) -> DynELF

        Looks up information about a loaded library via the link map.

        Arguments:
            libname(str):  Name of the library to resolve, or a substring (e.g. 'libc.so')

        Returns:
            A DynELF instance for the loaded library, or None.
        """
        cur     = self.link_map
        leak    = self.leak
        LinkMap = {32: elf.Elf32_Link_Map, 64: elf.Elf64_Link_Map}[self.elfclass]

        while cur:
            self.status("link_map entry %#x" % cur)
            p_name = leak.field(cur, LinkMap.l_name)
            name   = leak.s(p_name)

            if libname in name:
                break

            if name:
                self.status('Skipping %s' % name)

            cur = leak.field(cur, LinkMap.l_next)
        else:
            self.failure("Could not find library with name containing %r" % libname)
            return None

        libbase = leak.field(cur, LinkMap.l_addr)

        self.status("Resolved library at %#x" % libbase)

        lib = DynELF(leak, libbase)
        lib._dynamic = leak.field(cur, LinkMap.l_ld)
        lib._waitfor = self._waitfor
        return lib

    def _lookup(self, symb):
        """Performs the actual symbol lookup within one ELF file."""
        leak = self.leak
        Dyn  = {32: elf.Elf32_Dyn, 64: elf.Elf64_Dyn}[self.elfclass]
        name = lambda tag: next(k for k,v in ENUM_D_TAG.items() if v == tag)

        self.status('.gnu.hash/.hash, .strtab and .symtab offsets')

        #
        # We need all three of the hash, string table, and symbol table.
        #
        hshtab  = self._find_dt(constants.DT_GNU_HASH)
        strtab  = self._find_dt(constants.DT_STRTAB)
        symtab  = self._find_dt(constants.DT_SYMTAB)

        # Assume GNU hash will hit, since it is the default for GCC.
        if hshtab:
            hshtype = 'gnu'
        else:
            hshtab  = self._find_dt(constants.DT_HASH)
            hshtype = 'sysv'

        if not all([strtab, symtab, hshtab]):
            self.failure("Could not find all tables")

        # glibc pointers are relocated but uclibc are not
        if 0 < strtab < 0x400000:
            strtab  += self.libbase
            symtab  += self.libbase
            hshtab  += self.libbase

        #
        # Perform the hash lookup
        #
        routine = {'sysv': self._resolve_symbol_sysv,
                   'gnu':  self._resolve_symbol_gnu}[hshtype]
        return routine(self.libbase, symb, hshtab, strtab, symtab)

    def _resolve_symbol_sysv(self, libbase, symb, hshtab, strtab, symtab):
        """
        Internal Documentation:
            See the ELF manual for more information.  Search for the phrase
            "A hash table of Elf32_Word objects supports symbol table access", or see:
            https://docs.oracle.com/cd/E19504-01/802-6319/6ia12qkfo/index.html#chapter6-48031

            struct Elf_Hash {
                uint32_t nbucket;
                uint32_t nchain;
                uint32_t bucket[nbucket];
                uint32_t chain[nchain];
            }

            You can force an ELF to use this type of symbol table by compiling
            with 'gcc -Wl,--hash-style=sysv'
        """
        self.status('.hash parms')
        leak       = self.leak
        Sym        = {32: elf.Elf32_Sym, 64: elf.Elf64_Sym}[self.elfclass]

        nbuckets   = leak.field(hshtab, elf.Elf_HashTable.nbuckets)
        bucketaddr = hshtab + sizeof(elf.Elf_HashTable)
        chain      = bucketaddr + (nbuckets * 4)

        self.status('hashmap')
        hsh = sysv_hash(symb) % nbuckets

        # Get the index out of the bucket for the hash we computed
        idx = leak.d(bucketaddr, hsh)

        while idx != constants.STN_UNDEF:
            # Look up the symbol corresponding to the specified index
            sym     = symtab + (idx * sizeof(Sym))
            symtype = leak.field(sym, Sym.st_info) & 0xf

            # We only care about functions
            if symtype == constants.STT_FUNC:

                # Leak the name of the function from the symbol table
                name = leak.s(strtab + leak.field(sym, Sym.st_name))

                # Make sure it matches the name of the symbol we were looking for.
                if name == symb:
                    #Bingo
                    addr = libbase + leak.field(sym, Sym.st_value)
                    return addr

                self.status("%s (hash collision)" % name)

            # The name did not match what we were looking for, or we assume
            # it did not since it was not a function.
            # Follow the chain for this particular hash.
            idx = leak.d(chain, idx)
        else:
            self.failure('Could not find a SYSV hash that matched %#x' % hsh)
            return None

    def _resolve_symbol_gnu(self, libbase, symb, hshtab, strtab, symtab):
        """
        Internal Documentation:
            The GNU hash structure is a bit more complex than the normal hash
            structure.

            Again, Oracle has good documentation.
            https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections

            You can force an ELF to use this type of symbol table by compiling
            with 'gcc -Wl,--hash-style=gnu'
        """
        self.status('.gnu.hash parms')
        leak = self.leak
        Sym  = {32: elf.Elf32_Sym, 64: elf.Elf64_Sym}[self.elfclass]

        # The number of hash buckets (hash % nbuckets)
        nbuckets  = leak.field(hshtab, elf.GNU_HASH.nbuckets)

        # Index of the first accessible symbol in the hash table
        # Numbering doesn't start at zero, it starts at symndx
        symndx    = leak.field(hshtab, elf.GNU_HASH.symndx)

        # Number of things in the bloom filter.
        # We don't care about the contents, but we have to skip over it.
        maskwords = leak.field(hshtab, elf.GNU_HASH.maskwords)

        # Skip over the bloom filter to get to the buckets
        elfword = self.elfclass / 8
        buckets = hshtab + sizeof(elf.GNU_HASH) + (elfword * maskwords)

        # The chains come after the buckets
        chains  = buckets + (4 * nbuckets)

        self.status('hash chain index')

        # Hash the symbol, find its bucket
        hsh    = gnu_hash(symb)
        bucket = hsh % nbuckets

        # Get the first index in the chain for that bucket
        ndx    = leak.d(buckets, bucket)
        if ndx == 0:
            self.failure('Empty chain')
            return None

        # Find the start of the chain, taking into account that numbering
        # effectively starts at 'symndx' within the chains.
        chain  = chains + 4 * (ndx - symndx)

        self.status('hash chain')

        # Iteratively get the I'th entry from the hash chain, until we find
        # one that matches.
        i    = 0
        hsh &= ~1

        # The least significant bit is used as a stopper bit.
        # It is set to 1 when a symbol is the last symbol in a given hash chain.
        hsh2 = 0
        while not hsh2 & 1:
            hsh2 = leak.d(chain, i)
            if hsh == (hsh2 & ~1):
                # Check for collision on hash values
                sym  = symtab + sizeof(Sym) * (ndx + i)
                name = leak.s(strtab + leak.field(sym, Sym.st_name))

                if name == symb:
                    # No collision, get offset and calculate address
                    offset = leak.field(sym, Sym.st_value)
                    addr   = offset + libbase
                    return addr

                self.status("%s (hash collision)" % name)

            # Collision or no match, continue to the next item
            i += 1
        else:
            self.failure('Could not find a GNU hash that matched %#x' % hsh)
            return None
