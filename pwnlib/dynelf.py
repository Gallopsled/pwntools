from . import log, memleak
from .util.packing import p32
from .elf import *
from .memleak import MemLeak

sizeof = ctypes.sizeof

def sysv_hash(symbol):
    """sysv_hash(str) -> int

    Fallback hash function used in ELF files if .gnuhash is not present
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

    Hash function used in the .gnuhash section of ELF files
    """
    h = 5381
    for c in s:
        h = h * 33 + ord(c)
    return h & 0xffffffff

class DynELF(object):
    '''
    DynELF knows how to resolve symbols in remote processes via an infoleak/memleak vulnerability.

    Attributes:
        libbase(int): Base address of the loaded ELF
        elfclass(int): Type of ELF (32 or 64)
        link_map(int): Pointer to the link_map in the ELF.
            *Required* to resolve other modules' addresses.

    Usage Details:

        The following table shows supported configurations.

        +-------+---------+--------------+--------------+
        | arch  | norelro | relro        | relro,now    |
        +=======+=========+==============+==============+
        | i386  | all     | from_lib_ptr | from_lib_ptr |
        +-------+---------+--------------+--------------+
        | amd64 | all     | all          | from_lib_ptr |
        +-------+---------+--------------+--------------+

        Configurations that only support 'from_lib_ptr' do not have a link_map,
        so it is not possible to find other libraries in a standardized fashion.

        A suggested alternative is to manually leak a GOT pointer in the main
        binary, and then use :meth:`from_lib_ptr` to resolve other symbols in
        the library pointed at from the GOT.
    '''
    @classmethod
    def for_one_lib_only(cls, leak, ptr):
        '''for_one_lib_only(leak, ptr) -> DynELF

        Instantiates and returns a DynELF instance from an arbitrary pointer
        into a loaded library that can resolve symbols in that library only.

        Can be used for dynamically loaded libraries where the link_map is
        not stable, or does not exits.
        '''
        base     = cls.find_base(leak, ptr)
        elfclass = cls.find_elfclass(leak, base)

        return cls(leak, elfclass, libbase = base)

    @classmethod
    def from_lib_ptr(cls, leak, ptr):
        '''from_lib_ptr(leak, ptr) -> DynELF

        Instantiates and returns a DynELF instance from an arbitrary pointer into a loaded library.
        '''
        elf = cls.for_one_lib_only(leak, ptr)
        elf.link_map = elf.find_linkmap()
        return elf

    @classmethod
    def from_elf(cls, leak, path, base = None):
        '''Get an instance of DynELF initialized from a local ELF file.
           If you have used the constructor previously this method is the one you want.

        Arguments:
            leak(MemLeak): pwnlib.memleak.MemLeak instance
            path(str,ELF): Path to an ELF file on disk, or a pwnlib.elf.ELF object.
            base(int): Base address of the loaded ELF object.  Auto-detected for
                non-position-independent binaries, or from the ``address`` property
                if an ``ELF`` object is provided for ``Path``.
        '''
        # If the user provided a loaded ELF, extract the path and base address
        if isinstance(path, ELF):
            path = path.path
            base = base or path.address

        # Load a fresh copy of the ELF
        elf  = ELF(path)

        # Set the base address of the elf to the user-provided value, if any
        if base is not None:
            elf.address = base

        # If the address is zero, bail (e.g. PIE binary)
        if not elf.address:
            log.error("An address must be specified for %r" % path)
            return None

        # Create a fake leaker which just leaks out of the 'loaded' ELF
        @MemLeak
        def fake_leak(address):
            data = elf.read(address, 4)
            # log.info("(fake) %#x ==> %s" % (address, data.encode('hex')))
            return data

        # In case we didn't actually get a base address
        elf.address = cls.find_base(fake_leak, elf.address)
        # log.info("Using address %x %x" % (base, elf.address))

        # Create a temporary DynELF object which uses this fake leak,
        # in order to resolve what we need.
        tmp  = cls.from_lib_ptr(fake_leak, elf.address)

        # Find the PLTGOT entry, and load the link_map from the real copy
        pltgot   = tmp.find_pltgot()
        # log.info(".plt.got %#x" % pltgot)

        # Swap in the real leaker and resolve the linkmap
        tmp.leak     = leak
        tmp.link_map = tmp.find_linkmap(pltgot)
        # log.info("link_map %#x" % tmp.link_map)

        return tmp

    @staticmethod
    def find_elfclass(leak, base):
        '''find_elfclass(leak, base) -> int

        Given a leaker and the base address of an ELF, find its ELFCLASS

        Returns:
            32 or 64, depending on the elfclass
        '''
        elfclass = leak(base, Elf_eident.EI_CLASS)
        return {constants.ELFCLASS32: 32,
                constants.ELFCLASS64: 64}[elfclass]

    @staticmethod
    def find_base(leak, ptr):
        '''find_base(leak, ptr) -> int

        Given a pointer into an ELF, find that ELF's base address.'''
        page_size = 0x1000
        page_mask = ~(page_size - 1)

        ptr &= page_mask

        while True:
            if leak.b(ptr) == 0x7f and leak.n(ptr+1,3) == 'ELF':
                break
            ptr -= page_size

        return ptr

    def find_dynamic_phdr(self):
        """
        Returns the address of the first Program Header with the type
        PT_DYNAMIC.
        """
        leak  = self.leak
        base  = self.libbase

        #First find PT_DYNAMIC
        Ehdr  = {32: Elf32_Ehdr, 64: Elf64_Ehdr}[self.elfclass]
        Phdr  = {32: Elf32_Phdr, 64: Elf64_Phdr}[self.elfclass]

        phead = base + leak(base, Ehdr.e_phoff)
        phnum = leak(base, Ehdr.e_phnum)

        for i in range(phnum):
            #Check if program header type is PT_DYNAMIC
            if leak(phead, Phdr.p_type) == constants.PT_DYNAMIC:
                break
            #Skip to next
            phead += sizeof(Phdr)
        else:
            log.error("Could not find Program Header of type PT_DYNAMIC")
            return None

        dynamic = leak(phead, Phdr.p_vaddr)

        #Sometimes this is an offset instead of an address
        if dynamic < base:
            dynamic += base
        return dynamic

    def find_pltgot(self):
        leak    = self.leak
        base    = self.libbase
        dynamic = self.find_dynamic_phdr()

        Dyn = {32: Elf32_Dyn,    64: Elf64_Dyn}     [self.elfclass]

        # Found the _DYNAMIC program header, now find PLTGOT entry in it
        # An entry with a DT_NULL tag marks the end of the DYNAMIC array.
        while True:
            d_tag = leak(dynamic, Dyn.d_tag)
            # self.status("Got tag %i" % d_tag)
            if d_tag == constants.DT_NULL:
                log.error('Could not find PLTGOT')
                return None
            elif d_tag == constants.DT_PLTGOT:
                break
            #Skip to next
            dynamic += sizeof(Dyn)
        else:
            log.error("Could not find GOTPLT")
            return None

        # self.status("dynamic %#x" % dynamic)
        ptr = leak(dynamic, Dyn.d_ptr)
        # self.status("d_ptr %#x" % ptr)

        if ptr < self.libbase:
            ptr += self.libbase
            # self.status("d_ptr %#x" % ptr)


        return ptr

    def find_linkmap(self, pltgot=None):
        Got = {32: Elf_i386_GOT, 64: Elf_x86_64_GOT}[self.elfclass]
        result = self.leak(pltgot or self.find_pltgot(), Got.linkmap)

        if result < self.libbase:
            result += self.libbase

        return result


    def __init__(self, leak, elfclass, link_map = None, libbase = None):
        '''
        Instantiates a DynELF object. You should not use this directly but rather use one of the
        factory methods: for_one_lib_only(), from_lib_ptr() or from_elf()

        Arguments:
            leak(MemLeak): Instance of pwnlib.memleak.MemLeak for leaking memory
            elfclass(int): 32 or 64
            link_map(int): Address of the link_map within a dynamically linked ELF
            libbase(int):  Base address of the ELF
        '''
        self.leak     = leak
        self.elfclass = elfclass
        self.link_map = link_map
        self.libbase  = libbase

        self.waitfor  = None
        self._bases   = {}
        self._dyn     = []

    def status(self, msg):
        if not self.waitfor:
            log.info(msg)
        else:
            self.waitfor.status(msg)

    def lookup (self, symb = None, lib = None):
        """lookup(symb = None, lib = None) -> int

        Find the address of symbol, which is found in lib (or the current library)

        Arguments:
            symb(str): Named routine to look up
            lib(str): Optional, external library to resolve the routine from.
                Requires link_map.

        Returns:
            Address of the named routine, or ``None``.
        """

        self.waitfor = log.waitfor('Resolving "%s"' % symb or lib)

        if lib and self.link_map is None:
            log.error("Cannot look up symbols in other libraries without link_map")
            result = None

        elif lib and self.link_map == self.libbase:
            log.error("Binary does not contain a pointer to link_map; use DynELF.from_lib_ptr")
            result = None

        elif lib:
            result = self.lookup_dynamic_symbol(symb, lib or 'libc')

        else:
            leak    = self.leak
            base    = self.libbase
            dynamic = self.find_dynamic_phdr()
            result  = self.lookup_in(symb, base, self.find_dynamic_phdr())

        self.waitfor = None
        return result


    def bases(self):
        '''Resolve base addresses of all loaded libraries.

        Return a dictionary mapping library path to its base address.
        '''
        if not self.link_map:
            log.error("Cannot look up library addresses without link_map")
            return None

        if self.link_map == self.libbase:
            log.error("Binary does not contain a pointer to link_map; use DynELF.from_lib_ptr")
            return None

        if not self._bases:
            leak    = self.leak
            LinkMap = {32: Elf32_Link_Map, 64: Elf64_Link_Map}[self.elfclass]

            cur = self.link_map
            while cur:
                p_name = leak(cur, LinkMap.l_name)
                name   = leak.s(p_name)
                addr   = leak(cur, LinkMap.l_addr)
                cur    = leak(cur, LinkMap.l_next)

                self._bases[name] = addr

        return self._bases

    def lookup_dynamic_symbol(self, symb, libname):
        """
        Looks up a symbol in a dynamically loaded library, by using the link_map of the
        dynamically linked ELF.

        Arguments:
            symb(str): Name of the symbol to resolve
            libname(str):  Name of the library to resolve, or a substring (e.g. 'libc')

        Notes:
            Requires `link_map`.
        """
        if not self.link_map:
            log.error("lookup_dynamic_symbol requires a link_map!")
            return None

        cur     = self.link_map
        leak    = self.leak
        LinkMap = {32: Elf32_Link_Map, 64: Elf64_Link_Map}[self.elfclass]

        self.status('Resolving load address of library %r' % libname)

        while cur:
            p_name = leak(cur, LinkMap.l_name)
            name   = leak.s(p_name)

            if libname in name:
                break

            cur = leak(cur, LinkMap.l_next)
        else:
            log.error("Could not find library with name containing %r" % libname)
            return None

        libbase = leak(cur, LinkMap.l_addr)

        log.success("Resolved library at %#x" % libbase)

        if symb is None:
            return libbase

        dynamic = leak(cur, LinkMap.l_ld)

        return self.lookup_in(symb, libbase, dynamic)


    def lookup_in(self, symb, libbase, dynamic):
        leak = self.leak
        Dyn  = {32: Elf32_Dyn, 64: Elf64_Dyn}[self.elfclass]

        self.status('.gnu.hash/.hash, .strtab and .symtab offsets')
        hshtag = hshtab = strtab = symtab = None
        while None in [hshtab, strtab, symtab]:
            tag = leak(dynamic, Dyn.d_tag)
            ptr = leak(dynamic, Dyn.d_ptr)
            # self.status("tag %#x => %#x" % (tag,ptr))
            if tag in (constants.DT_HASH, constants.DT_GNU_HASH):
                hshtab = ptr
                hshtag = tag
            elif tag == constants.DT_STRTAB:
                strtab = ptr
            elif tag == constants.DT_SYMTAB:
                symtab = ptr
            elif tag == constants.DT_NULL:
                log.error("Could not find all offsets")
                return None
            dynamic += sizeof(Dyn)

        # with glibc the pointers are relocated whereas with f.x. uclibc they
        # are not
        if libbase > strtab:
            strtab += libbase
            symtab += libbase
            hshtab += libbase

        # Parse the the table according to the type of hash table
        routine= {constants.DT_GNU_HASH: self.resolve_symbol_gnuhash,
                  constants.DT_HASH: self.resolve_symbol_hash}[hshtag]

        return routine(libbase, symb, hshtab, strtab, symtab)

    def resolve_symbol_hash(self, libbase, symb, hshtab, strtab, symtab):
        """
        Internal Documentation:
            See the ELF manual for more information.  Search for the phrase
            "A hash table of Elf32_Word objects supports symbol table access", or see:
            http://docs.oracle.com/cd/E19504-01/802-6319/6ia12qkfo/index.html#chapter6-48031

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
        Sym        = {32: Elf32_Sym, 64: Elf64_Sym}[self.elfclass]

        nbuckets   = leak(hshtab, Elf_HashTable.nbuckets)
        bucketaddr = hshtab + sizeof(Elf_HashTable)
        chain      = bucketaddr + (nbuckets * 4)

        self.status('hashmap')
        h = sysv_hash(symb) % nbuckets

        # Get the index out of the bucket for the hash we computed
        idx = leak.d(bucketaddr, h)

        while idx != constants.STN_UNDEF:
            # Look up the symbol corresponding to the specified index
            sym     = symtab + (idx * sizeof(Sym))
            symtype = leak(sym, Sym.st_info) & 0xf

            # We only care about functions
            if symtype == constants.STT_FUNC:

                # Leak the name of the function from the symbol table
                name = leak.s(strtab + leak(sym, Sym.st_name))

                # Make sure it matches the name of the symbol we were looking for.
                if name == symb:
                    #Bingo
                    addr = libbase + leak(sym, Sym.st_value)
                    log.success("Found %s at 0x%x" % (name, addr))
                    return addr

            # The name did not match what we were looking for, or we assume
            # it did not since it was not a function.
            # Follow the chain for this particular hash.
            idx = leak.d(chain, idx)

    def resolve_symbol_gnuhash(self, libbase, symb, hshtab, strtab, symtab):
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
        Sym  = {32: Elf32_Sym, 64: Elf64_Sym}[self.elfclass]

        # The number of hash buckets (hash % nbuckets)
        nbuckets  = leak(hshtab, GNU_HASH.nbuckets)

        # Index of the first accessible symbol in the hash table
        # Numbering doesn't start at zero, it starts at symndx
        symndx    = leak(hshtab, GNU_HASH.symndx)

        # Number of things in the bloom filter.
        # We don't care about the contents, but we have to skip over it.
        maskwords = leak(hshtab, GNU_HASH.maskwords)

        # Skip over the bloom filter to get to the buckets
        elfword = self.elfclass / 8
        buckets = hshtab + sizeof(GNU_HASH) + (elfword * maskwords)

        # The chains come after the buckets
        chains  = buckets + (4 * nbuckets)

        self.status('hash chain index')

        # Hash the symbol, find its bucket
        hsh    = gnu_hash(symb)
        bucket = hsh % nbuckets

        # Get the first index in the chain for that bucket
        ndx    = leak.d(buckets, bucket)
        if ndx == 0:
            log.failed('Empty chain')
            return None

        # Find the start of the chain, taking into account that numbering
        # effectively starts at 'symndx' within the chains.
        chain  = chains + 4 * (ndx - symndx)

        self.status('hash chain')

        # Iteratively get the I'th entry from the hash chain,
        # until we find one that matches **and**
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
                name = leak.s(strtab + leak(sym, Sym.st_name))

                if name == symb:
                    # No collision, get offset and calculate address
                    offset = leak(sym, Sym.st_value)
                    addr   = offset + libbase
                    log.success('Found %s at 0x%x' % (name, addr))
                    return addr

            # Collision or no match, continue to the next item
            i += 1
        else:
            log.failed('Could not find a hash that matched %#x' % hsh)
            return None
