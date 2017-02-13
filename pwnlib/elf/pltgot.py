"""Utilities to parse the PLT and GOT of an ELF file.

Style note: these utilities should work with plain elftools ELFFiles.
"""

from elftools.elf.constants import SHN_INDICES
from elftools.elf.relocation import RelocationSection
from pwnlib.util import packing
from pwnlib.log import getLogger

log = getLogger(__name__)

def read_got(elf):
    """ Read GOT symbols and corresponding program locations from the binary. """

    got = {}

    # TODO: In reality, the canonical relocation list is the one linked from
    # the DYNAMIC segment; if we parse that, then we can get GOT even if the
    # section headers are missing or obfuscated away.
    for sect in elf.iter_sections():
        if not isinstance(sect, RelocationSection):
            continue

        if sect.header.sh_link == SHN_INDICES.SHN_UNDEF:
            continue

        # We have to examine all relocation sections.
        # Binaries (especially RELRO binaries) may put PLT GOT entries in *either*
        # .rel[a].dyn or .rel[a].plt.
        # This might pull in extraneous relocations, but it's better than missing
        # important external symbols.

        # Find the symbols for the relocation section
        sym_rel = elf.get_section(sect.header.sh_link)

        # Populate the GOT
        for rel in sect.iter_relocations():
            sym_idx  = rel.entry.r_info_sym
            symbol   = sym_rel.get_symbol(sym_idx)
            if not symbol:
                # local relocation
                continue
            name = symbol.name

            got[name] = rel.entry.r_offset

    return got


def _parse_plt_i386(symbols, revgot, pltsect):
    res = {}
    data = pltsect.data()
    saddr = pltsect.header.sh_addr
    pos = 0

    # Need the got base address for PIE executables
    # TODO: how might we get this if the symbol table is missing?
    gotaddr = symbols.get('_GLOBAL_OFFSET_TABLE_', 0)

    while pos < len(data):
        if data[pos:pos+2] == '\xff\x25':
            # jmp dword ptr ds:ABS (non-PIE)
            addr = packing.u32(data[pos+2:pos+6])
            if addr in revgot:
                res[revgot[addr]] = saddr + pos
            pos += 8
        elif data[pos:pos+2] == '\xff\xa3':
            # jmp dword ptr [ebx+REL] (PIE)
            addr = packing.u32(data[pos+2:pos+6]) + gotaddr
            if addr in revgot:
                res[revgot[addr]] = saddr + pos
            pos += 8
        else:
            # unknown/stub (add more cases for future/different PLT stub designs)
            pos += 4

    return res

def _parse_plt_amd64(symbols, revgot, pltsect):
    res = {}
    data = pltsect.data()
    saddr = pltsect.header.sh_addr
    pos = 0

    while pos < len(data):
        if data[pos:pos+2] == '\xff\x25':
            # jmp dword ptr [rip+REL]
            addr = packing.u32(data[pos+2:pos+6]) + saddr + pos + 6
            if addr in revgot:
                res[revgot[addr]] = saddr + pos
            pos += 8
        else:
            # unknown/stub (add more cases for future/different PLT stub designs)
            pos += 4

    return res

def _parse_plt_arm(symbols, revgot, pltsect):
    res = {}
    data = pltsect.data()
    saddr = pltsect.header.sh_addr
    pos = 0

    has_thumb = False
    while pos < len(data):
        if packing.u16(data[pos:pos+2]) == 0x4778:
            # bx pc (thumb PLT stub)
            has_thumb = True
            pos += 4
        elif (packing.u32(data[pos:pos+4]) & 0xffffff00) == 0xe28fc600 \
            and pos + 12 <= len(data):
            # add ip, pc, #PAGE_TOP, 12
            # add ip, ip, #PAGE_OFF, 20
            # ldr pc, [ip, #OFF]!
            addr = (((packing.u32(data[pos:pos+4]) & 0xff) << 20)
                   |((packing.u32(data[pos+4:pos+8]) & 0xff) << 12)
                   |(packing.u32(data[pos+8:pos+12]) & 0xfff)) + saddr + pos + 8

            if addr in revgot:
                res[revgot[addr]] = saddr + pos
                if has_thumb:
                    res[revgot[addr] + '$thumb'] = saddr + pos - 4

            has_thumb = False
            pos += 12
        else:
            has_thumb = False
            pos += 4

    return res

def _parse_plt_aarch64(symbols, revgot, pltsect):
    res = {}
    data = pltsect.data()
    saddr = pltsect.header.sh_addr
    words = packing.unpack_many(data, 32)
    pos = 0

    # Manual instruction decoding for speed (don't want to shell out to objdump right now)
    while pos < len(words):
        if (words[pos] & 0x8f00001f) == 0x80000010 \
            and pos + 4 <= len(words) \
            and words[pos+3] == 0xd61f0220:
            # adrp x16, PAGE
            # ldr  x17, [x16,#REL]
            # add  x16, x16, #REL
            # br   x17

            page = (((words[pos] & 0x60000000) >> 29)
                   |((words[pos] & 0x00ffffe0) >> 3))
            offs = ((words[pos+1] & 0x003ffc00) >> 7)
            curpage = (saddr + (pos << 2)) >> 12
            addr = ((page + curpage) << 12) + offs
            if addr in revgot:
                res[revgot[addr]] = saddr + pos
            pos += 4
        else:
            # unknown/stub (add more cases for future/different PLT stub designs)
            pos += 1

    return res

def _arch(elf):
    # pwntools overrides get_machine_arch with an incompatible version,
    # so we pick the pwntools version for consistency
    return {
            'EM_X86_64': 'amd64',
            'EM_386' :'i386',
            'EM_486': 'i386',
            'EM_ARM': 'arm',
            'EM_AARCH64': 'aarch64',
            'EM_MIPS': 'mips',
            'EM_PPC': 'powerpc',
            'EM_PPC64': 'powerpc64',
            'EM_SPARC32PLUS': 'sparc',
            'EM_SPARCV9': 'sparc64',
            'EM_IA_64': 'ia64'
        }.get(elf['e_machine'], elf['e_machine'])

def _fallback_plt_reader(elf):
    sections = list(elf.iter_sections())
    pltsect = elf.get_section_by_name('.plt')
    if not pltsect:
        return {}

    try:
        rel_plt = next(s for s in sections if
                        s.header.sh_info == sections.index(pltsect) and
                        isinstance(s, RelocationSection))
    except StopIteration:
        # Evidently whatever android-ndk uses to build binaries zeroed out sh_info for rel.plt
        rel_plt = elf.get_section_by_name('.rel.plt') or elf.get_section_by_name('.rela.plt')

    if not rel_plt:
        log.warning("Couldn't find relocations against PLT to get symbols")
        return {}

    # We have to fill out the GOT again here because read_got parses all .rel sections
    # (including symbols that aren't necessarily in the PLT)
    plt_got = {}
    if rel_plt.header.sh_link != SHN_INDICES.SHN_UNDEF:
        # Find the symbols for the relocation section
        sym_rel_plt = sections[rel_plt.header.sh_link]

        # Populate the GOT
        for rel in rel_plt.iter_relocations():
            sym_idx  = rel.entry.r_info_sym
            symbol   = sym_rel_plt.get_symbol(sym_idx)
            name     = symbol.name

            plt_got[name] = rel.entry.r_offset

    # Depending on the architecture, the beginning of the .plt will differ
    # in size, and each entry in the .plt will also differ in size.
    # Map architecture: offset, multiplier
    header_size, entry_size = {
        'i386':    (0x10, 0x10),
        'amd64':   (0x10, 0x10),
        'arm':     (0x14, 0xC),
        'aarch64': (0x20, 0x20),
    }.get(_arch(elf), (0,0))

    address = pltsect.header.sh_addr + header_size
    plt = {}

    # Based on the ordering of the GOT symbols, populate the PLT
    for name in sorted(plt_got, key=lambda name: plt_got[name]):
        plt[name] = address

        # Some PLT entries in ARM binaries have a thumb-mode stub that looks like:
        #
        # 00008304 <__gmon_start__@plt>:
        #     8304:   4778        bx  pc
        #     8306:   46c0        nop         ; (mov r8, r8)
        #     8308:   e28fc600    add ip, pc, #0, 12
        #     830c:   e28cca08    add ip, ip, #8, 20  ; 0x8000
        #     8310:   e5bcf228    ldr pc, [ip, #552]! ; 0x228
        if _arch(elf) == 'arm' and elf.u16(address) == 0x4778:
            address += 4

        address += entry_size

    return plt

def read_plt(elf, symbols, got):
    """Loads the PLT addresses.

    The following doctest checks the valitidy of the addresses.
    This assumes that each GOT entry points to its PLT entry,
    usually +6 bytes but could be anywhere within 0-16 bytes.

    >>> from pwnlib.util.packing import unpack
    >>> from pwnlib.util.misc import which
    >>> from pwnlib.elf.elf import ELF
    >>> bash = ELF(which('bash'))
    >>> def validate_got_plt(sym):
    ...     got      = bash.got[sym]
    ...     plt      = bash.plt[sym]
    ...     got_addr = unpack(bash.read(got, bash.bytes), bash.bits)
    ...     return got_addr in range(plt,plt+0x10)
    ...
    >>> all(map(validate_got_plt, bash.got.keys()))
    True
    """

    pltsects = [elf.get_section_by_name(name) for name in ('.plt', '.plt.got')]
    pltsects = [sect for sect in pltsects if sect]

    plt = {}

    try:
        if not pltsects:
            raise Exception("Couldn't find any PLT sections")

        plt_parser = globals().get('_parse_plt_' + _arch(elf), None)
        if not plt_parser:
            raise Exception("Don't know how to parse PLT relocations for arch %s" % _arch(elf))

        revgot = {v: k for k,v in got.iteritems()}
        for sect in pltsects:
            plt.update(plt_parser(symbols, revgot, sect))

        if not plt:
            raise Exception("Failed to parse PLT relocation table for arch %s" % _arch(elf))

    except Exception as e:
        log.warning(e)
        plt = _fallback_plt_reader(elf)

    return plt
