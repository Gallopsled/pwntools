from __future__ import absolute_import

import os
import tempfile

from pwnlib.tubes.process import process
from pwnlib.util.fiddling import unhex

# Pre-assembled shellcode for each architecture.
#
# This is literally the output of:
#     shellcraft $ARCH.linux.cat /proc/self/maps
#     shellcraft $ARCH.linux.syscalls.exit 0
CAT_PROC_MAPS_EXIT = {
    'i386':
        '680101010181342460717201686c662f6d68632f7365682f70726f89e331c931d26a0558cd806a015b89c131d268ffffff7f5e31c0b0bbcd80'
        '31db6a0158cd80',
    'amd64':
        '48b801010101010101015048b86d672e6c607172014831042448b82f70726f632f7365506a02584889e731f6990f0541baffffff7f4889c66a28586a015f990f05'
        '31ff6a3c580f05',
    'arm':
        '617007e3737040e304702de56c7606e32f7d46e304702de5637f02e3737546e304702de52f7007e3727f46e304702de50d00a0e1011021e0022022e00570a0e3000000ef0010a0e10100a0e3022022e00231e0e3bb70a0e3000000ef'
        '000020e00170a0e3000000ef',
    'thumb':
        '004f01e0617073ff4fea07274fea172780b4dff8047001e06c662f6d80b4dff8047001e0632f736580b4dff8047001e02f70726f80b4684681ea010182ea02024ff0050741df05464ff00100294682ea02026ff000434ff0bb0741df'
        '80ea00004ff0010741df',
    'mips':
        '726f093c2f702935f0ffa9af7365093c632f2935f4ffa9af2f6d093c6c662935f8ffa9af8cff193c9e8f393727482003fcffa9aff0ffbd272020a003ffff0528ffff0628a50f02340c010101feff192427202003fcffa2affcffa58fffff0628ff7f073cffffe7346f1002340c010101'
        'ffff0428a10f02340c010101',
    'aarch64':
        'ee058ed24eeeadf26eecc5f26eaeecf28fcd8cd2efa5adf22f0ccef26f0ee0f2ee3fbfa980f39fd2e0ffbff2e0ffdff2e0fffff2e1030091e2031faae3031faa080780d2010000d4e10300aa200080d2e2031faae3ff9fd2e3ffaff2e80880d2010000d4'
        'e0031faaa80b80d2010000d4',
}

def test_shellcode():
    """Only a test harness for checking CAT_PROC_MAPS_EXIT.

    >>> for arch in CAT_PROC_MAPS_EXIT:
    ...   with context.local(arch=arch):
    ...     sc = shellcraft.cat("/proc/self/maps")
    ...     sc += shellcraft.exit()
    ...     sc = asm(sc)
    ...     sc = enhex(sc)
    ...     assert sc == CAT_PROC_MAPS_EXIT[arch]
    >>> print "This should fail"
    LOLOLOL
    """
    pass

def patch_elf_and_read_maps(elf):
    """patch_elf_and_read_maps(elf) -> dict

    Given an :class:`.elf.ELF` instance, read ``/proc/self/maps`` as if it were executing.

    This is done by replacing the code at the entry point with shellcode which
    dumps ``/proc/self/maps`` and exits, and **actually executing the binary**.

    Arguments:
        elf(ELF): ELF instance to patch.

    Returns:
        A ``dict`` mapping file paths to the lowest address they appear at.
        Does not do any translation for e.g. QEMU emulation, the raw results
        are returned.

        If there is not enough space to inject the shellcode in the segment
        which contains the entry point, returns ``{}``.
    """

    # Get our shellcode
    sc = shellcode.get(elf.arch, None)

    if sc is None:
        log.error("Cannot patch /proc/self/maps shellcode into %r binary", elf.arch)

    sc = unhex(sc)

    # Ensure there is enough room in the segment where the entry point resides
    # in order to inject our shellcode.
    seg = elf.get_segment_for_address(elf.entry, len(sc))
    if not seg:
        log.warn_once("Could not inject code to determine memory mapping for %r: Not enough space", elf)
        return {}

    # Create our temporary file
    # NOTE: We cannot use "with NamedTemporaryFile() as foo", because we cannot
    # execute the file while the handle is open.
    fd, path = tempfile.mkstemp()

    # Close the file descriptor so that it may be executed
    os.close(fd)

    # Save off a copy of the ELF
    elf.save(path)

    # Load a new copy of the ELF at the temporary file location
    old = elf.read(elf.entry, len(sc))
    elf.write(elf.entry, sc)
    elf.save(path)
    elf.write(elf.entry, old)

    # Make the file executable
    os.chmod(path, 0o755)

    # Run a copy of it, get the maps
    io = process(path)
    data = io.recvall()
    io.wait()

    # Swap in the original ELF name
    data = data.replace(path, elf.path)

    # All we care about in the data is the load address of each file-backed mapping,
    # or each kernel-supplied mapping
    result = {}
    for line in data.splitlines():
        if '/' in line:
            index = line.index('/')
        elif '[' in line:
            index = line.index('[')
        else:
            continue

        address, _ = line.split('-', 1)

        address = int(address, 0x10)
        name = line[index:]

        result.setdefault(name, address)

    # Remove the temporary file, best-effort
    os.unlink(path)

    return result




