"""
Fetch a LIBC binary based on some heuristics.
"""
import codecs
import json
import os
import tempfile
import urlparse

from .context import context
from .elf import ELF
from .log import getLogger
from .util.fiddling import b64d
from .util.fiddling import hexdump
from .util.misc import read
from .util.misc import write
from .util.safeeval import const
from .util.web import wget

log = getLogger(__name__)

cache_dir = os.path.join(tempfile.gettempdir(), 'pwn')

def search_by_build_id(hex_encoded_id):
    """
    Given a hex-encoded Build ID, return the path to an ELF with that Build ID
    only the local system.

    If it can't be found, return None.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded Build ID (e.g. 'ABCDEF...') of the library

    Returns:
        Path to the downloaded library on disk, or ``None``.
    """
    cache = cache_dir + '-libc.so.' + hex_encoded_id

    if os.path.exists(cache) and read(cache).startswith('\x7FELF'):
        log.info_once("Using cached data from %r" % cache)
        return cache

    log.info("Downloading data from GitHub")

    url_base = "https://gitlab.com/libcdb/libcdb/raw/master/hashes/build_id/"
    url      = urlparse.urljoin(url_base, hex_encoded_id)

    data   = ""
    while not data.startswith('\x7fELF'):
        data = wget(url)

        if not data:
            return None

        if data.startswith('..'):
            url = os.path.dirname(url) + '/'
            url = urlparse.urljoin(url, data)

    write(cache, data)
    return cache

def get_build_id_offsets():
    """
    Returns a list of file offsets where the Build ID should reside within
    an ELF file of the currentlys-elected architecture.
    """
    # Given the corpus of almost all libc to have been released with
    # RedHat, Fedora, Ubuntu, Debian, etc. over the past several years,
    # we can say with 99% certainty that the GNU Build ID section will
    # be at one of the specified addresses.
    #
    # The point here is to get an easy win by reading less DWORDs than would
    # have otherwise been required to walk the section table and the string
    # stable.
    #
    # function check_arch() {
    # readelf -n $(file -L * | grep -i "$1" | cut -d ':' -f 1) \
    #       | grep -B3 BUILD_ID \
    #       | grep offset \
    #       | sort \
    #       | uniq -c
    # }

    return {
    # $ check_arch 80386
    #     181 Displaying notes found at file offset 0x00000174 with length 0x00000024:
        'i386': [0x174],
    # $ check_arch "ARM, EABI5"
    #      69 Displaying notes found at file offset 0x00000174 with length 0x00000024:
        'arm':  [0x174],
        'thumb':  [0x174],
    # $ check_arch "ARM aarch64"
    #       1 Displaying notes found at file offset 0x00000238 with length 0x00000024:
        'aarch64': [0x238],
    # $ check_arch "x86-64"
    #       6 Displaying notes found at file offset 0x00000174 with length 0x00000024:
    #      82 Displaying notes found at file offset 0x00000270 with length 0x00000024:
        'amd64': [0x270, 0x174],
    # $ check_arch "PowerPC or cisco"
    #      88 Displaying notes found at file offset 0x00000174 with length 0x00000024:
        'powerpc': [0x174],
    # $ check_arch "64-bit PowerPC"
    #      30 Displaying notes found at file offset 0x00000238 with length 0x00000024:
        'powerpc64': [0x238],
    # $ check_arch "SPARC32"
    #      32 Displaying notes found at file offset 0x00000174 with length 0x00000024:
        'sparc': [0x174],
    # $ check_arch "SPARC V9"
    #      33 Displaying notes found at file offset 0x00000270 with length 0x00000024:
        'sparc64': [0x270]
    }.get(context.arch, [])


__all__ = ['get_build_id_offsets', 'search_by_build_id']
