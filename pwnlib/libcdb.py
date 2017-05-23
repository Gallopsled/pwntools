"""
Fetch a LIBC binary based on some heuristics.
"""
from __future__ import absolute_import

import codecs
import json
import os
import tempfile
import urlparse

from pwnlib.context import context
from pwnlib.elf import ELF
from pwnlib.log import getLogger
from pwnlib.util.fiddling import b64d
from pwnlib.util.fiddling import hexdump
from pwnlib.util.misc import read
from pwnlib.util.misc import write
from pwnlib.util.safeeval import const
from pwnlib.util.web import wget

log = getLogger(__name__)

HASHES = ['build_id', 'sha1', 'sha256', 'md5']

def search_by_hash(hex_encoded_id, hash_type='build_id'):
    assert hash_type in HASHES, hash_type

    # Ensure that the libcdb cache directory exists
    cache_dir = os.path.join(context.cache_dir, 'libcdb', hash_type)

    if not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)

    # If we already downloaded the file, and it looks even passingly like
    # a valid ELF file, return it.
    cache = os.path.join(cache_dir, hex_encoded_id)

    if os.path.exists(cache):
        log.debug("Found existing cached libc at %r", cache)

        data = read(cache)
        if data.startswith('\x7FELF'):
            log.info_once("Using cached data from %r", cache)
            return cache
        else:
            log.info_once("Skipping unavialable libc %s", hex_encoded_id)
            return None

    # Build the URL using the requested hash type
    url_base = "https://gitlab.com/libcdb/libcdb/raw/master/hashes/%s/" % hash_type
    url      = urlparse.urljoin(url_base, hex_encoded_id)

    data   = ""
    while not data.startswith('\x7fELF'):
        log.debug("Downloading data from LibcDB: %s", url)
        data = wget(url)

        if not data:
            log.warn_once("Could not fetch libc for build_id %s", hex_encoded_id)
            break

        # GitLab serves up symlinks with
        if data.startswith('..'):
            url = os.path.dirname(url) + '/'
            url = urlparse.urljoin(url, data)

    # Save whatever we got to the cache
    write(cache, data or '')

    # Return ``None`` if we did not get a valid ELF file
    if not data or not data.startswith('\x7FELF'):
        return None

    return cache


def search_by_build_id(hex_encoded_id):
    """
    Given a hex-encoded Build ID, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded Build ID (e.g. 'ABCDEF...') of the library

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:
        >>> filename = search_by_build_id('fe136e485814fee2268cf19e5c124ed0f73f4400')
        >>> hex(ELF(filename).symbols.read)
        '0xda260'
        >>> None == search_by_build_id('XX')
        True
    """
    return search_by_hash(hex_encoded_id, 'build_id')

def search_by_md5(hex_encoded_id):
    """
    Given a hex-encoded md5sum, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded Build ID (e.g. 'ABCDEF...') of the library

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:
        >>> filename = search_by_md5('7a71dafb87606f360043dcd638e411bd')
        >>> hex(ELF(filename).symbols.read)
        '0xda260'
        >>> None == search_by_build_id('XX')
        True
    """
    return search_by_hash(hex_encoded_id, 'md5')

def search_by_sha1(hex_encoded_id):
    """
    Given a hex-encoded sha1, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded Build ID (e.g. 'ABCDEF...') of the library

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:
        >>> filename = search_by_sha1('34471e355a5e71400b9d65e78d2cd6ce7fc49de5')
        >>> hex(ELF(filename).symbols.read)
        '0xda260'
        >>> None == search_by_sha1('XX')
        True
    """
    return search_by_hash(hex_encoded_id, 'sha1')


def search_by_sha256(hex_encoded_id):
    """
    Given a hex-encoded sha256, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded Build ID (e.g. 'ABCDEF...') of the library

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:
        >>> filename = search_by_sha256('5e877a8272da934812d2d1f9ee94f73c77c790cbc5d8251f5322389fc9667f21')
        >>> hex(ELF(filename).symbols.read)
        '0xda260'
        >>> None == search_by_sha256('XX')
        True
    """
    return search_by_hash(hex_encoded_id, 'sha256')




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


__all__ = ['get_build_id_offsets', 'search_by_build_id', 'search_by_sha1', 'search_by_sha256', 'search_by_md5']
