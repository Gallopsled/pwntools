"""
Fetch a LIBC binary based on some heuristics.
"""
from __future__ import absolute_import
from __future__ import division

import codecs
import json
import os
import tempfile

from pwnlib.context import context
from pwnlib.elf import ELF
from pwnlib.log import getLogger
from pwnlib.tubes.process import process
from pwnlib.util.fiddling import b64d
from pwnlib.util.fiddling import enhex
from pwnlib.util.fiddling import hexdump
from pwnlib.util.misc import read
from pwnlib.util.misc import which
from pwnlib.util.misc import write
from pwnlib.util.safeeval import const
from pwnlib.util.web import wget

log = getLogger(__name__)

HASHES = ['build_id', 'sha1', 'sha256', 'md5']
DEBUGINFOD_SERVERS = ['https://debuginfod.elfutils.org/']

if 'DEBUGINFOD_URLS' in os.environ:
    urls = os.environ['DEBUGINFOD_URLS'].split(' ')
    DEBUGINFOD_SERVERS = urls + DEBUGINFOD_SERVERS

# https://gitlab.com/libcdb/libcdb wasn't updated after 2019,
# but still is a massive database of older libc binaries.
def provider_libcdb(hex_encoded_id, hash_type):
    # Deferred import because it's slow
    import requests
    from six.moves import urllib

    # Build the URL using the requested hash type
    url_base = "https://gitlab.com/libcdb/libcdb/raw/master/hashes/%s/" % hash_type
    url      = urllib.parse.urljoin(url_base, hex_encoded_id)

    data     = b""
    log.debug("Downloading data from LibcDB: %s", url)
    try:
        while not data.startswith(b'\x7fELF'):
            data = wget(url, timeout=20)

            if not data:
                log.warn_once("Could not fetch libc for %s %s from libcdb", hash_type, hex_encoded_id)
                break
            
            # GitLab serves up symlinks with
            if data.startswith(b'..'):
                url = os.path.dirname(url) + '/'
                url = urllib.parse.urljoin(url.encode('utf-8'), data)
    except requests.RequestException as e:
        log.warn_once("Failed to fetch libc for %s %s from libcdb: %s", hash_type, hex_encoded_id, e)
    return data

# https://libc.rip/
def provider_libc_rip(hex_encoded_id, hash_type):
    # Deferred import because it's slow
    import requests

    # Build the request for the hash type
    # https://github.com/niklasb/libc-database/blob/master/searchengine/api.yml
    if hash_type == 'build_id':
        hash_type = 'buildid'
    url    = "https://libc.rip/api/find"
    params = {hash_type: hex_encoded_id}

    data = b""
    try:
        result = requests.post(url, json=params, timeout=20)
        if result.status_code != 200 or len(result.json()) == 0:
            log.warn_once("Could not find libc for %s %s on libc.rip", hash_type, hex_encoded_id)
            log.debug("Error: %s", result.text)
            return None

        libc_match = result.json()
        assert len(libc_match) == 1, 'Invalid libc.rip response.'

        url = libc_match[0]['download_url']
        log.debug("Downloading data from libc.rip: %s", url)
        data = wget(url, timeout=20)

        if not data:
            log.warn_once("Could not fetch libc for %s %s from libc.rip", hash_type, hex_encoded_id)
            return None
    except requests.RequestException as e:
        log.warn_once("Failed to fetch libc for %s %s from libc.rip: %s", hash_type, hex_encoded_id, e)
    return data

PROVIDERS = [provider_libcdb, provider_libc_rip]

def search_by_hash(hex_encoded_id, hash_type='build_id', unstrip=True):
    assert hash_type in HASHES, hash_type

    # Ensure that the libcdb cache directory exists
    cache, cache_valid = _check_elf_cache('libcdb', hex_encoded_id, hash_type)
    if cache_valid:
        return cache

    # Run through all available libc database providers to see if we have a match.
    for provider in PROVIDERS:
        data = provider(hex_encoded_id, hash_type)
        if data and data.startswith(b'\x7FELF'):
            break

    if not data:
        log.warn_once("Could not find libc for %s %s anywhere", hash_type, hex_encoded_id)

    # Save whatever we got to the cache
    write(cache, data or b'')

    # Return ``None`` if we did not get a valid ELF file
    if not data or not data.startswith(b'\x7FELF'):
        return None

    # Try to find debug info for this libc.
    if unstrip:
        unstrip_libc(cache)

    return cache

def _search_debuginfo_by_hash(base_url, hex_encoded_id):
    # Deferred import because it's slow
    import requests
    from six.moves import urllib

    # Check if we tried this buildid before.
    cache, cache_valid = _check_elf_cache('libcdb_dbg', hex_encoded_id, 'build_id')
    if cache_valid:
        return cache

    # Try to find separate debuginfo.
    url  = '/buildid/{}/debuginfo'.format(hex_encoded_id)
    url  = urllib.parse.urljoin(base_url, url)
    data = b""
    log.debug("Downloading data from debuginfod: %s", url)
    try:
        data = wget(url, timeout=20)
    except requests.RequestException as e:
        log.warn_once("Failed to fetch libc debuginfo for build_id %s from %s: %s", hex_encoded_id, base_url, e)
    
    # Save whatever we got to the cache
    write(cache, data or b'')

    # Return ``None`` if we did not get a valid ELF file
    if not data or not data.startswith(b'\x7FELF'):
        log.warn_once("Could not fetch libc debuginfo for build_id %s from %s", hex_encoded_id, base_url)
        return None

    return cache

def _check_elf_cache(cache_type, hex_encoded_id, hash_type):
    """
    Check if there already is an ELF file for this hash in the cache.

    >>> cache, _ = _check_elf_cache('libcdb', '2d1c5e0b85cb06ff47fa6fa088ec22cb6e06074e', 'build_id')
    >>> os.unlink(cache) if os.path.exists(cache)
    >>> filename = search_by_hash('2d1c5e0b85cb06ff47fa6fa088ec22cb6e06074e', 'build_id', unstrip=False)
    >>> hex(ELF(filename).symbols.read)
    '0xe56c0'
    >>> filename == cache
    True
    """
    # Ensure that the cache directory exists
    cache_dir = os.path.join(context.cache_dir, cache_type, hash_type)

    if not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)

    # If we already downloaded the file, and it looks even passingly like
    # a valid ELF file, return it.
    cache = os.path.join(cache_dir, hex_encoded_id)

    if not os.path.exists(cache):
        return cache, False
    
    log.debug("Found existing cached ELF at %r", cache)

    data = read(cache)
    if not data.startswith(b'\x7FELF'):
        log.info_once("Skipping unavailable ELF %s", hex_encoded_id)
        return cache, False

    log.info_once("Using cached data from %r", cache)
    return cache, True

def unstrip_libc(filename):
    """
    Given a path to a libc binary, attempt to download matching debug info
    and add them back to the given binary.

    This modifies the given file.

    Arguments:
        filename(str):
            Path to the libc binary to unstrip.

    Returns:
        :const:`True` if binary was unstripped, :const:`False` otherwise.

    Examples:
        >>> filename = search_by_build_id('2d1c5e0b85cb06ff47fa6fa088ec22cb6e06074e', unstrip=False)
        >>> libc = ELF(filename)
        >>> hex(libc.symbols.read)
        '0xe56c0'
        >>> 'main_arena' in libc.symbols
        False
        >>> unstrip_libc(filename)
        True
        >>> libc = ELF(filename)
        >>> hex(libc.symbols.main_arena)
        '0x1d57a0'
        >>> unstrip_libc(which('python'))
        False
        >>> filename = search_by_build_id('06a8004be6e10c4aeabbe0db74423ace392a2d6b', unstrip=True)
        >>> 'main_arena' in ELF(filename).symbols
        True
    """
    if not which('eu-unstrip'):
        log.warn_once('Couldn\'t find "eu-unstrip" in PATH. Install elfutils first.')
        return False

    libc = ELF(filename, checksec=False)
    if not libc.buildid:
        log.warn_once('Given libc does not have a buildid. Cannot look for debuginfo to unstrip.')
        return False

    log.debug('Trying debuginfod servers: %r', DEBUGINFOD_SERVERS)

    for server_url in DEBUGINFOD_SERVERS:
        libc_dbg = _search_debuginfo_by_hash(server_url, enhex(libc.buildid))
        if libc_dbg:
            break
    else:
        log.warn_once('Couldn\'t find debug info for libc with build_id %s on any debuginfod server.', enhex(libc.buildid))
        return False

    # Add debug info to given libc binary inplace.
    p = process(['eu-unstrip', '-o', filename, filename, libc_dbg])
    output = p.recvall()
    p.close()

    if output:
        log.error('Failed to unstrip libc binary: %r', output)
        return False

    return True

def search_by_build_id(hex_encoded_id, unstrip=True):
    """
    Given a hex-encoded Build ID, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded Build ID (e.g. 'ABCDEF...') of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:
        >>> filename = search_by_build_id('fe136e485814fee2268cf19e5c124ed0f73f4400')
        >>> hex(ELF(filename).symbols.read)
        '0xda260'
        >>> None == search_by_build_id('XX')
        True
        >>> filename = search_by_build_id('a5a3c3f65fd94f4c7f323a175707c3a79cbbd614')
        >>> hex(ELF(filename).symbols.read)
        '0xeef40'
    """
    return search_by_hash(hex_encoded_id, 'build_id', unstrip)

def search_by_md5(hex_encoded_id, unstrip=True):
    """
    Given a hex-encoded md5sum, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded md5sum (e.g. 'ABCDEF...') of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:
        >>> filename = search_by_md5('7a71dafb87606f360043dcd638e411bd')
        >>> hex(ELF(filename).symbols.read)
        '0xda260'
        >>> None == search_by_md5('XX')
        True
        >>> filename = search_by_md5('74f2d3062180572fc8bcd964b587eeae')
        >>> hex(ELF(filename).symbols.read)
        '0xeef40'
    """
    return search_by_hash(hex_encoded_id, 'md5', unstrip)

def search_by_sha1(hex_encoded_id, unstrip=True):
    """
    Given a hex-encoded sha1, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded sha1sum (e.g. 'ABCDEF...') of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:
        >>> filename = search_by_sha1('34471e355a5e71400b9d65e78d2cd6ce7fc49de5')
        >>> hex(ELF(filename).symbols.read)
        '0xda260'
        >>> None == search_by_sha1('XX')
        True
        >>> filename = search_by_sha1('0041d2f397bc2498f62aeb4134d522c5b2635e87')
        >>> hex(ELF(filename).symbols.read)
        '0xeef40'
    """
    return search_by_hash(hex_encoded_id, 'sha1', unstrip)


def search_by_sha256(hex_encoded_id, unstrip=True):
    """
    Given a hex-encoded sha256, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded sha256sum (e.g. 'ABCDEF...') of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:
        >>> filename = search_by_sha256('5e877a8272da934812d2d1f9ee94f73c77c790cbc5d8251f5322389fc9667f21')
        >>> hex(ELF(filename).symbols.read)
        '0xda260'
        >>> None == search_by_sha256('XX')
        True
        >>> filename = search_by_sha256('5d78fc60054df18df20480c71f3379218790751090f452baffb62ac6b2aff7ee')
        >>> hex(ELF(filename).symbols.read)
        '0xeef40'
    """
    return search_by_hash(hex_encoded_id, 'sha256', unstrip)




def get_build_id_offsets():
    """
    Returns a list of file offsets where the Build ID should reside within
    an ELF file of the currently selected architecture.
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
        'i386': [0x174, 0x1b4, 0x1d4],
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
        'amd64': [0x270, 0x174, 0x2e0, 0x370],
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


__all__ = ['get_build_id_offsets', 'search_by_build_id', 'search_by_sha1', 'search_by_sha256', 'search_by_md5', 'unstrip_libc']
