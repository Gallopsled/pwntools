"""
Fetch a LIBC binary based on some heuristics.
"""
from collections.abc import Generator
import os
import re
import time
import struct

from pwnlib.context import context
from pwnlib.elf import ELF
from pwnlib.filesystem.path import Path
from pwnlib.internal.typing import BytesPath
from pwnlib.log import getLogger
from pwnlib.tubes.process import process
from pwnlib.util.fiddling import enhex, unhex
from pwnlib.util.hashes import sha1filehex, sha256filehex, md5filehex
from pwnlib.util.misc import read
from pwnlib.util.misc import which
from pwnlib.util.misc import write
from pwnlib.util.web import wget

log = getLogger(__name__)


def _turbofast_extract_build_id(path):
    """
    Elf_External_Note:

    0x00 +--------+
         | namesz | <- Size of entry's owner string
    0x04 +--------+
         | descsz | <- Size of the note descriptor
    0x08 +--------+
         |  type  | <- Interpretation of the descriptor
    0x0c +--------+
         |  name  | <- Start of the name+desc data
     ... +--------
         |  desc  |
     ... +--------+
    """
    data = read(path, 0x1000)
    # search NT_GNU_BUILD_ID and b"GNU\x00" (type+name)
    idx = data.find(unhex("03000000474e5500"))
    if idx == -1:
        return enhex(ELF(path, checksec=False).buildid or b'')
    descsz, = struct.unpack("<L", data[idx-4: idx])
    return enhex(data[idx+8: idx+8+descsz])


TYPES = {
    'libs_id': None,
    'build_id': _turbofast_extract_build_id,
    'sha1': sha1filehex,
    'sha256': sha256filehex,
    'md5': md5filehex,
}

# mapping for search result (same as libc.rip)
MAP_TYPES = {
    'libs_id': 'id',
    'build_id': 'buildid'
}

DEBUGINFOD_SERVERS = [
    'https://debuginfod.ubuntu.com/',
    'https://debuginfod.debian.net/',
    'https://debuginfod.elfutils.org/',
]

if 'DEBUGINFOD_URLS' in os.environ:
    urls = os.environ['DEBUGINFOD_URLS'].split(' ')
    DEBUGINFOD_SERVERS = urls + DEBUGINFOD_SERVERS

# Allow to override url with a caching proxy in CI
LIBC_RIP_URL = os.environ.get("PWN_LIBCRIP_URL", "https://libc.rip").rstrip("/")
GITLAB_LIBCDB_URL = os.environ.get("PWN_GITLAB_LIBCDB_URL", "https://gitlab.com").rstrip("/")

# Retry failed lookups after some time
NEGATIVE_CACHE_EXPIRY = 60 * 60 * 24 * 7 # 1 week

# https://gitlab.com/libcdb/libcdb wasn't updated after 2019,
# but still is a massive database of older libc binaries.
def provider_libcdb(hex_encoded_id, search_type):
    if search_type == 'libs_id':
        return None

    # Deferred import because it's slow
    import requests
    import urllib.parse

    # Build the URL using the requested hash type
    url_base = f"{GITLAB_LIBCDB_URL}/libcdb/libcdb/raw/master/hashes/{search_type}/"
    url      = urllib.parse.urljoin(url_base, hex_encoded_id)

    data     = b""
    log.debug("Downloading data from LibcDB: %s", url)
    try:
        while not data.startswith(b'\x7fELF'):
            data = wget(url, timeout=20)

            if not data:
                log.warn_once("Could not fetch libc for %s %s from libcdb", search_type, hex_encoded_id)
                break
            
            # GitLab serves up symlinks with
            if data.startswith(b'..'):
                url = os.path.dirname(url) + '/'
                url = urllib.parse.urljoin(url.encode('utf-8'), data)
    except requests.RequestException as e:
        log.warn_once("Failed to fetch libc for %s %s from libcdb: %s", search_type, hex_encoded_id, e)
    return data

def query_libc_rip(params):
    # Deferred import because it's slow
    import requests

    url = f"{LIBC_RIP_URL}/api/find"
    try:
        log.debug("Querying libc.rip at %s with parameters: %s", url, params)
        result = requests.post(url, json=params, timeout=20)
        result.raise_for_status()
        if result.status_code != 200:
            log.debug("Error: %s", result.text)
            return None
        return result.json()
    except requests.RequestException as e:
        log.warn_once("Failed to fetch libc info from libc.rip: %s", e)
        return None

# https://libc.rip/
def provider_libc_rip(search_target, search_type):
    # Build the request for the hash type
    # https://github.com/niklasb/libc-database/blob/master/searchengine/api.yml
    if search_type in MAP_TYPES.keys():
        search_type = MAP_TYPES[search_type]

    params = {search_type: search_target}

    libc_match = query_libc_rip(params)
    if not libc_match:
        log.warn_once("Could not find libc info for %s %s on libc.rip", search_type, search_target)
        return None

    if len(libc_match) > 1:
        log.debug("Received multiple matches. Choosing the first match and discarding the others.")
        log.debug("%r", libc_match)

    url = libc_match[0]['download_url']
    log.debug("Downloading data from libc.rip: %s", url)
    url = url.replace("https://libc.rip", LIBC_RIP_URL)
    data = wget(url, timeout=20)

    if not data:
        log.warn_once("Could not fetch libc binary for %s %s from libc.rip", search_type, search_target)
        return None
    return data

# Check if the local system libc matches the requested hash.
def provider_local_system(hex_encoded_id, search_type):
    if search_type == 'libs_id':
        return None
    shell_path = os.environ.get('SHELL', None) or '/bin/sh'
    if not os.path.exists(shell_path):
        log.debug('Shell path %r does not exist. Skipping local system libc matching.', shell_path)
        return None
    local_libc = ELF(shell_path, checksec=False).libc
    if not local_libc:
        log.debug('Cannot lookup libc from shell %r. Skipping local system libc matching.', shell_path)
        return None
    if TYPES[search_type](local_libc.path) == hex_encoded_id:
        return local_libc.data
    return None

# Offline search https://github.com/niklasb/libc-database for hash type
def provider_local_database(search_target, search_type):
    if not context.local_libcdb:
        return None

    localdb = Path(context.local_libcdb)
    if not localdb.is_dir():
        return None

    # Handle the specific search type 'libs_id'
    if search_type == 'libs_id':
        libc_list = list(localdb.rglob("%s.so" % search_target))
        if len(libc_list) == 0:
            return None
        return read(libc_list[0])

    log.debug("Searching local libc database, %s: %s", search_type, search_target)
    for libc_path in localdb.rglob("*.so"):
        if search_target == TYPES[search_type](libc_path):
            return read(libc_path)

    return None

def query_local_database(params):
    if not context.local_libcdb or not params.get("symbols"):
        return None

    localdb = Path(context.local_libcdb)
    if not localdb.is_dir():
        return None

    res = []
    query_syms = params["symbols"]

    # Loop through each '.symbols' file in the local database
    # Make sure `Path.rglod` order stable
    for symbol_file in sorted(localdb.rglob("*.symbols"), key=lambda x: x.as_posix()):
        libc_syms = _parse_libc_symbol(symbol_file)

        matched = 0
        for name, addr in query_syms.items():
            if isinstance(addr, str):
                addr = int(addr, 16) 

            # Compare last 12 bits
            if libc_syms.get(name) and (libc_syms.get(name) & 0xfff) == (addr & 0xfff):
                matched += 1
            else:
                # aborting this loop once there was a mismatch.
                break

        # Check if all symbols have been matched
        if matched == len(query_syms):
            libs_id = symbol_file.stem
            libc_path = symbol_file.parent / ("%s.so" % libs_id)
            libs_url = read(symbol_file.parent / ("%s.url" % libs_id)).decode().strip()
            res.append(_pack_libs_info(libc_path, libs_id, libs_url, libc_syms))

    return res

PROVIDERS = {
    "offline": [provider_local_system, provider_local_database],
    "online": [provider_libcdb, provider_libc_rip]
}

def search_by_hash(search_target, search_type='build_id', unstrip=True, offline_only=False):
    """search_by_hash(str, str, bool, bool) -> str
    Arguments:
        search_target(str):
            Use for searching the libc. This could be a hex encoded ID (`hex_encoded_id`) or a library
            name (`libs_id`). Depending on `search_type`, this can represent different types of encoded 
            values or names.
        search_type(str):
            The type of the search to be performed, it should be one of the keys in the `TYPES` dictionary.
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.
        offline_only(bool):
            If True, restricts the search to offline providers only (local database). If False, it will also
            search online providers. Default is False.

    Returns:
        The path to the cached directory containing the downloaded libraries.
    """
    assert search_type in TYPES, search_type

    # Ensure that the libcdb cache directory exists
    cache, cache_valid = _check_elf_cache('libcdb', search_target, search_type)
    if cache_valid:
        if unstrip:
            unstrip_libc(cache)
        return cache
    
    # We searched for this buildid before, but didn't find anything.
    if cache is None:
        return None

    providers = PROVIDERS["offline"]
    if not offline_only:
        providers += PROVIDERS["online"]

    # Run through all available libc database providers to see if we have a match.
    for provider in providers:
        data = provider(search_target, search_type)
        if data and data.startswith(b'\x7FELF'):
            break

    if not data:
        log.warn_once("Could not find libc for %s %s anywhere", search_type, search_target)

    # Save whatever we got to the cache
    write(cache, data or b'')

    # Return ``None`` if we did not get a valid ELF file
    if not data or not data.startswith(b'\x7FELF'):
        return None

    # Try to find debug info for this libc.
    if unstrip:
        unstrip_libc(cache)

    return cache

def _check_elf_cache(cache_type, search_target, search_type):
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
    cache_dir = os.path.join(context.cache_dir, cache_type, search_type)

    if not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)

    # If we already downloaded the file, and it looks even passingly like
    # a valid ELF file, return it.
    cache = os.path.join(cache_dir, search_target)

    if not os.path.exists(cache):
        return cache, False
    
    log.debug("Found existing cached ELF at %r", cache)

    data = read(cache)
    if not data.startswith(b'\x7FELF'):
        # Retry failed lookups after some time
        if time.time() > os.path.getmtime(cache) + NEGATIVE_CACHE_EXPIRY:
            return cache, False
        log.info_once("Skipping invalid cached ELF %s", search_target)
        return None, False

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

        >>> filename = search_by_build_id('69389d485a9793dbe873f0ea2c93e02efaa9aa3d', unstrip=False)
        >>> libc = ELF(filename)
        >>> 'main_arena' in libc.symbols
        False
        >>> unstrip_libc(filename) # doctest: +SKIP
        True
        >>> libc = ELF(filename)
        >>> hex(libc.symbols.main_arena) # doctest: +SKIP
        '0x219c80'
        >>> unstrip_libc(pwnlib.data.elf.get('test-x86'))
        False
        >>> filename = search_by_build_id('d1704d25fbbb72fa95d517b883131828c0883fe9', unstrip=True)
        >>> 'main_arena' in ELF(filename).symbols # doctest: +SKIP
        True
    """
    if not which('eu-unstrip'):
        log.warn_once('Couldn\'t find "eu-unstrip" in PATH. Install elfutils first.')
        return False

    libc = ELF(filename, checksec=False)
    if not libc.buildid:
        log.warn_once('Given libc does not have a buildid. Cannot look for debuginfo to unstrip.')
        return False

    if libc.debuginfo:
        log.debug('Given libc already contains debug information. Skipping unstrip.')
        return True

    log.debug('Trying debuginfod servers: %r', DEBUGINFOD_SERVERS)

    # Deferred import because it's slow
    import requests
    import urllib.parse

    hex_encoded_id = enhex(libc.buildid)

    # Check if we tried this buildid before.
    cache, cache_valid = _check_elf_cache('libcdb_dbg', hex_encoded_id, 'build_id')
    if not cache_valid:
        # Cached negative result so we don't look for missing debug info everytime.
        if cache is None:
            return False
        else:
            for server_url in DEBUGINFOD_SERVERS:
                # Try to find separate debuginfo.
                url  = f'/buildid/{hex_encoded_id}/debuginfo'
                url  = urllib.parse.urljoin(server_url, url)
                data = b""
                log.debug("Downloading data from debuginfod: %s", url)
                try:
                    data = wget(url, timeout=20)

                    # Try next server if we didn't get a valid ELF file
                    if not data or not data.startswith(b'\x7FELF'):
                        log.warn_once("Could not fetch libc debuginfo for build_id %s from %s", hex_encoded_id, server_url)
                        continue
                    break
                except requests.RequestException as e:
                    log.warn_once("Failed to fetch libc debuginfo for build_id %s from %s: %s", hex_encoded_id, server_url, e)
            else:
                write(cache, data or b'')
                log.warn_once('Couldn\'t find debug info for libc with build_id %s on any debuginfod server.', enhex(libc.buildid))
                return False
            
            # Save whatever we got to the cache
            write(cache, data or b'')

    # Add debug info to given libc binary inplace.
    p = process(['eu-unstrip', '-o', filename, filename, cache])
    output = p.recvall()
    p.close()

    if output:
        log.error('Failed to unstrip libc binary: %r', output)
        return False

    return True

def _extract_tarfile(cache_dir, data_filename, tarball):
    from io import BytesIO
    import tarfile
    # Handle zstandard compression, since tarfile only supports gz, bz2, and xz.
    if data_filename.endswith('.zst') or data_filename.endswith('.zstd'):
        import zstandard
        dctx = zstandard.ZstdDecompressor()
        decompressed_tar = BytesIO()
        dctx.copy_stream(tarball, decompressed_tar)
        decompressed_tar.seek(0)
        tarball.close()
        tarball = decompressed_tar

    with tarfile.open(fileobj=tarball) as tar_file:
        # Find the library folder in the archive (e.g. /lib/x86_64-linux-gnu/)
        lib_dir = None
        libc_name = None
        for member in tar_file.getmembers():
            if not member.isfile():
                continue
            libc_name = os.path.basename(member.name)
            if libc_name == 'libc.so.6' or (libc_name.startswith('libc') and libc_name.endswith('.so')):
                lib_dir = os.path.dirname(member.name)
                break
        else:
            log.error('Couldn\'t find library folder containing the libc in the archive.')

        # Extract everything in the library folder
        for member in tar_file.getmembers():
            if os.path.dirname(member.name) != lib_dir:
                continue
            if not member.isfile() and not member.issym():
                continue
            # Extract while keeping file permissions
            tar_file.extract(member, cache_dir)

        # Move the files up to the cache root
        target_dir = os.path.join(cache_dir, lib_dir)
        for file in os.listdir(target_dir):
            os.rename(os.path.join(target_dir, file), os.path.join(cache_dir, file))
        os.removedirs(target_dir)

        return os.path.join(cache_dir, libc_name)

def _extract_debfile(cache_dir, package_filename, package):
    # Extract data.tar in the .deb archive.
    import unix_ar
    from io import BytesIO
    ar_file = unix_ar.open(BytesIO(package))
    try:
        data_filename = next(filter(lambda f: f.name.startswith(b'data.tar'), ar_file.infolist())).name.decode()
        tarball = ar_file.open(data_filename)
        return _extract_tarfile(cache_dir, data_filename, tarball)
    finally:
        ar_file.close()

def _extract_pkgfile(cache_dir, package_filename, package):
    from io import BytesIO
    return _extract_tarfile(cache_dir, package_filename, BytesIO(package))

def _collect_extra_mirrors(extra_mirrors: str | list[str] | None) -> list[str]:
    """Normalize the user-supplied ``extra_mirrors`` argument and merge it with
    the comma- or whitespace-separated ``PWNLIB_EXTRA_LIBC_MIRRORS`` environment
    variable.

    Returns a list of ``str`` URL prefixes (each with no trailing slash). Empty
    entries are dropped.

    Examples:

        >>> from pwnlib.libcdb import _collect_extra_mirrors
        >>> _collect_extra_mirrors(None)
        []
        >>> _collect_extra_mirrors('https://example.com/m/')
        ['https://example.com/m']
        >>> _collect_extra_mirrors(['https://a/', 'https://b'])
        ['https://a', 'https://b']
    """
    mirrors = []
    if extra_mirrors:
        if isinstance(extra_mirrors, str):
            mirrors.append(extra_mirrors)
        else:
            mirrors.extend(extra_mirrors)
    env_mirrors = os.environ.get('PWNLIB_EXTRA_LIBC_MIRRORS')
    if env_mirrors:
        # Allow either commas or whitespace as separators so URL schemes
        # (https:) don't accidentally get split mid-URL.
        mirrors.extend(re.split(r'[,\s]+', env_mirrors))
    return [m.rstrip('/') for m in mirrors if m]


def _mirror_variants(url: str, extra_mirrors: list[str] | None) -> Generator[str, None, None]:
    """Yield ``url`` followed by mirror-swapped variants for each entry in
    ``extra_mirrors``.

    A mirror is applied by replacing everything before ``/pool/`` in the
    candidate URL with the mirror prefix. URLs without a ``/pool/`` segment are
    still yielded once but no mirror substitution is performed (for example,
    Launchpad's ``+files`` archive URLs do not follow the Debian pool layout).

    Examples:

        >>> from pwnlib.libcdb import _mirror_variants
        >>> list(_mirror_variants('http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.36_amd64.deb', None))
        ['http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.36_amd64.deb']
        >>> list(_mirror_variants('http://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36_amd64.deb',
        ...                      ['https://debian.sipwise.com/debian-security']))
        ['http://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36_amd64.deb', 'https://debian.sipwise.com/debian-security/pool/main/g/glibc/libc6_2.36_amd64.deb']
        >>> list(_mirror_variants('https://launchpad.net/ubuntu/+archive/primary/+files/libc6_2.36_amd64.deb',
        ...                      ['https://anywhere.example']))
        ['https://launchpad.net/ubuntu/+archive/primary/+files/libc6_2.36_amd64.deb']
    """
    yield url
    if not extra_mirrors:
        return
    match = re.search(r'/(pool/.+)$', url)
    if not match:
        return
    suffix = match.group(1)
    seen = {url}
    for prefix in extra_mirrors:
        candidate = '%s/%s' % (prefix, suffix)
        if candidate not in seen:
            seen.add(candidate)
            yield candidate


def _find_libc_package_lib_url(libc: ELF, extra_mirrors: list[str] | None = None) -> Generator[str, None, None]:
    # Check https://libc.rip for the libc package
    libc_match = query_libc_rip({'buildid': enhex(libc.buildid)})
    if libc_match is not None:
        for match in libc_match:
            # Allow to override url with a caching proxy in CI
            ubuntu_archive_url = os.environ.get('PWN_UBUNTU_ARCHIVE_URL', 'http://archive.ubuntu.com').rstrip('/')
            url = match['libs_url'].replace('http://archive.ubuntu.com', ubuntu_archive_url)
            for variant in _mirror_variants(url, extra_mirrors):
                yield variant

    # Check launchpad.net if it's an Ubuntu libc
    # GNU C Library (Ubuntu GLIBC 2.36-0ubuntu4)
    version = re.search(br'GNU C Library \(Ubuntu E?GLIBC ([^\)]+)\)', libc.data)
    if version is not None:
        libc_version = version.group(1).decode()
        yield f'https://launchpad.net/ubuntu/+archive/primary/+files/libc6_{libc_version}_{libc.arch}.deb'

def download_libraries(libc_path: BytesPath, unstrip: bool = True, extra_mirrors: str | list[str] | None = None) -> str | None:
    """download_libraries(str, bool, extra_mirrors=None) -> str
    Download the matching libraries for the given libc binary and cache
    them in a local directory. The libraries are looked up using `libc.rip <https://libc.rip>`_
    and fetched from the official package repositories if available.

    This commonly includes the ``ld-linux-x86-64.so.2`` and ``libpthread.so.0`` binaries
    which can be used to execute the program locally when the given libc is
    incompatible with the local dynamic loader.

    Note: Only .deb and .pkg.tar.* packages are currently supported (Debian/Ubuntu, Arch).

    Arguments:
        libc_path(str):
            The path the libc binary.
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.
        extra_mirrors(str or list of str):
            Optional additional Debian-style apt mirror prefix(es) to try
            after the libc.rip URL. Useful when the official mirror has
            dropped older vulnerable libc versions: each candidate URL is
            re-tried with everything before ``/pool/`` swapped for the
            mirror prefix. Mirrors can also be supplied via the
            ``PWNLIB_EXTRA_LIBC_MIRRORS`` environment variable as a
            comma- or whitespace-separated list. Example: pass
            ``"https://debian.sipwise.com/debian-security"`` to find
            ``GLIBC 2.36-9+deb12u6`` after the official Debian mirrors
            removed it.

    Returns:
        The path to the cached directory containing the downloaded libraries.

    Example:

        >>> libc_path = ELF(which('ls'), checksec=False).libc.path
        >>> lib_path = download_libraries(libc_path)
        >>> lib_path is not None
        True
        >>> os.path.exists(os.path.join(lib_path, 'libc.so.6'))
        True
        >>> os.path.exists(os.path.join(lib_path, 'ld-linux-x86-64.so.2'))
        True

        Fetch libraries from a different mirror for a vulnerable libc version
        ``libc6_2.36-9+deb12u6_amd64`` that was removed from the official Debian mirrors:
        
        >>> libc_path = libcdb.search_by_build_id("ee3145ecaaff87a133daea77fbc3eecd458fa0d1") # doctest: +SKIP
        >>> libcdb.download_libraries(libc_path, extra_mirrors="https://debian.sipwise.com/debian-security") # doctest: +ELLIPSIS +SKIP
        '.../libcdb_libs/ee3145ecaaff87a133daea77fbc3eecd458fa0d1'
    """

    libc = ELF(libc_path, checksec=False)
    if not libc.buildid:
        log.warn_once('Given libc does not have a buildid.')
        return None

    # Handle caching and don't redownload if it already exists.
    cache_dir = os.path.join(context.cache_dir, 'libcdb_libs')
    if not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)

    cache_dir = os.path.join(cache_dir, enhex(libc.buildid))
    if os.path.exists(cache_dir):
        return cache_dir

    extra_mirrors = _collect_extra_mirrors(extra_mirrors)

    for package_url in _find_libc_package_lib_url(libc, extra_mirrors=extra_mirrors):
        extension_handlers = {
            '.deb': _extract_debfile,
            '.pkg.tar.xz': _extract_pkgfile,
            '.pkg.tar.zst': _extract_pkgfile,
        }

        package_filename = os.path.basename(package_url)
        for extension, handler in extension_handlers.items():
            if package_filename.endswith(extension):
                break
        else:
            log.failure('Cannot handle %s (%s)', package_filename, package_url)
            continue

        # Download the package
        package = wget(package_url, timeout=20)
        if not package:
            continue

        # Create target cache directory to extract files into
        if not os.path.isdir(cache_dir):
            os.makedirs(cache_dir)

        try:
            # Extract the archive
            libc_path = handler(cache_dir, package_filename, package)
        except Exception as e:
            os.removedirs(cache_dir)
            log.failure('Failed to extract %s: %s', package_filename, e)
            continue
        # Unstrip the libc binary
        try:
            if unstrip:
                unstrip_libc(libc_path)
        except Exception:
            pass

        return cache_dir

    log.warn_once('Failed to find matching libraries for provided libc.')
    return None

def _handle_multiple_matching_libcs(matching_libcs):
    from pwnlib.term import text
    from pwnlib.ui import options
    log.info('Multiple matching libc libraries for requested symbols:')
    for idx, libc in enumerate(matching_libcs):
        log.info('%d. %s', idx+1, text.red(libc['id']))
        log.indented('\t%-20s %s', text.green('BuildID:'), libc['buildid'])
        log.indented('\t%-20s %s', text.green('MD5:'), libc['md5'])
        log.indented('\t%-20s %s', text.green('SHA1:'), libc['sha1'])
        log.indented('\t%-20s %s', text.green('SHA256:'), libc['sha256'])
        log.indented('\t%s', text.green('Symbols:'))
        for symbol, address in libc['symbols'].items():
            log.indented('\t%25s = %s', symbol, address)

    selected_index = options("Select the libc version to use:", [libc['id'] for libc in matching_libcs])
    return matching_libcs[selected_index]

def search_by_symbol_offsets(symbols, select_index=None, unstrip=True, offline_only=False, search_type='build_id', return_as_list=False, return_raw=False):
    """
    Lookup possible matching libc versions based on leaked function addresses.

    The leaked function addresses have to be provided as a dict mapping the
    function name to the leaked value. Only the lower 3 nibbles are relevant
    for the lookup.

    If there are multiple matches you are presented with a list to select one
    interactively, unless the ``select_index`` or ``return_as_list`` arguments
    are used.

    Arguments:
        symbols(dict):
            Dictionary mapping symbol names to their addresses.
        select_index(int):
            The libc to select if there are multiple matches (starting at 1).
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.
        offline_only(bool):
            When pass `offline_only=True`, restricts search mode to offline sources only,
            disable online lookup. Defaults to `False`, and enable both offline and online providers.
        search_type(str):
            An option to select searched hash.
        return_as_list(bool):
            Return a list of build ids of all matching libc versions
            instead of a path to a downloaded file.
        return_raw(bool):
            Return raw list of matched libc.

    Returns:
        Path to the downloaded library on disk, or :const:`None`.
        If the ``return_as_list`` argument is :const:`True`, a list of build ids
        is returned instead.

    Examples:

        >>> filename = search_by_symbol_offsets({'puts': 0x420, 'printf': 0xc90}, select_index=1)
        >>> libc = ELF(filename)
        >>> libc.sym.system == 0x52290
        True
        >>> matched_libcs = search_by_symbol_offsets({'__libc_start_main_ret': '7f89ad926550'}, return_as_list=True)
        >>> len(matched_libcs) > 1
        True
        >>> for buildid in matched_libcs: # doctest: +SKIP
        ...     libc = ELF(search_by_build_id(buildid)) # doctest: +SKIP
    """
    assert search_type in TYPES, search_type

    for symbol, address in symbols.items():
        if isinstance(address, int):
            symbols[symbol] = hex(address)

    params = {'symbols': symbols}
    log.debug('Request: %s', params)

    offline_matching = query_local_database(params)
    online_matching = query_libc_rip(params) if not offline_only else None

    if offline_matching is None:
        offline_matching = []
    if online_matching is None:
        online_matching = []

    # Aggregate and deduplicate matches from both sources
    matching_libcs = {}
    for libc in offline_matching + online_matching:
        if libc['id'] not in matching_libcs:
            matching_libcs[libc['id']] = libc

    log.debug('Offline search result: %s', offline_matching)
    if not offline_only:
        log.debug('Online search result: %s', online_matching)

    # Check if no matches are found
    if len(matching_libcs) == 0:
        log.warn_once("No matching libc for symbols %r", symbols)
        return None

    matching_list = list(matching_libcs.values())

    if return_as_list:
        return [libc['buildid'] for libc in matching_list]

    if return_raw:
        return matching_list

    mapped_type = MAP_TYPES.get(search_type, search_type)

    # If there's only one match, return it directly
    if len(matching_list) == 1:
        return search_by_hash(matching_list[0][mapped_type], search_type=search_type, unstrip=unstrip, offline_only=offline_only)

    # If a specific index is provided, validate it and return the selected libc
    if select_index is not None:
        if select_index > 0 and select_index <= len(matching_list):
            return search_by_hash(matching_list[select_index - 1][mapped_type], search_type=search_type, unstrip=unstrip, offline_only=offline_only)
        else:
            log.error('Invalid selected libc index. %d is not in the range of 1-%d.', select_index, len(matching_list))
            return None

    # Handle multiple matches interactively if no index is specified
    selected_libc = _handle_multiple_matching_libcs(matching_list)
    return search_by_hash(selected_libc[mapped_type], search_type=search_type, unstrip=unstrip, offline_only=offline_only)

def search_by_libs_id(libs_id, unstrip=True, offline_only=False):
    """
    Given a Libs ID, attempt to download a matching libc from libcdb.

    Arguments:
        libs_id(str):
            Libs ID (e.g. ``'libc6_...'``) of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.
        offline_only(bool):
            When pass ``offline_only=True``, restricts search mode to offline sources only,
            disable online lookup. Defaults to :const:`False`, and enable both offline and online providers.

    Returns:
        Path to the downloaded library on disk, or :const:`None`.

    Examples:

        >>> None == search_by_libs_id('XX')
        True
        >>> filename = search_by_libs_id('libc6_2.31-3_amd64')
        >>> hex(ELF(filename).symbols.read)
        '0xeef40'
    """
    return search_by_hash(libs_id, 'libs_id', unstrip, offline_only)

def search_by_build_id(hex_encoded_id, unstrip=True, offline_only=False):
    """
    Given a hex-encoded Build ID, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded Build ID (e.g. 'ABCDEF...') of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.
        offline_only(bool):
            When pass `offline_only=True`, restricts search mode to offline sources only,
            disable online lookup. Defaults to `False`, and enable both offline and online providers.

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
    return search_by_hash(hex_encoded_id, 'build_id', unstrip, offline_only)

def search_by_md5(hex_encoded_id, unstrip=True, offline_only=False):
    """
    Given a hex-encoded md5sum, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded md5sum (e.g. 'ABCDEF...') of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.
        offline_only(bool):
            When pass `offline_only=True`, restricts search mode to offline sources only,
            disable online lookup. Defaults to `False`, and enable both offline and online providers.

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
    return search_by_hash(hex_encoded_id, 'md5', unstrip, offline_only)

def search_by_sha1(hex_encoded_id, unstrip=True, offline_only=False):
    """
    Given a hex-encoded sha1, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded sha1sum (e.g. 'ABCDEF...') of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.
        offline_only(bool):
            When pass `offline_only=True`, restricts search mode to offline sources only,
            disable online lookup. Defaults to `False`, and enable both offline and online providers.

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
    return search_by_hash(hex_encoded_id, 'sha1', unstrip, offline_only)

def search_by_sha256(hex_encoded_id, unstrip=True, offline_only=False):
    """
    Given a hex-encoded sha256, attempt to download a matching libc from libcdb.

    Arguments:
        hex_encoded_id(str):
            Hex-encoded sha256sum (e.g. 'ABCDEF...') of the library
        unstrip(bool):
            Try to fetch debug info for the libc and apply it to the downloaded file.
        offline_only(bool):
            When pass `offline_only=True`, restricts search mode to offline sources only,
            disable online lookup. Defaults to `False`, and enable both offline and online providers.

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
    return search_by_hash(hex_encoded_id, 'sha256', unstrip, offline_only)

def _parse_libc_symbol(path):
    """
    Parse symbols file to `dict`, the format is same as https://github.com/niklasb/libc-database/
    """

    syms = {}

    with open(path, "r") as fd:
        for x in fd:
            name, addr = x.split(" ")
            syms[name] = int(addr, 16)

    return syms

def _pack_libs_info(path, libs_id, libs_url, syms):
    """ 
    The JSON format is the same as libc.rip, and the "download_url" field is by default an empty string, 
    as it's not required in offline mode.
    """

    info = {}

    info["id"] = libs_id
    info["libs_url"] = libs_url
    info["download_url"] = ""

    for search_type, hash_func in TYPES.items():
        # pass libs_id
        if search_type == 'libs_id':
            continue

        # replace search_type
        if search_type in MAP_TYPES.keys():
            search_type = MAP_TYPES[search_type]

        info[search_type] = hash_func(path)

    default_symbol_list = [
        "__libc_start_main_ret", "dup2", "printf", "puts", "read", "system", "str_bin_sh"
    ]

    info["symbols"] = {}
    for name in default_symbol_list:
        info["symbols"][name] = hex(syms[name])

    return info


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


__all__ = ['get_build_id_offsets', 'search_by_build_id', 'search_by_sha1', 'search_by_sha256', 'search_by_md5', 'search_by_libs_id', 'unstrip_libc', 'search_by_symbol_offsets', 'download_libraries']
