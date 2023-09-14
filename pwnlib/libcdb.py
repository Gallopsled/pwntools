"""
Fetch a LIBC binary based on some heuristics.
"""
from __future__ import absolute_import
from __future__ import division

import os
import six
import tempfile

from pwnlib.context import context
from pwnlib.elf import ELF
from pwnlib.log import getLogger
from pwnlib.tubes.process import process
from pwnlib.util.fiddling import enhex
from pwnlib.util.misc import read
from pwnlib.util.misc import which
from pwnlib.util.misc import write
from pwnlib.util.web import wget

log = getLogger(__name__)

HASHES = ['build_id', 'sha1', 'sha256', 'md5']
DEBUGINFOD_SERVERS = [
    'https://debuginfod.elfutils.org/',
]

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

def query_libc_rip(params):
    # Deferred import because it's slow
    import requests

    url = "https://libc.rip/api/find"
    try:
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
def provider_libc_rip(hex_encoded_id, hash_type):
    # Build the request for the hash type
    # https://github.com/niklasb/libc-database/blob/master/searchengine/api.yml
    if hash_type == 'build_id':
        hash_type = 'buildid'
    params = {hash_type: hex_encoded_id}

    libc_match = query_libc_rip(params)
    if not libc_match:
        log.warn_once("Could not find libc info for %s %s on libc.rip", hash_type, hex_encoded_id)
        return None

    if len(libc_match) > 1:
        log.debug("Received multiple matches. Choosing the first match and discarding the others.")
        log.debug("%r", libc_match)

    url = libc_match[0]['download_url']
    log.debug("Downloading data from libc.rip: %s", url)
    data = wget(url, timeout=20)

    if not data:
        log.warn_once("Could not fetch libc binary for %s %s from libc.rip", hash_type, hex_encoded_id)
        return None
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
        >>> filename = search_by_build_id('69389d485a9793dbe873f0ea2c93e02efaa9aa3d', unstrip=False)
        >>> libc = ELF(filename)
        >>> 'main_arena' in libc.symbols
        False
        >>> unstrip_libc(filename)
        True
        >>> libc = ELF(filename)
        >>> hex(libc.symbols.main_arena)
        '0x219c80'
        >>> unstrip_libc(pwnlib.data.elf.get('test-x86'))
        False
        >>> filename = search_by_build_id('d1704d25fbbb72fa95d517b883131828c0883fe9', unstrip=True)
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

def _extract_tarfile(cache_dir, data_filename, tarball):
    from six import BytesIO
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

    if six.PY2 and data_filename.endswith('.xz'):
        # Python 2's tarfile doesn't support xz, so we need to decompress it first.
        # Shell out to xz, since the Python 2 pylzma module is broken.
        # (https://github.com/fancycode/pylzma/issues/67)
        if not which('xz'):
            log.error('Couldn\'t find "xz" in PATH. Please install xz first.')
        import subprocess
        try:
            uncompressed_tarball = subprocess.check_output(['xz', '--decompress', '--stdout', tarball.name])
            tarball = BytesIO(uncompressed_tarball)
        except subprocess.CalledProcessError:
            log.error('Failed to decompress xz archive.')

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
    if six.PY2:
        if not which('ar'):
            log.error('Missing command line tool "ar" to extract .deb archive. Please install "ar" first.')

        import atexit
        import shutil
        import subprocess

        # Use mkdtemp instead of TemporaryDirectory because the latter is not available in Python 2.
        tempdir = tempfile.mkdtemp(prefix=".pwntools-tmp")
        atexit.register(shutil.rmtree, tempdir)
        with tempfile.NamedTemporaryFile(mode='wb', dir=tempdir) as debfile:
            debfile.write(package)
            debfile.flush()
            try:
                files_in_deb = subprocess.check_output(['ar', 't', debfile.name]).split(b'\n')
            except subprocess.CalledProcessError:
                log.error('Failed to list files in .deb archive.')
            [data_filename] = filter(lambda f: f.startswith(b'data.tar'), files_in_deb)

            try:
                subprocess.check_call(['ar', 'x', debfile.name, data_filename], cwd=tempdir)
            except subprocess.CalledProcessError:
                log.error('Failed to extract data.tar from .deb archive.')

            with open(os.path.join(tempdir, data_filename), 'rb') as tarball:
                return _extract_tarfile(cache_dir, data_filename, tarball)
    else:
        import unix_ar
        from six import BytesIO
        ar_file = unix_ar.open(BytesIO(package))
        try:
            data_filename = next(filter(lambda f: f.name.startswith(b'data.tar'), ar_file.infolist())).name.decode()
            tarball = ar_file.open(data_filename)
            return _extract_tarfile(cache_dir, data_filename, tarball)
        finally:
            ar_file.close()

def _extract_pkgfile(cache_dir, package_filename, package):
    from six import BytesIO
    return _extract_tarfile(cache_dir, package_filename, BytesIO(package))

def _find_libc_package_lib_url(libc):
    # Check https://libc.rip for the libc package
    libc_match = query_libc_rip({'buildid': enhex(libc.buildid)})
    if libc_match is not None:
        for match in libc_match:
            yield match['libs_url']
    
    # Check launchpad.net if it's an Ubuntu libc
    # GNU C Library (Ubuntu GLIBC 2.36-0ubuntu4)
    import re
    version = re.search(br'GNU C Library \(Ubuntu E?GLIBC ([^\)]+)\)', libc.data)
    if version is not None:
        libc_version = version.group(1).decode()
        yield 'https://launchpad.net/ubuntu/+archive/primary/+files/libc6_{}_{}.deb'.format(libc_version, libc.arch)

def download_libraries(libc_path, unstrip=True):
    """download_libraries(str, bool) -> str
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

    for package_url in _find_libc_package_lib_url(libc):
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

def search_by_symbol_offsets(symbols, select_index=None, unstrip=True, return_as_list=False):
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
        return_as_list(bool):
            Return a list of build ids of all matching libc versions
            instead of a path to a downloaded file.

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
        >>> for buildid in matched_libcs: # doctest +SKIP
        ...     libc = ELF(search_by_build_id(buildid)) # doctest +SKIP
    """
    for symbol, address in symbols.items():
        if isinstance(address, int):
            symbols[symbol] = hex(address)

    params = {'symbols': symbols}
    log.debug('Request: %s', params)
    matching_libcs = query_libc_rip(params)
    log.debug('Result: %s', matching_libcs)
    if matching_libcs is None or len(matching_libcs) == 0:
        log.warn_once("No matching libc for symbols %r on libc.rip", symbols)
        return None

    if return_as_list:
        return [libc['buildid'] for libc in matching_libcs]

    if len(matching_libcs) == 1:
        return search_by_build_id(matching_libcs[0]['buildid'], unstrip=unstrip)

    if select_index is not None:
        if select_index > 0 and select_index <= len(matching_libcs):
            return search_by_build_id(matching_libcs[select_index - 1]['buildid'], unstrip=unstrip)
        else:
            log.error('Invalid selected libc index. %d is not in the range of 1-%d.', select_index, len(matching_libcs))
            return None

    selected_libc = _handle_multiple_matching_libcs(matching_libcs)
    return search_by_build_id(selected_libc['buildid'], unstrip=unstrip)

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


__all__ = ['get_build_id_offsets', 'search_by_build_id', 'search_by_sha1', 'search_by_sha256', 'search_by_md5', 'unstrip_libc', 'search_by_symbol_offsets', 'download_libraries']
