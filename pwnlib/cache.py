import os
import sys
import tempfile

def get_default_cache_directory():
    """Directory used for caching data.

    Note:
        May be either a path string, or :const:`None`.

    Example:

        >>> directory = get_default_cache_directory()
        >>> os.path.isdir(directory)
        True
    """
    linux = os.environ.get('XDG_CACHE_HOME')
    other = os.path.join(os.path.expanduser('~'), '.cache')

    cache = linux or other

    cache = os.path.join(cache, '.pwntools-cache-%d.%d' % sys.version_info[:2])

    if not os.path.isdir(cache):
        os.makedirs(cache)

    return cache