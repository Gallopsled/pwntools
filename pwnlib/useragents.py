"""
Database of >22,000 user agent strings
"""
from __future__ import division

__all__ = ['getall', 'random']

import os
import random as randommod

_cache = None

def _load():
    global _cache
    if _cache is None:
        _cache = set()
        with open(os.path.join(os.path.dirname(__file__),
                               'data/useragents/useragents.txt'
                               ), 'r') as fd:
            for line in fd:
                if line:
                    _cache.add(line.strip())
    return _cache

def getall():
    """getall() -> str set

    Get all the user agents that we know about.

    Arguments:
        None

    Returns:
        A set of user agent strings.

    Examples:
        >>> 'libcurl-agent/1.0' in getall()
        True
        >>> 'wget' in getall()
        True
    """
    return _load().copy()

def random():
    """random() -> str

    Get a random user agent string.

    Arguments:
        None

    Returns:
        A random user agent string selected from :func:`getall`.

    >>> import random as randommod
    >>> randommod.seed(1)
    >>> random() # doctest: +SKIP
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FunWebProducts; FunWebProducts-MyTotalSearch; iebar)'
    """
    return randommod.choice(list(_load()))
