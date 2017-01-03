from __future__ import absolute_import

import string

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import packing

log = getLogger(__name__)

# Taken from https://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
def de_bruijn(alphabet = string.ascii_lowercase, n = None):
    """de_bruijn(alphabet = string.ascii_lowercase, n = 4) -> generator

    Generator for a sequence of unique substrings of length `n`. This is implemented using a
    De Bruijn Sequence over the given `alphabet`.

    The returned generator will yield up to ``len(alphabet)**n`` elements.

    Arguments:
        alphabet: List or string to generate the sequence over.
        n(int): The length of subsequences that should be unique.
    """
    if n is None:
        n = 4
    k = len(alphabet)
    a = [0] * k * n
    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            for c in db(t + 1, p):
                yield c

            for j in range(a[t - p] + 1, k):
                a[t] = j
                for c in db(t + 1, t):
                    yield c

    return db(1,1)

def cyclic(length = None, alphabet = string.ascii_lowercase, n = None):
    """cyclic(length = None, alphabet = string.ascii_lowercase, n = 4) -> list/str

    A simple wrapper over :func:`de_bruijn`. This function returns at most
    `length` elements.

    If the given alphabet is a string, a string is returned from this function. Otherwise
    a list is returned.

    Arguments:
        length: The desired length of the list or None if the entire sequence is desired.
        alphabet: List or string to generate the sequence over.
        n(int): The length of subsequences that should be unique.

    Example:
        >>> cyclic(alphabet = "ABC", n = 3)
        'AAABAACABBABCACBACCBBBCBCCC'
        >>> cyclic(20)
        'aaaabaaacaaadaaaeaaa'
        >>> alphabet, n = range(30), 3
        >>> len(alphabet)**n, len(cyclic(alphabet = alphabet, n = n))
        (27000, 27000)
    """
    if n is None:
        n = 4

    if len(alphabet) ** n < length:
        log.error("Can't create a pattern length=%i with len(alphabet)==%i and n==%i" \
                  % (length, len(alphabet), n))

    out = []
    for ndx, c in enumerate(de_bruijn(alphabet, n)):
        if length != None and ndx >= length:
            break
        else:
            out.append(c)

    if isinstance(alphabet, str):
        return ''.join(out)
    else:
        return out

def cyclic_find(subseq, alphabet = string.ascii_lowercase, n = None):
    """cyclic_find(subseq, alphabet = string.ascii_lowercase, n = None) -> int

    Calculates the position of a substring into a De Bruijn sequence.

    .. todo:

       "Calculates" is an overstatement. It simply traverses the list.

       There exists better algorithms for this, but they depend on generating
       the De Bruijn sequence in another fashion. Somebody should look at it:

       https://www.sciencedirect.com/science/article/pii/S0012365X00001175

    Arguments:
        subseq: The subsequence to look for. This can be a string, a list or an
                integer. If an integer is provided it will be packed as a
                little endian integer.
        alphabet: List or string to generate the sequence over.
        n(int): The length of subsequences that should be unique.


    Examples:

        >>> cyclic_find(cyclic(1000)[514:518])
        514
        >>> cyclic_find(0x61616162)
        4
    """
    if isinstance(subseq, (int, long)):
        width = 'all' if n is None else n * 8
        subseq = packing.pack(subseq, width, 'little', False)

    if n is None and len(subseq) != 4:
        log.warn_once("cyclic_find() expects 4-byte subsequences by default, you gave %r\n" % subseq \
            + "Unless you specified cyclic(..., n=%i), you probably just want the first 4 bytes.\n" % len(subseq) \
            + "Truncating the data at 4 bytes.  Specify cyclic_find(..., n=%i) to override this." % len(subseq))
        subseq = subseq[:4]

    if any(c not in alphabet for c in subseq):
        return -1

    n = n or len(subseq)

    return _gen_find(subseq, de_bruijn(alphabet, n))

def metasploit_pattern(sets = None):
    """metasploit_pattern(sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]) -> generator

    Generator for a sequence of characters as per Metasploit Framework's
    `Rex::Text.pattern_create` (aka `pattern_create.rb`).

    The returned generator will yield up to
    ``len(sets) * reduce(lambda x,y: x*y, map(len, sets))`` elements.

    Arguments:
        sets: List of strings to generate the sequence over.
    """
    sets = sets or [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]
    offsets = [ 0 ] * len(sets)
    offsets_indexes_reversed = list(reversed(range(len(offsets))))

    while True:
        for i, j in zip(sets, offsets):
            yield i[j]
        # increment offsets with cascade
        for i in offsets_indexes_reversed:
            offsets[i] = (offsets[i] + 1) % len(sets[i])
            if offsets[i] != 0:
                break
        # finish up if we've exhausted the sequence
        if offsets == [ 0 ] * len(sets):
            return

def cyclic_metasploit(length = None, sets = None):
    """cyclic_metasploit(length = None, sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]) -> str

    A simple wrapper over :func:`metasploit_pattern`. This function returns a
    string of length `length`.

    Arguments:
        length: The desired length of the string or None if the entire sequence is desired.
        sets: List of strings to generate the sequence over.

    Example:
        >>> cyclic_metasploit(32)
        'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab'
        >>> cyclic_metasploit(sets = ["AB","ab","12"])
        'Aa1Aa2Ab1Ab2Ba1Ba2Bb1Bb2'
        >>> cyclic_metasploit()[1337:1341]
        '5Bs6'
        >>> len(cyclic_metasploit())
        20280
    """
    sets = sets or [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]
    out = []

    for ndx, c in enumerate(metasploit_pattern(sets)):
        if length != None and ndx >= length:
            break
        else:
            out.append(c)

    out = ''.join(out)

    if len(out) < length:
        log.error("Can't create a pattern of length %i with sets of lengths %s. Maximum pattern length is %i." \
                  % (length, map(len, sets), len(out)))

    return ''.join(out)

def cyclic_metasploit_find(subseq, sets = None):
    """cyclic_metasploit_find(subseq, sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]) -> int

    Calculates the position of a substring into a Metasploit Pattern sequence.

    Arguments:
        subseq: The subsequence to look for. This can be a string or an
                integer. If an integer is provided it will be packed as a
                little endian integer.
        sets: List of strings to generate the sequence over.

    Examples:

        >>> cyclic_metasploit_find(cyclic_metasploit(1000)[514:518])
        514
        >>> cyclic_metasploit_find(0x61413161)
        4
    """
    sets = sets or [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]

    if isinstance(subseq, (int, long)):
        subseq = packing.pack(subseq, 'all', 'little', False)

    return _gen_find(subseq, metasploit_pattern(sets))

def _gen_find(subseq, generator):
    """Returns the first position of `subseq` in the generator or -1 if there is no such position."""
    subseq = list(subseq)
    pos = 0
    saved = []

    for c in generator:
        saved.append(c)
        if len(saved) > len(subseq):
            saved.pop(0)
            pos += 1
        if saved == subseq:
            return pos
    return -1
