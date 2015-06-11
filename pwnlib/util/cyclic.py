import string

from . import packing


# Taken from https://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
def de_bruijn(alphabet = string.ascii_lowercase, n = 4):
    """de_bruijn(alphabet = string.ascii_lowercase, n = 4) -> generator

    Generator for a sequence of unique substrings of length `n`. This is implemented using a
    De Bruijn Sequence over the given `alphabet`.

    The returned generator will yield up to ``len(alphabet)**n`` elements.

    Arguments:
      alphabet: List or string to generate the sequence over.
      n(int): The length of subsequences that should be unique.
"""
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

def cyclic(length = None, alphabet = string.ascii_lowercase, n = 4):
    """cyclic(length = None, alphabet = string.ascii_lowercase, n = 4) -> list/str

    A simple wrapper over :func:`de_bruijn`. This function returns a
    at most `length` elements.

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
      subseq: The subsequence to look for. This can either be a string, a list
              or an integer. If an integer is provided it will be packed as a
              little endian integer.
      alphabet: List or string to generate the sequence over.
      n(int): The length of subsequences that should be unique.


    Examples:

      >>> cyclic_find(cyclic(1000)[514:518])
      514
    """
    if any(c not in alphabet for c in subseq):
        return -1

    if isinstance(subseq, (int, long)):
        width = n * 8 or 'all'
        subseq = packing.pack(subseq, width, 'little', False)

    n = n or len(subseq)

    return _gen_find(subseq, de_bruijn(alphabet, n))

def _gen_find(subseq, generator):
    """Returns the first position of subseq in the generator or -1 if there is no such position."""
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
