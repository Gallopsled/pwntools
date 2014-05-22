import string, pwn

# Taken from http://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
def de_bruijn_generator(alphabet = string.ascii_lowercase, n = 4):
    """Generator for a De Bruijn Sequence for the given alphabet and subsequences of length n.

    The yielded result contains len(alphabet)**n elements"""
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

def de_bruijn(length = -1, alphabet = string.ascii_lowercase, n = 4, join = True):
    """Returns the first length elements in the a De Bruijn Sequence for the given alphabet and subsequences of length n. If length is negative, then return the entire sequence. If join is True, then the sequence is joined into a string, otherwise a generator is returned."""
    if length < 0 or length >= len(alphabet)**n:
        helper = lambda length: de_bruijn_generator(alphabet, n)
    else:
        def helper(length):
            for c in de_bruijn_generator(alphabet, n):
                if length > 0:
                    length -= 1
                    yield c
                else:
                    return
    if join:
        return ''.join(helper(length))
    return list(helper(length))

def de_bruijn_find(subseq, alphabet = string.ascii_lowercase, n = None):
    """Returns the index for the subsequence of a De Bruijn Sequence for the given alphabet and subsequences of length n. If not specified, n will default to len(subseq).

    There exists better algorithms for this, but they depend on generating the De Bruijn sequence in another fashion. Somebody should look at it:
    http://www.sciencedirect.com/science/article/pii/S0012365X00001175
    """
    if pwn.isint(subseq):
        subseq = pwn.pint(subseq)
    if n == None:
        n = len(subseq)
    return gen_find(subseq, de_bruijn_generator(alphabet, n))

def de_bruijn_large(length = -1, n = 4, join = True):
    """Same as de_bruijn but with a larger alphabet. Gives a up to 74 MB unique subsequences."""
    return de_bruijn(length, string.digits + string.ascii_letters + string.punctuation, n, join)

def de_bruijn_large_find(subseq, n = None):
    """Same as de_bruijn_find but with a larger alphabet."""
    return de_bruijn_find(subseq, string.digits + string.ascii_letters + string.punctuation, n)

def gen_find(subseq, generator):
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
