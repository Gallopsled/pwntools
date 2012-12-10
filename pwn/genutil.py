import string

# Taken from http://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
def de_bruijn_generator(alphabet = string.ascii_lowercase, n = 4):
    """Generator for a De Bruijn Sequence for the given alphabet and subsequences of length n."""
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
    def helper(length):
        for c in de_bruijn_generator(alphabet, n):
            if length == 0: return
            if length > 0: length -= 1
            yield c
    if join:
        return ''.join(helper(length))
    return helper(length)

def de_bruijn_find(subseq, alphabet = string.ascii_lowercase, n = None):
    """Returns the index for the subsequence of a De Bruijn Sequence for the given alphabet and subsequences of length n. If not specified, n will default to len(subseq). There exists better algorithms for this, but why bother?"""
    if n == None:
        n = len(subseq)
    return gen_find(subseq, de_bruijn_generator(alphabet, n))

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
