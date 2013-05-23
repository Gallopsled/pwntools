import string, pwn, math

class DeBruijn:
    def __init__(self, alphabet = string.lowercase, n = 4, size = -1):
        # If alphabet not defined, or if too small, use the smallest possible.
        if not alphabet:
            alphabet = ''.join(
                [x for x in string.letters
                 + string.digits + string.punctuation
                 if not x in string.whitespace])
            i = int(math.ceil(size**(1./n)))
            self.alphabet = alphabet[:i]
        else:
            self.alphabet = alphabet

        if size > len(self.alphabet)**n:
            pwn.die('Size too great for alphabet.')
        
        self.n = n
        self.size = size

    # Taken from http://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
    def _generator(self):
        """Generator for a De Bruijn Sequence for the given alphabet and subsequences of length n.

        The yielded result contains len(alphabet)**n elements"""
        k = len(self.alphabet)
        a = [0] * k * self.n
        def db(t, p):
            if t > self.n:
                if self.n % p == 0:
                    for j in range(1, p + 1):
                        yield self.alphabet[a[j]]
            else:
                a[t] = a[t - p]
                for c in db(t + 1, p):
                    yield c

                for j in range(a[t - p] + 1, k):
                    a[t] = j
                    for c in db(t + 1, t):
                        yield c

        return db(1,1)

    def sequence(self, join = True):
        """Returns the first length elements in the a De Bruijn Sequence for the given alphabet and subsequences of length n. If length is negative, then return the entire sequence. If join is True, then the sequence is joined into a string, otherwise a generator is returned."""
        if self.size < 0:
            helper = lambda size: self._generator()
        else:
            def helper(length):
                for c in self._generator():
                    if length > 0:
                        length -= 1
                        yield c
                    else:
                        return
        if join:
            return ''.join(helper(self.size))
        return list(helper(self.size))

    def find(self, subseq):
        """Returns the index for the subsequence of a De Bruijn Sequence for the given alphabet and subsequences of length n. If not specified, n will default to len(subseq).

        There exists better algorithms for this, but they depend on generating the De Bruijn sequence in another fashion. Somebody should look at it:
        http://www.sciencedirect.com/science/article/pii/S0012365X00001175
        """
        if isinstance(subseq, int):
            subseq = pwn.pint(subseq)
        return self.gen_find(subseq, self._generator())

    def gen_find(self, subseq, generator):
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
