import pwn

def partition(lst, f, save_keys = False):
    """parition([1,2,3,4,5], lambda x: x&1) => [[1,3,5], [2,4]]

    Partitions a list into sublists using a function to specify which group they belong to.

    If you want to save the output from the function, set save_keys to True, to return a dictionary instead of a list.
    """
    d = {}

    for l in lst:
        c = f(l)
        s = d.get(c)

        if s == None:
            d[c] = [l]
        else:
            s.append(l)
    if save_keys:
        return d
    else:
        return d.values()

def group(lst, n, discard_underfull = False):
    """Split sequence into subsequences of given size.  Optionally discard or
    include last subsequence if it is underfull
    """
    out = []
    for i in range(0, len(lst), n):
        out.append(lst[i:i+n])
    if discard_underfull and len(out[-1]) < n:
        out.pop()
    return out

def concat(l):
    """concat([[1,2], [3]]) => [1,2,3]

    Concats a list of lists into a list.
    """

    res = []
    for k in l:
        res.extend(k)

    return res

def concat_all(*args):
    """concat_all([1,[2,3]], [[[[4,5,6]]]]) => [1,2,3,4,5,6]

    Concats all the arguments together.
    """

    if len(args) != 1: return concat_all(list(args))
    if not (isinstance(args[0], list) or isinstance(args[0], tuple)): return [args[0]]

    res = []
    for k in args[0]:
        res.extend(concat_all(k))

    return res

def combinations(*args):
    """Returns all the combinations of the arguments as a generator. Example:
    combinations([1,2,3], 'abc') ==> generator([[1, 'a'], [1, 'b'], [1, 'c'], [2, 'a'], [2, 'b'], [2, 'c']])
    """

    if len(args) == 0:
        pwn.die('Combinations called without an argument')

    if len(args) == 1:
        args = args[0]

    def recurse(args):
        if len(args) == 0:
            return
        if len(args) == 1:
            for a in args[0]:
                yield [a]
        else:
            for rest in recurse(args[:-1]):
                for a in args[-1]:
                    yield rest + [a]

    return recurse(args)

def powerset(lst, include_empty = True, proper = False):
    res = []
    n = len(lst)
    fr = 0 if include_empty else 1
    to = 2**n - 1 if proper else 2**n
    for i in xrange(fr, to):
        yield [lst[j] for j in range(n) if 2**j & i]

def ordlist(s):
    return [ord(c) for c in s]

def unordlist(cs):
    return pwn.flat(cs, func=pwn.p8)

def __kmp_table(W):
    pos = 1
    cnd = 0
    T = []
    T.append(-1)
    T.append(0)
    while pos < len(W):
        if W[pos] == W[cnd]:
            cnd += 1
            pos += 1
            T.append(cnd)
        elif cnd > 0:
            cnd = T[cnd]
        else:
            pos += 1
            T.append(0)
    return T

def __kmp_search(S, W):
    m = 0
    i = 0
    T = __kmp_table(W)
    while m + i < len(S):
        if S[m + i] == W[i]:
            i += 1
            if i == len(W):
                yield m
                m += i - T[i]
                i = max(T[i], 0)
        else:
            m += i - T[i]
            i = max(T[i], 0)

def __single_search(S, w):
    for i in xrange(len(S)):
        if S[i] == w:
            yield i

def findall(haystack, needle):
    '''Find all occurences of needle in haystack

    Uses the Knuth-Morris-Pratt algorithm'''
    if type(haystack) <> type(needle):
        needle = [needle]
    if len(needle) == 1:
        return __single_search(haystack, needle[0])
    else:
        return __kmp_search(haystack, needle)

def listify(*args):
    '''Creates lists from all arguments, and returns concatenation'''
    return sum((list(x) if hasattr(x, '__iter__') else [x] for x in args), [])

def tuplify(*args):
    '''Creates tuples from all arguments, and returns concatenation'''
    return sum((tuple(x) if hasattr(x, '__iter__') else (x,) for x in args), ())
