def group(lst, n):
    """group([0,3,4,10,2,3], 2) => [(0,3), (4,10), (2,3)]

    Group a list into consecutive n-tuples. Incomplete tuples are
    discarded e.g.

    >>> group(range(10), 3)
    [(0, 1, 2), (3, 4, 5), (6, 7, 8)]
    """
    return zip(*[lst[i::n] for i in range(n)])

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
    if not isinstance(args[0], list): return [args[0]]

    res = []
    for k in args[0]:
        res.extend(concat_all(k))

    return res

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
