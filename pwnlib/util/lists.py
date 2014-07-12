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

def group(n, lst, underfull_action = 'ignore', fill_value = None):
    """Split sequence into subsequences of given size. If the values cannot be
    evenly distributed among into groups, then the last group will either be
    returned as is, thrown out or padded with the value specified in fill_value.

    Args:
        n (int): The size of resulting groups
        lst: The list, tuple or string to group
        underfull_action (str): The action to take in case of an underfull group at the end. Possible values are 'ignore', 'drop' or 'fill'.
        fill_value: The value to fill into an underfull remaining group.

    Returns:
        A list containing the grouped values.
    """

    out = []
    for i in range(0, len(lst), n):
        out.append(lst[i:i+n])

    if out and len(out[-1]) < n:
        if underfull_action == 'ignore':
            pass
        elif underfull_action == 'drop':
            out.pop()
        elif underfull_action == 'fill':
            if isinstance(out[-1], tuple):
                out[-1] = out[-1] + (fill_value,) * (n - len(out[-1]))
            elif isinstance(out[-1], list):
                out[-1] = out[-1] + [fill_value] * (n - len(out[-1]))
            else:
                out[-1] = out[-1] + fill_value * (n - len(out[-1]))
        else:
            raise ValueError("underfull_action must be either 'ignore', 'drop' or 'fill'")

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

def ordlist(s, size = 1):
    """Turns a string into a list of the corresponding ascii values."""
# TODO: Fix pwn reference
    return [pwn.uint(c) for c in group(size, s)]

def unordlist(cs):
    """Takes a list of ascii values and returns the corresponding string"""
# TODO: Fix pwn reference
    return pwn.flat(cs, func = pwn.p8)

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
