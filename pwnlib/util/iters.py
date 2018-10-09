"""
This module includes and extends the standard module :mod:`itertools`.
"""
from __future__ import absolute_import
from __future__ import division

import collections
import copy
import multiprocessing
import operator
import random
import time
from itertools import *

from pwnlib.context import context
from pwnlib.log import getLogger

__all__ = [
    'bruteforce'                             ,
    'mbruteforce'                            ,
    'chained'                                ,
    'consume'                                ,
    'cyclen'                                 ,
    'dotproduct'                             ,
    'flatten'                                ,
    'group'                                  ,
    'iter_except'                            ,
    'lexicographic'                          ,
    'lookahead'                              ,
    'nth'                                    ,
    'pad'                                    ,
    'pairwise'                               ,
    'powerset'                               ,
    'quantify'                               ,
    'random_combination'                     ,
    'random_combination_with_replacement'    ,
    'random_permutation'                     ,
    'random_product'                         ,
    'repeat_func'                            ,
    'roundrobin'                             ,
    'tabulate'                               ,
    'take'                                   ,
    'unique_everseen'                        ,
    'unique_justseen'                        ,
    'unique_window'                          ,
    # these are re-exported from itertools
    'chain'                                  ,
    'combinations'                           ,
    'combinations_with_replacement'          ,
    'compress'                               ,
    'count'                                  ,
    'cycle'                                  ,
    'dropwhile'                              ,
    'groupby'                                ,
    'ifilter'                                ,
    'ifilterfalse'                           ,
    'imap'                                   ,
    'islice'                                 ,
    'izip'                                   ,
    'izip_longest'                           ,
    'permutations'                           ,
    'product'                                ,
    'repeat'                                 ,
    'starmap'                                ,
    'takewhile'                              ,
    'tee'
]



log = getLogger(__name__)

def take(n, iterable):
    """take(n, iterable) -> list

    Returns first `n` elements of `iterable`.  If `iterable` is a iterator it
    will be advanced.

    Arguments:
      n(int):  Number of elements to take.
      iterable:  An iterable.

    Returns:
      A list of the first `n` elements of `iterable`.  If there are fewer than
      `n` elements in `iterable` they will all be returned.

    Examples:
      >>> take(2, range(10))
      [0, 1]
      >>> i = count()
      >>> take(2, i)
      [0, 1]
      >>> take(2, i)
      [2, 3]
      >>> take(9001, [1, 2, 3])
      [1, 2, 3]
    """
    return list(islice(iterable, n))

def tabulate(func, start = 0):
    """tabulate(func, start = 0) -> iterator

    Arguments:
      func(function):  The function to tabulate over.
      start(int):  Number to start on.

    Returns:
      An iterator with the elements ``func(start), func(start + 1), ...``.

    Examples:
      >>> take(2, tabulate(str))
      ['0', '1']
      >>> take(5, tabulate(lambda x: x**2, start = 1))
      [1, 4, 9, 16, 25]
    """
    return imap(func, count(start))

def consume(n, iterator):
    """consume(n, iterator)

    Advance the iterator `n` steps ahead. If `n is :const:`None`, consume
    everything.

    Arguments:
      n(int):  Number of elements to consume.
      iterator(iterator):  An iterator.

    Returns:
      :const:`None`.

    Examples:
      >>> i = count()
      >>> consume(5, i)
      >>> next(i)
      5
      >>> i = iter([1, 2, 3, 4, 5])
      >>> consume(2, i)
      >>> list(i)
      [3, 4, 5]
    """
    # Use functions that consume iterators at C speed.
    if n is None:
        # feed the entire iterator into a zero-length deque
        collections.deque(iterator, maxlen = 0)
    else:
        # advance to the empty slice starting at position n
        next(islice(iterator, n, n), None)

def nth(n, iterable, default = None):
    """nth(n, iterable, default = None) -> object

    Returns the element at index `n` in `iterable`.  If `iterable` is a
    iterator it will be advanced.

    Arguments:
      n(int):  Index of the element to return.
      iterable:  An iterable.
      default(objext):  A default value.

    Returns:
      The element at index `n` in `iterable` or `default` if `iterable` has too
      few elements.

    Examples:
      >>> nth(2, [0, 1, 2, 3])
      2
      >>> nth(2, [0, 1], 42)
      42
      >>> i = count()
      >>> nth(42, i)
      42
      >>> nth(42, i)
      85
    """
    return next(islice(iterable, n, None), default)

def quantify(iterable, pred = bool):
    """quantify(iterable, pred = bool) -> int

    Count how many times the predicate `pred` is :const:`True`.

    Arguments:
        iterable:  An iterable.
        pred:  A function that given an element from `iterable` returns either
               :const:`True` or :const:`False`.

    Returns:
      The number of elements in `iterable` for which `pred` returns
      :const:`True`.

    Examples:
      >>> quantify([1, 2, 3, 4], lambda x: x % 2 == 0)
      2
      >>> quantify(['1', 'two', '3', '42'], str.isdigit)
      3
    """
    return sum(imap(pred, iterable))

def pad(iterable, value = None):
    """pad(iterable, value = None) -> iterator

    Pad an `iterable` with `value`, i.e. returns an iterator whoose elements are
    first the elements of `iterable` then `value` indefinitely.

    Arguments:
      iterable:  An iterable.
      value:  The value to pad with.

    Returns:
      An iterator whoose elements are first the elements of `iterable` then
      `value` indefinitely.

    Examples:
      >>> take(3, pad([1, 2]))
      [1, 2, None]
      >>> i = pad(iter([1, 2, 3]), 42)
      >>> take(2, i)
      [1, 2]
      >>> take(2, i)
      [3, 42]
      >>> take(2, i)
      [42, 42]
    """
    return chain(iterable, repeat(value))

def cyclen(n, iterable):
    """cyclen(n, iterable) -> iterator

    Repeats the elements of `iterable` `n` times.

    Arguments:
      n(int):  The number of times to repeat `iterable`.
      iterable:  An iterable.

    Returns:
      An iterator whoose elements are the elements of `iterator` repeated `n`
      times.

    Examples:
      >>> take(4, cyclen(2, [1, 2]))
      [1, 2, 1, 2]
      >>> list(cyclen(10, []))
      []
    """
    return chain.from_iterable(repeat(tuple(iterable), n))

def dotproduct(x, y):
    """dotproduct(x, y) -> int

    Computes the dot product of `x` and `y`.

    Arguments:
      x(iterable):  An iterable.
      x(iterable):  An iterable.

    Returns:
      The dot product of `x` and `y`, i.e.: ``x[0] * y[0] + x[1] * y[1] + ...``.

    Example:
      >>> dotproduct([1, 2, 3], [4, 5, 6])
      ... # 1 * 4 + 2 * 5 + 3 * 6 == 32
      32
    """
    return sum(imap(operator.mul, x, y))

def flatten(xss):
    """flatten(xss) -> iterator

    Flattens one level of nesting; when `xss` is an iterable of iterables,
    returns an iterator whoose elements is the concatenation of the elements of
    `xss`.

    Arguments:
      xss:  An iterable of iterables.

    Returns:
      An iterator whoose elements are the concatenation of the iterables in
      `xss`.

    Examples:
      >>> list(flatten([[1, 2], [3, 4]]))
      [1, 2, 3, 4]
      >>> take(6, flatten([[43, 42], [41, 40], count()]))
      [43, 42, 41, 40, 0, 1]
    """
    return chain.from_iterable(xss)

def repeat_func(func, *args, **kwargs):
    """repeat_func(func, *args, **kwargs) -> iterator

    Repeatedly calls `func` with positional arguments `args` and keyword
    arguments `kwargs`.  If no keyword arguments is given the resulting iterator
    will be computed using only functions from :mod:`itertools` which are very
    fast.

    Arguments:
      func(function):  The function to call.
      args:  Positional arguments.
      kwargs:  Keyword arguments.

    Returns:
      An iterator whoose elements are the results of calling ``func(*args,
      **kwargs)`` repeatedly.

    Examples:
      >>> def f(x):
      ...     x[0] += 1
      ...     return x[0]
      >>> i = repeat_func(f, [0])
      >>> take(2, i)
      [1, 2]
      >>> take(2, i)
      [3, 4]
      >>> def f(**kwargs):
      ...     return kwargs.get('x', 43)
      >>> i = repeat_func(f, x = 42)
      >>> take(2, i)
      [42, 42]
      >>> i = repeat_func(f, 42)
      >>> take(2, i)
      Traceback (most recent call last):
          ...
      TypeError: f() takes exactly 0 arguments (1 given)
    """
    if kwargs:
        return starmap(lambda args, kwargs: func(*args, **kwargs),
                       repeat((args, kwargs))
                       )
    else:
        return starmap(func, repeat(args))

def pairwise(iterable):
    """pairwise(iterable) -> iterator

    Arguments:
      iterable:  An iterable.

    Returns:
      An iterator whoose elements are pairs of neighbouring elements of
      `iterable`.

    Examples:
      >>> list(pairwise([1, 2, 3, 4]))
      [(1, 2), (2, 3), (3, 4)]
      >>> i = starmap(operator.add, pairwise(count()))
      >>> take(5, i)
      [1, 3, 5, 7, 9]
    """
    a, b = tee(iterable)
    next(b, None)
    return izip(a, b)

def group(n, iterable, fill_value = None):
    """group(n, iterable, fill_value = None) -> iterator

    Similar to :func:`pwnlib.util.lists.group`, but returns an iterator and uses
    :mod:`itertools` fast build-in functions.

    Arguments:
      n(int):  The group size.
      iterable:  An iterable.
      fill_value:  The value to fill into the remaining slots of the last group
        if the `n` does not divide the number of elements in `iterable`.

    Returns:
      An iterator whoose elements are `n`-tuples of the elements of `iterable`.

    Examples:
      >>> list(group(2, range(5)))
      [(0, 1), (2, 3), (4, None)]
      >>> take(3, group(2, count()))
      [(0, 1), (2, 3), (4, 5)]
      >>> [''.join(x) for x in group(3, 'ABCDEFG', 'x')]
      ['ABC', 'DEF', 'Gxx']
    """
    args = [iter(iterable)] * n
    return izip_longest(fillvalue = fill_value, *args)

def roundrobin(*iterables):
    """roundrobin(*iterables)

    Take elements from `iterables` in a round-robin fashion.

    Arguments:
      *iterables:  One or more iterables.

    Returns:
      An iterator whoose elements are taken from `iterables` in a round-robin
      fashion.

    Examples:
      >>> ''.join(roundrobin('ABC', 'D', 'EF'))
      'ADEBFC'
      >>> ''.join(take(10, roundrobin('ABC', 'DE', repeat('x'))))
      'ADxBExCxxx'
    """
    # Recipe credited to George Sakkis
    pending = len(iterables)
    nexts = cycle(iter(it) for it in iterables)
    while pending:
        try:
            for nxt in nexts:
                yield next(nxt)
        except StopIteration:
            pending -= 1
            nexts = cycle(islice(nexts, pending))

def powerset(iterable, include_empty = True):
    """powerset(iterable, include_empty = True) -> iterator

    The powerset of an iterable.

    Arguments:
      iterable:  An iterable.
      include_empty(bool):  Whether to include the empty set.

    Returns:
      The powerset of `iterable` as an interator of tuples.

    Examples:
      >>> list(powerset(range(3)))
      [(), (0,), (1,), (2,), (0, 1), (0, 2), (1, 2), (0, 1, 2)]
      >>> list(powerset(range(2), include_empty = False))
      [(0,), (1,), (0, 1)]
    """
    s = list(iterable)
    i = chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))
    if not include_empty:
        next(i)
    return i

def unique_everseen(iterable, key = None):
    """unique_everseen(iterable, key = None) -> iterator

    Get unique elements, preserving order. Remember all elements ever seen.  If
    `key` is not :const:`None` then for each element ``elm`` in `iterable` the
    element that will be rememberes is ``key(elm)``.  Otherwise ``elm`` is
    remembered.

    Arguments:
      iterable:  An iterable.
      key:  A function to map over each element in `iterable` before remembering
        it.  Setting to :const:`None` is equivalent to the identity function.

    Returns:
      An iterator of the unique elements in `iterable`.

    Examples:
      >>> ''.join(unique_everseen('AAAABBBCCDAABBB'))
      'ABCD'
      >>> ''.join(unique_everseen('ABBCcAD', str.lower))
      'ABCD'
    """
    seen = set()
    seen_add = seen.add
    if key is None:
        for element in ifilterfalse(seen.__contains__, iterable):
            seen_add(element)
            yield element
    else:
        for element in iterable:
            k = key(element)
            if k not in seen:
                seen_add(k)
                yield element

def unique_justseen(iterable, key = None):
    """unique_everseen(iterable, key = None) -> iterator

    Get unique elements, preserving order. Remember only the elements just seen.
    If `key` is not :const:`None` then for each element ``elm`` in `iterable`
    the element that will be rememberes is ``key(elm)``.  Otherwise ``elm`` is
    remembered.

    Arguments:
      iterable:  An iterable.
      key:  A function to map over each element in `iterable` before remembering
        it.  Setting to :const:`None` is equivalent to the identity function.

    Returns:
      An iterator of the unique elements in `iterable`.

    Examples:
      >>> ''.join(unique_justseen('AAAABBBCCDAABBB'))
      'ABCDAB'
      >>> ''.join(unique_justseen('ABBCcAD', str.lower))
      'ABCAD'
    """
    return imap(next, imap(operator.itemgetter(1), groupby(iterable, key)))

def unique_window(iterable, window, key = None):
    """unique_everseen(iterable, window, key = None) -> iterator

    Get unique elements, preserving order. Remember only the last `window`
    elements seen.  If `key` is not :const:`None` then for each element ``elm``
    in `iterable` the element that will be rememberes is ``key(elm)``.
    Otherwise ``elm`` is remembered.

    Arguments:
      iterable:  An iterable.
      window(int):  The number of elements to remember.
      key:  A function to map over each element in `iterable` before remembering
        it.  Setting to :const:`None` is equivalent to the identity function.

    Returns:
      An iterator of the unique elements in `iterable`.

    Examples:
      >>> ''.join(unique_window('AAAABBBCCDAABBB', 6))
      'ABCDA'
      >>> ''.join(unique_window('ABBCcAD', 5, str.lower))
      'ABCD'
      >>> ''.join(unique_window('ABBCcAD', 4, str.lower))
      'ABCAD'
    """
    seen = collections.deque(maxlen = window)
    seen_add = seen.append
    if key is None:
        for element in iterable:
            if element not in seen:
                yield element
            seen_add(element)
    else:
        for element in iterable:
            k = key(element)
            if k not in seen:
                yield element
            seen_add(k)

def iter_except(func, exception):
    """iter_except(func, exception)

    Calls `func` repeatedly until an exception is raised.  Works like the
    build-in :func:`iter` but uses an exception instead of a sentinel to signal
    the end.

    Arguments:
      func(callable): The function to call.
      exception(Exception):  The exception that signals the end.  Other
        exceptions will not be caught.

    Returns:
      An iterator whoose elements are the results of calling ``func()`` until an
      exception matching `exception` is raised.

    Examples:
      >>> s = {1, 2, 3}
      >>> i = iter_except(s.pop, KeyError)
      >>> next(i)
      1
      >>> next(i)
      2
      >>> next(i)
      3
      >>> next(i)
      Traceback (most recent call last):
          ...
      StopIteration
    """
    try:
        while True:
            yield func()
    except exception:
        pass

def random_product(*args, **kwargs):
    """random_product(*args, repeat = 1) -> tuple

    Arguments:
      args:  One or more iterables
      repeat(int):  Number of times to repeat `args`.

    Returns:
      A random element from ``itertools.product(*args, repeat = repeat)``.

    Examples:
      >>> args = (range(2), range(2))
      >>> random_product(*args) in {(0, 0), (0, 1), (1, 0), (1, 1)}
      True
      >>> args = (range(3), range(3), range(3))
      >>> random_product(*args, repeat = 2) in product(*args, repeat = 2)
      True
    """
    repeat = kwargs.pop('repeat', 1)

    if kwargs != {}:
        raise TypeError('random_product() does not support argument %s' % kwargs.popitem())

    pools = list(map(tuple, args)) * repeat
    return tuple(random.choice(pool) for pool in pools)

def random_permutation(iterable, r = None):
    """random_product(iterable, r = None) -> tuple

    Arguments:
      iterable:  An iterable.
      r(int):  Size of the permutation.  If :const:`None` select all elements in
        `iterable`.

    Returns:
      A random element from ``itertools.permutations(iterable, r = r)``.

    Examples:
      >>> random_permutation(range(2)) in {(0, 1), (1, 0)}
      True
      >>> random_permutation(range(10), r = 2) in permutations(range(10), r = 2)
      True
    """
    pool = tuple(iterable)
    r = len(pool) if r is None else r
    return tuple(random.sample(pool, r))

def random_combination(iterable, r):
    """random_combination(iterable, r) -> tuple

    Arguments:
      iterable:  An iterable.
      r(int):  Size of the combination.

    Returns:
      A random element from ``itertools.combinations(iterable, r = r)``.

    Examples:
      >>> random_combination(range(2), 2)
      (0, 1)
      >>> random_combination(range(10), r = 2) in combinations(range(10), r = 2)
      True
    """
    pool = tuple(iterable)
    n = len(pool)
    indices = sorted(random.sample(xrange(n), r))
    return tuple(pool[i] for i in indices)

def random_combination_with_replacement(iterable, r):
    """random_combination(iterable, r) -> tuple

    Arguments:
      iterable:  An iterable.
      r(int):  Size of the combination.

    Returns:
      A random element from ``itertools.combinations_with_replacement(iterable,
      r = r)``.

    Examples:
      >>> cs = {(0, 0), (0, 1), (1, 1)}
      >>> random_combination_with_replacement(range(2), 2) in cs
      True
      >>> i = combinations_with_replacement(range(10), r = 2)
      >>> random_combination_with_replacement(range(10), r = 2) in i
      True
    """
    pool = tuple(iterable)
    n = len(pool)
    indices = sorted(random.randrange(n) for i in xrange(r))
    return tuple(pool[i] for i in indices)

def lookahead(n, iterable):
    """lookahead(n, iterable) -> object

    Inspects the upcoming element at index `n` without advancing the iterator.
    Raises ``IndexError`` if `iterable` has too few elements.

    Arguments:
      n(int):  Index of the element to return.
      iterable:  An iterable.

    Returns:
      The element in `iterable` at index `n`.

    Examples:
      >>> i = count()
      >>> lookahead(4, i)
      4
      >>> next(i)
      0
      >>> i = count()
      >>> nth(4, i)
      4
      >>> next(i)
      5
      >>> lookahead(4, i)
      10
    """
    for value in islice(copy.copy(iterable), n, None):
        return value
    raise IndexError(n)

def lexicographic(alphabet):
    """lexicographic(alphabet) -> iterator

    The words with symbols in `alphabet`, in lexicographic order (determined by
    the order of `alphabet`).

    Arguments:
      alphabet:  The alphabet to draw symbols from.

    Returns:
      An iterator of the words with symbols in `alphabet`, in lexicographic
      order.

    Example:
      >>> take(8, imap(lambda x: ''.join(x), lexicographic('01')))
      ['', '0', '1', '00', '01', '10', '11', '000']
    """
    for n in count():
        for e in product(alphabet, repeat = n):
            yield e

def chained(func):
    """chained(func)

    A decorator chaining the results of `func`.  Useful for generators.

    Arguments:
      func(function):  The function being decorated.

    Returns:
      A generator function whoose elements are the concatenation of the return
      values from ``func(*args, **kwargs)``.

    Example:
      >>> @chained
      ... def g():
      ...     for x in count():
      ...         yield (x, -x)
      >>> take(6, g())
      [0, 0, 1, -1, 2, -2]
    """
    def wrapper(*args, **kwargs):
        for xs in func(*args, **kwargs):
            for x in xs:
                yield x
    return wrapper

def bruteforce(func, alphabet, length, method = 'upto', start = None, databag = None):
    """bruteforce(func, alphabet, length, method = 'upto', start = None)

    Bruteforce `func` to return :const:`True`.  `func` should take a string
    input and return a :func:`bool`.  `func` will be called with strings from
    `alphabet` until it returns :const:`True` or the search space has been
    exhausted.

    The argument `start` can be used to split the search space, which is useful
    if multiple CPU cores are available.

    Arguments:
      func(function):  The function to bruteforce.
      alphabet:  The alphabet to draw symbols from.
      length:  Longest string to try.
      method:  If 'upto' try strings of length ``1 .. length``, if 'fixed' only
        try strings of length ``length`` and if 'downfrom' try strings of length
        ``length .. 1``.
      start: a tuple ``(i, N)`` which splits the search space up into `N` pieces
        and starts at piece `i` (1..N). :const:`None` is equivalent to ``(1, 1)``.

    Returns:
      A string `s` such that ``func(s)`` returns :const:`True` or :const:`None`
      if the search space was exhausted.

    Example:
      >>> bruteforce(lambda x: x == 'hello', string.ascii_lowercase, length = 10)
      'hello'
      >>> bruteforce(lambda x: x == 'hello', 'hllo', 5) is None
      True
    """

    if   method == 'upto' and length > 1:
        iterator = product(alphabet, repeat = 1)
        for i in xrange(2, length + 1):
            iterator = chain(iterator, product(alphabet, repeat = i))

    elif method == 'downfrom' and length > 1:
        iterator = product(alphabet, repeat = length)
        for i in xrange(length - 1, 1, -1):
            iterator = chain(iterator, product(alphabet, repeat = i))

    elif method == 'fixed':
        iterator = product(alphabet, repeat = length)

    else:
        raise TypeError('bruteforce(): unknown method')

    if method == 'fixed':
        total_iterations = len(alphabet) ** length
    else:
        total_iterations = (len(alphabet) ** (length + 1) // (len(alphabet) - 1)) - 1

    if start is not None:
        i, N = start
        if i > N:
            raise ValueError('bruteforce(): invalid starting point')

        i -= 1
        chunk_size = total_iterations // N
        rest = total_iterations % N
        starting_point = 0

        for chunk in range(N):
            if chunk >= i:
                break
            if chunk <= rest:
                starting_point += chunk_size + 1
            else:
                starting_point += chunk_size

        if rest >= i:
            chunk_size += 1

        total_iterations = chunk_size

    h = log.waitfor('Bruteforcing')
    cur_iteration = 0
    if start != None:
        consume(i, iterator)
    for e in iterator:
        cur = ''.join(e)
        cur_iteration += 1
        if cur_iteration % 2000 == 0:
            progress = 100.0 * cur_iteration / total_iterations
            h.status('Trying "%s", %0.3f%%' % (cur, progress))
            if databag:
                databag["current_item"] = cur
                databag["items_done"] = cur_iteration
                databag["items_total"] = total_iterations
        res = func(cur)
        if res:
            h.success('Found key: "%s"' % cur)
            return cur
        if start != None:
            consume(N - 1, iterator)

    h.failure('No matches found')



def mbruteforce(func, alphabet, length, method = 'upto', start = None, threads = None):
    """mbruteforce(func, alphabet, length, method = 'upto', start = None, threads = None)

    Same functionality as bruteforce(), but multithreaded.

    Arguments:
      func, alphabet, length, method, start: same as for bruteforce()
      threads: Amount of threads to spawn, default is the amount of cores.
    """

    def bruteforcewrap(func, alphabet, length, method, start, databag):
        oldloglevel = context.log_level
        context.log_level = 'critical'
        res = bruteforce(func, alphabet, length, method=method, start=start, databag=databag)
        context.log_level = oldloglevel
        databag["result"] = res

    if start == None:
        start = (1, 1)

    if threads == None:
        try:
            threads = multiprocessing.cpu_count()
        except NotImplementedError:
            threads = 1

    h = log.waitfor('MBruteforcing')
    processes = [None] * threads
    shareddata = [None] * threads

    (i2, N2) = start
    totalchunks = threads * N2

    for i in range(threads):
        shareddata[i] = multiprocessing.Manager().dict()
        shareddata[i]['result'] = None
        shareddata[i]['current_item'] = ""
        shareddata[i]['items_done'] = 0
        shareddata[i]['items_total'] = 0

        chunkid = (i2-1) + (i * N2) + 1

        processes[i] = multiprocessing.Process(target=bruteforcewrap,
                args=(func, alphabet, length, method, (chunkid, totalchunks),
                        shareddata[i]))
        processes[i].start()

    done = False

    while not done:
        # log status
        current_item_list = ",".join(["\"%s\"" % x["current_item"]
                                for x in shareddata if x != None])
        items_done = sum([x["items_done"] for x in shareddata if x != None])
        items_total = sum([x["items_total"] for x in shareddata if x != None])

        progress = 100.0 * items_done / items_total if items_total != 0 else 0.0

        h.status('Trying %s -- %0.3f%%' % (current_item_list, progress))

        # handle finished threads
        for i in range(threads):
            if processes[i] and processes[i].exitcode != None:
                # thread has terminated
                res = shareddata[i]["result"]
                processes[i].join()
                processes[i] = None

                # if successful, kill all other threads and return success
                if res != None:
                    for i in range(threads):
                        if processes[i] != None:
                            processes[i].terminate()
                            processes[i].join()
                            processes[i] = None
                    h.success('Found key: "%s"' % res)
                    return res

                if all([x == None for x in processes]):
                    done = True
        time.sleep(0.3)
    h.failure('No matches found')
