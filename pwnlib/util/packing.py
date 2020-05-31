 # -*- coding: utf-8 -*-
r"""
Module for packing and unpacking integers.

Simplifies access to the standard ``struct.pack`` and ``struct.unpack``
functions, and also adds support for packing/unpacking arbitrary-width
integers.

The packers are all context-aware for ``endian`` and ``signed`` arguments,
though they can be overridden in the parameters.

Examples:

    >>> p8(0)
    b'\x00'
    >>> p32(0xdeadbeef)
    b'\xef\xbe\xad\xde'
    >>> p32(0xdeadbeef, endian='big')
    b'\xde\xad\xbe\xef'
    >>> with context.local(endian='big'): p32(0xdeadbeef)
    b'\xde\xad\xbe\xef'

    Make a frozen packer, which does not change with context.

    >>> p=make_packer('all')
    >>> p(0xff)
    b'\xff'
    >>> p(0x1ff)
    b'\xff\x01'
    >>> with context.local(endian='big'): print(repr(p(0x1ff)))
    b'\xff\x01'
"""
from __future__ import absolute_import
from __future__ import division

import six
import struct
import sys

from six.moves import range

from pwnlib.context import LocalNoarchContext
from pwnlib.context import context
from pwnlib.util import iters

mod = sys.modules[__name__]

def pack(number, word_size = None, endianness = None, sign = None, **kwargs):
    """pack(number, word_size = None, endianness = None, sign = None, **kwargs) -> str

    Packs arbitrary-sized integer.

    Word-size, endianness and signedness is done according to context.

    `word_size` can be any positive number or the string "all". Choosing the
    string "all" will output a string long enough to contain all the significant
    bits and thus be decodable by :func:`unpack`.

    `word_size` can be any positive number. The output will contain word_size/8
    rounded up number of bytes. If word_size is not a multiple of 8, it will be
    padded with zeroes up to a byte boundary.

    Arguments:
        number (int): Number to convert
        word_size (int): Word size of the converted integer or the string 'all' (in bits).
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a string.

    Examples:
        >>> pack(0x414243, 24, 'big', True)
        b'ABC'
        >>> pack(0x414243, 24, 'little', True)
        b'CBA'
        >>> pack(0x814243, 24, 'big', False)
        b'\\x81BC'
        >>> pack(0x814243, 24, 'big', True)
        Traceback (most recent call last):
           ...
        ValueError: pack(): number does not fit within word_size
        >>> pack(0x814243, 25, 'big', True)
        b'\\x00\\x81BC'
        >>> pack(-1, 'all', 'little', True)
        b'\\xff'
        >>> pack(-256, 'all', 'big', True)
        b'\\xff\\x00'
        >>> pack(0x0102030405, 'all', 'little', True)
        b'\\x05\\x04\\x03\\x02\\x01'
        >>> pack(-1)
        b'\\xff\\xff\\xff\\xff'
        >>> pack(0x80000000, 'all', 'big', True)
        b'\\x00\\x80\\x00\\x00\\x00'
"""
    if sign is None and number < 0:
        sign = True

    if word_size != 'all':
        kwargs.setdefault('word_size', word_size)

    kwargs.setdefault('endianness', endianness)
    kwargs.setdefault('sign', sign)

    with context.local(**kwargs):
        # Lookup in context if not found
        word_size  = 'all' if word_size == 'all' else context.word_size
        endianness = context.endianness
        sign       = context.sign

        if not isinstance(number, six.integer_types):
            raise ValueError("pack(): number must be of type (int,long) (got %r)" % type(number))

        if sign not in [True, False]:
            raise ValueError("pack(): sign must be either True or False (got %r)" % sign)

        if endianness not in ['little', 'big']:
            raise ValueError("pack(): endianness must be either 'little' or 'big' (got %r)" % endianness)

        # Verify that word_size make sense
        if word_size == 'all':
            if number == 0:
                word_size = 8
            elif number > 0:
                if sign == False:
                    word_size = ((number.bit_length() - 1) | 7) + 1
                else:
                    word_size = (number.bit_length() | 7) + 1
            else:
                if sign == False:
                    raise ValueError("pack(): number does not fit within word_size")
                word_size = ((number + 1).bit_length() | 7) + 1
        elif not isinstance(word_size, six.integer_types) or word_size <= 0:
            raise ValueError("pack(): word_size must be a positive integer or the string 'all'")

        if sign == True:
            limit = 1 << (word_size-1)
            if not -limit <= number < limit:
                raise ValueError("pack(): number does not fit within word_size")
        else:
            limit = 1 << word_size
            if not 0 <= number < limit:
                raise ValueError("pack(): number does not fit within word_size [%i, %r, %r]" % (0, number, limit))

        # Normalize number and size now that we have verified them
        # From now on we can treat positive and negative numbers the same
        number = number & ((1 << word_size) - 1)
        byte_size = (word_size + 7) // 8

        out = []

        for _ in range(byte_size):
            out.append(_p8lu(number & 0xff))
            number = number >> 8

        if endianness == 'little':
            return b''.join(out)
        else:
            return b''.join(reversed(out))

@LocalNoarchContext
def unpack(data, word_size = None):
    """unpack(data, word_size = None, endianness = None, sign = None, **kwargs) -> int

    Packs arbitrary-sized integer.

    Word-size, endianness and signedness is done according to context.

    `word_size` can be any positive number or the string "all". Choosing the
    string "all" is equivalent to ``len(data)*8``.

    If `word_size` is not a multiple of 8, then the bits used for padding
    are discarded.

    Arguments:
        number (int): String to convert
        word_size (int): Word size of the converted integer or the string "all" (in bits).
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked number.

    Examples:
        >>> hex(unpack(b'\\xaa\\x55', 16, endian='little', sign=False))
        '0x55aa'
        >>> hex(unpack(b'\\xaa\\x55', 16, endian='big', sign=False))
        '0xaa55'
        >>> hex(unpack(b'\\xaa\\x55', 16, endian='big', sign=True))
        '-0x55ab'
        >>> hex(unpack(b'\\xaa\\x55', 15, endian='big', sign=True))
        '0x2a55'
        >>> hex(unpack(b'\\xff\\x02\\x03', 'all', endian='little', sign=True))
        '0x302ff'
        >>> hex(unpack(b'\\xff\\x02\\x03', 'all', endian='big', sign=True))
        '-0xfdfd'
    """

    # Lookup in context if not found
    word_size  = word_size  or context.word_size
    endianness = context.endianness
    sign       = context.sign

    # Verify that word_size make sense
    if word_size == 'all':
        word_size = len(data) * 8
    elif not isinstance(word_size, six.integer_types) or word_size <= 0:
        raise ValueError("unpack(): word_size must be a positive integer or the string 'all'")

    byte_size = (word_size + 7) // 8

    if byte_size != len(data):
        raise ValueError("unpack(): data must have length %d, since word_size was %d" % (byte_size, word_size))

    number = 0

    if endianness == "little":
        data = reversed(data)
    data = bytearray(data)

    for c in data:
        number = (number << 8) + c

    number = number & ((1 << word_size) - 1)

    if not sign:
        return int(number)

    signbit = number & (1 << (word_size-1))
    return int(number - 2*signbit)

@LocalNoarchContext
def unpack_many(data, word_size = None):
    """unpack(data, word_size = None, endianness = None, sign = None) -> int list

    Splits `data` into groups of ``word_size//8`` bytes and calls :func:`unpack` on each group.  Returns a list of the results.

    `word_size` must be a multiple of `8` or the string "all".  In the latter case a singleton list will always be returned.

    Args
        number (int): String to convert
        word_size (int): Word size of the converted integers or the string "all" (in bits).
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked numbers.

    Examples:
        >>> list(map(hex, unpack_many(b'\\xaa\\x55\\xcc\\x33', 16, endian='little', sign=False)))
        ['0x55aa', '0x33cc']
        >>> list(map(hex, unpack_many(b'\\xaa\\x55\\xcc\\x33', 16, endian='big', sign=False)))
        ['0xaa55', '0xcc33']
        >>> list(map(hex, unpack_many(b'\\xaa\\x55\\xcc\\x33', 16, endian='big', sign=True)))
        ['-0x55ab', '-0x33cd']
        >>> list(map(hex, unpack_many(b'\\xff\\x02\\x03', 'all', endian='little', sign=True)))
        ['0x302ff']
        >>> list(map(hex, unpack_many(b'\\xff\\x02\\x03', 'all', endian='big', sign=True)))
        ['-0xfdfd']
    """
    # Lookup in context if None
    word_size  = word_size  or context.word_size
    endianness = context.endianness
    sign       = context.sign

    if word_size == 'all':
        return [unpack(data, word_size)]

    # Currently we only group on byte boundaries
    if word_size % 8 != 0:
        raise ValueError("unpack_many(): word_size must be a multiple of 8")

    out = []
    n = word_size // 8
    for i in range(0, len(data), n):
        out.append(unpack(data[i:i+n], word_size))

    return list(map(int, out))



#
# Make individual packers, e.g. _p8lu
#
ops   = {'p': struct.pack, 'u': lambda *a: struct.unpack(*(
                                             x.encode('latin1') if not hasattr(x, 'decode') else x
                                             for x in a))[0]}
sizes = {8:'b', 16:'h', 32:'i', 64:'q'}
ends  = ['b','l']
signs = ['s','u']

def make_single(op,size,end,sign):
    name = '_%s%s%s%s' % (op, size, end, sign)
    fmt  = sizes[size]
    end = '>' if end == 'b' else '<'

    if sign == 'u':
        fmt = fmt.upper()
    fmt = end+fmt

    def routine(data):
        return ops[op](fmt,data)
    routine.__name__ = routine.__qualname__ = name

    return name, routine

for op,size,end,sign in iters.product(ops, sizes, ends, signs):
    name, routine = make_single(op,size,end,sign)
    setattr(mod, name, routine)

return_types     = {'p': 'str', 'u': 'int'}
op_verbs         = {'p': 'pack', 'u': 'unpack'}
arg_doc          = {'p': 'number (int): Number to convert',
                    'u': 'data (str): String to convert'}
rv_doc           = {'p': 'The packed number as a string',
                    'u': 'The unpacked number'}

#
# Make normal user-oriented packers, e.g. p8
#
def make_multi(op, size):

    name = "%s%s" % (op,size)

    ls = getattr(mod, "_%sls" % (name))
    lu = getattr(mod, "_%slu" % (name))
    bs = getattr(mod, "_%sbs" % (name))
    bu = getattr(mod, "_%sbu" % (name))

    @LocalNoarchContext
    def routine(number):
        endian = context.endian
        signed = context.signed
        return {("little", True  ): ls,
                ("little", False):  lu,
                ("big",    True  ): bs,
                ("big",    False):  bu}[endian, signed](number)

    routine.__name__ = name
    routine.__doc__  = """%s%s(number, sign, endian, ...) -> %s

    %ss an %s-bit integer

    Arguments:
        %s
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")
        kwargs (dict): Arguments passed to context.local(), such as
            ``endian`` or ``signed``.

    Returns:
        %s
    """ % (op, size, return_types[op], op_verbs[op].title(), size, arg_doc[op], rv_doc[op])

    return name, routine


for op,size in iters.product(ops, sizes):
    name, routine = make_multi(op,size)
    setattr(mod, name, routine)

def make_packer(word_size = None, sign = None, **kwargs):
    """make_packer(word_size = None, endianness = None, sign = None) -> number → str

    Creates a packer by "freezing" the given arguments.

    Semantically calling ``make_packer(w, e, s)(data)`` is equivalent to calling
    ``pack(data, w, e, s)``. If word_size is one of 8, 16, 32 or 64, it is however
    faster to call this function, since it will then use a specialized version.

    Arguments:
        word_size (int): The word size to be baked into the returned packer or the string all (in bits).
        endianness (str): The endianness to be baked into the returned packer. ("little"/"big")
        sign (str): The signness to be baked into the returned packer. ("unsigned"/"signed")
        kwargs: Additional context flags, for setting by alias (e.g. ``endian=`` rather than index)

    Returns:
        A function, which takes a single argument in the form of a number and returns a string
        of that number in a packed form.

    Examples:
        >>> p = make_packer(32, endian='little', sign='unsigned')
        >>> p
        <function _p32lu at 0x...>
        >>> p(42)
        b'*\\x00\\x00\\x00'
        >>> p(-1)
        Traceback (most recent call last):
            ...
        error: integer out of range for 'I' format code
        >>> make_packer(33, endian='little', sign='unsigned')
        <function ...<lambda> at 0x...>
"""
    with context.local(sign=sign, **kwargs):
        word_size  = word_size or context.word_size
        endianness = context.endianness
        sign       = sign if sign is None else context.sign

        if word_size in [8, 16, 32, 64]:
            packer = {
                (8, 0, 0):  _p8lu,
                (8, 0, 1):  _p8ls,
                (8, 1, 0):  _p8bu,
                (8, 1, 1):  _p8bs,
                (16, 0, 0): _p16lu,
                (16, 0, 1): _p16ls,
                (16, 1, 0): _p16bu,
                (16, 1, 1): _p16bs,
                (32, 0, 0): _p32lu,
                (32, 0, 1): _p32ls,
                (32, 1, 0): _p32bu,
                (32, 1, 1): _p32bs,
                (64, 0, 0): _p64lu,
                (64, 0, 1): _p64ls,
                (64, 1, 0): _p64bu,
                (64, 1, 1): _p64bs,
            }.get((word_size, {'big': 1, 'little': 0}[endianness], sign), None)

            if packer:
                return packer

        return lambda number: pack(number, word_size, endianness, sign)

@LocalNoarchContext
def make_unpacker(word_size = None, endianness = None, sign = None, **kwargs):
    """make_unpacker(word_size = None, endianness = None, sign = None,  **kwargs) -> str → number

    Creates a unpacker by "freezing" the given arguments.

    Semantically calling ``make_unpacker(w, e, s)(data)`` is equivalent to calling
    ``unpack(data, w, e, s)``. If word_size is one of 8, 16, 32 or 64, it is however
    faster to call this function, since it will then use a specialized version.

    Arguments:
        word_size (int): The word size to be baked into the returned packer (in bits).
        endianness (str): The endianness to be baked into the returned packer. ("little"/"big")
        sign (str): The signness to be baked into the returned packer. ("unsigned"/"signed")
        kwargs: Additional context flags, for setting by alias (e.g. ``endian=`` rather than index)

    Returns:
        A function, which takes a single argument in the form of a string and returns a number
        of that string in an unpacked form.

    Examples:
        >>> u = make_unpacker(32, endian='little', sign='unsigned')
        >>> u
        <function _u32lu at 0x...>
        >>> hex(u('/bin'))
        '0x6e69622f'
        >>> u('abcde')
        Traceback (most recent call last):
            ...
        error: unpack requires a string argument of length 4
        >>> make_unpacker(33, endian='little', sign='unsigned')
        <function ...<lambda> at 0x...>
"""
    word_size  = word_size or context.word_size
    endianness = context.endianness
    sign       = context.sign

    if word_size in [8, 16, 32, 64]:
        endianness = 1 if endianness == 'big'    else 0

        return {
            (8, 0, 0):  _u8lu,
            (8, 0, 1):  _u8ls,
            (8, 1, 0):  _u8bu,
            (8, 1, 1):  _u8bs,
            (16, 0, 0): _u16lu,
            (16, 0, 1): _u16ls,
            (16, 1, 0): _u16bu,
            (16, 1, 1): _u16bs,
            (32, 0, 0): _u32lu,
            (32, 0, 1): _u32ls,
            (32, 1, 0): _u32bu,
            (32, 1, 1): _u32bs,
            (64, 0, 0): _u64lu,
            (64, 0, 1): _u64ls,
            (64, 1, 0): _u64bu,
            (64, 1, 1): _u64bs,
        }[word_size, endianness, sign]
    else:
        return lambda number: unpack(number, word_size, endianness, sign)

def _fit(pieces, preprocessor, packer, filler):
    # Pulls bytes from `filler` and adds them to `pad` until it ends in `key`.
    # Returns the index of `key` in `pad`.
    pad = bytearray()
    def fill(key):
        key = bytearray(key)
        while len(pad) < len(key) or pad[-len(key):] != key:
            pad.append(next(filler))
        return len(pad) - len(key)

    # Key conversion:
    # - convert str/unicode keys to offsets
    # - convert large int (no null-bytes in a machine word) keys to offsets
    pieces_ = dict()
    large_key = 2**(context.word_size-8)
    for k, v in pieces.items():
        if isinstance(k, six.integer_types):
            if k >= large_key:
                k = fill(pack(k))
        elif isinstance(k, six.text_type):
            k = fill(k.encode('utf8'))
        elif isinstance(k, (bytearray, bytes)):
            k = fill(k)
        else:
            raise TypeError("flat(): offset must be of type int or str, but got '%s'" % type(k))
        if k in pieces_:
            raise ValueError("flag(): multiple values at offset %d" % k)
        pieces_[k] = v
    pieces = pieces_

    # We must "roll back" `filler` so each recursive call to `_flat` gets it in
    # the right position
    filler = iters.chain(pad, filler)

    # Build output
    out = b''
    for k, v in sorted(pieces.items()):
        if k < len(out):
            raise ValueError("flat(): data at offset %d overlaps with previous data which ends at offset %d" % (k, len(out)))

        # Fill up to offset
        while len(out) < k:
            out += p8(next(filler))

        # Recursively flatten data
        out += _flat([v], preprocessor, packer, filler)

    return filler, out

def _flat(args, preprocessor, packer, filler):
    out = []
    for arg in args:

        if not isinstance(arg, (list, tuple, dict)):
            arg_ = preprocessor(arg)
            if arg_ != None:
                arg = arg_

        if hasattr(arg, '__flat__'):
            val = arg.__flat__()
        elif isinstance(arg, (list, tuple)):
            val = _flat(arg, preprocessor, packer, filler)
        elif isinstance(arg, dict):
            filler, val = _fit(arg, preprocessor, packer, filler)
        elif isinstance(arg, bytes):
            val = arg
        elif isinstance(arg, six.text_type):
            val = arg.encode('utf8')
        elif isinstance(arg, six.integer_types):
            val = packer(arg)
        elif isinstance(arg, bytearray):
            val = str(arg)
        else:
            raise ValueError("flat(): Flat does not support values of type %s" % type(arg))

        out.append(val)

        # Advance `filler` for "non-recursive" values
        if not isinstance(arg, (list, tuple, dict)):
            for _ in range(len(val)):
                next(filler)

    return b''.join(out)

@LocalNoarchContext
def flat(*args, **kwargs):
    r"""flat(\*args, preprocessor = None, length = None, filler = de_bruijn(),
     word_size = None, endianness = None, sign = None) -> str

    Flattens the arguments into a string.

    This function takes an arbitrary number of arbitrarily nested lists, tuples
    and dictionaries.  It will then find every string and number inside those
    and flatten them out.  Strings are inserted directly while numbers are
    packed using the :func:`pack` function.  Unicode strings are UTF-8 encoded.

    Dictionary keys give offsets at which to place the corresponding values
    (which are recursively flattened).  Offsets are relative to where the
    flattened dictionary occurs in the output (i.e. `{0: 'foo'}` is equivalent
    to `'foo'`).  Offsets can be integers, unicode strings or regular strings.
    Integer offsets >= ``2**(word_size-8)`` are converted to a string using
    `:func:pack`.  Unicode strings are UTF-8 encoded.  After these conversions
    offsets are either integers or strings.  In the latter case, the offset will
    be the lowest index at which the string occurs in `filler`.  See examples
    below.

    Space between pieces of data is filled out using the iterable `filler`.  The
    `n`'th byte in the output will be byte at index ``n % len(iterable)`` byte
    in `filler` if it has finite length or the byte at index `n` otherwise.

    If `length` is given, the output will be padded with bytes from `filler` to
    be this size.  If the output is longer than `length`, a :py:exc:`ValueError`
    exception is raised.

    The three kwargs `word_size`, `endianness` and `sign` will default to using
    values in :mod:`pwnlib.context` if not specified as an argument.

    Arguments:
      args: Values to flatten
      preprocessor (function): Gets called on every element to optionally
         transform the element before flattening. If :const:`None` is
         returned, then the original value is used.
      length: The length of the output.
      filler: Iterable to use for padding.
      word_size (int): Word size of the converted integer.
      endianness (str): Endianness of the converted integer ("little"/"big").
      sign (str): Signedness of the converted integer (False/True)

    Examples:
      >>> flat(1, "test", [[["AB"]*2]*3], endianness = 'little', word_size = 16, sign = False)
      b'\x01\x00testABABABABABAB'
      >>> flat([1, [2, 3]], preprocessor = lambda x: str(x+1))
      b'234'
      >>> flat({12: 0x41414141,
      ...       24: 'Hello',
      ...      })
      b'aaaabaaacaaaAAAAeaaafaaaHello'
      >>> flat({'caaa': ''})
      b'aaaabaaa'
      >>> flat({12: 'XXXX'}, filler = (ord('A'), ord('B')), length = 20)
      b'ABABABABABABXXXXABAB'
      >>> flat({ 8: [0x41414141, 0x42424242],
      ...       20: 'CCCC'})
      b'aaaabaaaAAAABBBBeaaaCCCC'
      >>> flat({ 0x61616162: 'X'})
      b'aaaaX'
      >>> flat({4: {0: 'X', 4: 'Y'}})
      b'aaaaXaaaY'

    """
    # HACK: To avoid circular imports we need to delay the import of `cyclic`
    from pwnlib.util import cyclic

    preprocessor = kwargs.pop('preprocessor', lambda x: None)
    filler       = kwargs.pop('filler', cyclic.de_bruijn())
    length       = kwargs.pop('length', None)

    if kwargs != {}:
        raise TypeError("flat() does not support argument %r" % kwargs.popitem()[0])

    filler = iters.cycle(filler)
    out = _flat(args, preprocessor, make_packer(), filler)

    if length:
        if len(out) > length:
            raise ValueError("flat(): Arguments does not fit within `length` (= %d) bytes" % length)
        out += b''.join(p8(next(filler)) for _ in range(length - len(out)))

    return out

def fit(*args, **kwargs):
    """Legacy alias for `:func:flat`"""
    return flat(*args, **kwargs)

"""
    Generates a string from a dictionary mapping offsets to data to place at
    that offset.

    For each key-value pair in `pieces`, the key is either an offset or a byte
    sequence.  In the latter case, the offset will be the lowest index at which
    the sequence occurs in `filler`.  See examples below.

    Each piece of data is passed to :meth:`flat` along with the keyword
    arguments `word_size`, `endianness` and `sign`.

    Space between pieces of data is filled out using the iterable `filler`.  The
    `n`'th byte in the output will be byte at index ``n % len(iterable)`` byte
    in `filler` if it has finite length or the byte at index `n` otherwise.

    If `length` is given, the output will padded with bytes from `filler` to be
    this size.  If the output is longer than `length`, a :py:exc:`ValueError`
    exception is raised.

    If entries in `pieces` overlap, a :py:exc:`ValueError` exception is
    raised.

    Arguments:
      pieces: Offsets and values to output.
      length: The length of the output.
      filler: Iterable to use for padding.
      preprocessor (function): Gets called on every element to optionally
         transform the element before flattening. If :const:`None` is
         returned, then the original value is used.
      word_size (int): Word size of the converted integer (in bits).
      endianness (str): Endianness of the converted integer ("little"/"big").
      sign (str): Signedness of the converted integer (False/True)

    Examples:

    """

def signed(integer):
    return unpack(pack(integer), signed=True)

def unsigned(integer):
    return unpack(pack(integer))

def dd(dst, src, count = 0, skip = 0, seek = 0, truncate = False):
    """dd(dst, src, count = 0, skip = 0, seek = 0, truncate = False) -> dst

    Inspired by the command line tool ``dd``, this function copies `count` byte
    values from offset `seek` in `src` to offset `skip` in `dst`.  If `count` is
    0, all of ``src[seek:]`` is copied.

    If `dst` is a mutable type it will be updated.  Otherwise a new instance of
    the same type will be created.  In either case the result is returned.

    `src` can be an iterable of characters or integers, a unicode string or a
    file object.  If it is an iterable of integers, each integer must be in the
    range [0;255].  If it is a unicode string, its UTF-8 encoding will be used.

    The seek offset of file objects will be preserved.

    Arguments:
        dst: Supported types are `:class:file`, `:class:list`, `:class:tuple`,
             `:class:str`, `:class:bytearray` and `:class:unicode`.
        src: An iterable of byte values (characters or integers), a unicode
             string or a file object.
        count (int): How many bytes to copy.  If `count` is 0 or larger than
                     ``len(src[seek:])``, all bytes until the end of `src` are
                     copied.
        skip (int): Offset in `dst` to copy to.
        seek (int): Offset in `src` to copy from.
        truncate (bool): If `:const:True`, `dst` is truncated at the last copied
                         byte.

    Returns:
        A modified version of `dst`.  If `dst` is a mutable type it will be
        modified in-place.

    Examples:
        >>> dd(tuple('Hello!'), b'?', skip = 5)
        ('H', 'e', 'l', 'l', 'o', b'?')
        >>> dd(list('Hello!'), (63,), skip = 5)
        ['H', 'e', 'l', 'l', 'o', b'?']
        >>> _ = open('/tmp/foo', 'w').write('A' * 10)
        >>> dd(open('/tmp/foo'), open('/dev/zero'), skip = 3, count = 4).read()
        'AAA\\x00\\x00\\x00\\x00AAA'
        >>> _ = open('/tmp/foo', 'w').write('A' * 10)
        >>> dd(open('/tmp/foo'), open('/dev/zero'), skip = 3, count = 4, truncate = True).read()
        'AAA\\x00\\x00\\x00\\x00'
    """

    # Re-open file objects to make sure we have the mode right
    if hasattr(src, 'name'):
        src = open(src.name, 'rb')
    if hasattr(dst, 'name'):
        real_dst = dst
        dst = open(dst.name, 'rb+')

    # Special case: both `src` and `dst` are files, so we don't need to hold
    # everything in memory
    if hasattr(src, 'seek') and hasattr(dst, 'seek'):
        src.seek(seek)
        dst.seek(skip)
        n = 0
        if count:
            while n < count:
                s = src.read(min(count - n, 0x1000))
                if not s:
                    break
                n += len(s)
                dst.write(s)
        else:
            while True:
                s = src.read(0x1000)
                if not s:
                    break
                n += len(s)
                dst.write(s)
        if truncate:
            dst.truncate(skip + n)
        src.close()
        dst.close()
        return real_dst

    # Otherwise get `src` in canonical form, i.e. a string of at most `count`
    # bytes
    if isinstance(src, six.text_type):
        if count:
            # The only way to know where the `seek`th byte is, is to decode, but
            # we only need to decode up to the first `seek + count` code points
            src = src[:seek + count].encode('utf8')
            # The code points may result in more that `seek + count` bytes
            src = src[seek : seek + count]
        else:
            src = src.encode('utf8')[seek:]

    elif hasattr(src, 'seek'):
        src.seek(seek)
        src_ = b''
        if count:
            while len(src_) < count:
                s = src.read(count - len(src_))
                if not s:
                    break
                src_ += s
        else:
            while True:
                s = src.read()
                if not s:
                    break
                src_ += s
        src.close()
        src = src_

    elif isinstance(src, bytes):
        if count:
            src = src[seek : seek + count]
        else:
            src = src[seek:]

    elif hasattr(src, '__iter__'):
        src = src[seek:]
        src_ = b''
        for i, b in enumerate(src, seek):
            if count and i > count + seek:
                break
            if isinstance(b, bytes):
                src_ += b
            elif isinstance(b, six.integer_types):
                if b > 255 or b < 0:
                    raise ValueError("dd(): Source value %d at index %d is not in range [0;255]" % (b, i))
                src_ += _p8lu(b)
            else:
                raise TypeError("dd(): Unsupported `src` element type: %r" % type(b))
        src = src_

    else:
        raise TypeError("dd(): Unsupported `src` type: %r" % type(src))

    # If truncate, then where?
    if truncate:
        truncate = skip + len(src)

    # UTF-8 encode unicode `dst`
    if isinstance(dst, six.text_type):
        dst = dst.encode('utf8')
        utf8 = True
    else:
        utf8 = False

    # Match on the type of `dst`
    if   hasattr(dst, 'seek'):
        dst.seek(skip)
        dst.write(src)
        if truncate:
            dst.truncate(truncate)
        dst.close()
        dst = real_dst

    elif isinstance(dst, (list, bytearray)):
        dst[skip : skip + len(src)] = list(map(p8, bytearray(src)))
        if truncate:
            while len(dst) > truncate:
                dst.pop()

    elif isinstance(dst, tuple):
        tail = dst[skip + len(src):]
        dst = dst[:skip] + tuple(map(p8, bytearray(src)))
        if not truncate:
            dst = dst + tail

    elif isinstance(dst, bytes):
        tail = dst[skip + len(src):]
        dst = dst[:skip] + src
        if not truncate:
            dst = dst + tail

    else:
        raise TypeError("dd(): Unsupported `dst` type: %r" % type(dst))

    if utf8:
        dst = dst.decode('utf8')

    return dst
