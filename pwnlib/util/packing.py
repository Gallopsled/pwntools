 # -*- coding: utf-8 -*-

from .. import context
import struct

def pack(number, word_size = None, endianness = None, sign = None):
    """pack(number, word_size = None, endianness = None, sign = None) -> str

    Packs arbitrary-sized integer.

    Word-size, endianness and signedness is done according to context.

    `word_size` can be any positive number or the string "all". Choosing the
    string "all" will output a string long enough to contain all the significant
    bits and thus be decodable by :func:`unpack`.

    `word_size` can be any positive number. The output will contain word_size/8
    rounded up number of bytes. If word_size is not a multiple of 8, it will be
    padded with zeroes up to a byte boundary.

    Args:
        number (int): Number to convert
        word_size (int): Word size of the converted integer or the string 'all'.
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string.

    Examples:
        >>> pack(0x414243, 24, 'big', 'signed')
        'ABC'
        >>> pack(0x414243, 24, 'little', 'signed')
        'CBA'
        >>> pack(0x814243, 24, 'big', 'unsigned')
        '\\x81BC'
        >>> pack(0x814243, 24, 'big', 'signed')
        Traceback (most recent call last):
           ...
        ValueError: pack(): number does not fit within word_size
        >>> pack(0x814243, 25, 'big', 'signed')
        '\\x00\\x81BC'
        >>> pack(-1, 'all', 'little', 'signed')
        '\\xff'
        >>> pack(-256, 'all', 'big', 'signed')
        '\\xff\\x00'
        >>> pack(0x0102030405, 'all', 'little', 'signed')
        '\\x05\\x04\\x03\\x02\\x01'
"""

    # Lookup in context if not found
    word_size  = word_size  or context.word_size
    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    if sign not in ['signed', 'unsigned']:
        raise ValueError("pack(): sign must be either 'signed' or 'unsigned'")

    if endianness not in ['little', 'big']:
        raise ValueError("pack(): endianness must be either 'little' or 'big'")

    # Verify that word_size make sense
    if word_size == 'all':
        if number == 0:
            word_size = 8
        elif number > 0:
            word_size = ((number.bit_length() - 1) | 7) + 1
        else:
            if sign == 'unsigned':
                raise ValueError("pack(): number does not fit within word_size")
            word_size = ((number + 1).bit_length() | 7) + 1
    elif not isinstance(word_size, (int, long)) or word_size <= 0:
        raise ValueError("pack(): word_size must be a positive integer or the string 'all'")

    if sign == 'signed':
        limit = 1 << (word_size-1)
        if not -limit <= number < limit:
            raise ValueError("pack(): number does not fit within word_size")
    else:
        limit = 1 << word_size
        if not 0 <= number < limit:
            raise ValueError("pack(): number does not fit within word_size")

    # Normalize number and size now that we have verified them
    # From now on we can treat positive and negative numbers the same
    number = number & ((1 << word_size) - 1)
    byte_size = (word_size + 7) / 8

    out = []

    for _ in range(byte_size):
        out.append(chr(number & 0xff))
        number = number >> 8

    if endianness == 'little':
        return ''.join(out)
    else:
        return ''.join(reversed(out))


def unpack(data, word_size = None, endianness = None, sign = None):
    """unpack(data, word_size = None, endianness = None, sign = None) -> int

    Packs arbitrary-sized integer.

    Word-size, endianness and signedness is done according to context.

    `word_size` can be any positive number or the string "all". Choosing the
    string "all" is equivalent to ``len(data)*8``.

    If `word_size` is not a multiple of 8, then the bits used for padding
    are discarded.

    Args:
        number (int): String to convert
        word_size (int): Word size of the converted integer or the string "all".
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number.

    Examples:
        >>> hex(unpack('\\xaa\\x55', 16, 'little', 'unsigned'))
        '0x55aa'
        >>> hex(unpack('\\xaa\\x55', 16, 'big', 'unsigned'))
        '0xaa55'
        >>> hex(unpack('\\xaa\\x55', 16, 'big', 'signed'))
        '-0x55ab'
        >>> hex(unpack('\\xaa\\x55', 15, 'big', 'signed'))
        '0x2a55'
        >>> hex(unpack('\\xff\\x02\\x03', 'all', 'little', 'signed'))
        '0x302ff'
        >>> hex(unpack('\\xff\\x02\\x03', 'all', 'big', 'signed'))
        '-0xfdfd'
    """

    # Lookup in context if not found
    word_size  = word_size  or context.word_size
    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    # Verify that word_size make sense
    if word_size == 'all':
        word_size = len(data) * 8
    elif not isinstance(word_size, (int, long)) or word_size <= 0:
        raise ValueError("unpack(): word_size must be a positive integer or the string 'all'")

    byte_size = (word_size + 7) / 8

    if byte_size != len(data):
        raise ValueError("unpack(): data must have length %d, since word_size was %d" % (byte_size, word_size))

    number = 0

    if endianness == "little":
        for c in reversed(data):
            number = (number << 8) + ord(c)
    elif endianness == "big":
        for c in data:
            number = (number << 8) + ord(c)
    else:
        raise ValueError("endianness must be either 'little' or 'big'")

    number = number & ((1 << word_size) - 1)

    if sign == "unsigned":
        return number
    elif sign == "signed":
        signbit = number & (1 << (word_size-1))
        return number - 2*signbit
    else:
        raise ValueError("unpack(): sign must be either 'signed' or 'unsigned'")


def unpack_many(data, word_size = None, endianness = None, sign = None):
    """unpack(data, word_size = None, endianness = None, sign = None) -> int list

    Splits `data` into groups of ``word_size//8`` bytes and calls :func:`unpack` on each group.  Returns a list of the results.

    `word_size` must be a multiple of `8` or the string "all".  In the latter case a singleton list will always be returned.

    Args
        number (int): String to convert
        word_size (int): Word size of the converted integers or the string "all".
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked numbers.

    Examples:
        >>> map(hex, unpack_many('\\xaa\\x55\\xcc\\x33', 16, 'little', 'unsigned'))
        ['0x55aa', '0x33cc']
        >>> map(hex, unpack_many('\\xaa\\x55\\xcc\\x33', 16, 'big', 'unsigned'))
        ['0xaa55', '0xcc33']
        >>> map(hex, unpack_many('\\xaa\\x55\\xcc\\x33', 16, 'big', 'signed'))
        ['-0x55ab', '-0x33cd']
        >>> map(hex, unpack_many('\\xff\\x02\\x03', 'all', 'little', 'signed'))
        ['0x302ff']
        >>> map(hex, unpack_many('\\xff\\x02\\x03', 'all', 'big', 'signed'))
        ['-0xfdfd']
    """

    # Lookup in context if None
    word_size  = word_size  or context.word_size

    if word_size == 'all':
        return [unpack(data, word_size, endianness, sign)]

    # Currently we only group on byte boundaries
    if word_size % 8 != 0:
        raise ValueError("unpack_many(): word_size must be a multiple of 8")

    out = []
    n = word_size // 8
    for i in range(0, len(data), n):
        out.append(unpack(data[i:i+n], word_size, endianness, sign))

    return out


def p8(number, endianness = None, sign = None):
    """p8(number, endianness = None, sign = None) -> str

    Packs 8-bit integer.
    Endianness and signedness is done according to context.

    This is a faster special case of calling :func:`pack` with ``word_size = 8``.

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""

    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    return {("little", "signed"  ): _p8ls,
            ("little", "unsigned"): _p8lu,
            ("big",    "signed"  ): _p8bs,
            ("big",    "unsigned"): _p8bu}[endianness, sign](number)


def p16(number, endianness = None, sign = None):
    """p16(number, endianness = None, sign = None) -> str

    Packs 16-bit integer.
    Endianness and signedness is done according to context.

    This is a faster special case of calling :func:`pack` with ``word_size = 16``.

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""

    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    return {("little", "signed"  ): _p16ls,
            ("little", "unsigned"): _p16lu,
            ("big",    "signed"  ): _p16bs,
            ("big",    "unsigned"): _p16bu}[endianness, sign](number)


def p32(number, endianness = None, sign = None):
    """p32(number, endianness = None, sign = None) -> str

    Packs 32-bit integer.
    Endianness and signedness is done according to context.

    This is a faster special case of calling :func:`pack` with ``word_size = 32``.

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""

    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    return {("little", "signed"  ): _p32ls,
            ("little", "unsigned"): _p32lu,
            ("big",    "signed"  ): _p32bs,
            ("big",    "unsigned"): _p32bu}[endianness, sign](number)


def p64(number, endianness = None, sign = None):
    """p64(number, endianness = None, sign = None) -> str

    Packs 64-bit integer.
    Endianness and signedness is done according to context.

    This is a faster special case of calling :func:`pack` with ``word_size = 64``.

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""

    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    return {("little", "signed"  ): _p64ls,
            ("little", "unsigned"): _p64lu,
            ("big",    "signed"  ): _p64bs,
            ("big",    "unsigned"): _p64bu}[endianness, sign](number)


def u8(data, endianness = None, sign = None):
    """u8(data, endianness = None, sign = None) -> int

    Unpacks 8-bit integer.
    Endianness and signedness is done according to context.

    This is a faster special case of calling :func:`unpack` with ``word_size = 8``.

    Args:
        data (str): String to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""

    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    return {("little", "signed"  ): _u8ls,
            ("little", "unsigned"): _u8lu,
            ("big",    "signed"  ): _u8bs,
            ("big",    "unsigned"): _u8bu}[endianness, sign](data)


def u16(data, endianness = None, sign = None):
    """u16(data, endianness = None, sign = None) -> int

    Unpacks 16-bit integer.
    Endianness and signedness is done according to context.

    This is a faster special case of calling :func:`unpack` with ``word_size = 16``.

    Args:
        data (str): String to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""

    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    return {("little", "signed"  ): _u16ls,
            ("little", "unsigned"): _u16lu,
            ("big",    "signed"  ): _u16bs,
            ("big",    "unsigned"): _u16bu}[endianness, sign](data)


def u32(data, endianness = None, sign = None):
    """u32(data, endianness = None, sign = None) -> int

    Unpacks 32-bit integer.
    Endianness and signedness is done according to context.

    This is a faster special case of calling :func:`unpack` with ``word_size = 32``.

    Args:
        data (str): String to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""

    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    return {("little", "signed"  ): _u32ls,
            ("little", "unsigned"): _u32lu,
            ("big",    "signed"  ): _u32bs,
            ("big",    "unsigned"): _u32bu}[endianness, sign](data)


def u64(data, endianness = None, sign = None):
    """u64(data, endianness = None, sign = None) -> int

    Unpacks 64-bit integer.
    Endianness and signedness is done according to context.

    This is a faster special case of calling :func:`unpack` with ``word_size = 64``.

    Args:
        data (str): String to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""

    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    return {("little", "signed"  ): _u64ls,
            ("little", "unsigned"): _u64lu,
            ("big",    "signed"  ): _u64bs,
            ("big",    "unsigned"): _u64bu}[endianness, sign](data)


def _u8lu(data):
    return struct.unpack("<B", data)[0]


def _u8ls(data):
    return struct.unpack("<b", data)[0]


def _u8bu(data):
    return struct.unpack(">B", data)[0]


def _u8bs(data):
    return struct.unpack(">b", data)[0]


def _u16lu(data):
    return struct.unpack("<H", data)[0]


def _u16ls(data):
    return struct.unpack("<h", data)[0]


def _u16bu(data):
    return struct.unpack(">H", data)[0]


def _u16bs(data):
    return struct.unpack(">h", data)[0]


def _u32lu(data):
    return struct.unpack("<I", data)[0]


def _u32ls(data):
    return struct.unpack("<i", data)[0]


def _u32bu(data):
    return struct.unpack(">I", data)[0]


def _u32bs(data):
    return struct.unpack(">i", data)[0]


def _u64lu(data):
    return struct.unpack("<Q", data)[0]


def _u64ls(data):
    return struct.unpack("<q", data)[0]


def _u64bu(data):
    return struct.unpack(">Q", data)[0]


def _u64bs(data):
    return struct.unpack(">q", data)[0]


def _p8lu(number):
    return struct.pack("<B", number)


def _p8ls(number):
    return struct.pack("<b", number)


def _p8bu(number):
    return struct.pack(">B", number)


def _p8bs(number):
    return struct.pack(">b", number)


def _p16lu(number):
    return struct.pack("<H", number)


def _p16ls(number):
    return struct.pack("<h", number)


def _p16bu(number):
    return struct.pack(">H", number)


def _p16bs(number):
    return struct.pack(">h", number)


def _p32lu(number):
    return struct.pack("<I", number)


def _p32ls(number):
    return struct.pack("<i", number)


def _p32bu(number):
    return struct.pack(">I", number)


def _p32bs(number):
    return struct.pack(">i", number)


def _p64lu(number):
    return struct.pack("<Q", number)


def _p64ls(number):
    return struct.pack("<q", number)


def _p64bu(number):
    return struct.pack(">Q", number)


def _p64bs(number):
    return struct.pack(">q", number)


def make_packer(word_size = None, endianness = None, sign = None):
    """make_packer(word_size = None, endianness = None, sign = None) -> number → str

    Creates a packer by "freezing" the given arguments.

    Semantically calling ``make_packer(w, e, s)(data)`` is equivalent to calling
    ``pack(data, w, e, s)``. If word_size is one of 8, 16, 32 or 64, it is however
    faster to call this function, since it will then use a specialized version.

    Args:
        word_size (int): The word size to be baked into the returned packer or the string all.
        endianness (str): The endianness to be baked into the returned packer. ("little"/"big")
        sign (str): The signness to be baked into the returned packer. ("unsigned"/"signed")

    Returns:
        A function, which takes a single argument in the form of a number and returns a string
        of that number in a packed form.

    Examples:
        >>> p = make_packer(32, 'little', 'unsigned')
        >>> p
        <function _p32lu at 0x...>
        >>> p(42)
        '*\\x00\\x00\\x00'
        >>> p(-1)
        Traceback (most recent call last):
            ...
        error: integer out of range for 'I' format code
        >>> make_packer(33, 'little', 'unsigned')
        <function <lambda> at 0x...>
"""

    word_size  = word_size  or context.word_size
    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    if not isinstance(word_size, (int, long)) and word_size > 0:
        raise ValueError("make_packer(): word_size needs to be a positive integer")

    if endianness not in ['little', 'big']:
        raise ValueError("make_packer(): endianness needs to be the string 'little' or 'big'")

    if sign not in ['signed', 'unsigned']:
        raise ValueError("make_packer(): sign needs to be the string 'signed' or 'unsigned'")

    if word_size in [8, 16, 32, 64]:
        sign       = 1 if sign       == 'signed' else 0
        endianness = 1 if endianness == 'big'    else 0

        return {
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
        }[word_size, endianness, sign]
    else:
        return lambda number: pack(number, word_size, endianness, sign)

def make_unpacker(word_size = None, endianness = None, sign = None):
    """make_unpacker(word_size = None, endianness = None, sign = None) -> str → number

    Creates a unpacker by "freezing" the given arguments.

    Semantically calling ``make_unpacker(w, e, s)(data)`` is equivalent to calling
    ``unpack(data, w, e, s)``. If word_size is one of 8, 16, 32 or 64, it is however
    faster to call this function, since it will then use a specialized version.

    Args:
        word_size (int): The word size to be baked into the returned packer.
        endianness (str): The endianness to be baked into the returned packer. ("little"/"big")
        sign (str): The signness to be baked into the returned packer. ("unsigned"/"signed")

    Returns:
        A function, which takes a single argument in the form of a string and returns a number
        of that string in an unpacked form.

    Examples:
        >>> u = make_unpacker(32, 'little', 'unsigned')
        >>> u
        <function _u32lu at 0x...>
        >>> hex(u('/bin'))
        '0x6e69622f'
        >>> u('abcde')
        Traceback (most recent call last):
            ...
        error: unpack requires a string argument of length 4
        >>> make_unpacker(33, 'little', 'unsigned')
        <function <lambda> at 0x...>
"""

    word_size  = word_size  or context.word_size
    endianness = endianness or context.endianness
    sign       = sign       or context.sign

    if not (word_size == 'all' or isinstance(word_size, (int, long)) and word_size > 0):
        raise ValueError("make_unpacker(): word_size needs to be a positive integer")

    if endianness not in ['little', 'big']:
        raise ValueError("make_unpacker(): endianness needs to be the string 'little' or 'big'")

    if sign not in ['signed', 'unsigned']:
        raise ValueError("make_unpacker(): sign needs to be the string 'signed' or 'unsigned'")

    if word_size in [8, 16, 32, 64]:
        sign       = 1 if sign       == 'signed' else 0
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


def _flat(args, preprocessor, packer):
    out = []
    for arg in args:

        if not isinstance(arg, (list, tuple)):
            arg_ = preprocessor(arg)
            if arg_ != None:
                arg = arg_

        if isinstance(arg, (list, tuple)):
            out.append(_flat(arg, preprocessor, packer))
        elif isinstance(arg, str):
            out.append(arg)
        elif isinstance(arg, unicode):
            out.append(arg.encode('utf8'))
        elif isinstance(arg, (int, long)):
            out.append(packer(arg))
        else:
            raise ValueError("flat(): Flat does not support values of type %s" % type(arg))
    return ''.join(out)


def flat(*args, **kwargs):
    """flat(*args, preprocessor = None, word_size = None, endianness = None, sign = None)

    Flattens the arguments into a string.

    This function takes an arbitrary number of arbitrarily nested lists and
    tuples. It will then find every string and number inside those and flatten
    them out. Strings are inserted directly while numbers are packed using the
    :func:`pack` function.

    The three kwargs `word_size`, `endianness` and `sign` will default to using
    values in :mod:`pwnlib.context` if not specified as an argument.

    Args:
      args: Values to flatten
      preprocessor (function): Gets called on every element to optionally
         transform the element before flattening. If :const:`None` is
         returned, then the original value is uded.
      word_size (int): Word size of the converted integer.
      endianness (str): Endianness of the converted integer ("little"/"big").
      sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Examples:
      >>> flat(1, "test", [[["AB"]*2]*3], endianness = 'little', word_size = 16, sign = 'unsigned')
      '\\x01\\x00testABABABABABAB'
      >>> flat([1, [2, 3]], preprocessor = lambda x: str(x+1))
      '234'
"""

    preprocessor = kwargs.pop('preprocessor', lambda x: None)
    word_size    = kwargs.pop('word_size', None)
    endianness   = kwargs.pop('endianness', None)
    sign         = kwargs.pop('sign', None)

    if kwargs != {}:
        raise TypeError("flat() does not support argument %r" % kwargs.popitem()[0])

    return _flat(args, preprocessor, make_packer(word_size, endianness, sign))
