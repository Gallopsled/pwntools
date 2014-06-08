from pwnlib import context
import struct

def pack(number, word_size=None, endianness=None, sign=None):
    """Packs arbitrary-sized integer.

    Word-size, endianness and signedness is done according to context.

    word_size can be any positive number. The output will contain word_size/8
    rounded up number of bytes. If word_size is not a multiple of 8, it will be
    padded with zeroes up to a byte boundary.

    Args:
        number (int): Number to convert
        word_size (int): Word size of the converted integer
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""

    # Lookup in context if not found
    if word_size == None:
        word_size = context.word_size
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign

    # Verify that word_size make sense
    if not isinstance(word_size, (int, long)) or word_size <= 0:
        raise ValueError("word_size must be a positive integer")

    if sign == 'signed':
        limit = 1 << (word_size-1)
        if not (-limit <= number < limit):
            raise ValueError("number does not fit within word_size")
    elif sign == 'unsigned':
        limit = 1 << word_size
        if not (0 <= number < limit):
            raise ValueError("number does not fit within word_size")
    else:
        raise ValueError("sign must be either 'signed' or 'unsigned'")

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
    elif endianness == 'big':
        return ''.join(reversed(out))
    else:
        raise ValueError("endianness must be either 'little' or 'big'")


def unpack(data, word_size=None, endianness=None, sign=None):
    """Packs arbitrary-sized integer.

    Word-size, endianness and signedness is done according to context.

    word_size can be any positive number. If word_size is not a multiple of 8,
    it will be, then the bits used for padding are discarded.

    Args:
        number (int): Number to convert
        word_size (int): Word size of the converted integer
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""

    # Lookup in context if not found
    if word_size == None:
        word_size = context.word_size
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign

    # Verify that word_size make sense
    if not isinstance(word_size, (int, long)) or word_size <= 0:
        raise ValueError("word_size must be a positive integer")

    byte_size = (word_size + 7) / 8

    if byte_size != len(data):
        raise ValueError("data must have length %d, since word_size was %d" % (byte_size, word_size))

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
        raise ValueError("sign must be either 'signed' or 'unsigned'")


def p8(number, endianness=None, sign=None):
    """Packs 8-bit integer.
    Endianness and signedness is done according to context.

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign
    return {("little", "signed"  ): p8ls,
            ("little", "unsigned"): p8lu,
            ("big",    "signed"  ): p8bs,
            ("big",    "unsigned"): p8bu}[endianness, sign](number)


def p16(number, endianness=None, sign=None):
    """Packs 16-bit integer.
    Endianness and signedness is done according to context.

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign
    return {("little", "signed"  ): p16ls,
            ("little", "unsigned"): p16lu,
            ("big",    "signed"  ): p16bs,
            ("big",    "unsigned"): p16bu}[endianness, sign](number)


def p32(number, endianness=None, sign=None):
    """Packs 32-bit integer.
    Endianness and signedness is done according to context.

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign
    return {("little", "signed"  ): p32ls,
            ("little", "unsigned"): p32lu,
            ("big",    "signed"  ): p32bs,
            ("big",    "unsigned"): p32bu}[endianness, sign](number)


def p64(number, endianness=None, sign=None):
    """Packs 64-bit integer.
    Endianness and signedness is done according to context.

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The packed number as a string"""
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign
    return {("little", "signed"  ): p64ls,
            ("little", "unsigned"): p64lu,
            ("big",    "signed"  ): p64bs,
            ("big",    "unsigned"): p64bu}[endianness, sign](number)


def u8(data, endianness=None, sign=None):
    """Unpacks 8-bit integer.
    Endianness and signedness is done according to context.

    Args:
        data (str): stuff to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign
    return {("little", "signed"  ): u8ls,
            ("little", "unsigned"): u8lu,
            ("big",    "signed"  ): u8bs,
            ("big",    "unsigned"): u8bu}[endianness, sign](data)


def u16(data, endianness=None, sign=None):
    """Unpacks 16-bit integer.
    Endianness and signedness is done according to context.

    Args:
        data (str): stuff to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign
    return {("little", "signed"  ): u16ls,
            ("little", "unsigned"): u16lu,
            ("big",    "signed"  ): u16bs,
            ("big",    "unsigned"): u16bu}[endianness, sign](data)


def u32(data, endianness=None, sign=None):
    """Unpacks 32-bit integer.
    Endianness and signedness is done according to context.

    Args:
        data (str): stuff to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign
    return {("little", "signed"  ): u32ls,
            ("little", "unsigned"): u32lu,
            ("big",    "signed"  ): u32bs,
            ("big",    "unsigned"): u32bu}[endianness, sign](data)


def u64(data, endianness=None, sign=None):
    """Unpacks 64-bit integer.
    Endianness and signedness is done according to context.

    Args:
        data (str): stuff to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        The unpacked number"""
    if endianness == None:
        endianness = context.endianness
    if sign == None:
        sign = context.sign
    return {("little", "signed"  ): u64ls,
            ("little", "unsigned"): u64lu,
            ("big",    "signed"  ): u64bs,
            ("big",    "unsigned"): u64bu}[endianness, sign](data)


def u8lu(data):
    return struct.unpack("<B", data)[0]


def u8ls(data):
    return struct.unpack("<s", data)[0]


def u8bu(data):
    return struct.unpack(">B", data)[0]


def u8bs(data):
    return struct.unpack(">s", data)[0]


def u16lu(data):
    return struct.unpack("<H", data)[0]


def u16ls(data):
    return struct.unpack("<h", data)[0]


def u16bu(data):
    return struct.unpack(">H", data)[0]


def u16bs(data):
    return struct.unpack(">h", data)[0]


def u32lu(data):
    return struct.unpack("<I", data)[0]


def u32ls(data):
    return struct.unpack("<i", data)[0]


def u32bu(data):
    return struct.unpack(">I", data)[0]


def u32bs(data):
    return struct.unpack(">i", data)[0]


def u64lu(data):
    return struct.unpack("<Q", data)[0]


def u64ls(data):
    return struct.unpack("<q", data)[0]


def u64bu(data):
    return struct.unpack(">Q", data)[0]


def u64bs(data):
    return struct.unpack(">q", data)[0]


def p8lu(number):
    return struct.pack("<B", number)


def p8ls(number):
    return struct.pack("<b", number)


def p8bu(number):
    return struct.pack(">B", number)


def p8bs(number):
    return struct.pack(">b", number)


def p16lu(number):
    return struct.pack("<H", number)


def p16ls(number):
    return struct.pack("<h", number)


def p16bu(number):
    return struct.pack(">H", number)


def p16bs(number):
    return struct.pack(">h", number)


def p32lu(number):
    return struct.pack("<I", number)


def p32ls(number):
    return struct.pack("<i", number)


def p32bu(number):
    return struct.pack(">I", number)


def p32bs(number):
    return struct.pack(">i", number)


def p64lu(number):
    return struct.pack("<Q", number)


def p64ls(number):
    return struct.pack("<q", number)


def p64bu(number):
    return struct.pack(">Q", number)


def p64bs(number):
    return struct.pack(">q", number)

def flat(*args, **kwargs):
    """Flattens the arguments into a string.

    This function takes an arbitrary number of arbitrarily nested lists and
    tuples. It will then find every string and number inside those and flatten
    them out. Strings are inserted directly while numbers are packed using the
    :func:`pack` function.

    Args:
      *args: Values to flatten
      word_size (int): Word size of the converted integer
      endianness (str): Endianness of the converted integer ("little"/"big")
      sign (str): Signedness of the converted integer ("unsigned"/"signed")"""

    out = []
    for arg in args:
        if isinstance(arg, (list, tuple)):
            out.append(flat(*arg, **kwargs))
        elif isinstance(arg, str):
            out.append(arg)
        elif isinstance(arg, (int, long)):
            out.append(pack(arg, **kwargs))
        else:
            raise ValueError("Flat does not support values of type %s" % type(arg))
    return ''.join(out)
