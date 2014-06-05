from pwnlib import context
import struct

def p8(number, endianness=None, sign=None):
    """Packs 8-bit integer.
    Endianness and signedness is done according to context

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        A string of the number converted"""
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
    Endianness and signedness is done according to context

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        A string of the number converted"""
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
    Endianness and signedness is done according to context

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        A string of the number converted"""
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
    Endianness and signedness is done according to context

    Args:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        A string of the number converted"""
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
    Endianness and signedness is done according to context

    Args:
        data (str): stuff to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        A string of the number converted"""
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
    Endianness and signedness is done according to context

    Args:
        data (str): stuff to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        A string of the number converted"""
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
    Endianness and signedness is done according to context

    Args:
        data (str): stuff to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        A string of the number converted"""
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
    Endianness and signedness is done according to context

    Args:
        data (str): stuff to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (str): Signedness of the converted integer ("unsigned"/"signed")

    Returns:
        A string of the number converted"""
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
