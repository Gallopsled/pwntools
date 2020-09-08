""" Module to convert shellcode to shellcode that contains only ascii characters
"""

import struct
from itertools import chain
from itertools import product
import six

from pwnlib.util.iters import group
from pwnlib.context import LocalContext
from pwnlib.context import context

__all__ = ['asciify_shellcode']


@LocalContext
def asciify_shellcode(shellcode, slop, vocab = None):
    """ Pack shellcode into only ascii characters that unpacks itself and executes (on the stack)

    Args:
        shellcode (bytes): The shellcode to be packed
        slop (int): The amount esp will be increased by in the allocation phase
        vocab (bytes, optional): Allowed characters. Defaults to 0x21-0x7e.

    Raises:
        RuntimeError: A required character is not in ``vocab``
        RuntimeError: Not supported architecture

    Returns:
        bytes: The packed shellcode

    Examples:

        >>> sc = b"\\x83\\xc4\\x181\\xc01\\xdb\\xb0\\x06\\xcd\\x80Sh/ttyh/dev\\x89\\xe31\\xc9f\\xb9\\x12'\\xb0\\x05\\xcd\\x80j\\x17X1\\xdb\\xcd\\x80j.XS\\xcd\\x801\\xc0Ph//shh/bin\\x89\\xe3PS\\x89\\xe1\\x99\\xb0\\x0b\\xcd\\x80"
        >>> asciify_shellcode(sc, 300, arch='i386')
        b"TX-!!!!-5_``-~~~~P\\\\%!!!!%@@@@-!6!!-V~!!-~~<-P-!mha-a~~~P-!!L`-a^~~-~~~~P-!!if-9`~~P-!!!!-aOaf-~~~~P-!&!<-!~`~--~~~P-!!!!-!!H^-+A~~P-U!![-~A1~P-,<V!-~~~!-~~~GP-!2!8-j~O~P-!]!!-!~!r-y~w~P-c!!!-~<(+P-N!_W-~1~~P-!!]!-Mn~!-~~~<P-!<!!-r~!P-~~x~P-fe!$-~~S~-~~~~P-!!'$-%z~~P-A!!!-~!#!-~*~=P-!7!!-T~!!-~~E^PPP"
    """
    if not vocab:
        vocab = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    else:
        required_chars = b'\\-%TXP'
        if not all((c in vocab) for c in required_chars):
            raise RuntimeError(
                "These characters ({}) are required because they assemble into instructions used to unpack the shellcode".format(str(required_chars, 'ascii')))

    if context.arch != 'i386' or context.bits != 32:
        raise RuntimeError('Only 32-bit i386 is currently supported')

    int_size = context.bits // 8

    # Prepend with NOPs for the NOP sled
    shellcode = b'\x90'*int_size + shellcode
    allocator = _get_allocator(slop, vocab)
    subtractions = _get_subtractions(shellcode, vocab)
    nop_sled = b'P' * (slop - len(subtractions) - len(allocator))  # push eax
    return allocator + subtractions + nop_sled


@LocalContext
def _get_allocator(slop, vocab):
    """ Allocate enough space on the stack for the shellcode

    int_size is taken from the context (context.bits / 8)

    Args:
        slop (int): The slop
        vocab (bytes): Allowed characters

    Returns:
        bytes: The allocator shellcode

    Examples:

        >>> vocab = b'!"#$%&\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
        >>> _get_allocator(300, vocab, arch='i386')
        b'TX-!!!!-5_``-~~~~P\\\\%!!!!%@@@@'
    """
    int_size = context.bits // 8
    # Use eax for subtractions because sub esp, X doesn't assemble to ascii
    result = b'TX'  # push esp; pop eax
    # Set target to the `slop` arg
    target = struct.pack('=I', slop)
    # All we are doing here is adding (subtracting) `slop` to esp (to allocate
    # space on the stack), so we don't care about esp's actual value.
    # That's why the `last` parameter for `calc_subtractions` can just be zero
    for subtraction in _calc_subtractions(b'\x00'*int_size, target, vocab):
        if six.PY2:
            subtraction = str(subtraction)
        # sub eax, subtraction
        result += struct.pack('=c{}s'.format(int_size), b'-', subtraction)
    result += b'P\\'  # push eax, pop esp
    # Zero out eax for the unpacking part
    pos, neg = _find_negatives(vocab)
    # and eax, pos; and eax, neg ; (0b00010101 & 0b00101010 = 0b0)
    result += struct.pack('=cIcI', b'%', pos, b'%', neg)
    return result


@LocalContext
def _find_negatives(vocab):
    """ Find two bitwise negatives in the vocab so that when they are and-ed the result is 0.

    int_size is taken from the context (context.bits / 8)

    Args:
        vocab (bytes): Allowed characters

    Returns:
        Tuple[int, int]: value A, value B

    Examples:

        >>> vocab = b'!"#$%&\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
        >>> a, b = _find_negatives(vocab, arch='i386')
        >>> a & b
        0
    """
    int_size = context.bits // 8
    for products in product(*[vocab for _ in range(2)]):
        if six.PY3:
            if products[0] & products[1] == 0:
                return tuple(int.from_bytes(x.to_bytes(1, 'little')*int_size, 'little') for x in products)
        elif six.PY2:
            if six.byte2int(products[0]) & six.byte2int(products[1]) == 0:
                return tuple(struct.unpack('=I', x*int_size)[0] for x in products)
    else:
        raise ArithmeticError(
            'Could not find two bitwise negatives in the provided vocab')


@LocalContext
def _get_subtractions(shellcode, vocab):
    """ Covert the sellcode to sub eax and posh eax instructions

    int_size is taken from the context (context.bits / 8)

    Args:
        shellcode (bytes): The shellcode to pack
        vocab (bytes): Allowed characters

    Returns:
        bytes: packed shellcode

    Examples:

        >>> sc = b'ABCDEFGHIGKLMNOPQRSTUVXYZ'
        >>> vocab = b'!"#$%&\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
        >>> _get_subtractions(sc, vocab, arch='i386')
        b'-(!!!-~NNNP-!=;:-f~~~-~~~~P-!!!!-edee-~~~~P-!!!!-eddd-~~~~P-!!!!-egdd-~~~~P-!!!!-eadd-~~~~P-!!!!-eddd-~~~~P'
    """
    int_size = context.bits // 8
    result = bytes()
    last = b'\x00'*int_size
    # Group the shellcode into bytes of stack cell size, pad with NOPs
    # if the shellcode does not divide into stack cell size and reverse.
    # The shellcode will be reversed again back to it's original order once
    # it's pushed onto the stack
    if six.PY3:
        sc = tuple(group(int_size, shellcode, 0x90))[::-1]
    elif six.PY2:
        sc = []
        for byte in group(int_size, shellcode, b'\x90'):
            sc.append(''.join(byte))
        sc = sc[::-1]
    # Pack the shellcode to a sub/push sequence
    for x in map(bytes, sc):
        for subtraction in _calc_subtractions(last, x, vocab):
            if six.PY2:
                subtraction = str(subtraction)
            # sub eax, `subtraction`
            result += struct.pack('=c{}s'.format(int_size), b'-', subtraction)
        last = x
        result += b'P'  # push eax
    return result


@LocalContext
def _calc_subtractions(last, target, vocab, max_subs = 4):
    """ Given `target` and `last`, return a list of integers that when subtracted from 
    `last` will equal `target` while only constructing integers from bytes in `vocab`

    int_size is take from the context (context.bits / 8)

    Args:
        last (bytes): Current value of eax
        target (bytes): Desired value of eax
        vocab (bytes): Allowed characters
        max_subs (int): Maximum subtraction attempts

    Raises:
        ArithmeticError: If a sequence of subtractions could not be found

    Returns:
        List[bytearray]: List of numbers that would need to be subtracted from `last` to get to `target`

    Examples:

        >>> vocab = b'!"#$%&\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
        >>> print(_calc_subtractions(b'\x10'*4, b'\x11'*4, vocab))
        [bytearray(b'!!!!'), bytearray(b'`___'), bytearray(b'~~~~')]
        >>> print(_calc_subtractions(b'\x11\x12\x13\x14', b'\x15\x16\x17\x18', vocab))
        [bytearray(b'~}}}'), bytearray(b'~~~~')]
    """
    int_size = context.bits // 8
    subtractions = [bytearray(b'\x00'*int_size)]
    if six.PY2:
        last = map(ord, last)
        target = map(ord, target)
    for subtraction in range(max_subs):
        carry = success_count = 0
        for byte in range(int_size):
            # Try all combinations of all the characters in vocab of
            # `subtraction` characters in each combination. So if `max_subs`
            # is 4 and we're on the second subtraction attempt, products will
            # equal [\, ", #, %, ...], [\, ", #, %, ...], 0, 0
            for products in product(
                *[x <= subtraction and vocab or (0,) for x in range(max_subs)]
            ):
                if six.PY2:
                    products = map(lambda x: isinstance(x, str) and ord(x) or x, products)
                # Sum up all the products, carry from last byte and the target
                attempt = sum(chain(
                    (target[byte], carry), products
                ))
                # If the attempt equals last, we've found the combination
                if last[byte] == attempt & 0xff:
                    carry = (attempt & 0xff00) >> 8
                    # Update the result with the current `products`
                    for p, i in zip(products, range(subtraction+1)):
                        subtractions[i][byte] = p
                    success_count += 1
                    break
        if success_count == int_size:
            return subtractions
        else:
            subtractions.append(bytearray(b'\x00'*int_size))
    else:
        raise ArithmeticError(
            str.format('Could not find the correct subtraction sequence to get the the desired target ({}) from ({})', target[byte], last[byte]))
