""" Module to convert shellcode to shellcode that contains only ascii characters
"""

import struct
from itertools import chain
from itertools import product
from typing import List
from typing import Sequence
from typing import Tuple
from typing import Union

from pwnlib.util.iters import group
from pwnlib.context import LocalContext
from pwnlib.context import context

__all__ = ['asciify_shellcode']


@LocalContext
def asciify_shellcode(shellcode: bytes, slop: int, vocab: bytes = None) -> bytes:
    """ Pack i386 shellcode to ascii shellcode.

    Args:
        shellcode (bytes): The shellcode
        slop (int): How much to add to the esp minus the shellcod length
        vocab (bytes, optional): Allowed characters. Defaults to None.

    Raises:
        RuntimeError: A required character is not in ``vocab``
        RuntimeError: Not supported architecture

    Returns:
        bytes: The packed shellcode

    Examples:

        >>> sc = bytes.fromhex('83c41831c031dbb006cd8053682f747479682f64657689e331c966b91227b005cd806a175831dbcd806a2e5853cd8031c050682f2f7368682f62696e89e3505389e199b00bcd80')
        >>> print(asciify_shellcode(sc, 300, arch='i386').hex())
        54582d212121212d355f60602d7e7e7e7e505c252121212125404040402d213621212d567e21212d7e7e3c2d502d216d68612d617e7e7e502d21214c602d615e7e7e2d7e7e7e7e502d212169662d39607e7e502d212121212d614f61662d7e7e7e7e502d2126213c2d217e607e2d2d7e7e7e502d212121212d2121485e2d2b417e7e502d5521215b2d7e41317e502d2c3c56212d7e7e7e212d7e7e7e47502d213221382d6a7e4f7e502d215d21212d217e21722d797e777e502d632121212d7e3c282b502d4e215f572d7e317e7e502d21215d212d4d6e7e212d7e7e7e3c502d213c21212d727e21502d7e7e787e502d666521242d7e7e537e2d7e7e7e7e502d212127242d257a7e7e502d412121212d7e2123212d7e2a7e3d502d213721212d547e21212d7e7e455e505050
    """
    if not vocab:
        vocab = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    else:
        required_chars = b'\\-%TXP'
        if not all((c in required_chars) for c in vocab):
            raise RuntimeError(
                "These characters ({}) are required because they assemble into instructions used to unpack the shellcode".format(str(required_chars, 'ascii')))

    if context.arch != 'i386' and context.bits != 32:
        raise RuntimeError('Only 32-bit i386 is currently supported')

    int_size = context.bits // 8

    # Prepend with NOPs for the NOP sled
    shellcode = b'\x90'*int_size + shellcode
    allocator = _get_allocator(slop, vocab)
    subtractions = _get_subtractions(shellcode, vocab)
    nop_sled = b'P' * (slop - len(subtractions) - len(allocator))  # push eax
    return allocator + subtractions + nop_sled


@LocalContext
def _get_allocator(slop: int, vocab: bytes) -> bytes:
    """Allocate enough space on the stack for the shellcode

    int_size is taken from the context (context.bits / 8)

    Args:
        slop (int): The slop
        vocab (bytes): Allowed characters

    Returns:
        Tuple[bytes, bytes]: The allocator shellcode, the value of eax

    Examples:

        >>> vocab = bytes.fromhex('2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e')
        >>> print(_get_allocator(300, vocab, arch='i386').hex())
        54582d212121212d355f60602d7e7e7e7e505c25212121212540404040
    """
    int_size = context.bits // 8
    # Use eax for subtractions because sub esp, X doesn't assemble to ascii
    result = b'TX'  # push esp; pop eax
    # Set target to the `slop` arg
    target = slop.to_bytes(int_size, 'little')
    # All we are doing here is adding (subtracting) `slop` to esp (to allocate
    # space on the stack), so we don't care about esp's actual value.
    # That's why the `last` parameter for `calc_subtractions` can just be zero
    for subtraction in _calc_subtractions(b'\x00'*int_size, target, vocab):
        # sub eax, subtraction
        result += struct.pack('=c{}s'.format(int_size), b'-', subtraction)
    result += b'P\\'  # push eax, pop esp
    # Zero out eax for the unpacking part
    pos, neg = _find_negatives(vocab)
    # and eax, pos; and eax, neg ; (0b00010101 & 0b00101010 = 0b0)
    result += struct.pack('=cIcI', b'%', pos, b'%', neg)
    return result


@LocalContext
def _find_negatives(vocab: bytes) -> Tuple[int, int]:
    """ Find two bitwise negatives in the vocab so that when they are and-ed the result is 0.

    int_size is taken from the context (context.bits / 8)

    Args:
        vocab (bytes): Allowed characters

    Returns:
        Tuple[int, int]: value A, value B

    Examples:

        >>> vocab = bytes.fromhex('2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e')
        >>> a, b = _find_negatives(vocab, arch='i386')
        >>> a & b
        0
    """
    int_size = context.bits // 8
    for products in product(*[vocab for _ in range(2)]):
        if products[0] & products[1] == 0:
            return tuple(int.from_bytes(x.to_bytes(1, 'little')*int_size, 'little') for x in products)
    else:
        raise ArithmeticError(
            'Could not find two bitwise negatives in the provided vocab')


@LocalContext
def _get_subtractions(
        shellcode: bytes, vocab: bytes) -> bytes:
    """ Covert the sellcode to sub eax and posh eax instructions

    int_size is taken from the context (context.bits / 8)

    Args:
        last (bytes): The value of eax
        shellcode (bytes): The shellcode to pack
        vocab (bytes): Allowed characters

    Returns:
        Tuple[bytes, bytes]: packed shellcode, eax

    Examples:

        >>> sc = bytes.fromhex('414243444546474849474b4c4d4e4f5051525354555658595a')
        >>> vocab = bytes.fromhex('2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e')
        >>> print(_get_subtractions(sc, vocab, arch='i386').hex())
        2d282121212d7e4e4e4e502d213d3b3a2d667e7e7e2d7e7e7e7e502d212121212d656465652d7e7e7e7e502d212121212d656464642d7e7e7e7e502d212121212d656764642d7e7e7e7e502d212121212d656164642d7e7e7e7e502d212121212d656464642d7e7e7e7e50
    """
    int_size = context.bits // 8
    result = bytes()
    last = b'\x00'*int_size
    # Group the shellcode into bytes of stack cell size, pad with NOPs
    # if the shellcode does not divide into stack cell size and reverse.
    # The shellcode will be reversed again back to it's original order once
    # it's pushed onto the stack
    sc = tuple(group(int_size, shellcode, 0x90))[::-1]
    # Pack the shellcode to a sub/push sequence
    for x in [bytes(y) for y in sc]:
        for subtraction in _calc_subtractions(last, x, vocab):
            # sub eax, `subtraction`
            result += struct.pack('=c{}s'.format(int_size), b'-', subtraction)
        last = x
        result += b'P'  # push eax
    return result


@LocalContext
def _calc_subtractions(
        last: bytes, target: bytes, vocab: bytes, max_subs: int = 4) -> List[bytearray]:
    """Given `target` and `last`, return a list of integers that when subtracted from `last` will equal `target` while only constructing integers from bytes in `vocab`

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

        >>> vocab = bytes.fromhex('2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e')
        >>> print(_calc_subtractions(b'\x10'*4, b'\x11'*4, vocab))
        [bytearray(b'!!!!'), bytearray(b'`___'), bytearray(b'~~~~')]
        >>> print(_calc_subtractions(b'\x11\x12\x13\x14', b'\x15\x16\x17\x18', vocab))
        [bytearray(b'~}}}'), bytearray(b'~~~~')]
    """
    int_size = context.bits // 8
    subtractions = [bytearray(b'\x00'*int_size)]
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
