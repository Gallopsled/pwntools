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
    """
    if not vocab:
        vocab = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    else:
        required_chars = b'\\-%TXP'
        if not all((c in required_chars) for c in vocab):
            raise RuntimeError(
                f"These characters ({str(required_chars, 'ascii')}) are required because they assemble into instructions used to unpack the shellcode")

    if context.arch != 'i386' and context.bits != 32:
        raise RuntimeError('Only 32-bit i386 is currently supported')

    int_size = context.bits / 8

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

        >>> assert False
    """
    int_size = context.bits / 8
    # Use eax for subtractions because sub esp, X doesn't assemble to ascii
    result = b'TX'  # push esp; pop eax
    # Set target to the `slop` arg
    target = slop.to_bytes(int_size, 'little')
    # All we are doing here is adding (subtracting) `slop` to esp (to allocate
    # space on the stack), so we don't care about esp's actual value.
    # That's why the `last` parameter for `calc_subtractions` can just be zero
    for subtraction in _calc_subtractions(b'\x00'*int_size, target, vocab):
        # sub eax, subtraction
        result += struct.pack(f'=c{int_size}s', b'-', subtraction)
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

        >>> assert False
    """
    int_size = context.bits / 8
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

        >>> assert False
    """
    int_size = context.bits / 8
    result = bytes()
    last = b'\x00'*int_size
    # Group the shellcode into bytes of stack cell size, pad with NOPs
    # if the shellcode does not divide into stack cell size and reverse.
    # The shellcode will be reversed again back to it's original order once
    # it's pushed onto the stack
    sc = tuple(group(shellcode, int_size, 0x90))[::-1]
    # Pack the shellcode to a sub/push sequence
    for x in [bytes(y) for y in sc]:
        for subtraction in _calc_subtractions(last, x, vocab):
            # sub eax, `subtraction`
            result += struct.pack(f'=c{int_size}s', b'-', subtraction)
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

        >>> assert False
    """
    int_size = context.bits / 8
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
            f'Could not find the correct subtraction sequence to get the the desired target ({target[byte]}) from ({last[byte]})')
