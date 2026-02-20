"""
Some glibc related convenient functions.
"""
from pwnlib.context import context
from pwnlib.util.fiddling import ror, rol

def ptr_mangle(guard: int, value: int) -> int:
    """ptr_mangle(int, int) -> int
    Perform ``PTR_MANGLE`` in glibc to protect pointers.

    Arguments:
        guard(int): The value of %fs:POINTER_GUARD.
        value(int): The value to protect.

    Returns:
        Mangled value.
    """
    return rol(value ^ guard, context.bytes * 2 + 1)

def ptr_demangle(guard: int, mangled: int) -> int:
    """ptr_demangle(int, int) -> int
    Perform ``PTR_DEMANGLE`` in glibc to demangle protected pointer.

    Arguments:
        guard(int): The value of %fs:POINTER_GUARD.
        mangled(int): The value to demangle.

    Returns:
        Demangled value.
    """
    return ror(mangled, context.bytes * 2 + 1) ^ guard

def protect_ptr(word_addr: int, value: int) -> int:
    """protect_ptr(int, int) -> int
    Perform ``PROTECT_PTR`` in glibc heap macros to protect pointers.
    ``REVEAL_PTR`` is basically ``PROTECT_PTR``, and since we don't know
    the address of the word, so use ``protect_ptr`` instead.

    Arguments:
        word_addr(int): The address of where ``value`` is stored.
        value(int): The value to protect/reveal

    Returns:
        Protected/Revealed value
    """
    return (word_addr >> 12) ^ value
